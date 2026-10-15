use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::time::Instant;

use crate::core::{ModeConfig, OperationMode};
use crate::pipeline::{ExecutionDAG, Pipeline};
use crate::sandbox::{ContainerRuntime, IsolationLevel, Sandbox, SandboxConfig};
use crate::storage::{Receipt, StepResult, Storage};

#[derive(Clone)]
pub struct ExecutorConfig {
    pub isolated: bool,
    pub sign_results: bool,
    pub max_parallel: usize,
    pub deterministic: bool,
    pub container_image: Option<String>,
    pub container_runtime: Option<ContainerRuntime>,
    pub sandbox_config: Option<SandboxConfig>,
    /// Reproducibility mode: normalize the build environment
    /// (SOURCE_DATE_EPOCH, TZ, locale) and do not inherit ambient env vars.
    pub hermetic_env: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            isolated: false,
            sign_results: false,
            max_parallel: num_cpus::get(),
            deterministic: true,
            container_image: None,
            container_runtime: None,
            sandbox_config: None,
            hermetic_env: false,
        }
    }
}

/// Normalized environment injected in hermetic mode (normative).
pub const HERMETIC_ENV: [(&str, &str); 4] = [
    ("SOURCE_DATE_EPOCH", "1704067200"),
    ("TZ", "UTC"),
    ("LC_ALL", "C.UTF-8"),
    ("LANG", "C.UTF-8"),
];

/// Seconds value of the `SOURCE_DATE_EPOCH` entry in [`HERMETIC_ENV`]
/// (2024-01-01T00:00:00Z). Hermetic receipts are stamped with this
/// instant so byte-identical builds produce byte-identical receipts.
pub const HERMETIC_SOURCE_DATE_EPOCH: i64 = 1_704_067_200;

pub struct Executor<'a> {
    // Mutable because the causal ledger is written during a run: the event
    // ids and the chain root belong in the receipt, and therefore have to
    // exist before it is signed.
    storage: &'a mut Storage,
    config: ExecutorConfig,
    sandbox: Option<Sandbox>,
    mode_config: Option<ModeConfig>,
    /// How to obtain the signing authority, called once every project
    /// command has finished and not before. Producing evidence and signing
    /// it are different trust operations: nothing a step runs should share
    /// the process that holds the key, so the key is not held while steps
    /// run.
    key_loader: Option<KeyLoader>,
    /// How the executed steps' declared inputs were held: how many steps
    /// ran, how many of those in a capsule (read-only mounts, enforced by
    /// the runtime), and whether the permission-bit guard could be applied
    /// at all (not as root, not without permission bits).
    inputs_held: InputsHeld,
}

#[derive(Default)]
struct InputsHeld {
    executed: usize,
    in_capsule: usize,
    guard_applied: bool,
}

/// A copy of a step's declared inputs, taken at hashing time and hashed
/// again to prove it is the state the receipt describes. Kept outside
/// the writable workspace so a step cannot change it through another
/// mount of the same files; removed when dropped.
struct InputSnapshot {
    root: std::path::PathBuf,
    paths: Vec<std::path::PathBuf>,
    _directory: tempfile::TempDir,
}

impl InputSnapshot {
    fn take(
        workspace: &std::path::Path,
        step_name: &str,
        step: &crate::pipeline::Step,
        expected_input_hash: &str,
    ) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("attest-inputs-")
            .tempdir()?;
        let root = directory.path().canonicalize()?;
        if root.starts_with(workspace.canonicalize()?) {
            anyhow::bail!("capsule snapshots require a temporary directory outside the workspace; set TMPDIR accordingly");
        }
        // Copy each tree once. Repeated declarations and a directory
        // declared alongside one of its children describe the same bytes.
        let mut paths = Vec::new();
        for input in &step.inputs {
            let mut relative = std::path::PathBuf::new();
            for component in input.components() {
                match component {
                    std::path::Component::Normal(part) => relative.push(part),
                    std::path::Component::CurDir => {}
                    _ => anyhow::bail!(
                        "capsule input {} must be a relative path without '..'",
                        input.display()
                    ),
                }
            }
            paths.push(relative);
        }
        paths.sort();
        paths.dedup();
        let mut minimal = Vec::<std::path::PathBuf>::new();
        for path in paths {
            if !minimal.iter().any(|parent| path.starts_with(parent)) {
                minimal.push(path);
            }
        }
        let snapshot = Self {
            root,
            paths: minimal,
            _directory: directory,
        };
        for input in &snapshot.paths {
            let from = workspace.join(input);
            let to = snapshot.root.join(input);
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)?;
            }
            copy_tree(&from, &to)
                .with_context(|| format!("cannot snapshot input {}", input.display()))?;
        }
        let hashed =
            crate::hashing::hash_inputs(&snapshot.root, step_name, &step.run, &step.inputs)?;
        if hashed != expected_input_hash {
            anyhow::bail!(
                "step '{}': declared inputs changed between hashing and snapshot (hashed {}, \
                 snapshot {}); the step did not run",
                step_name,
                expected_input_hash,
                hashed
            );
        }
        Ok(snapshot)
    }
}

impl Drop for InputSnapshot {
    fn drop(&mut self) {
        // InputGuard made the source directories read-only before the
        // copy. Restore access only on private snapshot directories, never
        // following a link, so TempDir can remove their contents too.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in walkdir::WalkDir::new(&self.root)
                .follow_links(false)
                .into_iter()
                .flatten()
            {
                if entry.file_type().is_dir() {
                    if let Ok(meta) = entry.metadata() {
                        let mode = meta.permissions().mode() | 0o700;
                        let _ = std::fs::set_permissions(
                            entry.path(),
                            std::fs::Permissions::from_mode(mode),
                        );
                    }
                }
            }
        }
    }
}

/// Copy a file, a directory tree or a symbolic link as it is: links stay
/// links (never followed), modes are kept. Directory entries are copied in
/// name order, so two snapshots of the same tree are built the same way.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(from)?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(from)?;
        if target.is_absolute() {
            anyhow::bail!(
                "capsule snapshots require relative symbolic links: {}",
                from.display()
            );
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, to)?;
        #[cfg(not(unix))]
        anyhow::bail!("symbolic links in snapshots need a Unix platform");
        return Ok(());
    }
    if meta.is_dir() {
        std::fs::create_dir_all(to)?;
        let mut entries: Vec<_> = std::fs::read_dir(from)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        }
        std::fs::set_permissions(to, meta.permissions())?;
        return Ok(());
    }
    std::fs::copy(from, to)?;
    Ok(())
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    fn step(inputs: &[&str]) -> crate::pipeline::Step {
        let mut step: crate::pipeline::Step = serde_yaml::from_str("run: cat src/a.txt").unwrap();
        step.inputs = inputs.iter().map(std::path::PathBuf::from).collect();
        step
    }

    fn workspace() -> tempfile::TempDir {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("src")).unwrap();
        std::fs::write(workspace.path().join("src/a.txt"), "original\n").unwrap();
        workspace
    }

    fn hash(workspace: &std::path::Path, step: &crate::pipeline::Step) -> String {
        crate::hashing::hash_inputs(workspace, "build", &step.run, &step.inputs).unwrap()
    }

    #[test]
    fn snapshot_is_outside_the_writable_workspace() {
        let workspace = workspace();
        let step = step(&["src"]);
        let expected = hash(workspace.path(), &step);
        let guard = InputGuard::hold(workspace.path(), &step.inputs).unwrap();
        let snapshot = InputSnapshot::take(workspace.path(), "build", &step, &expected).unwrap();
        let root = snapshot.root.clone();
        assert!(
            !root
                .canonicalize()
                .unwrap()
                .starts_with(workspace.path().canonicalize().unwrap()),
            "a writable workspace alias would bypass the read-only input mount"
        );
        drop(snapshot);
        assert!(
            !root.exists(),
            "read-only directories must be cleaned up too"
        );
        drop(guard);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_accepts_overlapping_and_repeated_inputs() {
        let workspace = workspace();
        std::os::unix::fs::symlink("src/a.txt", workspace.path().join("link")).unwrap();
        let step = step(&["src", "src/a.txt", "link", "link", "src"]);
        let expected = hash(workspace.path(), &step);
        let snapshot = InputSnapshot::take(workspace.path(), "build", &step, &expected).unwrap();
        assert_eq!(hash(&snapshot.root, &step), expected);
        assert_eq!(
            std::fs::read_to_string(snapshot.root.join("link")).unwrap(),
            "original\n"
        );
    }

    #[test]
    fn snapshot_refuses_inputs_changed_since_hashing() {
        let workspace = workspace();
        let step = step(&["src"]);
        let expected = hash(workspace.path(), &step);
        std::fs::write(workspace.path().join("src/a.txt"), "changed\n").unwrap();
        let error = InputSnapshot::take(workspace.path(), "build", &step, &expected)
            .err()
            .unwrap();
        assert!(error
            .to_string()
            .contains("changed between hashing and snapshot"));
    }
}

/// Declared inputs held unwritable while a step runs, restored afterwards.
///
/// Permission bits, not a mount: every regular file and directory under a
/// declared input loses its write bits before the step starts and gets
/// them back when the guard drops, on success or failure. A process
/// running as the same user could put the bits back itself; the re-hash
/// catches only changes that are still present afterwards. Root is not
/// bound by permission bits, and the receipt reports this limitation.
struct InputGuard {
    restore: Vec<(std::path::PathBuf, u32)>,
    enforced: bool,
}

impl InputGuard {
    fn hold(workspace: &std::path::Path, inputs: &[std::path::PathBuf]) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // SAFETY: geteuid has no preconditions and cannot fail.
            if unsafe { libc::geteuid() } == 0 {
                return Ok(Self {
                    restore: Vec::new(),
                    enforced: false,
                });
            }
            // Construct the guard before the first chmod so a later
            // failure also restores paths already made read-only.
            let mut guard = Self {
                restore: Vec::new(),
                enforced: true,
            };
            for input in inputs {
                let root = workspace.join(input);
                let Ok(meta) = std::fs::symlink_metadata(&root) else {
                    // A missing input is reported by hashing, with the
                    // right error; nothing to hold here.
                    continue;
                };
                let paths: Vec<std::path::PathBuf> = if meta.is_dir() {
                    walkdir::WalkDir::new(&root)
                        .follow_links(false)
                        .into_iter()
                        .filter_map(Result::ok)
                        .filter(|e| !e.file_type().is_symlink())
                        .map(|e| e.into_path())
                        .collect()
                } else if meta.file_type().is_symlink() {
                    Vec::new()
                } else {
                    vec![root]
                };
                for path in paths {
                    let mode = std::fs::symlink_metadata(&path)?.permissions().mode();
                    if mode & 0o222 == 0 {
                        continue;
                    }
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & !0o222))
                        .map_err(|e| {
                            anyhow::anyhow!("cannot make input {} read-only: {e}", path.display())
                        })?;
                    guard.restore.push((path, mode));
                }
            }
            Ok(guard)
        }
        #[cfg(not(unix))]
        {
            let _ = (workspace, inputs);
            Ok(Self {
                restore: Vec::new(),
                enforced: false,
            })
        }
    }

    fn enforced(&self) -> bool {
        self.enforced
    }
}

impl Drop for InputGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for (path, mode) in self.restore.drain(..).rev() {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
            }
        }
    }
}

/// Loads the keypair that signs the receipt and the ledger events. Invoked
/// after the last step, so a step cannot observe or influence the
/// authority; a loader that fails fails the run, with no receipt written.
pub type KeyLoader = Box<dyn FnOnce() -> Result<crate::crypto::sign::AttestKeypair> + Send + Sync>;

impl<'a> Executor<'a> {
    pub fn new(storage: &'a mut Storage, config: ExecutorConfig) -> Result<Self> {
        Self::with_mode(storage, config, None)
    }

    pub fn with_mode(
        storage: &'a mut Storage,
        config: ExecutorConfig,
        mode_config: Option<ModeConfig>,
    ) -> Result<Self> {
        // Create sandbox if isolation is enabled
        let sandbox = if config.isolated {
            let mut sandbox_config = config
                .sandbox_config
                .clone()
                .unwrap_or_else(|| Self::create_default_sandbox_config(&config));
            if config.hermetic_env {
                sandbox_config.inherit_environment = false;
            }
            Some(Sandbox::new(sandbox_config)?)
        } else {
            None
        };

        Ok(Self {
            storage,
            config,
            sandbox,
            mode_config,
            key_loader: None,
            inputs_held: InputsHeld::default(),
        })
    }

    /// Sign this run's receipt with the authority `loader` produces, loaded
    /// only once every step has run.
    pub fn sign_with(&mut self, loader: KeyLoader) {
        self.key_loader = Some(loader);
    }

    /// The moment signing authority becomes available: after the steps,
    /// before the ledger events and the receipt are assembled. Nothing the
    /// project controls runs past this point.
    fn load_signing_key(&mut self) -> Result<()> {
        if let Some(loader) = self.key_loader.take() {
            let keypair = loader()?;
            self.storage.set_keypair(keypair);
        }
        Ok(())
    }

    fn create_default_sandbox_config(config: &ExecutorConfig) -> SandboxConfig {
        let isolation_level = if config.container_image.is_some() {
            IsolationLevel::Container
        } else {
            IsolationLevel::Process
        };

        let container_config = config
            .container_image
            .as_ref()
            .map(|image| crate::sandbox::container::ContainerUtils::secure_attest_config(image));

        SandboxConfig {
            isolation_level,
            deterministic_time: config.deterministic,
            fixed_timestamp: None,
            resource_limits: crate::sandbox::ResourceLimits::default(),
            network_policy: crate::sandbox::NetworkPolicy::Disabled,
            filesystem_policy: crate::sandbox::FilesystemPolicy::default(),
            container_config,
            seccomp_profile: Some("minimal".to_string()),
            security_level: crate::sandbox::SecurityLevel::Minimal,
            inherit_environment: !config.hermetic_env,
        }
    }

    pub async fn run(&mut self, pipeline: &Pipeline) -> Result<Receipt> {
        let start_time = Instant::now();
        let mut provenance = crate::provenance::collect(
            &std::env::current_dir()?,
            pipeline.name.clone(),
            self.config.hermetic_env
                || self
                    .config
                    .sandbox_config
                    .as_ref()
                    .is_some_and(|s| s.deterministic_time && s.fixed_timestamp.is_some()),
        );
        provenance.steps = pipeline
            .steps
            .iter()
            .map(|(name, step)| {
                crate::provenance::step(
                    name,
                    &step.run,
                    step.needs.as_deref().unwrap_or(&[]),
                    &step.inputs,
                    &step.outputs,
                )
            })
            .collect();
        provenance.steps.sort_by(|a, b| a.name.cmp(&b.name));

        // Build DAG for execution order
        let dag = ExecutionDAG::build(pipeline)?;
        let execution_order = dag.topological_sort()?;

        let mut step_results = Vec::new();
        let mut completed_steps = std::collections::HashSet::new();
        // Steps whose command failed, or that were skipped because a
        // dependency did not succeed. Dependents of either must not run:
        // their declared inputs may not exist, and executing them would
        // record success for work built on a failed foundation.
        // Skipped steps are left out of the receipt entirely — a receipt
        // step must carry real input/output hashes, which a step that
        // never ran cannot produce.
        let mut unsuccessful_steps = std::collections::HashSet::new();

        // Execute steps in topological order
        for step_name in execution_order {
            let step = pipeline
                .steps
                .get(&step_name)
                .context("Step not found in pipeline")?;

            if let Some(needs) = &step.needs {
                if let Some(dep) = needs.iter().find(|dep| unsuccessful_steps.contains(*dep)) {
                    tracing::warn!(
                        "Skipping step '{}': dependency '{}' did not succeed",
                        step_name,
                        dep
                    );
                    unsuccessful_steps.insert(step_name.clone());
                    completed_steps.insert(step_name);
                    continue;
                }
            }

            // Wait for dependencies to complete
            if let Some(needs) = &step.needs {
                for dep in needs {
                    while !completed_steps.contains(dep) {
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }

            tracing::info!("Processing step: {}", step_name);

            let step_start = Instant::now();

            // Prepare environment variables
            // The pipeline stores env in an ordered map so that its hash is
            // canonical; execution only needs a lookup table.
            let mut env: HashMap<String, String> = pipeline.env.clone().into_iter().collect();
            if let Some(step_env) = &step.env {
                env.extend(step_env.clone());
            }
            env.insert("ATTEST_STEP_NAME".to_string(), step_name.to_string());
            env.insert(
                "ATTEST_DETERMINISTIC".to_string(),
                self.config.deterministic.to_string(),
            );

            // Apply mode-specific environment variables
            env.extend(self.apply_mode_optimizations());

            // Hermetic mode: normalized vars override anything declared.
            if self.config.hermetic_env {
                for (key, value) in HERMETIC_ENV {
                    env.insert(key.to_string(), value.to_string());
                }
            }

            // Capsule steps: load and validate the manifest up
            // front, record its hash in the receipt, and fold it into the
            // cache key via the environment so a capsule change is a miss.
            let capsule = step
                .capsule
                .as_deref()
                .map(|name| {
                    let workspace = std::env::current_dir()?;
                    crate::capsule::load(&workspace, name)
                })
                .transpose()?;
            let capsule_hash = capsule
                .as_ref()
                .and_then(|manifest| manifest.capsule_hash.clone());
            if let Some(hash) = &capsule_hash {
                env.insert("ATTEST_CAPSULE_HASH".to_string(), hash.clone());
            }

            let duration = step_start.elapsed();

            // Check cache before execution. The key is derived from the
            // canonical manifest input hash, so a missing declared input
            // fails the run here instead of being silently skipped.
            let workspace = std::env::current_dir()?;
            // The step's shape, so that changing where or how it runs is a
            // cache miss rather than someone else's result.
            let step_shape = step.execution_shape();
            let content_hash = self.storage.compute_content_hash(
                &workspace,
                &step_name,
                &step.run,
                &step.inputs,
                &env,
                &step_shape,
            )?;

            // The receipt's input hash has to describe the inputs the step
            // *read*, so it is computed here, before anything runs. Taking
            // it afterwards let a step read a file, produce its result, then
            // rewrite that file: the receipt attested the rewritten version
            // and verification passed on an artifact built from the old one.
            let input_hash = self.compute_input_hash(&step_name, step)?;

            // `cache: false` steps neither consult nor populate the cache.
            let cached_entry = if step.cache {
                self.storage.get_cached_entry(&content_hash)?
            } else {
                None
            };

            let cached_entry = cached_entry
                .filter(|entry| outputs_still_match(&workspace, &step_name, step, entry));

            let (step_result, cache_hit) = if let Some(cached_entry) = cached_entry {
                tracing::info!("Cache hit for step: {}", step_name);
                (cached_entry.result, true)
            } else {
                tracing::info!("Cache miss for step: {}, executing...", step_name);
                // The declared inputs are what the receipt will say the
                // step read. For as long as the step runs they are not
                // writable through the filesystem: a step that tries to
                // rewrite one fails at the write, instead of the receipt
                // failing afterwards to describe what was built.
                let guard = InputGuard::hold(&workspace, &step.inputs)?;
                self.inputs_held.executed += 1;
                self.inputs_held.guard_applied = (self.inputs_held.executed == 1
                    || self.inputs_held.guard_applied)
                    && guard.enforced();
                if capsule.is_some() {
                    self.inputs_held.in_capsule += 1;
                }
                let execution_result = if let Some(manifest) = &capsule {
                    Self::execute_step_in_capsule(
                        manifest,
                        &step_name,
                        step,
                        &workspace,
                        &input_hash,
                    )
                } else {
                    self.execute_step(&step_name, step, &env).await
                };
                drop(guard);
                let execution_result = execution_result?;

                // A step that rewrites its own declared input leaves the
                // receipt unable to describe the build honestly: the hash
                // recorded is of bytes the step never read. Refuse rather
                // than sign a receipt that cannot be reproduced.
                let inputs_after = self.compute_input_hash(&step_name, step)?;
                if inputs_after != input_hash {
                    anyhow::bail!(
                        "step '{}' modified its own declared inputs while running \
                         (before {}, after {}); the receipt could not describe what was built",
                        step_name,
                        input_hash,
                        inputs_after
                    );
                }

                let (output_hash, artifacts) =
                    crate::hashing::outputs_with_artifacts(&workspace, &step_name, &step.outputs)?;
                provenance.artifacts.extend(artifacts);
                let step_result = StepResult {
                    name: step_name.clone(),
                    input_hash: input_hash.clone(),
                    output_hash,
                    duration_secs: step_start.elapsed().as_secs(),
                    exit_code: execution_result.exit_code,
                    cache_hit: false,
                    stdout: execution_result.stdout,
                    stderr: execution_result.stderr,
                    capsule_hash: capsule_hash.clone(),
                };

                // Only successful results are cached: a
                // cached failure would be replayed on every later run
                // with the same inputs, turning a transient failure
                // into a persistent one.
                if step.cache && step_result.exit_code == 0 {
                    let cache_entry = self.storage.create_cache_entry(
                        &workspace,
                        &step_name,
                        &step.run,
                        step.inputs.clone(),
                        step.outputs.clone(),
                        &env,
                        step_result.clone(),
                        step.needs.clone().unwrap_or_default(),
                        &step_shape,
                    )?;

                    self.storage.cache_entry(&cache_entry)?;
                    tracing::info!(
                        "Cached result for step: {} with hash: {}",
                        step_name,
                        content_hash
                    );
                }

                (step_result, false)
            };

            let mut final_step_result = step_result;
            final_step_result.cache_hit = cache_hit;

            // Log mode-specific metrics
            self.log_mode_metrics(&step_name, duration, cache_hit);

            if final_step_result.exit_code != 0 {
                unsuccessful_steps.insert(step_name.clone());
            }
            step_results.push(final_step_result);
            completed_steps.insert(step_name);
        }

        // Every project command has completed. Only now does the signing
        // authority exist in this process.
        self.load_signing_key()?;

        let total_duration = start_time.elapsed();
        let pipeline_hash = self.compute_pipeline_hash(pipeline).await?;
        let timestamp = self.receipt_timestamp();

        // Record what happened into the causal ledger before building the
        // receipt: the event ids and the chain root are receipt fields, so
        // they have to exist before the signature covers them.
        let (causal_events, causal_chain_hash) = self
            .record_causal_events(pipeline, &step_results, &pipeline_hash)
            .await?;

        // What this run can claim about isolation: derived from the sandbox
        // that ran the steps, or the absence of one, never from the mode's
        // name. Capsule steps are listed apart, under their own controls.
        let mut isolation = match &self.sandbox {
            Some(sandbox) => sandbox.isolation_report(self.config.hermetic_env),
            None => crate::sandbox::unisolated_report(self.config.hermetic_env),
        };
        isolation.capsule_steps = step_results
            .iter()
            .filter(|s| s.capsule_hash.is_some())
            .map(|s| s.name.clone())
            .collect();
        // Declared inputs. A capsule mounts them read-only and the runtime
        // refuses the write, whatever the step runs as: that is enforced. A
        // local step gets its inputs' write bits dropped, which refuses a
        // plain write but not a step that puts the bits back, changes the
        // file and restores it before it ends; the re-hash afterwards sees
        // nothing. So the row says not enforced outside a capsule, and says
        // why, rather than naming a guard as a guarantee.
        let held = &self.inputs_held;
        let (status, detail) = if held.executed == 0 {
            (
                crate::sandbox::ControlStatus::NotEnforced,
                "no step executed (every step was a cache hit)".to_string(),
            )
        } else if held.in_capsule == held.executed {
            (
                crate::sandbox::ControlStatus::Enforced,
                "every step ran in a capsule with its declared inputs mounted read-only from a \
                 snapshot taken at hashing time: the runtime refuses writes from inside, and a \
                 change on the host during the step never reaches the step's view"
                    .to_string(),
            )
        } else if held.guard_applied {
            (
                crate::sandbox::ControlStatus::NotEnforced,
                format!(
                    "write bits dropped on declared inputs while each step ran, which refuses a \
                     plain write but not a step that restores the bits, changes a file and puts \
                     it back before it ends; changes still present after the step are detected \
                     by re-hashing, changes undone before it ends are not. Only a capsule \
                     enforces this ({} of {} steps ran in one)",
                    held.in_capsule, held.executed
                ),
            )
        } else if cfg!(unix) {
            (
                crate::sandbox::ControlStatus::NotEnforced,
                "running as root, permission bits do not bind; changes to declared inputs are \
                 detected by re-hashing after the step, not prevented"
                    .to_string(),
            )
        } else {
            (
                crate::sandbox::ControlStatus::NotAvailable,
                "no read-only view on this platform; changes to declared inputs are detected by \
                 re-hashing after the step, not prevented"
                    .to_string(),
            )
        };
        isolation.controls.push(crate::sandbox::IsolationControl {
            name: "inputs".to_string(),
            status,
            detail,
        });

        let mut receipt = Receipt {
            schema_version: Some(crate::storage::RECEIPT_SCHEMA_VERSION),
            pipeline_hash,
            steps: step_results,
            timestamp,
            total_duration_secs: total_duration.as_secs(),
            signature: None,
            signer_public_key: None,
            attest_version: env!("CARGO_PKG_VERSION").to_string(),
            causal_events,
            causal_chain_hash,
            reproducibility: None,
            provenance: Some(provenance),
            timestamp_token: None,
            isolation: Some(isolation),
        };

        // Sign the receipt based on mode configuration
        if self.should_sign_receipt() {
            receipt = self.storage.sign_receipt(&receipt)?;
        }

        Ok(receipt)
    }

    /// Write one ledger event per executed step and return their ids plus
    /// the Merkle root of the resulting chain.
    ///
    /// Parents come from the pipeline's `needs`: a step's event points at
    /// the events of the steps it waited for, which is what makes the
    /// ledger a causal DAG rather than a list. A dependency that produced
    /// no event — because it was skipped — contributes no parent, so the
    /// chain never references something that did not happen.
    async fn record_causal_events(
        &mut self,
        pipeline: &Pipeline,
        step_results: &[StepResult],
        pipeline_hash: &str,
    ) -> Result<(Vec<String>, Option<String>)> {
        if step_results.is_empty() {
            return Ok((Vec::new(), None));
        }

        // The environment a step ran in is part of why its output is what it
        // is, so it is recorded alongside the hashes.
        let environment_hash = blake3::hash(
            format!(
                "{}:{}:{}",
                std::env::consts::OS,
                std::env::consts::ARCH,
                self.config.hermetic_env
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string();

        let mut by_step: HashMap<String, String> = HashMap::new();
        let mut ordered = Vec::with_capacity(step_results.len());

        for result in step_results {
            let parents: Vec<String> = pipeline
                .steps
                .get(&result.name)
                .and_then(|step| step.needs.as_ref())
                .map(|needs| {
                    needs
                        .iter()
                        .filter_map(|dep| by_step.get(dep).cloned())
                        .collect()
                })
                .unwrap_or_default();

            let event = self
                .storage
                .record_causal_event(
                    &result.name,
                    parents,
                    result,
                    pipeline_hash,
                    &environment_hash,
                )
                .await
                .with_context(|| {
                    format!("cannot record causal event for step '{}'", result.name)
                })?;

            by_step.insert(result.name.clone(), event.event_id.clone());
            ordered.push(event);
        }

        // The root is computed over the execution order, which is the order
        // the receipt publishes. Anyone holding the events and the receipt
        // can recompute it; deriving the order again would risk a different
        // one and a spurious mismatch.
        let chain_hash = crate::storage::causal_ledger::CausalLedger::chain_hash(&ordered);
        let ids = ordered.into_iter().map(|event| event.event_id).collect();
        Ok((ids, Some(chain_hash)))
    }

    /// Timestamp recorded in the receipt.
    ///
    /// By default the receipt records when the run actually happened:
    /// key revocation compares this against `revoked_at`, so
    /// wall-clock is the only safe default. Reproducible runs are the
    /// explicit exception: a sandbox configured with
    /// `deterministic_time` and a `fixed_timestamp`, or hermetic mode
    /// (which pins `SOURCE_DATE_EPOCH`), stamps that fixed instant so
    /// identical builds yield identical receipts. Opting in trades
    /// revocation-window precision for reproducibility: verifiers must
    /// treat a pinned timestamp as the declared build epoch, not as
    /// evidence the signature predates a revocation.
    fn receipt_timestamp(&self) -> chrono::DateTime<Utc> {
        if let Some(fixed) = self
            .config
            .sandbox_config
            .as_ref()
            .filter(|sandbox| sandbox.deterministic_time)
            .and_then(|sandbox| sandbox.fixed_timestamp)
        {
            return fixed;
        }
        if self.config.hermetic_env {
            if let Some(epoch) = chrono::DateTime::from_timestamp(HERMETIC_SOURCE_DATE_EPOCH, 0) {
                return epoch;
            }
        }
        Utc::now()
    }

    /// Execute a `capsule:` step inside its capsule. The
    /// capsule's own isolation replaces the sandbox for this step; the
    /// process env is the manifest env + normalization set only.
    fn execute_step_in_capsule(
        manifest: &crate::capsule::CapsuleManifest,
        step_name: &str,
        step: &crate::pipeline::Step,
        workspace: &std::path::Path,
        input_hash: &str,
    ) -> Result<crate::sandbox::SandboxResult> {
        let command = vec!["sh".to_string(), "-c".to_string(), step.run.clone()];
        // The step reads its declared inputs from a snapshot, not from the
        // workspace: a copy taken now, hashed, and required to match the
        // hash the receipt will carry. A process on the host can change the
        // workspace while the step runs; it cannot change what the step
        // sees, and if it changes the workspace between the hash and the
        // copy, the mismatch refuses the step.
        let snapshot = InputSnapshot::take(workspace, step_name, step, input_hash)?;
        let mounts = crate::capsule::InputMounts {
            root: snapshot.root.clone(),
            paths: snapshot.paths.clone(),
        };
        let output = crate::capsule::run_captured(manifest, workspace, &mounts, &command);
        drop(snapshot);
        let output = output?;
        Ok(crate::sandbox::SandboxResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            execution_time: std::time::Duration::from_secs(0),
            deterministic_timestamp: None,
            resource_usage: crate::sandbox::ResourceUsage::default(),
            isolation_violations: vec![],
        })
    }

    async fn execute_step(
        &mut self,
        _step_name: &str,
        step: &crate::pipeline::Step,
        env: &HashMap<String, String>,
    ) -> Result<crate::sandbox::SandboxResult> {
        let working_dir = step.working_dir.as_deref();
        let timeout = step.timeout_secs.map(std::time::Duration::from_secs);

        if let Some(sandbox) = &mut self.sandbox {
            // Execute in sandbox
            let command = if cfg!(target_os = "windows") {
                "cmd"
            } else {
                "sh"
            };
            let args = if cfg!(target_os = "windows") {
                vec!["/C".to_string(), step.run.clone()]
            } else {
                vec!["-c".to_string(), step.run.clone()]
            };

            sandbox
                .execute_with_timeout(command, &args, env, working_dir, timeout)
                .await
        } else {
            // Direct execution without sandbox
            let (program, args) = if cfg!(target_os = "windows") {
                ("cmd", ["/C", step.run.as_str()])
            } else {
                ("sh", ["-c", step.run.as_str()])
            };
            let mut command = std::process::Command::new(program);
            command.args(args);
            if let Some(dir) = working_dir {
                // A relative working_dir is resolved against the workspace
                // root (the attest process cwd). Declared inputs/outputs are
                // always workspace-root-relative, independent of working_dir.
                let dir = std::env::current_dir()?.join(dir);
                if !dir.is_dir() {
                    anyhow::bail!(
                        "working_dir '{}' does not exist or is not a directory",
                        dir.display()
                    );
                }
                command.current_dir(dir);
            }
            if self.config.hermetic_env {
                // Ambient env must not leak into the build; keep only PATH
                // (needed to resolve tools) unless the pipeline declares it.
                command.env_clear();
                if !env.contains_key("PATH") {
                    if let Ok(path) = std::env::var("PATH") {
                        command.env("PATH", path);
                    }
                }
            }
            command.envs(env);
            let output = crate::sandbox::run_with_timeout(&mut command, timeout)?;

            Ok(crate::sandbox::SandboxResult {
                exit_code: output.exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
                execution_time: std::time::Duration::from_secs(0),
                deterministic_timestamp: None,
                resource_usage: crate::sandbox::ResourceUsage::default(),
                isolation_violations: vec![],
            })
        }
    }

    fn compute_input_hash(&self, step_name: &str, step: &crate::pipeline::Step) -> Result<String> {
        let workspace = std::env::current_dir()?;
        Ok(crate::hashing::hash_inputs(
            &workspace,
            step_name,
            &step.run,
            &step.inputs,
        )?)
    }

    async fn compute_pipeline_hash(&self, pipeline: &Pipeline) -> Result<String> {
        let serialized = serde_yaml::to_string(pipeline)?;
        let hash = blake3::hash(serialized.as_bytes());
        Ok(hash.to_hex().to_string())
    }

    /// Determine if receipt should be signed based on mode configuration
    fn should_sign_receipt(&self) -> bool {
        if let Some(mode_config) = &self.mode_config {
            mode_config.crypto.signatures_enabled
        } else {
            self.config.sign_results
        }
    }

    /// Get the hash algorithm to use based on mode configuration
    fn get_hash_algorithm(&self) -> &str {
        if let Some(mode_config) = &self.mode_config {
            match mode_config.crypto.hash_algorithm {
                crate::core::HashAlgorithm::Blake3 => "blake3",
                crate::core::HashAlgorithm::Sha256 => "sha256",
                crate::core::HashAlgorithm::Sha3_256 => "sha3-256",
            }
        } else {
            "blake3" // Default
        }
    }

    /// Apply mode-specific execution optimizations
    fn apply_mode_optimizations(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();

        if let Some(mode_config) = &self.mode_config {
            // Add mode information to environment
            env.insert("ATTEST_MODE".to_string(), mode_config.mode.to_string());
            env.insert(
                "ATTEST_HASH_ALGORITHM".to_string(),
                self.get_hash_algorithm().to_string(),
            );

            // Performance optimizations for Light mode
            if matches!(mode_config.mode, OperationMode::Light) {
                env.insert(
                    "ATTEST_SKIP_EXPENSIVE_CHECKS".to_string(),
                    "true".to_string(),
                );
                env.insert("ATTEST_CACHE_AGGRESSIVE".to_string(), "true".to_string());
            }

            // Security settings for Formal Proof mode
            if matches!(mode_config.mode, OperationMode::FormalProof) {
                env.insert("ATTEST_STRICT_MODE".to_string(), "true".to_string());
                env.insert("ATTEST_REQUIRE_SIGNATURES".to_string(), "true".to_string());
            }

            // Compliance framework
            if let Some(framework) = &mode_config.audit.compliance_framework {
                env.insert(
                    "ATTEST_COMPLIANCE_FRAMEWORK".to_string(),
                    format!("{:?}", framework),
                );
            }
        }

        env
    }

    /// Log mode-specific execution metrics
    fn log_mode_metrics(&self, step_name: &str, duration: std::time::Duration, cache_hit: bool) {
        if let Some(mode_config) = &self.mode_config {
            if mode_config.audit.detailed_logging {
                tracing::info!(
                    mode = %mode_config.mode,
                    step = %step_name,
                    duration_ms = duration.as_millis(),
                    cache_hit = cache_hit,
                    isolation = ?mode_config.isolation.isolation_level,
                    "Step execution completed"
                );
            }
        }
    }
}

/// Whether a cache entry's outputs are still the ones on disk.
///
/// A cache entry records what some earlier run produced. It is not evidence
/// that those outputs still exist. Replaying one unchecked signed a receipt
/// attesting artifacts that had been deleted: the run reported success, a
/// fresh receipt was written, and the file was simply not there. An entry
/// that cannot be reproduced from the workspace is treated as a miss, and
/// the step runs again.
fn outputs_still_match(
    workspace: &std::path::Path,
    step_name: &str,
    step: &crate::pipeline::Step,
    entry: &crate::storage::CacheEntry,
) -> bool {
    match crate::hashing::hash_outputs(workspace, step_name, &step.outputs) {
        Ok(on_disk) => {
            let same = on_disk == entry.result.output_hash;
            if !same {
                tracing::warn!(
                    "step '{}': cached outputs no longer match the workspace; re-running",
                    step_name
                );
            }
            same
        }
        Err(err) => {
            tracing::warn!(
                "step '{}': cached outputs cannot be verified ({}); re-running",
                step_name,
                err
            );
            false
        }
    }
}
