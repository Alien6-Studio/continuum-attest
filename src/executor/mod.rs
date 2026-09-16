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
}

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
            let sandbox_config = config
                .sandbox_config
                .clone()
                .unwrap_or_else(|| Self::create_default_sandbox_config(&config));
            Some(Sandbox::new(sandbox_config)?)
        } else {
            None
        };

        Ok(Self {
            storage,
            config,
            sandbox,
            mode_config,
        })
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
            let mut env = pipeline.env.clone();
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
            let content_hash = self.storage.compute_content_hash(
                &workspace,
                &step_name,
                &step.run,
                &step.inputs,
                &env,
            )?;

            // `cache: false` steps neither consult nor populate the cache.
            let cached_entry = if step.cache {
                self.storage.get_cached_entry(&content_hash)?
            } else {
                None
            };
            let (step_result, cache_hit) = if let Some(cached_entry) = cached_entry {
                tracing::info!("Cache hit for step: {}", step_name);
                (cached_entry.result, true)
            } else {
                tracing::info!("Cache miss for step: {}, executing...", step_name);
                let execution_result = if let Some(manifest) = &capsule {
                    Self::execute_step_in_capsule(manifest, step, &workspace)?
                } else {
                    self.execute_step(&step_name, step, &env).await?
                };

                let (output_hash, artifacts) =
                    crate::hashing::outputs_with_artifacts(&workspace, &step_name, &step.outputs)?;
                provenance.artifacts.extend(artifacts);
                let step_result = StepResult {
                    name: step_name.clone(),
                    input_hash: self.compute_input_hash(&step_name, step)?,
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

        let total_duration = start_time.elapsed();
        let pipeline_hash = self.compute_pipeline_hash(pipeline).await?;
        let timestamp = self.receipt_timestamp();

        // Record what happened into the causal ledger before building the
        // receipt: the event ids and the chain root are receipt fields, so
        // they have to exist before the signature covers them.
        let (causal_events, causal_chain_hash) = self
            .record_causal_events(pipeline, &step_results, &pipeline_hash)
            .await?;

        let mut receipt = Receipt {
            schema_version: Some(crate::storage::RECEIPT_SCHEMA_VERSION),
            pipeline_hash,
            steps: step_results,
            timestamp,
            total_duration_secs: total_duration.as_secs(),
            signature: None,
            signer_public_key: None,
            attest_version: "0.1.0".to_string(),
            causal_events,
            causal_chain_hash,
            reproducibility: None,
            provenance: Some(provenance),
            timestamp_token: None,
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
        step: &crate::pipeline::Step,
        workspace: &std::path::Path,
    ) -> Result<crate::sandbox::SandboxResult> {
        let command = vec!["sh".to_string(), "-c".to_string(), step.run.clone()];
        let output = crate::capsule::run_captured(manifest, workspace, &command)?;
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
