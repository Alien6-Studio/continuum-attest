//! ATTEST Core - Main orchestration logic with operation modes support

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use crate::pipeline::Pipeline;
use crate::storage::Storage;

/// Operation modes for ATTEST pipeline execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OperationMode {
    /// Light mode: Minimal overhead with basic hashing and reproductibility
    #[default]
    Light,
    /// Verifiable mode: Intermediate cryptographic guarantees
    Verifiable,
    /// Formal Proof mode: Maximum attestation with legal-grade evidence
    FormalProof,
}

impl std::fmt::Display for OperationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationMode::Light => write!(f, "light"),
            OperationMode::Verifiable => write!(f, "verifiable"),
            OperationMode::FormalProof => write!(f, "formal-proof"),
        }
    }
}

impl std::str::FromStr for OperationMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "light" => Ok(OperationMode::Light),
            "verifiable" => Ok(OperationMode::Verifiable),
            "formal-proof" | "formal_proof" => Ok(OperationMode::FormalProof),
            _ => anyhow::bail!(
                "Invalid operation mode: {}. Valid modes: light, verifiable, formal-proof",
                s
            ),
        }
    }
}

/// Configuration specific to each operation mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeConfig {
    pub mode: OperationMode,
    pub crypto: CryptoConfig,
    pub isolation: IsolationConfig,
    pub audit: AuditConfig,
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub signatures_enabled: bool,
    pub sign_all_steps: bool,
    pub hash_algorithm: HashAlgorithm,
    pub key_rotation_days: Option<u32>,
    pub hardware_security: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationConfig {
    pub isolation_level: crate::sandbox::IsolationLevel,
    pub container_runtime: Option<crate::sandbox::ContainerRuntime>,
    pub deterministic_environment: bool,
    pub fixed_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub enforce_resource_limits: bool,
    pub network_policy: crate::sandbox::NetworkPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub detailed_logging: bool,
    pub store_execution_logs: bool,
    pub merkle_tree_enabled: bool,
    pub external_ledger: Option<String>,
    pub compliance_framework: Option<ComplianceFramework>,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub cache_enabled: bool,
    pub max_parallel_steps: usize,
    pub lazy_evaluation: bool,
    pub skip_expensive_checks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
    Sha3_256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceFramework {
    Basic,
    SOX,
    PCI,
    HIPAA,
    FedRAMP,
    SLSA,
}

impl ModeConfig {
    /// Create configuration for Light mode
    pub fn light() -> Self {
        Self {
            mode: OperationMode::Light,
            crypto: CryptoConfig {
                signatures_enabled: false,
                sign_all_steps: false,
                hash_algorithm: HashAlgorithm::Blake3,
                key_rotation_days: None,
                hardware_security: false,
            },
            isolation: IsolationConfig {
                isolation_level: crate::sandbox::IsolationLevel::Process,
                container_runtime: None,
                deterministic_environment: true,
                fixed_timestamp: None,
                enforce_resource_limits: false,
                network_policy: crate::sandbox::NetworkPolicy::Disabled,
            },
            audit: AuditConfig {
                detailed_logging: false,
                store_execution_logs: false,
                merkle_tree_enabled: false,
                external_ledger: None,
                compliance_framework: Some(ComplianceFramework::Basic),
                retention_days: 7,
            },
            performance: PerformanceConfig {
                cache_enabled: true,
                max_parallel_steps: num_cpus::get(),
                lazy_evaluation: true,
                skip_expensive_checks: true,
            },
        }
    }

    /// Create configuration for Verifiable mode
    pub fn verifiable() -> Self {
        Self {
            mode: OperationMode::Verifiable,
            crypto: CryptoConfig {
                signatures_enabled: true,
                sign_all_steps: false,
                hash_algorithm: HashAlgorithm::Blake3,
                key_rotation_days: Some(90),
                hardware_security: false,
            },
            isolation: IsolationConfig {
                isolation_level: crate::sandbox::IsolationLevel::Container,
                container_runtime: Some(crate::sandbox::ContainerRuntime::Docker),
                deterministic_environment: true,
                fixed_timestamp: None,
                enforce_resource_limits: true,
                network_policy: crate::sandbox::NetworkPolicy::Restricted,
            },
            audit: AuditConfig {
                detailed_logging: true,
                store_execution_logs: true,
                merkle_tree_enabled: true,
                external_ledger: None,
                compliance_framework: Some(ComplianceFramework::SLSA),
                retention_days: 90,
            },
            performance: PerformanceConfig {
                cache_enabled: true,
                max_parallel_steps: num_cpus::get(),
                lazy_evaluation: false,
                skip_expensive_checks: false,
            },
        }
    }

    /// Create configuration for Formal Proof mode
    pub fn formal_proof() -> Self {
        Self {
            mode: OperationMode::FormalProof,
            crypto: CryptoConfig {
                signatures_enabled: true,
                sign_all_steps: true,
                hash_algorithm: HashAlgorithm::Blake3,
                key_rotation_days: Some(30),
                hardware_security: true,
            },
            isolation: IsolationConfig {
                isolation_level: crate::sandbox::IsolationLevel::StrictContainer,
                container_runtime: Some(crate::sandbox::ContainerRuntime::Podman),
                deterministic_environment: true,
                fixed_timestamp: Some(chrono::Utc::now()),
                enforce_resource_limits: true,
                network_policy: crate::sandbox::NetworkPolicy::Disabled,
            },
            audit: AuditConfig {
                detailed_logging: true,
                store_execution_logs: true,
                merkle_tree_enabled: true,
                external_ledger: Some("blockchain".to_string()),
                compliance_framework: Some(ComplianceFramework::FedRAMP),
                retention_days: 2555,
            },
            performance: PerformanceConfig {
                cache_enabled: true,
                max_parallel_steps: num_cpus::get() / 2,
                lazy_evaluation: false,
                skip_expensive_checks: false,
            },
        }
    }

    /// Create configuration from operation mode
    pub fn from_mode(mode: OperationMode) -> Self {
        match mode {
            OperationMode::Light => Self::light(),
            OperationMode::Verifiable => Self::verifiable(),
            OperationMode::FormalProof => Self::formal_proof(),
        }
    }

    /// Customize configuration with overrides
    pub fn with_overrides(
        mut self,
        overrides: HashMap<String, serde_json::Value>,
    ) -> anyhow::Result<Self> {
        for (key, value) in overrides {
            match key.as_str() {
                "crypto.signatures_enabled" => {
                    self.crypto.signatures_enabled =
                        value.as_bool().unwrap_or(self.crypto.signatures_enabled);
                }
                "crypto.sign_all_steps" => {
                    self.crypto.sign_all_steps =
                        value.as_bool().unwrap_or(self.crypto.sign_all_steps);
                }
                "isolation.deterministic_environment" => {
                    self.isolation.deterministic_environment = value
                        .as_bool()
                        .unwrap_or(self.isolation.deterministic_environment);
                }
                "audit.detailed_logging" => {
                    self.audit.detailed_logging =
                        value.as_bool().unwrap_or(self.audit.detailed_logging);
                }
                "performance.cache_enabled" => {
                    self.performance.cache_enabled =
                        value.as_bool().unwrap_or(self.performance.cache_enabled);
                }
                "performance.max_parallel_steps" => {
                    if let Some(num) = value.as_u64() {
                        self.performance.max_parallel_steps = num as usize;
                    }
                }
                _ => {
                    tracing::warn!("Unknown configuration override: {}", key);
                }
            }
        }
        Ok(self)
    }

    /// Validate configuration consistency
    pub fn validate(&self) -> anyhow::Result<()> {
        match self.mode {
            OperationMode::Light => {
                if self.crypto.signatures_enabled && self.crypto.sign_all_steps {
                    anyhow::bail!("Light mode should not sign all steps for performance reasons");
                }
            }
            OperationMode::Verifiable => {
                if !self.crypto.signatures_enabled {
                    anyhow::bail!("Verifiable mode requires cryptographic signatures");
                }
                if !self.audit.merkle_tree_enabled {
                    anyhow::bail!("Verifiable mode requires Merkle tree for audit trail");
                }
            }
            OperationMode::FormalProof => {
                if !self.crypto.signatures_enabled || !self.crypto.sign_all_steps {
                    anyhow::bail!("Formal proof mode requires signatures on all steps");
                }
                if self.isolation.network_policy != crate::sandbox::NetworkPolicy::Disabled {
                    anyhow::bail!("Formal proof mode requires network isolation");
                }
                if !self.audit.detailed_logging {
                    anyhow::bail!("Formal proof mode requires detailed audit logging");
                }
            }
        }

        if self.crypto.hardware_security && !self.crypto.signatures_enabled {
            anyhow::bail!("Hardware security requires signatures to be enabled");
        }

        if self.performance.max_parallel_steps == 0 {
            anyhow::bail!("max_parallel_steps must be greater than 0");
        }

        Ok(())
    }

    /// Get human-readable description of the mode
    pub fn description(&self) -> &'static str {
        match self.mode {
            OperationMode::Light => "Light mode: Fast execution with minimal overhead",
            OperationMode::Verifiable => "Verifiable mode: Balanced security and performance",
            OperationMode::FormalProof => "Formal Proof mode: Maximum security and compliance",
        }
    }

    /// Get estimated performance impact
    pub fn performance_impact(&self) -> &'static str {
        match self.mode {
            OperationMode::Light => "~5-15% overhead",
            OperationMode::Verifiable => "~15-30% overhead",
            OperationMode::FormalProof => "~30-50% overhead",
        }
    }

    /// Check if this mode is suitable for a given use case
    pub fn is_suitable_for(&self, use_case: &str) -> bool {
        matches!(
            (self.mode, use_case),
            (OperationMode::Light, "development")
                | (OperationMode::Light, "testing")
                | (OperationMode::Light, "personal-projects")
                | (OperationMode::Verifiable, "enterprise-ci")
                | (OperationMode::Verifiable, "open-source")
                | (OperationMode::Verifiable, "production-builds")
                | (OperationMode::FormalProof, "regulated-industry")
                | (OperationMode::FormalProof, "critical-infrastructure")
                | (OperationMode::FormalProof, "financial-services")
                | (OperationMode::FormalProof, "medical-devices")
                | (OperationMode::FormalProof, "aerospace")
        )
    }
}

pub struct AttestCore {
    mode_config: ModeConfig,
}

impl AttestCore {
    pub async fn new() -> Result<Self> {
        Self::with_mode(OperationMode::default()).await
    }

    pub async fn with_mode(mode: OperationMode) -> Result<Self> {
        let root_dir = std::env::current_dir()?;
        // Validate storage layout and .attestignore before proceeding.
        Storage::new(&root_dir)?;
        let mode_config = ModeConfig::from_mode(mode);

        Ok(Self { mode_config })
    }

    pub async fn with_mode_config(mode_config: ModeConfig) -> Result<Self> {
        mode_config.validate()?;
        let root_dir = std::env::current_dir()?;
        // Validate storage layout and .attestignore before proceeding.
        Storage::new(&root_dir)?;

        Ok(Self { mode_config })
    }

    /// Get current operation mode
    pub fn get_mode(&self) -> OperationMode {
        self.mode_config.mode
    }

    /// Get current mode configuration
    pub fn get_mode_config(&self) -> &ModeConfig {
        &self.mode_config
    }

    /// Set new operation mode
    pub async fn set_mode(&mut self, mode: OperationMode) -> Result<()> {
        self.mode_config = ModeConfig::from_mode(mode);
        self.mode_config.validate()?;
        info!("Operation mode changed to: {}", mode);
        Ok(())
    }

    /// Set custom mode configuration
    pub async fn set_mode_config(&mut self, config: ModeConfig) -> Result<()> {
        config.validate()?;
        self.mode_config = config;
        info!(
            "Custom mode configuration applied: {}",
            self.mode_config.mode
        );
        Ok(())
    }

    /// Show current mode information
    pub async fn show_mode_info(&self) -> Result<()> {
        info!("Current Operation Mode: {}", self.mode_config.mode);
        info!("Description: {}", self.mode_config.description());
        info!(
            "Performance Impact: {}",
            self.mode_config.performance_impact()
        );
        info!("");
        info!("Configuration:");
        info!(
            "  Cryptographic signatures: {}",
            self.mode_config.crypto.signatures_enabled
        );
        info!(
            "  Sign all steps: {}",
            self.mode_config.crypto.sign_all_steps
        );
        info!(
            "  Hash algorithm: {:?}",
            self.mode_config.crypto.hash_algorithm
        );
        info!(
            "  Isolation level: {:?}",
            self.mode_config.isolation.isolation_level
        );
        info!(
            "  Deterministic environment: {}",
            self.mode_config.isolation.deterministic_environment
        );
        info!(
            "  Detailed logging: {}",
            self.mode_config.audit.detailed_logging
        );
        info!(
            "  Cache enabled: {}",
            self.mode_config.performance.cache_enabled
        );
        info!(
            "  Max parallel steps: {}",
            self.mode_config.performance.max_parallel_steps
        );

        if let Some(framework) = &self.mode_config.audit.compliance_framework {
            info!("  Compliance framework: {:?}", framework);
        }

        Ok(())
    }

    /// Initialize the ATTEST repository layout in the current directory.
    ///
    /// Idempotent: each item is created only if absent, nothing is ever
    /// overwritten. Reports what was created vs already present.
    pub async fn init(&self) -> Result<()> {
        let workspace = std::env::current_dir()?;
        let mut created: Vec<String> = Vec::new();
        let mut present: Vec<String> = Vec::new();

        for sub in [".attest/receipts", ".attest/cache", ".attest/objects"] {
            let dir = workspace.join(sub);
            if dir.is_dir() {
                present.push(format!("{}/", sub));
            } else {
                std::fs::create_dir_all(&dir)?;
                created.push(format!("{}/", sub));
            }
        }

        let manifest = workspace.join("attest.yaml");
        if manifest.exists() {
            present.push("attest.yaml".to_string());
        } else {
            std::fs::write(&manifest, STARTER_PIPELINE)?;
            created.push("attest.yaml".to_string());
        }

        // Keys must never be committed; prepared here so key generation
        // on first `run --sign` is already covered.
        let gitignore = workspace.join(".gitignore");
        let keys_entry = ".attest/keys/";
        let gitignore_content = if gitignore.exists() {
            std::fs::read_to_string(&gitignore)?
        } else {
            String::new()
        };
        if gitignore_content.lines().any(|l| l.trim() == keys_entry) {
            present.push(".gitignore (.attest/keys/ entry)".to_string());
        } else {
            let mut updated = gitignore_content;
            if !updated.is_empty() && !updated.ends_with('\n') {
                updated.push('\n');
            }
            updated.push_str(keys_entry);
            updated.push('\n');
            std::fs::write(&gitignore, updated)?;
            created.push(".gitignore (.attest/keys/ entry)".to_string());
        }

        for item in &created {
            println!("created: {}", item);
        }
        for item in &present {
            println!("already present: {}", item);
        }
        info!(
            "ATTEST repository initialized (mode: {})",
            self.mode_config.mode
        );
        Ok(())
    }

    /// Run a pipeline through the real executor.
    ///
    /// Returns the process exit code: 0 = all steps succeeded, 1 = a step or
    /// a manifest check failed (receipt still written when steps ran).
    /// Operational errors (bad pipeline file, missing `.attest/`) are
    /// returned as `Err` and map to exit code 2 in the CLI.
    pub async fn run_pipeline(
        &self,
        pipeline_path: Option<&str>,
        config: crate::executor::ExecutorConfig,
        key: Option<&str>,
        tsa: Option<&str>,
    ) -> Result<i32> {
        let pipeline_path = pipeline_path.unwrap_or("attest.yaml");
        let workspace = std::env::current_dir()?;

        if !workspace.join(".attest").is_dir() {
            anyhow::bail!("not an ATTEST repository (run 'attest init')");
        }

        let pipeline = Pipeline::load(pipeline_path).await?;
        info!("Running pipeline: {}", pipeline_path);
        info!("Using operation mode: {}", self.mode_config.mode);

        let mut storage = Storage::new(&workspace)?;
        if config.sign_results {
            let store = crate::keys::KeyStore::new(&workspace);
            match store.select_signing_key(key)? {
                Some(signing_key) => storage.set_keypair(
                    crate::crypto::sign::AttestKeypair::from_signing_key(signing_key),
                ),
                // No managed key: fall back to the legacy auto-generated
                // raw keypair under .attest/keys/.
                None => storage.load_keypair(true)?,
            }
        }

        let mut executor = crate::executor::Executor::new(&mut storage, config)?;
        let receipt = match executor.run(&pipeline).await {
            Ok(receipt) => receipt,
            Err(err) => {
                if let Some(hashing_err) = err.downcast_ref::<crate::hashing::HashingError>() {
                    if matches!(
                        hashing_err,
                        crate::hashing::HashingError::MissingInput { .. }
                            | crate::hashing::HashingError::MissingOutput { .. }
                    ) {
                        eprintln!("error: {}", hashing_err);
                        return Ok(1);
                    }
                }
                return Err(err);
            }
        };

        let receipt = match timestamp_if_requested(&storage, receipt, tsa) {
            Ok(receipt) => receipt,
            Err(code) => return Ok(code),
        };

        let label: String = pipeline
            .name
            .clone()
            .map(|n| {
                n.chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                            c
                        } else {
                            '-'
                        }
                    })
                    .collect()
            })
            .unwrap_or_else(|| receipt.pipeline_hash.chars().take(8).collect());

        let receipts_dir = workspace.join(".attest").join("receipts");
        std::fs::create_dir_all(&receipts_dir)?;
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let receipt_path = crate::storage::write_receipt_unique(
            &receipts_dir,
            &stamp,
            Some(&label),
            &serde_yaml::to_string(&receipt)?,
        )?;
        println!("{}", receipt_path.display());

        // Failures must be visible on the console, not only
        // buried in the receipt: name the failed step, its exit code, and
        // the tail of its captured output.
        let mut any_failed = false;
        for step in &receipt.steps {
            if step.exit_code != 0 {
                any_failed = true;
                eprintln!(
                    "step '{}' failed with exit code {}",
                    step.name, step.exit_code
                );
                let output = if step.stderr.trim().is_empty() {
                    ("stdout", &step.stdout)
                } else {
                    ("stderr", &step.stderr)
                };
                if !output.1.trim().is_empty() {
                    eprintln!("--- {} of '{}' (tail) ---", output.0, step.name);
                    for line in output_tail(output.1, 20) {
                        eprintln!("  {}", line);
                    }
                }
            }
        }
        // Steps the executor skipped because a dependency did not succeed
        // are absent from the receipt (they produced no hashes to record).
        for name in pipeline.steps.keys() {
            if !receipt.steps.iter().any(|s| &s.name == name) {
                eprintln!("step '{}' skipped: a dependency did not succeed", name);
            }
        }
        Ok(if any_failed { 1 } else { 0 })
    }

    /// Run the pipeline twice in two distinct fresh workspaces and compare
    /// per-step output hashes (`attest run --check-reproducibility`).
    ///
    /// Both runs are hermetic (normalized env, ambient env not inherited)
    /// and start from an empty cache. The two workspaces deliberately have
    /// different absolute paths so builds that embed their build path
    /// diverge. Returns 0 when every step's output hash matches, 1 on
    /// divergence or step failure; the run-1 receipt is written to the
    /// original workspace with a `reproducibility` block attached (and
    /// signed after attachment when signing is requested).
    pub async fn run_pipeline_check_reproducibility(
        &self,
        pipeline_path: Option<&str>,
        config: crate::executor::ExecutorConfig,
        key: Option<&str>,
        tsa: Option<&str>,
    ) -> Result<i32> {
        let pipeline_path = pipeline_path.unwrap_or("attest.yaml");
        let workspace = std::env::current_dir()?;

        if !workspace.join(".attest").is_dir() {
            anyhow::bail!("not an ATTEST repository (run 'attest init')");
        }

        let pipeline = Pipeline::load(pipeline_path).await?;
        info!("Reproducibility check: {}", pipeline_path);

        // Two fresh workspace copies under distinct absolute paths.
        let mut run_dirs = Vec::new();
        for tag in ["a", "b"] {
            let dir =
                std::env::temp_dir().join(format!("attest-repro-{}-{}", std::process::id(), tag));
            if dir.exists() {
                std::fs::remove_dir_all(&dir)?;
            }
            copy_tree(&workspace, &dir)?;
            for sub in [".attest/receipts", ".attest/cache", ".attest/objects"] {
                std::fs::create_dir_all(dir.join(sub))?;
            }
            run_dirs.push(dir);
        }

        // Execute both runs, restoring the working directory whatever
        // happens (executor hashing and step commands are cwd-relative).
        let outcome = self.repro_runs(&pipeline, &config, &run_dirs).await;
        std::env::set_current_dir(&workspace)?;
        let receipts = match outcome {
            Ok(receipts) => receipts,
            Err(err) => {
                cleanup_dirs(&run_dirs);
                if let Some(hashing_err) = err.downcast_ref::<crate::hashing::HashingError>() {
                    if matches!(
                        hashing_err,
                        crate::hashing::HashingError::MissingInput { .. }
                            | crate::hashing::HashingError::MissingOutput { .. }
                    ) {
                        eprintln!("error: {}", hashing_err);
                        return Ok(1);
                    }
                }
                return Err(err);
            }
        };
        let [mut receipt_a, receipt_b]: [crate::storage::Receipt; 2] = receipts;

        // Compare per-step output hashes.
        let hashes_b: HashMap<&str, &str> = receipt_b
            .steps
            .iter()
            .map(|s| (s.name.as_str(), s.output_hash.as_str()))
            .collect();
        let mut divergent: Vec<(String, String, String)> = Vec::new();
        for step in &receipt_a.steps {
            if let Some(hash_b) = hashes_b.get(step.name.as_str()) {
                if step.output_hash != *hash_b {
                    divergent.push((
                        step.name.clone(),
                        step.output_hash.clone(),
                        (*hash_b).to_string(),
                    ));
                }
            }
        }

        if !divergent.is_empty() {
            eprintln!(
                "reproducibility check failed: {} step(s) diverged between the two runs",
                divergent.len()
            );
            for (name, hash_a, hash_b) in &divergent {
                eprintln!("step {}:", name);
                eprintln!("  output hash (run A): {}", hash_a);
                eprintln!("  output hash (run B): {}", hash_b);
                if let Some(step) = pipeline.steps.get(name) {
                    print_manifest_diff(name, &step.outputs, &run_dirs[0], &run_dirs[1]);
                }
            }
        }

        let verified = divergent.is_empty();
        receipt_a.reproducibility = Some(crate::storage::ReproducibilityInfo {
            verified,
            runs: 2,
            method: "double-build/v1".to_string(),
        });

        // Sign only after the reproducibility block is attached, so the
        // signature covers it. Signing uses the original workspace's keys.
        if config.sign_results {
            let mut storage = Storage::new(&workspace)?;
            let store = crate::keys::KeyStore::new(&workspace);
            match store.select_signing_key(key)? {
                Some(signing_key) => storage.set_keypair(
                    crate::crypto::sign::AttestKeypair::from_signing_key(signing_key),
                ),
                None => storage.load_keypair(true)?,
            }
            receipt_a = storage.sign_receipt(&receipt_a)?;
            receipt_a = match timestamp_if_requested(&storage, receipt_a, tsa) {
                Ok(receipt) => receipt,
                Err(code) => return Ok(code),
            };
        } else if tsa.is_some() {
            eprintln!("error: --timestamp requires --sign; there is no signature to timestamp");
            return Ok(2);
        }

        cleanup_dirs(&run_dirs);

        let label: String = pipeline
            .name
            .clone()
            .map(|n| {
                n.chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                            c
                        } else {
                            '-'
                        }
                    })
                    .collect()
            })
            .unwrap_or_else(|| receipt_a.pipeline_hash.chars().take(8).collect());
        let receipts_dir = workspace.join(".attest").join("receipts");
        std::fs::create_dir_all(&receipts_dir)?;
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let receipt_path = crate::storage::write_receipt_unique(
            &receipts_dir,
            &stamp,
            Some(&label),
            &serde_yaml::to_string(&receipt_a)?,
        )?;
        println!("{}", receipt_path.display());

        let any_failed = receipt_a.steps.iter().any(|s| s.exit_code != 0)
            || receipt_b.steps.iter().any(|s| s.exit_code != 0);
        Ok(if any_failed || !verified { 1 } else { 0 })
    }

    /// Execute the pipeline once in each prepared directory (hermetic env,
    /// no signing, fresh cache) and return both receipts. Leaves the
    /// process working directory in the last run dir — the caller restores.
    async fn repro_runs(
        &self,
        pipeline: &Pipeline,
        config: &crate::executor::ExecutorConfig,
        run_dirs: &[std::path::PathBuf],
    ) -> Result<[crate::storage::Receipt; 2]> {
        let mut receipts = Vec::new();
        for dir in run_dirs {
            std::env::set_current_dir(dir)?;
            let mut storage = Storage::new(dir)?;
            let run_config = crate::executor::ExecutorConfig {
                sign_results: false,
                hermetic_env: true,
                ..config.clone()
            };
            let mut executor = crate::executor::Executor::new(&mut storage, run_config)?;
            receipts.push(executor.run(pipeline).await?);
        }
        receipts
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected exactly two runs"))
    }
}

/// Print the first differing output-manifest lines between the two runs of
/// one step (best effort — outputs may be unreadable after a failed step).
fn print_manifest_diff(
    step_name: &str,
    outputs: &[std::path::PathBuf],
    dir_a: &std::path::Path,
    dir_b: &std::path::Path,
) {
    const MAX_LINES: usize = 20;
    let manifest_a = crate::hashing::output_manifest(dir_a, step_name, outputs);
    let manifest_b = crate::hashing::output_manifest(dir_b, step_name, outputs);
    let (Ok(manifest_a), Ok(manifest_b)) = (manifest_a, manifest_b) else {
        return;
    };
    let lines_a: Vec<&str> = manifest_a.lines().collect();
    let lines_b: Vec<&str> = manifest_b.lines().collect();
    let mut shown = 0;
    for i in 0..lines_a.len().max(lines_b.len()) {
        let a = lines_a.get(i).copied().unwrap_or("<absent>");
        let b = lines_b.get(i).copied().unwrap_or("<absent>");
        if a != b {
            if shown == MAX_LINES {
                eprintln!("  ... (more differences truncated)");
                break;
            }
            eprintln!("  A: {}", a);
            eprintln!("  B: {}", b);
            shown += 1;
        }
    }
}

/// Recursively copy a source tree, excluding `.attest` and `.git`.
/// Last `max_lines` lines of a step's captured output, for failure reports.
fn output_tail(output: &str, max_lines: usize) -> Vec<&str> {
    let lines: Vec<&str> = output.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].to_vec()
}

fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".attest" || name == ".git" {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(&name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_tree(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
        }
        // Symlinks and special files are skipped: build inputs must be
        // regular files for hashing anyway.
    }
    Ok(())
}

fn cleanup_dirs(dirs: &[std::path::PathBuf]) {
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Starter pipeline written by `attest init` when no attest.yaml exists.
/// Attach a timestamp token when the run asked for one.
///
/// A failure here fails the run. Someone who passed `--timestamp` wants
/// third-party evidence of when they signed; quietly handing them a receipt
/// without it would leave them believing they have a guarantee they do not.
fn timestamp_if_requested(
    storage: &Storage,
    receipt: crate::storage::Receipt,
    tsa: Option<&str>,
) -> std::result::Result<crate::storage::Receipt, i32> {
    let Some(url) = tsa else {
        return Ok(receipt);
    };
    if receipt.signature.is_none() {
        eprintln!("error: --timestamp requires --sign; there is no signature to timestamp");
        return Err(2);
    }
    match storage.timestamp_receipt(&receipt, url) {
        Ok(timestamped) => {
            tracing::info!("Signature timestamped by {}", url);
            Ok(timestamped)
        }
        Err(err) => {
            eprintln!("error: timestamping failed: {err:#}");
            Err(2)
        }
    }
}

const STARTER_PIPELINE: &str = r#"version: "1.0"
name: starter
steps:
  hello:
    run: "echo hello from attest"
    inputs: []
    outputs: []
    cache: false
"#;
