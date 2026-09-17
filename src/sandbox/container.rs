use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{ContainerConfig, ContainerRuntime, ResourceUsage, SandboxResult};
use crate::crypto::image_verification::{
    ImageVerificationConfig, ImageVerifier, VerificationResult,
};

pub struct ContainerSandbox {
    config: ContainerConfig,
    runtime: Box<dyn ContainerRuntimeTrait>,
    image_verifier: Option<ImageVerifier>,
}

impl ContainerSandbox {
    pub fn new(config: ContainerConfig) -> Result<Self> {
        let runtime: Box<dyn ContainerRuntimeTrait> = match config.runtime {
            ContainerRuntime::Docker => Box::new(DockerRuntime::new()?),
            ContainerRuntime::Podman => Box::new(PodmanRuntime::new()?),
            ContainerRuntime::Containerd => Box::new(ContainerdRuntime::new()?),
        };

        // Initialize image verifier with default configuration
        let verification_config = ImageVerificationConfig::default();
        let image_verifier = match ImageVerifier::new(verification_config) {
            Ok(verifier) => {
                info!("Image signature verification enabled");
                Some(verifier)
            }
            Err(e) => {
                warn!("Failed to initialize image verifier: {}. Running without signature verification.", e);
                None
            }
        };

        Ok(Self {
            config,
            runtime,
            image_verifier,
        })
    }

    /// Create a new container sandbox with custom image verification configuration
    pub fn new_with_verification(
        config: ContainerConfig,
        verification_config: ImageVerificationConfig,
    ) -> Result<Self> {
        let runtime: Box<dyn ContainerRuntimeTrait> = match config.runtime {
            ContainerRuntime::Docker => Box::new(DockerRuntime::new()?),
            ContainerRuntime::Podman => Box::new(PodmanRuntime::new()?),
            ContainerRuntime::Containerd => Box::new(ContainerdRuntime::new()?),
        };

        let image_verifier = Some(ImageVerifier::new(verification_config)?);
        info!("Container sandbox created with custom image verification");

        Ok(Self {
            config,
            runtime,
            image_verifier,
        })
    }

    pub async fn execute(
        &self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        working_dir: Option<&Path>,
    ) -> Result<SandboxResult> {
        // Verify container image signature before execution
        if let Some(verifier) = &self.image_verifier {
            info!("Verifying container image signature: {}", self.config.image);
            match verifier.verify_image_signature(&self.config.image).await {
                Ok(verification_result) => {
                    if !verification_result.is_valid {
                        anyhow::bail!(
                            "Container image signature verification failed for {}: {}",
                            self.config.image,
                            verification_result.messages.join(", ")
                        );
                    }
                    info!("Container image signature verified: {}", self.config.image);
                    debug!("Verification details: {:?}", verification_result);
                }
                Err(e) => {
                    anyhow::bail!("Image verification error for {}: {}", self.config.image, e);
                }
            }
        } else {
            warn!(
                "warning:  Running container without signature verification: {}",
                self.config.image
            );
        }

        let container_id = format!("attest-{}", Uuid::new_v4());

        // Create temporary directory for container workspace
        let temp_dir = TempDir::new().context("Failed to create temporary directory")?;

        let mut run_config = ContainerRunConfig {
            container_id: container_id.clone(),
            image: self.config.image.clone(),
            command: command.to_string(),
            args: args.to_vec(),
            environment: env.clone(),
            working_dir: working_dir.map(|p| p.to_path_buf()),
            volumes: self.config.volumes.clone(),
            user: self.config.user.clone(),
            entrypoint: self.config.entrypoint.clone(),
            network_mode: "none".to_string(), // Disable network by default
            temp_dir: temp_dir.path().to_path_buf(),
            resource_limits: ResourceLimits {
                memory_mb: Some(512),
                cpu_cores: Some(1.0),
                timeout_secs: Some(300),
            },
        };

        // Add deterministic environment to container
        run_config
            .environment
            .extend(self.config.environment.clone());

        let result = self
            .runtime
            .run_container(&run_config)
            .await
            .context("Failed to run container")?;

        // Cleanup
        let _ = self.runtime.remove_container(&container_id).await;

        Ok(result)
    }

    pub fn check_runtime_available(&self) -> Result<bool> {
        self.runtime.is_available()
    }

    /// Verify the container image signature without executing
    pub async fn verify_image(&self) -> Result<VerificationResult> {
        match &self.image_verifier {
            Some(verifier) => verifier.verify_image_signature(&self.config.image).await,
            None => {
                // Return a default "unverified" result
                Ok(VerificationResult {
                    is_valid: true, // Allow execution but mark as unverified
                    image_digest: self.config.image.clone(),
                    signature_info: None,
                    messages: vec!["Image verification disabled".to_string()],
                    verified_at: chrono::Utc::now(),
                })
            }
        }
    }

    /// Get information about image verification capabilities
    pub fn get_verification_status(&self) -> (bool, Option<&ImageVerificationConfig>) {
        match &self.image_verifier {
            Some(verifier) => (true, Some(verifier.get_config())),
            None => (false, None),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContainerRunConfig {
    pub container_id: String,
    pub image: String,
    pub command: String,
    pub args: Vec<String>,
    pub environment: HashMap<String, String>,
    pub working_dir: Option<std::path::PathBuf>,
    pub volumes: Vec<super::VolumeMount>,
    pub user: Option<String>,
    pub entrypoint: Option<Vec<String>>,
    pub network_mode: String,
    pub temp_dir: std::path::PathBuf,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub memory_mb: Option<u64>,
    pub cpu_cores: Option<f64>,
    pub timeout_secs: Option<u64>,
}

#[async_trait::async_trait]
pub trait ContainerRuntimeTrait: Send + Sync {
    async fn run_container(&self, config: &ContainerRunConfig) -> Result<SandboxResult>;
    async fn remove_container(&self, container_id: &str) -> Result<()>;
    fn is_available(&self) -> Result<bool>;
    fn runtime_name(&self) -> &'static str;
}

pub struct DockerRuntime {
    docker_cmd: String,
}

impl DockerRuntime {
    pub fn new() -> Result<Self> {
        let docker_cmd = which::which("docker")
            .context("Docker not found in PATH")?
            .to_string_lossy()
            .to_string();

        Ok(Self { docker_cmd })
    }
}

#[async_trait::async_trait]
impl ContainerRuntimeTrait for DockerRuntime {
    async fn run_container(&self, config: &ContainerRunConfig) -> Result<SandboxResult> {
        let mut cmd = Command::new(&self.docker_cmd);
        cmd.arg("run")
            .arg("--rm")
            .arg("--name")
            .arg(&config.container_id)
            .arg("--network")
            .arg(&config.network_mode);

        // Add resource limits
        if let Some(memory) = config.resource_limits.memory_mb {
            cmd.arg("--memory").arg(format!("{}m", memory));
        }

        if let Some(cpu) = config.resource_limits.cpu_cores {
            cmd.arg("--cpus").arg(cpu.to_string());
        }

        // Add environment variables
        for (key, value) in &config.environment {
            cmd.arg("-e").arg(format!("{}={}", key, value));
        }

        // Add volumes
        for volume in &config.volumes {
            let mount_spec = if volume.read_only {
                format!(
                    "{}:{}:ro",
                    volume.host_path.display(),
                    volume.container_path.display()
                )
            } else {
                format!(
                    "{}:{}",
                    volume.host_path.display(),
                    volume.container_path.display()
                )
            };
            cmd.arg("-v").arg(mount_spec);
        }

        // Set working directory
        if let Some(work_dir) = &config.working_dir {
            cmd.arg("-w").arg(work_dir);
        }

        // Set user
        if let Some(user) = &config.user {
            cmd.arg("--user").arg(user);
        }

        // Set entrypoint if specified
        if let Some(entrypoint) = &config.entrypoint {
            for entry in entrypoint {
                cmd.arg("--entrypoint").arg(entry);
            }
        }

        // Add image
        cmd.arg(&config.image);

        // Add command and args
        cmd.arg(&config.command);
        for arg in &config.args {
            cmd.arg(arg);
        }

        // Set timeout
        let timeout = config.resource_limits.timeout_secs.unwrap_or(300);

        let output = tokio::time::timeout(
            Duration::from_secs(timeout),
            tokio::task::spawn_blocking(move || cmd.output()),
        )
        .await
        .context("Container execution timed out")?
        .context("Failed to spawn container command")?
        .context("Container command failed")?;

        Ok(SandboxResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            execution_time: Duration::from_secs(0), // Will be set by caller
            deterministic_timestamp: None,          // Will be set by caller
            resource_usage: ResourceUsage::default(),
            isolation_violations: vec![],
        })
    }

    async fn remove_container(&self, container_id: &str) -> Result<()> {
        let mut cmd = Command::new(&self.docker_cmd);
        cmd.arg("rm").arg("-f").arg(container_id);

        let _ = cmd.output(); // Ignore errors on cleanup
        Ok(())
    }

    fn is_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.docker_cmd);
        cmd.arg("version")
            .arg("--format")
            .arg("{{.Server.Version}}");

        match cmd.output() {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    fn runtime_name(&self) -> &'static str {
        "docker"
    }
}

pub struct PodmanRuntime {
    podman_cmd: String,
}

impl PodmanRuntime {
    pub fn new() -> Result<Self> {
        let podman_cmd = which::which("podman")
            .context("Podman not found in PATH")?
            .to_string_lossy()
            .to_string();

        Ok(Self { podman_cmd })
    }
}

#[async_trait::async_trait]
impl ContainerRuntimeTrait for PodmanRuntime {
    async fn run_container(&self, config: &ContainerRunConfig) -> Result<SandboxResult> {
        let mut cmd = Command::new(&self.podman_cmd);
        cmd.arg("run")
            .arg("--rm")
            .arg("--name")
            .arg(&config.container_id)
            .arg("--network")
            .arg(&config.network_mode);

        // Add resource limits (Podman syntax is similar to Docker)
        if let Some(memory) = config.resource_limits.memory_mb {
            cmd.arg("--memory").arg(format!("{}m", memory));
        }

        if let Some(cpu) = config.resource_limits.cpu_cores {
            cmd.arg("--cpus").arg(cpu.to_string());
        }

        // Add environment variables
        for (key, value) in &config.environment {
            cmd.arg("-e").arg(format!("{}={}", key, value));
        }

        // Add volumes
        for volume in &config.volumes {
            let mount_spec = if volume.read_only {
                format!(
                    "{}:{}:ro",
                    volume.host_path.display(),
                    volume.container_path.display()
                )
            } else {
                format!(
                    "{}:{}",
                    volume.host_path.display(),
                    volume.container_path.display()
                )
            };
            cmd.arg("-v").arg(mount_spec);
        }

        // Set working directory and other options similar to Docker
        if let Some(work_dir) = &config.working_dir {
            cmd.arg("-w").arg(work_dir);
        }

        if let Some(user) = &config.user {
            cmd.arg("--user").arg(user);
        }

        // Add image and command
        cmd.arg(&config.image);
        cmd.arg(&config.command);
        for arg in &config.args {
            cmd.arg(arg);
        }

        let timeout = config.resource_limits.timeout_secs.unwrap_or(300);

        let output = tokio::time::timeout(
            Duration::from_secs(timeout),
            tokio::task::spawn_blocking(move || cmd.output()),
        )
        .await
        .context("Container execution timed out")?
        .context("Failed to spawn container command")?
        .context("Container command failed")?;

        Ok(SandboxResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            execution_time: Duration::from_secs(0),
            deterministic_timestamp: None,
            resource_usage: ResourceUsage::default(),
            isolation_violations: vec![],
        })
    }

    async fn remove_container(&self, container_id: &str) -> Result<()> {
        let mut cmd = Command::new(&self.podman_cmd);
        cmd.arg("rm").arg("-f").arg(container_id);

        let _ = cmd.output(); // Ignore errors on cleanup
        Ok(())
    }

    fn is_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.podman_cmd);
        cmd.arg("version")
            .arg("--format")
            .arg("{{.Server.Version}}");

        match cmd.output() {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    fn runtime_name(&self) -> &'static str {
        "podman"
    }
}

pub struct ContainerdRuntime {
    ctr_cmd: String,
}

impl ContainerdRuntime {
    pub fn new() -> Result<Self> {
        let ctr_cmd = which::which("ctr")
            .context("containerd ctr not found in PATH")?
            .to_string_lossy()
            .to_string();

        Ok(Self { ctr_cmd })
    }
}

#[async_trait::async_trait]
impl ContainerRuntimeTrait for ContainerdRuntime {
    async fn run_container(&self, config: &ContainerRunConfig) -> Result<SandboxResult> {
        // containerd is driven through `ctr`, whose interface is narrower
        // than docker's: no per-run resource limits, no seccomp profile
        // selection. A step that needs those should use docker or podman.
        let mut cmd = Command::new(&self.ctr_cmd);
        cmd.arg("run")
            .arg("--rm")
            .arg(&config.image)
            .arg(&config.container_id);

        // Add command and args
        cmd.arg(&config.command);
        for arg in &config.args {
            cmd.arg(arg);
        }

        let timeout = config.resource_limits.timeout_secs.unwrap_or(300);

        let output = tokio::time::timeout(
            Duration::from_secs(timeout),
            tokio::task::spawn_blocking(move || cmd.output()),
        )
        .await
        .context("Container execution timed out")?
        .context("Failed to spawn container command")?
        .context("Container command failed")?;

        Ok(SandboxResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            execution_time: Duration::from_secs(0),
            deterministic_timestamp: None,
            resource_usage: ResourceUsage::default(),
            isolation_violations: vec![],
        })
    }

    async fn remove_container(&self, container_id: &str) -> Result<()> {
        let mut cmd = Command::new(&self.ctr_cmd);
        cmd.arg("container").arg("delete").arg(container_id);

        let _ = cmd.output(); // Ignore errors on cleanup
        Ok(())
    }

    fn is_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.ctr_cmd);
        cmd.arg("version");

        match cmd.output() {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    fn runtime_name(&self) -> &'static str {
        "containerd"
    }
}

/// Utility functions for container management
pub struct ContainerUtils;

impl ContainerUtils {
    /// Auto-detect available container runtime
    pub fn detect_runtime() -> Option<ContainerRuntime> {
        if DockerRuntime::new().is_ok() {
            return Some(ContainerRuntime::Docker);
        }

        if PodmanRuntime::new().is_ok() {
            return Some(ContainerRuntime::Podman);
        }

        if ContainerdRuntime::new().is_ok() {
            return Some(ContainerRuntime::Containerd);
        }

        None
    }

    /// Check if any container runtime is available
    pub fn is_container_runtime_available() -> bool {
        Self::detect_runtime().is_some()
    }

    /// Get default minimal container configuration
    pub fn default_container_config(image: &str) -> ContainerConfig {
        ContainerConfig {
            image: image.to_string(),
            volumes: vec![],
            environment: HashMap::new(),
            working_dir: Some(std::path::PathBuf::from("/workspace")),
            user: Some("1000:1000".to_string()), // Non-root user
            entrypoint: None,
            runtime: Self::detect_runtime().unwrap_or(ContainerRuntime::Docker),
        }
    }

    /// Create a secure container configuration for ATTEST
    pub fn secure_attest_config(image: &str) -> ContainerConfig {
        let mut config = Self::default_container_config(image);

        // Add ATTEST-specific environment
        config
            .environment
            .insert("ATTEST_CONTAINER_MODE".to_string(), "1".to_string());
        config
            .environment
            .insert("HOME".to_string(), "/tmp".to_string());
        config
            .environment
            .insert("TMPDIR".to_string(), "/tmp".to_string());

        // Set secure defaults
        config.user = Some("65534:65534".to_string()); // nobody:nobody
        config.working_dir = Some(std::path::PathBuf::from("/workspace"));

        config
    }
}
