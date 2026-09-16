//! Enhanced container sandbox with advanced security features
//!
//! This module extends the basic container sandbox with seccomp filtering,
//! filesystem isolation, and violation detection for maximum security.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::container::{ContainerRunConfig, ContainerRuntimeTrait, ResourceLimits};
use super::filesystem_security::{AccessMode, FilesystemSecurityManager};
use super::seccomp::{SeccompManager, SeccompViolation, ViolationDetector};
use super::{
    ContainerConfig, ContainerRuntime, NetworkPolicy, ResourceUsage, SandboxResult, SecurityLevel,
};

/// Enhanced container sandbox with security features
pub struct EnhancedContainerSandbox {
    config: ContainerConfig,
    runtime: Box<dyn ContainerRuntimeTrait>,
    seccomp_manager: SeccompManager,
    violation_detector: ViolationDetector,
    filesystem_security: FilesystemSecurityManager,
    security_level: SecurityLevel,
    network_policy: NetworkPolicy,
}

impl EnhancedContainerSandbox {
    /// Create new enhanced container sandbox
    pub fn new(
        config: ContainerConfig,
        security_level: SecurityLevel,
        network_policy: NetworkPolicy,
    ) -> Result<Self> {
        let runtime: Box<dyn ContainerRuntimeTrait> = match config.runtime {
            ContainerRuntime::Docker => Box::new(super::container::DockerRuntime::new()?),
            ContainerRuntime::Podman => Box::new(super::container::PodmanRuntime::new()?),
            ContainerRuntime::Containerd => Box::new(super::container::ContainerdRuntime::new()?),
        };

        let mut seccomp_manager = SeccompManager::new();
        let profile_name = match security_level {
            SecurityLevel::Minimal => "minimal",
            SecurityLevel::Standard => "standard",
            SecurityLevel::Maximum => "maximum",
        };

        seccomp_manager
            .set_profile(profile_name)
            .with_context(|| format!("Failed to set seccomp profile: {}", profile_name))?;

        let violation_detector = ViolationDetector::new(1000);

        // Initialize filesystem security based on security level
        let filesystem_security = match security_level {
            SecurityLevel::Minimal => FilesystemSecurityManager::with_default_policy(),
            SecurityLevel::Standard => FilesystemSecurityManager::with_default_policy(),
            SecurityLevel::Maximum => FilesystemSecurityManager::with_strict_policy(),
        };

        info!(
            "Enhanced container sandbox created with {} security level",
            match security_level {
                SecurityLevel::Minimal => "minimal",
                SecurityLevel::Standard => "standard",
                SecurityLevel::Maximum => "maximum",
            }
        );

        Ok(Self {
            config,
            runtime,
            seccomp_manager,
            violation_detector,
            filesystem_security,
            security_level,
            network_policy,
        })
    }

    /// Execute command with enhanced security
    pub async fn execute_secure(
        &mut self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        working_dir: Option<&Path>,
    ) -> Result<SandboxResult> {
        let container_id = format!("attest-secure-{}", Uuid::new_v4());

        // Create isolated temporary directory
        let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
        let temp_path = temp_dir.path().to_path_buf();

        // Generate seccomp profile for container runtime
        let seccomp_profile_json = self.seccomp_manager.generate_container_profile(
            &self
                .seccomp_manager
                .get_current_profile()
                .ok_or_else(|| anyhow::anyhow!("No seccomp profile set"))?
                .name,
        )?;

        // Write seccomp profile to temporary file
        let seccomp_file = temp_path.join("seccomp-profile.json");
        std::fs::write(&seccomp_file, &seccomp_profile_json)
            .context("Failed to write seccomp profile")?;

        // Create secure volumes first (requires mutable reference)
        let secure_volumes = self.create_secure_volumes(&temp_path)?;

        // Create enhanced run configuration
        let mut run_config = ContainerRunConfig {
            container_id: container_id.clone(),
            image: self.config.image.clone(),
            command: command.to_string(),
            args: args.to_vec(),
            environment: self.create_secure_environment(env),
            working_dir: working_dir.map(|p| p.to_path_buf()),
            volumes: secure_volumes,
            user: Some("65534:65534".to_string()), // nobody:nobody
            entrypoint: self.config.entrypoint.clone(),
            network_mode: self.get_network_mode(),
            temp_dir: temp_path.clone(),
            resource_limits: self.create_resource_limits(),
        };

        // Execute with security monitoring
        let start_time = std::time::Instant::now();

        info!(
            "Starting secure container execution: {} (security: {:?})",
            container_id, self.security_level
        );

        let result = self
            .execute_with_security_monitoring(&mut run_config, &seccomp_file)
            .await?;

        let execution_time = start_time.elapsed();
        info!(
            "Container execution completed: {} (time: {:?})",
            container_id, execution_time
        );

        // Cleanup
        let _ = self.runtime.remove_container(&container_id).await;

        Ok(SandboxResult {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            execution_time,
            deterministic_timestamp: None,
            resource_usage: ResourceUsage::default(),
            isolation_violations: vec![], // Convert seccomp violations if needed
        })
    }

    /// Execute with security monitoring
    async fn execute_with_security_monitoring(
        &mut self,
        config: &mut ContainerRunConfig,
        seccomp_file: &Path,
    ) -> Result<ContainerExecutionResult> {
        // Add seccomp profile to container arguments
        let result = match self.config.runtime {
            ContainerRuntime::Docker => {
                self.execute_docker_with_seccomp(config, seccomp_file).await
            }
            ContainerRuntime::Podman => {
                self.execute_podman_with_seccomp(config, seccomp_file).await
            }
            ContainerRuntime::Containerd => {
                // containerd seccomp support is more limited
                self.execute_containerd_basic(config).await
            }
        }?;

        // Monitor for security violations during execution
        self.check_for_violations(&config.container_id).await?;

        Ok(result)
    }

    /// Execute with Docker and seccomp
    async fn execute_docker_with_seccomp(
        &self,
        config: &ContainerRunConfig,
        seccomp_file: &Path,
    ) -> Result<ContainerExecutionResult> {
        let mut cmd = Command::new("docker");
        cmd.arg("run")
            .arg("--rm")
            .arg("--name")
            .arg(&config.container_id)
            .arg("--network")
            .arg(&config.network_mode)
            .arg("--security-opt")
            .arg(format!("seccomp={}", seccomp_file.display()));

        // Add strict security options for enhanced modes
        if self.security_level != SecurityLevel::Minimal {
            cmd.arg("--security-opt")
                .arg("no-new-privileges:true")
                .arg("--cap-drop")
                .arg("ALL")
                .arg("--read-only")
                .arg("--tmpfs")
                .arg("/tmp:rw,noexec,nosuid,size=100m");
        }

        // Maximum security mode additional restrictions
        if self.security_level == SecurityLevel::Maximum {
            cmd.arg("--security-opt")
                .arg("apparmor:docker-default")
                .arg("--pids-limit")
                .arg("100")
                .arg("--ulimit")
                .arg("nofile=1024:1024")
                .arg("--ulimit")
                .arg("nproc=64:64");
        }

        // Add standard container configuration
        self.add_standard_docker_config(&mut cmd, config);

        let timeout = config.resource_limits.timeout_secs.unwrap_or(300);
        let output = tokio::time::timeout(
            Duration::from_secs(timeout),
            tokio::task::spawn_blocking(move || cmd.output()),
        )
        .await
        .context("Container execution timed out")?
        .context("Failed to spawn container command")?
        .context("Container command failed")?;

        Ok(ContainerExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Execute with Podman and seccomp
    async fn execute_podman_with_seccomp(
        &self,
        config: &ContainerRunConfig,
        seccomp_file: &Path,
    ) -> Result<ContainerExecutionResult> {
        let mut cmd = Command::new("podman");
        cmd.arg("run")
            .arg("--rm")
            .arg("--name")
            .arg(&config.container_id)
            .arg("--network")
            .arg(&config.network_mode)
            .arg("--security-opt")
            .arg(format!("seccomp={}", seccomp_file.display()));

        // Podman-specific security options
        if self.security_level != SecurityLevel::Minimal {
            cmd.arg("--security-opt")
                .arg("no-new-privileges")
                .arg("--cap-drop")
                .arg("ALL")
                .arg("--read-only")
                .arg("--tmpfs")
                .arg("/tmp:rw,noexec,nosuid,size=100m");
        }

        self.add_standard_podman_config(&mut cmd, config);

        let timeout = config.resource_limits.timeout_secs.unwrap_or(300);
        let output = tokio::time::timeout(
            Duration::from_secs(timeout),
            tokio::task::spawn_blocking(move || cmd.output()),
        )
        .await
        .context("Container execution timed out")?
        .context("Failed to spawn container command")?
        .context("Container command failed")?;

        Ok(ContainerExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Execute with containerd (basic security)
    async fn execute_containerd_basic(
        &self,
        config: &ContainerRunConfig,
    ) -> Result<ContainerExecutionResult> {
        warn!("containerd has limited seccomp support, using basic execution");

        let mut cmd = Command::new("ctr");
        cmd.arg("run")
            .arg("--rm")
            .arg(&config.image)
            .arg(&config.container_id)
            .arg(&config.command);

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

        Ok(ContainerExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Create secure environment variables
    fn create_secure_environment(
        &self,
        base_env: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        let mut env = base_env.clone();

        // Add security-related environment variables
        env.insert(
            "ATTEST_SECURITY_LEVEL".to_string(),
            match self.security_level {
                SecurityLevel::Minimal => "minimal",
                SecurityLevel::Standard => "standard",
                SecurityLevel::Maximum => "maximum",
            }
            .to_string(),
        );

        env.insert("ATTEST_SANDBOX_MODE".to_string(), "enhanced".to_string());

        // Secure defaults
        env.insert("HOME".to_string(), "/tmp".to_string());
        env.insert("TMPDIR".to_string(), "/tmp".to_string());
        env.insert("USER".to_string(), "nobody".to_string());

        // Remove potentially dangerous environment variables
        env.remove("LD_PRELOAD");
        env.remove("LD_LIBRARY_PATH");
        env.remove("PATH"); // Will be set to safe default by container

        env
    }

    /// Create secure volume mounts
    fn create_secure_volumes(&mut self, temp_dir: &Path) -> Result<Vec<super::VolumeMount>> {
        let mut volumes = Vec::new();

        // Only mount necessary directories with strict permissions
        for volume in &self.config.volumes {
            // Check if volume mount is allowed by filesystem security policy
            let is_allowed = self
                .filesystem_security
                .check_path_access(&volume.host_path, AccessMode::ReadOnly)
                .unwrap_or(false);

            if is_allowed && self.is_volume_safe(&volume.host_path) {
                volumes.push(super::VolumeMount {
                    host_path: volume.host_path.clone(),
                    container_path: volume.container_path.clone(),
                    read_only: true, // Force read-only for security
                });
            } else {
                warn!(
                    "Skipping unsafe or forbidden volume mount: {}",
                    volume.host_path.display()
                );
            }
        }

        // Add secure temp directory
        volumes.push(super::VolumeMount {
            host_path: temp_dir.to_path_buf(),
            container_path: PathBuf::from("/workspace"),
            read_only: false,
        });

        // Add filesystem security mount restrictions
        let security_restrictions = self.filesystem_security.generate_mount_restrictions();
        for restriction in security_restrictions {
            debug!("Filesystem security restriction: {}", restriction);
            // These would be applied as additional docker/podman arguments
        }

        Ok(volumes)
    }

    /// Check if volume mount is safe
    fn is_volume_safe(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // First check if it matches any safe prefixes
        let safe_prefixes = ["/tmp", "/workspace", "/data"];
        let is_safe_prefix = safe_prefixes
            .iter()
            .any(|prefix| path_str.starts_with(prefix));

        if !is_safe_prefix {
            return false;
        }

        // Block specific dangerous subdirectories even within safe prefixes
        let dangerous_paths = [
            "/boot", "/dev", "/etc", "/proc", "/sys", "/run", "/usr", "/var", "/opt", "/root",
            "/home",
        ];

        for dangerous in &dangerous_paths {
            if path_str.starts_with(dangerous) {
                return false;
            }
        }

        true
    }

    /// Get network mode based on policy
    fn get_network_mode(&self) -> String {
        match self.network_policy {
            NetworkPolicy::Disabled => "none".to_string(),
            NetworkPolicy::Restricted => "bridge".to_string(),
            NetworkPolicy::Full => "bridge".to_string(),
        }
    }

    /// Create resource limits based on security level
    fn create_resource_limits(&self) -> ResourceLimits {
        match self.security_level {
            SecurityLevel::Minimal => ResourceLimits {
                memory_mb: Some(1024),   // 1GB
                cpu_cores: Some(2.0),    // 2 cores
                timeout_secs: Some(600), // 10 minutes
            },
            SecurityLevel::Standard => ResourceLimits {
                memory_mb: Some(512),    // 512MB
                cpu_cores: Some(1.0),    // 1 core
                timeout_secs: Some(300), // 5 minutes
            },
            SecurityLevel::Maximum => ResourceLimits {
                memory_mb: Some(256),    // 256MB
                cpu_cores: Some(0.5),    // 0.5 cores
                timeout_secs: Some(120), // 2 minutes
            },
        }
    }

    /// Add standard Docker configuration
    fn add_standard_docker_config(&self, cmd: &mut Command, config: &ContainerRunConfig) {
        // Resource limits
        if let Some(memory) = config.resource_limits.memory_mb {
            cmd.arg("--memory").arg(format!("{}m", memory));
        }
        if let Some(cpu) = config.resource_limits.cpu_cores {
            cmd.arg("--cpus").arg(cpu.to_string());
        }

        // Environment variables
        for (key, value) in &config.environment {
            cmd.arg("-e").arg(format!("{}={}", key, value));
        }

        // Volumes
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

        // Working directory and user
        if let Some(work_dir) = &config.working_dir {
            cmd.arg("-w").arg(work_dir);
        }
        if let Some(user) = &config.user {
            cmd.arg("--user").arg(user);
        }

        // Image and command
        cmd.arg(&config.image).arg(&config.command);
        for arg in &config.args {
            cmd.arg(arg);
        }
    }

    /// Add standard Podman configuration
    fn add_standard_podman_config(&self, cmd: &mut Command, config: &ContainerRunConfig) {
        // Podman configuration is similar to Docker
        self.add_standard_docker_config(cmd, config);
    }

    /// Check for security violations after execution
    async fn check_for_violations(&mut self, container_id: &str) -> Result<()> {
        // In a real implementation, this would:
        // 1. Parse container logs for seccomp violations
        // 2. Check audit logs for syscall denials
        // 3. Monitor for unexpected process behavior

        debug!(
            "Checking for security violations in container: {}",
            container_id
        );

        // Simulate violation detection from container logs
        let log_output = self.get_container_logs(container_id).await?;
        self.parse_security_violations(&log_output)?;

        Ok(())
    }

    /// Get container logs for violation analysis
    async fn get_container_logs(&self, container_id: &str) -> Result<String> {
        let cmd_name = match self.config.runtime {
            ContainerRuntime::Docker => "docker",
            ContainerRuntime::Podman => "podman",
            ContainerRuntime::Containerd => "ctr",
        };

        let mut cmd = Command::new(cmd_name);
        match self.config.runtime {
            ContainerRuntime::Docker | ContainerRuntime::Podman => {
                cmd.arg("logs").arg(container_id);
            }
            ContainerRuntime::Containerd => {
                // containerd has different log access
                return Ok(String::new());
            }
        }

        let output = cmd.output().unwrap_or_else(|_| {
            use std::process::{ExitStatus, Output};
            // Create a mock failed status - this is platform specific
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                Output {
                    status: ExitStatus::from_raw(1),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }
            }
            #[cfg(not(unix))]
            {
                // Fallback for non-Unix systems
                Output {
                    status: ExitStatus::from_raw(1),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }
            }
        });

        Ok(String::from_utf8_lossy(&output.stderr).to_string())
    }

    /// Parse container logs for security violations
    fn parse_security_violations(&mut self, logs: &str) -> Result<()> {
        // Look for seccomp violation patterns
        for line in logs.lines() {
            if line.contains("seccomp") && (line.contains("killed") || line.contains("denied")) {
                // Extract violation information
                let violation = SeccompViolation {
                    timestamp: chrono::Utc::now(),
                    pid: self.extract_pid_from_log(line).unwrap_or(0),
                    syscall: self
                        .extract_syscall_from_log(line)
                        .unwrap_or_else(|| "unknown".to_string()),
                    action: super::seccomp::SeccompAction::Kill,
                    context: line.to_string(),
                };

                self.violation_detector.record_violation(violation);
            }
        }

        Ok(())
    }

    /// Extract PID from log line
    fn extract_pid_from_log(&self, line: &str) -> Option<u32> {
        // Simple regex-like extraction (in real implementation would use proper regex)
        line.split_whitespace()
            .find(|part| part.starts_with("pid="))
            .and_then(|part| part.strip_prefix("pid="))
            .and_then(|pid_str| pid_str.parse().ok())
    }

    /// Extract syscall name from log line
    fn extract_syscall_from_log(&self, line: &str) -> Option<String> {
        // Simple extraction (in real implementation would use proper regex)
        line.split_whitespace()
            .find(|part| part.starts_with("syscall="))
            .and_then(|part| part.strip_prefix("syscall="))
            .map(|s| s.to_string())
    }

    /// Get violation statistics
    pub fn get_violation_stats(&self) -> (usize, Vec<String>) {
        let violations = self.violation_detector.get_violations();
        let count = violations.len();
        let syscalls: Vec<String> = violations.iter().map(|v| v.syscall.clone()).collect();

        (count, syscalls)
    }

    /// Export security report
    pub fn export_security_report(&self) -> Result<String> {
        let seccomp_violations = self.violation_detector.export_violations()?;
        let filesystem_violations = self.filesystem_security.export_violations()?;
        let stats = self.seccomp_manager.get_profile_stats(
            &self
                .seccomp_manager
                .get_current_profile()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "unknown".to_string()),
        );

        let report = serde_json::json!({
            "security_level": match self.security_level {
                SecurityLevel::Minimal => "minimal",
                SecurityLevel::Standard => "standard",
                SecurityLevel::Maximum => "maximum",
            },
            "network_policy": match self.network_policy {
                NetworkPolicy::Disabled => "disabled",
                NetworkPolicy::Restricted => "restricted",
                NetworkPolicy::Full => "full",
            },
            "seccomp": {
                "profile": stats,
                "violations": serde_json::from_str::<serde_json::Value>(&seccomp_violations)?,
            },
            "filesystem": {
                "policy_summary": self.filesystem_security.get_policy_summary(),
                "violations": serde_json::from_str::<serde_json::Value>(&filesystem_violations)?,
            },
            "generated_at": chrono::Utc::now().to_rfc3339(),
        });

        serde_json::to_string_pretty(&report).context("Failed to generate security report")
    }
}

/// Container execution result
#[derive(Debug)]
struct ContainerExecutionResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
}
