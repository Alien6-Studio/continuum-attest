use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

pub mod container;
pub mod deterministic;
pub mod enhanced_container;
pub mod filesystem_security;
pub mod seccomp;

pub use container::ContainerSandbox;
pub use deterministic::DeterministicTime;
pub use enhanced_container::EnhancedContainerSandbox;
pub use seccomp::{SeccompManager, SecurityLevel, ViolationDetector};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub isolation_level: IsolationLevel,
    pub deterministic_time: bool,
    pub fixed_timestamp: Option<DateTime<Utc>>,
    pub resource_limits: ResourceLimits,
    pub network_policy: NetworkPolicy,
    pub filesystem_policy: FilesystemPolicy,
    pub container_config: Option<ContainerConfig>,
    pub seccomp_profile: Option<String>,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IsolationLevel {
    None,            // No isolation
    Process,         // Process-level isolation
    Container,       // Container-based isolation
    StrictContainer, // Maximum isolation for formal proof mode
    VM,              // Full VM isolation (future)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Enforced under process isolation via RLIMIT_AS; containers map it to
    /// their runtime's memory flag.
    pub memory_mb: Option<u64>,
    /// Advisory under process isolation: there is no portable per-process
    /// core cap (Linux affinity does not exist on macOS). Only container
    /// isolation enforces it, via the runtime's `--cpus` flag.
    pub cpu_cores: Option<f64>,
    /// Enforced: the command is killed once the timeout elapses and fails
    /// with exit code 124 (mirroring GNU timeout).
    pub timeout_secs: Option<u64>,
    /// Enforced under process isolation via RLIMIT_NOFILE.
    pub max_files: Option<u64>,
    pub max_file_size_mb: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum NetworkPolicy {
    Disabled,   // No network access
    Restricted, // Limited network access
    Full,       // Full network access
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    pub read_only_paths: Vec<PathBuf>,
    pub writable_paths: Vec<PathBuf>,
    pub temp_dir: Option<PathBuf>,
    pub max_disk_usage_mb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    pub image: String,
    pub volumes: Vec<VolumeMount>,
    pub environment: HashMap<String, String>,
    pub working_dir: Option<PathBuf>,
    pub user: Option<String>,
    pub entrypoint: Option<Vec<String>>,
    pub runtime: ContainerRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub host_path: PathBuf,
    pub container_path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContainerRuntime {
    Docker,
    Podman,
    Containerd,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            isolation_level: IsolationLevel::Process,
            deterministic_time: true,
            fixed_timestamp: None,
            resource_limits: ResourceLimits::default(),
            network_policy: NetworkPolicy::Disabled,
            filesystem_policy: FilesystemPolicy::default(),
            container_config: None,
            seccomp_profile: Some("minimal".to_string()),
            security_level: SecurityLevel::Minimal,
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            // No memory limit by default: process isolation maps memory_mb to
            // RLIMIT_AS (virtual address space), and modern toolchains (rustc,
            // lld, JVMs) reserve far more address space than resident memory.
            // A default cap makes their thread/mmap allocations fail with
            // EAGAIN, so memory limiting is opt-in.
            memory_mb: None,
            cpu_cores: Some(1.0),
            // No timeout by default, for the same reason as memory_mb: now
            // that the timeout is actually enforced, a silent 300s default
            // would kill legitimate long-running steps (a cargo release
            // build easily exceeds it). Timeouts are opt-in, per step
            // (`timeout_secs` in attest.yaml) or per sandbox config.
            timeout_secs: None,
            max_files: Some(1000),
            max_file_size_mb: Some(100),
        }
    }
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            read_only_paths: vec![],
            writable_paths: vec![],
            temp_dir: None,
            max_disk_usage_mb: Some(1024),
        }
    }
}

pub struct Sandbox {
    config: SandboxConfig,
    container_sandbox: Option<ContainerSandbox>,
    enhanced_container_sandbox: Option<EnhancedContainerSandbox>,
    deterministic_time: Option<DeterministicTime>,
    seccomp_manager: SeccompManager,
    violation_detector: ViolationDetector,
}

impl Sandbox {
    pub fn new(config: SandboxConfig) -> Result<Self> {
        // Choose between regular and enhanced container sandbox based on security level
        let (container_sandbox, enhanced_container_sandbox) = match config.isolation_level {
            IsolationLevel::Container => {
                let container_config = config
                    .container_config
                    .clone()
                    .context("Container config required for container isolation")?;
                (Some(ContainerSandbox::new(container_config)?), None)
            }
            IsolationLevel::StrictContainer => {
                // Use enhanced container sandbox for strict isolation
                let container_config = config
                    .container_config
                    .clone()
                    .context("Container config required for strict container isolation")?;

                let enhanced_sandbox = EnhancedContainerSandbox::new(
                    container_config,
                    config.security_level,
                    config.network_policy,
                )?;
                (None, Some(enhanced_sandbox))
            }
            _ => (None, None),
        };

        let deterministic_time = if config.deterministic_time {
            Some(DeterministicTime::new(config.fixed_timestamp)?)
        } else {
            None
        };

        // Initialize seccomp manager
        let mut seccomp_manager = SeccompManager::new();
        if let Some(profile_name) = &config.seccomp_profile {
            seccomp_manager
                .set_profile(profile_name)
                .with_context(|| format!("Failed to set seccomp profile: {}", profile_name))?;
        }

        // Initialize violation detector
        let violation_detector = ViolationDetector::new(1000); // Max 1000 violations

        Ok(Self {
            config,
            container_sandbox,
            enhanced_container_sandbox,
            deterministic_time,
            seccomp_manager,
            violation_detector,
        })
    }

    pub async fn execute(
        &mut self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        working_dir: Option<&Path>,
    ) -> Result<SandboxResult> {
        self.execute_with_timeout(command, args, env, working_dir, None)
            .await
    }

    /// Like [`execute`](Self::execute), with an additional per-invocation
    /// timeout (e.g. a step's `timeout_secs`). The stricter of this timeout
    /// and `resource_limits.timeout_secs` wins. Container isolation manages
    /// its own timeouts and ignores the per-invocation value.
    pub async fn execute_with_timeout(
        &mut self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        working_dir: Option<&Path>,
        timeout: Option<Duration>,
    ) -> Result<SandboxResult> {
        let start_time = SystemTime::now();

        let timeout = match (timeout, self.config.resource_limits.timeout_secs) {
            (Some(a), Some(b)) => Some(a.min(Duration::from_secs(b))),
            (a, b) => a.or(b.map(Duration::from_secs)),
        };

        let result = match self.config.isolation_level {
            IsolationLevel::None => {
                self.execute_direct(command, args, env, working_dir, timeout)
                    .await
            }
            IsolationLevel::Process => {
                self.execute_process_isolated(command, args, env, working_dir, timeout)
                    .await
            }
            IsolationLevel::Container => {
                self.execute_container_isolated(command, args, env, working_dir)
                    .await
            }
            IsolationLevel::StrictContainer => {
                // Use enhanced container sandbox with strict security
                self.execute_enhanced_container_isolated(command, args, env, working_dir)
                    .await
            }
            IsolationLevel::VM => {
                anyhow::bail!("VM isolation not yet implemented")
            }
        };

        let execution_time = start_time.elapsed().unwrap_or(Duration::from_secs(0));

        match result {
            Ok(mut sandbox_result) => {
                sandbox_result.execution_time = execution_time;
                sandbox_result.deterministic_timestamp =
                    self.deterministic_time.as_ref().map(|dt| dt.current_time());
                Ok(sandbox_result)
            }
            Err(e) => Err(e),
        }
    }

    async fn execute_direct(
        &self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        working_dir: Option<&Path>,
        timeout: Option<Duration>,
    ) -> Result<SandboxResult> {
        let mut cmd = Command::new(command);
        cmd.args(args);

        // Set environment variables
        let mut effective_env = std::env::vars().collect::<HashMap<_, _>>();
        effective_env.extend(env.clone());

        // Add deterministic time if configured
        if let Some(det_time) = &self.deterministic_time {
            effective_env.extend(det_time.environment_variables());
        }

        cmd.envs(&effective_env);

        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }

        let output = run_with_timeout(&mut cmd, timeout)?;

        Ok(SandboxResult {
            exit_code: output.exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
            execution_time: Duration::from_secs(0), // Will be set by caller
            deterministic_timestamp: None,          // Will be set by caller
            resource_usage: ResourceUsage::default(),
            isolation_violations: vec![],
        })
    }

    async fn execute_process_isolated(
        &self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        working_dir: Option<&Path>,
        timeout: Option<Duration>,
    ) -> Result<SandboxResult> {
        // Use process isolation with resource limits
        #[cfg(unix)]
        {
            self.execute_unix_isolated(command, args, env, working_dir, timeout)
                .await
        }
        #[cfg(not(unix))]
        {
            // Fallback to direct execution on non-Unix systems
            self.execute_direct(command, args, env, working_dir, timeout)
                .await
        }
    }

    #[cfg(unix)]
    async fn execute_unix_isolated(
        &self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        working_dir: Option<&Path>,
        timeout: Option<Duration>,
    ) -> Result<SandboxResult> {
        use std::os::unix::process::CommandExt;

        let mut cmd = Command::new(command);
        cmd.args(args);

        // Set environment
        let mut effective_env = HashMap::new();

        // Add deterministic time environment
        if let Some(det_time) = &self.deterministic_time {
            effective_env.extend(det_time.environment_variables());
        }

        effective_env.extend(env.clone());
        cmd.envs(&effective_env);

        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }

        // Set resource limits using setrlimit
        let memory_limit = self.config.resource_limits.memory_mb;
        let file_limit = self.config.resource_limits.max_files;

        unsafe {
            cmd.pre_exec(move || {
                // Set memory limit
                if let Some(memory_mb) = memory_limit {
                    let rlimit = libc::rlimit {
                        rlim_cur: (memory_mb * 1024 * 1024) as libc::rlim_t,
                        rlim_max: (memory_mb * 1024 * 1024) as libc::rlim_t,
                    };
                    libc::setrlimit(libc::RLIMIT_AS, &rlimit);
                }

                // Set file limit
                if let Some(max_files) = file_limit {
                    let rlimit = libc::rlimit {
                        rlim_cur: max_files as libc::rlim_t,
                        rlim_max: max_files as libc::rlim_t,
                    };
                    libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit);
                }

                Ok(())
            });
        }

        let output = run_with_timeout(&mut cmd, timeout)?;

        Ok(SandboxResult {
            exit_code: output.exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
            execution_time: Duration::from_secs(0),
            deterministic_timestamp: None,
            resource_usage: ResourceUsage::default(),
            isolation_violations: vec![],
        })
    }

    async fn execute_container_isolated(
        &self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        working_dir: Option<&Path>,
    ) -> Result<SandboxResult> {
        let container_sandbox = self
            .container_sandbox
            .as_ref()
            .context("Container sandbox not initialized")?;

        container_sandbox
            .execute(command, args, env, working_dir)
            .await
    }

    async fn execute_enhanced_container_isolated(
        &mut self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
        working_dir: Option<&Path>,
    ) -> Result<SandboxResult> {
        let enhanced_sandbox = self
            .enhanced_container_sandbox
            .as_mut()
            .context("Enhanced container sandbox not initialized")?;

        enhanced_sandbox
            .execute_secure(command, args, env, working_dir)
            .await
    }

    /// Get security violation statistics
    pub fn get_violation_stats(&self) -> (usize, Vec<String>) {
        match &self.enhanced_container_sandbox {
            Some(enhanced) => enhanced.get_violation_stats(),
            None => (self.violation_detector.violations_count(), vec![]),
        }
    }

    /// Export security report (if enhanced sandbox is available)
    pub fn export_security_report(&self) -> Result<Option<String>> {
        match &self.enhanced_container_sandbox {
            Some(enhanced) => Ok(Some(enhanced.export_security_report()?)),
            None => Ok(None),
        }
    }

    /// Get current seccomp profile information
    pub fn get_seccomp_profile_info(&self) -> Option<String> {
        self.seccomp_manager
            .get_current_profile()
            .map(|profile| format!("{} ({})", profile.name, profile.description))
    }

    /// Check if enhanced security features are enabled
    pub fn has_enhanced_security(&self) -> bool {
        self.enhanced_container_sandbox.is_some()
            || self.config.isolation_level == IsolationLevel::StrictContainer
    }
}

/// Captured output of a command run under an optional wall-clock timeout.
pub(crate) struct TimedOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run `cmd` to completion, killing it if `timeout` elapses first.
///
/// On timeout the whole process group is killed (the command is made its
/// own group leader on Unix, so shell-spawned children die with it), the
/// exit code is 124 — mirroring GNU timeout — and a note is appended to
/// the captured stderr.
pub(crate) fn run_with_timeout(
    cmd: &mut Command,
    timeout: Option<Duration>,
) -> Result<TimedOutput> {
    let Some(timeout) = timeout else {
        let output = cmd.output().context("Failed to execute command")?;
        return Ok(TimedOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    };

    use std::io::Read;
    use std::process::Stdio;

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // New process group, so the timeout kill reaches every child
            // the command spawned, not just the immediate shell.
            libc::setpgid(0, 0);
            Ok(())
        });
    }

    let mut child = cmd.spawn().context("Failed to execute command")?;

    // Drain the pipes on threads so a chatty child cannot deadlock on a
    // full pipe buffer while we only poll its exit status.
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = std::time::Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().context("Failed to wait for command")? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            #[cfg(unix)]
            unsafe {
                libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            break child.wait().context("Failed to reap timed-out command")?;
        }
        std::thread::sleep(Duration::from_millis(25));
    };

    let stdout = String::from_utf8_lossy(&stdout_thread.join().unwrap_or_default()).to_string();
    let mut stderr = String::from_utf8_lossy(&stderr_thread.join().unwrap_or_default()).to_string();
    if timed_out {
        if !stderr.is_empty() && !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        stderr.push_str(&format!(
            "command timed out after {}s and was killed\n",
            timeout.as_secs()
        ));
    }

    Ok(TimedOutput {
        exit_code: if timed_out {
            124
        } else {
            status.code().unwrap_or(-1)
        },
        stdout,
        stderr,
    })
}

#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub execution_time: Duration,
    pub deterministic_timestamp: Option<DateTime<Utc>>,
    pub resource_usage: ResourceUsage,
    pub isolation_violations: Vec<IsolationViolation>,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    pub max_memory_mb: u64,
    pub cpu_time_ms: u64,
    pub files_created: u64,
    pub disk_usage_mb: u64,
    pub network_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct IsolationViolation {
    pub violation_type: ViolationType,
    pub description: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    NetworkAccess,
    FileSystemAccess,
    ResourceLimit,
    TimeViolation,
}
