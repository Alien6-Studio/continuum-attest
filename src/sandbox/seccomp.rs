//! Seccomp (Secure Computing) syscall filtering for container isolation
//!
//! This module provides system call filtering capabilities for enhanced security
//! in containerized environments. It supports different security profiles based
//! on operational modes and provides violation detection.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

/// Seccomp action when a system call matches a rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeccompAction {
    /// Allow the system call
    Allow,
    /// Kill the process
    Kill,
    /// Return errno
    Errno(u32),
    /// Trap and send SIGSYS
    Trap,
    /// Trace (log and allow)
    Trace,
    /// Log and allow (requires kernel support)
    Log,
}

/// System call filter rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRule {
    /// System call name or number
    pub syscall: String,
    /// Action to take
    pub action: SeccompAction,
    /// Optional arguments constraints
    pub args: Vec<SyscallArg>,
    /// Comment/description
    pub comment: Option<String>,
}

/// System call argument constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallArg {
    /// Argument index (0-5)
    pub index: u8,
    /// Value to compare
    pub value: u64,
    /// Comparison operator
    pub op: ArgOp,
}

/// Argument comparison operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgOp {
    /// Not equal
    NotEqual,
    /// Less than
    LessThan,
    /// Less than or equal
    LessEqual,
    /// Equal
    Equal,
    /// Greater than or equal
    GreaterEqual,
    /// Greater than
    GreaterThan,
    /// Masked equality (arg & mask == value)
    MaskedEqual(u64),
}

/// Seccomp profile for different security levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfile {
    /// Profile name
    pub name: String,
    /// Default action for unmatched syscalls
    pub default_action: SeccompAction,
    /// List of syscall rules
    pub rules: Vec<SyscallRule>,
    /// Architecture-specific rules
    pub architectures: Vec<String>,
    /// Profile description
    pub description: String,
}

/// Security profile levels aligned with operation modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Minimal restrictions (Light mode)
    Minimal,
    /// Standard restrictions (Verifiable mode)
    Standard,
    /// Maximum restrictions (Formal Proof mode)
    Maximum,
}

/// Seccomp filter manager
pub struct SeccompManager {
    profiles: HashMap<String, SeccompProfile>,
    current_profile: Option<String>,
}

impl Default for SeccompManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SeccompManager {
    /// Create a new seccomp manager with built-in profiles
    pub fn new() -> Self {
        let mut manager = Self {
            profiles: HashMap::new(),
            current_profile: None,
        };

        // Load built-in profiles
        manager.load_builtin_profiles();
        manager
    }

    /// Load built-in security profiles
    fn load_builtin_profiles(&mut self) {
        // Minimal profile for Light mode
        let minimal_profile = SeccompProfile {
            name: "minimal".to_string(),
            default_action: SeccompAction::Allow,
            rules: vec![
                // Block potentially dangerous syscalls
                SyscallRule {
                    syscall: "ptrace".to_string(),
                    action: SeccompAction::Kill,
                    args: vec![],
                    comment: Some("Block debugging/tracing".to_string()),
                },
                SyscallRule {
                    syscall: "kexec_load".to_string(),
                    action: SeccompAction::Kill,
                    args: vec![],
                    comment: Some("Block kernel replacement".to_string()),
                },
                SyscallRule {
                    syscall: "module_load".to_string(),
                    action: SeccompAction::Kill,
                    args: vec![],
                    comment: Some("Block kernel module loading".to_string()),
                },
                SyscallRule {
                    syscall: "reboot".to_string(),
                    action: SeccompAction::Kill,
                    args: vec![],
                    comment: Some("Block system restart".to_string()),
                },
            ],
            architectures: vec!["SCMP_ARCH_X86_64".to_string()],
            description: "Minimal security profile with basic protections".to_string(),
        };

        // Standard profile for Verifiable mode
        let standard_profile = SeccompProfile {
            name: "standard".to_string(),
            default_action: SeccompAction::Errno(1), // EPERM
            rules: vec![
                // Essential syscalls - allow
                SyscallRule {
                    syscall: "read".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow file reading".to_string()),
                },
                SyscallRule {
                    syscall: "write".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow file writing".to_string()),
                },
                SyscallRule {
                    syscall: "open".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow file opening".to_string()),
                },
                SyscallRule {
                    syscall: "openat".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow file opening (modern)".to_string()),
                },
                SyscallRule {
                    syscall: "close".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow file closing".to_string()),
                },
                SyscallRule {
                    syscall: "mmap".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow memory mapping".to_string()),
                },
                SyscallRule {
                    syscall: "munmap".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow memory unmapping".to_string()),
                },
                SyscallRule {
                    syscall: "brk".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow heap management".to_string()),
                },
                SyscallRule {
                    syscall: "exit".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow process exit".to_string()),
                },
                SyscallRule {
                    syscall: "exit_group".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow thread group exit".to_string()),
                },
                SyscallRule {
                    syscall: "execve".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Allow process execution".to_string()),
                },
                // Process management - restricted
                SyscallRule {
                    syscall: "fork".to_string(),
                    action: SeccompAction::Trace,
                    args: vec![],
                    comment: Some("Trace process creation".to_string()),
                },
                SyscallRule {
                    syscall: "vfork".to_string(),
                    action: SeccompAction::Trace,
                    args: vec![],
                    comment: Some("Trace process creation".to_string()),
                },
                SyscallRule {
                    syscall: "clone".to_string(),
                    action: SeccompAction::Trace,
                    args: vec![],
                    comment: Some("Trace thread/process creation".to_string()),
                },
                // Network - blocked by default
                SyscallRule {
                    syscall: "socket".to_string(),
                    action: SeccompAction::Kill,
                    args: vec![],
                    comment: Some("Block network socket creation".to_string()),
                },
                // Dangerous syscalls - blocked
                SyscallRule {
                    syscall: "ptrace".to_string(),
                    action: SeccompAction::Kill,
                    args: vec![],
                    comment: Some("Block debugging".to_string()),
                },
                SyscallRule {
                    syscall: "mount".to_string(),
                    action: SeccompAction::Kill,
                    args: vec![],
                    comment: Some("Block filesystem mounting".to_string()),
                },
                SyscallRule {
                    syscall: "umount".to_string(),
                    action: SeccompAction::Kill,
                    args: vec![],
                    comment: Some("Block filesystem unmounting".to_string()),
                },
                SyscallRule {
                    syscall: "chroot".to_string(),
                    action: SeccompAction::Kill,
                    args: vec![],
                    comment: Some("Block chroot".to_string()),
                },
            ],
            architectures: vec!["SCMP_ARCH_X86_64".to_string()],
            description: "Standard security profile with balanced restrictions".to_string(),
        };

        // Maximum profile for Formal Proof mode
        let maximum_profile = SeccompProfile {
            name: "maximum".to_string(),
            default_action: SeccompAction::Kill,
            rules: vec![
                // Only essential syscalls allowed
                SyscallRule {
                    syscall: "read".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Essential: file reading".to_string()),
                },
                SyscallRule {
                    syscall: "write".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Essential: file writing".to_string()),
                },
                SyscallRule {
                    syscall: "openat".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Essential: file access".to_string()),
                },
                SyscallRule {
                    syscall: "close".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Essential: file closing".to_string()),
                },
                SyscallRule {
                    syscall: "mmap".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![SyscallArg {
                        index: 3,    // flags
                        value: 0x02, // MAP_PRIVATE
                        op: ArgOp::MaskedEqual(0x02),
                    }],
                    comment: Some("Essential: memory mapping (private only)".to_string()),
                },
                SyscallRule {
                    syscall: "munmap".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Essential: memory cleanup".to_string()),
                },
                SyscallRule {
                    syscall: "brk".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Essential: heap management".to_string()),
                },
                SyscallRule {
                    syscall: "exit".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Essential: process exit".to_string()),
                },
                SyscallRule {
                    syscall: "exit_group".to_string(),
                    action: SeccompAction::Allow,
                    args: vec![],
                    comment: Some("Essential: thread group exit".to_string()),
                },
                // All other syscalls are killed by default action
            ],
            architectures: vec!["SCMP_ARCH_X86_64".to_string()],
            description: "Maximum security profile with minimal syscall allowlist".to_string(),
        };

        self.profiles.insert("minimal".to_string(), minimal_profile);
        self.profiles
            .insert("standard".to_string(), standard_profile);
        self.profiles.insert("maximum".to_string(), maximum_profile);
    }

    /// Get profile for security level
    pub fn get_profile_for_level(&self, level: SecurityLevel) -> Option<&SeccompProfile> {
        let profile_name = match level {
            SecurityLevel::Minimal => "minimal",
            SecurityLevel::Standard => "standard",
            SecurityLevel::Maximum => "maximum",
        };
        self.profiles.get(profile_name)
    }

    /// Set current active profile
    pub fn set_profile(&mut self, profile_name: &str) -> Result<()> {
        if self.profiles.contains_key(profile_name) {
            self.current_profile = Some(profile_name.to_string());
            info!("Seccomp profile set to: {}", profile_name);
            Ok(())
        } else {
            anyhow::bail!("Unknown seccomp profile: {}", profile_name);
        }
    }

    /// Get current profile
    pub fn get_current_profile(&self) -> Option<&SeccompProfile> {
        self.current_profile
            .as_ref()
            .and_then(|name| self.profiles.get(name))
    }

    /// Generate Docker/Podman seccomp profile JSON
    pub fn generate_container_profile(&self, profile_name: &str) -> Result<String> {
        let profile = self
            .profiles
            .get(profile_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown profile: {}", profile_name))?;

        let container_profile = ContainerSeccompProfile {
            default_action: self.action_to_string(profile.default_action),
            architectures: profile.architectures.clone(),
            syscalls: profile
                .rules
                .iter()
                .map(|rule| ContainerSyscall {
                    names: vec![rule.syscall.clone()],
                    action: self.action_to_string(rule.action),
                    args: rule
                        .args
                        .iter()
                        .map(|arg| ContainerSyscallArg {
                            index: arg.index as u32,
                            value: arg.value,
                            op: self.op_to_string(arg.op),
                        })
                        .collect(),
                })
                .collect(),
        };

        serde_json::to_string_pretty(&container_profile)
            .context("Failed to serialize seccomp profile")
    }

    /// Load custom profile from file
    pub fn load_profile_from_file(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read profile from {}", path.display()))?;

        let profile: SeccompProfile =
            serde_json::from_str(&content).context("Failed to parse seccomp profile")?;

        let name = profile.name.clone();
        self.profiles.insert(name.clone(), profile);
        info!("Loaded custom seccomp profile: {}", name);

        Ok(())
    }

    /// Save profile to file
    pub fn save_profile_to_file(&self, profile_name: &str, path: &Path) -> Result<()> {
        let profile = self
            .profiles
            .get(profile_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown profile: {}", profile_name))?;

        let content =
            serde_json::to_string_pretty(profile).context("Failed to serialize profile")?;

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write profile to {}", path.display()))?;

        info!(
            "Saved seccomp profile {} to {}",
            profile_name,
            path.display()
        );
        Ok(())
    }

    /// List available profiles
    pub fn list_profiles(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }

    /// Get profile statistics
    pub fn get_profile_stats(&self, profile_name: &str) -> Option<ProfileStats> {
        let profile = self.profiles.get(profile_name)?;

        let mut stats = ProfileStats {
            name: profile.name.clone(),
            total_rules: profile.rules.len(),
            allowed_syscalls: 0,
            blocked_syscalls: 0,
            traced_syscalls: 0,
            default_action: profile.default_action,
        };

        for rule in &profile.rules {
            match rule.action {
                SeccompAction::Allow => stats.allowed_syscalls += 1,
                SeccompAction::Kill | SeccompAction::Errno(_) => stats.blocked_syscalls += 1,
                SeccompAction::Trace | SeccompAction::Log => stats.traced_syscalls += 1,
                SeccompAction::Trap => stats.blocked_syscalls += 1,
            }
        }

        Some(stats)
    }

    // Helper methods for serialization
    fn action_to_string(&self, action: SeccompAction) -> String {
        match action {
            SeccompAction::Allow => "SCMP_ACT_ALLOW".to_string(),
            SeccompAction::Kill => "SCMP_ACT_KILL".to_string(),
            SeccompAction::Errno(errno) => format!("SCMP_ACT_ERRNO({})", errno),
            SeccompAction::Trap => "SCMP_ACT_TRAP".to_string(),
            SeccompAction::Trace => "SCMP_ACT_TRACE".to_string(),
            SeccompAction::Log => "SCMP_ACT_LOG".to_string(),
        }
    }

    fn op_to_string(&self, op: ArgOp) -> String {
        match op {
            ArgOp::NotEqual => "SCMP_CMP_NE".to_string(),
            ArgOp::LessThan => "SCMP_CMP_LT".to_string(),
            ArgOp::LessEqual => "SCMP_CMP_LE".to_string(),
            ArgOp::Equal => "SCMP_CMP_EQ".to_string(),
            ArgOp::GreaterEqual => "SCMP_CMP_GE".to_string(),
            ArgOp::GreaterThan => "SCMP_CMP_GT".to_string(),
            ArgOp::MaskedEqual(mask) => format!("SCMP_CMP_MASKED_EQ({})", mask),
        }
    }
}

/// Statistics for a seccomp profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileStats {
    pub name: String,
    pub total_rules: usize,
    pub allowed_syscalls: usize,
    pub blocked_syscalls: usize,
    pub traced_syscalls: usize,
    pub default_action: SeccompAction,
}

/// Container runtime seccomp format structures
#[derive(Serialize)]
struct ContainerSeccompProfile {
    #[serde(rename = "defaultAction")]
    default_action: String,
    architectures: Vec<String>,
    syscalls: Vec<ContainerSyscall>,
}

#[derive(Serialize)]
struct ContainerSyscall {
    names: Vec<String>,
    action: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    args: Vec<ContainerSyscallArg>,
}

#[derive(Serialize)]
struct ContainerSyscallArg {
    index: u32,
    value: u64,
    op: String,
}

/// Seccomp violation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompViolation {
    /// Timestamp of violation
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Process ID that caused violation
    pub pid: u32,
    /// System call that was blocked
    pub syscall: String,
    /// Action taken
    pub action: SeccompAction,
    /// Additional context
    pub context: String,
}

/// Violation detector and logger
pub struct ViolationDetector {
    violations: Vec<SeccompViolation>,
    max_violations: usize,
}

impl ViolationDetector {
    pub fn new(max_violations: usize) -> Self {
        Self {
            violations: Vec::new(),
            max_violations,
        }
    }

    /// Record a seccomp violation
    pub fn record_violation(&mut self, violation: SeccompViolation) {
        warn!(
            "Seccomp violation: PID {} attempted syscall '{}' (action: {:?})",
            violation.pid, violation.syscall, violation.action
        );

        self.violations.push(violation);

        // Keep only the most recent violations
        if self.violations.len() > self.max_violations {
            self.violations.remove(0);
        }
    }

    /// Get all recorded violations
    pub fn get_violations(&self) -> &[SeccompViolation] {
        &self.violations
    }

    /// Get violations count
    pub fn violations_count(&self) -> usize {
        self.violations.len()
    }

    /// Clear all violations
    pub fn clear_violations(&mut self) {
        self.violations.clear();
    }

    /// Export violations to JSON
    pub fn export_violations(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.violations).context("Failed to serialize violations")
    }
}
