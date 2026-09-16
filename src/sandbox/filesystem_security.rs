//! Advanced filesystem security restrictions for container isolation
//!
//! This module provides fine-grained filesystem access control, path traversal
//! prevention, and filesystem violation detection for enhanced security.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::warn;

/// Filesystem access mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessMode {
    /// Read-only access
    ReadOnly,
    /// Write access (includes read)
    ReadWrite,
    /// Execute access
    Execute,
    /// No access allowed
    Forbidden,
}

/// Filesystem access rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemRule {
    /// Path pattern (supports glob patterns)
    pub path_pattern: String,
    /// Access mode for this path
    pub access_mode: AccessMode,
    /// Whether this rule applies recursively to subdirectories
    pub recursive: bool,
    /// Rule priority (higher numbers take precedence)
    pub priority: u32,
    /// Description of the rule
    pub description: String,
}

/// Filesystem security policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemSecurityPolicy {
    /// Default access mode for unmatched paths
    pub default_access: AccessMode,
    /// List of filesystem rules
    pub rules: Vec<FilesystemRule>,
    /// Maximum file size allowed (in bytes)
    pub max_file_size: Option<u64>,
    /// Maximum total disk usage (in bytes)
    pub max_disk_usage: Option<u64>,
    /// Allowed file extensions
    pub allowed_extensions: Option<HashSet<String>>,
    /// Forbidden file extensions
    pub forbidden_extensions: HashSet<String>,
    /// Enable path traversal protection
    pub prevent_path_traversal: bool,
    /// Enable symlink following restrictions
    pub restrict_symlinks: bool,
}

impl Default for FilesystemSecurityPolicy {
    fn default() -> Self {
        Self {
            default_access: AccessMode::Forbidden,
            rules: vec![
                // Allow basic system operations
                FilesystemRule {
                    path_pattern: "/tmp/*".to_string(),
                    access_mode: AccessMode::ReadWrite,
                    recursive: true,
                    priority: 100,
                    description: "Temporary directory access".to_string(),
                },
                FilesystemRule {
                    path_pattern: "/workspace/*".to_string(),
                    access_mode: AccessMode::ReadWrite,
                    recursive: true,
                    priority: 200,
                    description: "Workspace directory access".to_string(),
                },
                // Block dangerous system directories
                FilesystemRule {
                    path_pattern: "/etc/*".to_string(),
                    access_mode: AccessMode::Forbidden,
                    recursive: true,
                    priority: 1000,
                    description: "Block system configuration".to_string(),
                },
                FilesystemRule {
                    path_pattern: "/proc/*".to_string(),
                    access_mode: AccessMode::Forbidden,
                    recursive: true,
                    priority: 1000,
                    description: "Block process filesystem".to_string(),
                },
                FilesystemRule {
                    path_pattern: "/sys/*".to_string(),
                    access_mode: AccessMode::Forbidden,
                    recursive: true,
                    priority: 1000,
                    description: "Block system filesystem".to_string(),
                },
            ],
            max_file_size: Some(100 * 1024 * 1024),   // 100MB
            max_disk_usage: Some(1024 * 1024 * 1024), // 1GB
            allowed_extensions: None,                 // Allow all by default
            forbidden_extensions: [
                "exe".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "com".to_string(),
                "scr".to_string(),
            ]
            .into_iter()
            .collect(),
            prevent_path_traversal: true,
            restrict_symlinks: true,
        }
    }
}

/// Filesystem violation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemViolation {
    /// Timestamp of violation
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Path that was accessed
    pub path: PathBuf,
    /// Attempted access mode
    pub attempted_access: AccessMode,
    /// Reason for violation
    pub violation_type: FilesystemViolationType,
    /// Additional context
    pub context: String,
}

/// Types of filesystem violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilesystemViolationType {
    /// Access to forbidden path
    ForbiddenPath,
    /// Path traversal attempt
    PathTraversal,
    /// Symlink restriction violation
    SymlinkViolation,
    /// File size limit exceeded
    FileSizeLimit,
    /// Disk usage limit exceeded
    DiskUsageLimit,
    /// Forbidden file extension
    ForbiddenExtension,
    /// Invalid path format
    InvalidPath,
}

/// Filesystem security manager
pub struct FilesystemSecurityManager {
    policy: FilesystemSecurityPolicy,
    violations: Vec<FilesystemViolation>,
    max_violations: usize,
    disk_usage_tracker: HashMap<PathBuf, u64>,
}

impl FilesystemSecurityManager {
    /// Create new filesystem security manager
    pub fn new(policy: FilesystemSecurityPolicy) -> Self {
        Self {
            policy,
            violations: Vec::new(),
            max_violations: 1000,
            disk_usage_tracker: HashMap::new(),
        }
    }

    /// Create manager with default security policy
    pub fn with_default_policy() -> Self {
        Self::new(FilesystemSecurityPolicy::default())
    }

    /// Create manager with strict security policy
    pub fn with_strict_policy() -> Self {
        let mut policy = FilesystemSecurityPolicy {
            default_access: AccessMode::Forbidden,
            max_file_size: Some(10 * 1024 * 1024),   // 10MB
            max_disk_usage: Some(100 * 1024 * 1024), // 100MB
            prevent_path_traversal: true,
            restrict_symlinks: true,
            ..Default::default()
        };

        // Add more restrictive rules
        policy.rules.push(FilesystemRule {
            path_pattern: "/workspace/*.tmp".to_string(),
            access_mode: AccessMode::ReadWrite,
            recursive: false,
            priority: 50,
            description: "Allow only temporary files in workspace".to_string(),
        });

        Self::new(policy)
    }

    /// Check if path access is allowed
    pub fn check_path_access(&mut self, path: &Path, access_mode: AccessMode) -> Result<bool> {
        let normalized_path = self.normalize_path(path)?;

        // Check for path traversal
        if self.policy.prevent_path_traversal && self.has_path_traversal(&normalized_path) {
            self.record_violation(FilesystemViolation {
                timestamp: chrono::Utc::now(),
                path: normalized_path,
                attempted_access: access_mode,
                violation_type: FilesystemViolationType::PathTraversal,
                context: "Path traversal detected".to_string(),
            });
            return Ok(false);
        }

        // Check file extension
        if let Some(extension) = normalized_path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();

            // Check forbidden extensions
            if self.policy.forbidden_extensions.contains(&ext_str) {
                self.record_violation(FilesystemViolation {
                    timestamp: chrono::Utc::now(),
                    path: normalized_path,
                    attempted_access: access_mode,
                    violation_type: FilesystemViolationType::ForbiddenExtension,
                    context: format!("Forbidden file extension: {}", ext_str),
                });
                return Ok(false);
            }

            // Check allowed extensions (if specified)
            if let Some(allowed) = &self.policy.allowed_extensions {
                if !allowed.contains(&ext_str) {
                    self.record_violation(FilesystemViolation {
                        timestamp: chrono::Utc::now(),
                        path: normalized_path,
                        attempted_access: access_mode,
                        violation_type: FilesystemViolationType::ForbiddenExtension,
                        context: format!("File extension not in allowlist: {}", ext_str),
                    });
                    return Ok(false);
                }
            }
        }

        // Find matching rule with highest priority
        let matching_rule = self.find_matching_rule(&normalized_path);

        let allowed_access = matching_rule
            .map(|rule| &rule.access_mode)
            .unwrap_or(&self.policy.default_access);

        let is_allowed = match (allowed_access, &access_mode) {
            (AccessMode::ReadWrite, _) => true,
            (AccessMode::ReadOnly, AccessMode::ReadOnly) => true,
            (AccessMode::Execute, AccessMode::Execute) => true,
            (AccessMode::Forbidden, _) => false,
            _ => false,
        };

        if !is_allowed {
            self.record_violation(FilesystemViolation {
                timestamp: chrono::Utc::now(),
                path: normalized_path,
                attempted_access: access_mode,
                violation_type: FilesystemViolationType::ForbiddenPath,
                context: "Access denied by policy rule".to_string(),
            });
        }

        Ok(is_allowed)
    }

    /// Check file size limit
    pub fn check_file_size(&mut self, path: &Path, size: u64) -> Result<bool> {
        if let Some(max_size) = self.policy.max_file_size {
            if size > max_size {
                self.record_violation(FilesystemViolation {
                    timestamp: chrono::Utc::now(),
                    path: path.to_path_buf(),
                    attempted_access: AccessMode::ReadWrite,
                    violation_type: FilesystemViolationType::FileSizeLimit,
                    context: format!("File size {} exceeds limit {}", size, max_size),
                });
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Track disk usage for a path
    pub fn track_disk_usage(&mut self, path: &Path, size: u64) -> Result<bool> {
        // Update disk usage tracking
        let parent = path.parent().unwrap_or(path);
        *self
            .disk_usage_tracker
            .entry(parent.to_path_buf())
            .or_insert(0) += size;

        // Check total disk usage limit
        if let Some(max_usage) = self.policy.max_disk_usage {
            let total_usage: u64 = self.disk_usage_tracker.values().sum();
            if total_usage > max_usage {
                self.record_violation(FilesystemViolation {
                    timestamp: chrono::Utc::now(),
                    path: path.to_path_buf(),
                    attempted_access: AccessMode::ReadWrite,
                    violation_type: FilesystemViolationType::DiskUsageLimit,
                    context: format!(
                        "Total disk usage {} exceeds limit {}",
                        total_usage, max_usage
                    ),
                });
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Generate filesystem mount restrictions for container runtime
    pub fn generate_mount_restrictions(&self) -> Vec<String> {
        let mut restrictions = Vec::new();

        // Add read-only mounts for system directories
        let readonly_paths = [
            "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/opt", "/var/lib", "/root",
        ];

        for path in &readonly_paths {
            restrictions.push(format!("{}:{}:ro", path, path));
        }

        // Add tmpfs for writable temporary directories
        restrictions.push("tmpfs:/tmp:rw,noexec,nosuid,size=100m".to_string());
        restrictions.push("tmpfs:/var/tmp:rw,noexec,nosuid,size=50m".to_string());

        restrictions
    }

    /// Get policy summary
    pub fn get_policy_summary(&self) -> String {
        format!(
            "Filesystem Security Policy:\n\
             - Default access: {:?}\n\
             - Rules: {} active\n\
             - Max file size: {:?}\n\
             - Max disk usage: {:?}\n\
             - Path traversal protection: {}\n\
             - Symlink restrictions: {}\n\
             - Forbidden extensions: {}",
            self.policy.default_access,
            self.policy.rules.len(),
            self.policy.max_file_size,
            self.policy.max_disk_usage,
            self.policy.prevent_path_traversal,
            self.policy.restrict_symlinks,
            self.policy.forbidden_extensions.len()
        )
    }

    /// Get violations
    pub fn get_violations(&self) -> &[FilesystemViolation] {
        &self.violations
    }

    /// Clear violations
    pub fn clear_violations(&mut self) {
        self.violations.clear();
    }

    /// Export violations as JSON
    pub fn export_violations(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.violations)
            .context("Failed to serialize filesystem violations")
    }

    // Private helper methods

    fn normalize_path(&self, path: &Path) -> Result<PathBuf> {
        // Convert to absolute path and resolve . and .. components
        let path_str = path.to_string_lossy();
        if path_str.contains("..") || path_str.contains("./") {
            // Basic path traversal detection
            let normalized = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
            Ok(normalized)
        } else {
            Ok(path.to_path_buf())
        }
    }

    fn has_path_traversal(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        path_str.contains("../") || path_str.contains("..\\") || path_str.contains("/..")
    }

    fn find_matching_rule(&self, path: &Path) -> Option<&FilesystemRule> {
        let mut matching_rules: Vec<&FilesystemRule> = self
            .policy
            .rules
            .iter()
            .filter(|rule| self.path_matches_pattern(path, &rule.path_pattern, rule.recursive))
            .collect();

        // Sort by priority (highest first)
        matching_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        matching_rules.first().copied()
    }

    fn path_matches_pattern(&self, path: &Path, pattern: &str, recursive: bool) -> bool {
        let path_str = path.to_string_lossy();

        if let Some(prefix) = pattern.strip_suffix("/*") {
            if recursive {
                path_str.starts_with(prefix)
            } else {
                path_str.starts_with(prefix)
                    && path_str[prefix.len()..]
                        .chars()
                        .filter(|&c| c == '/')
                        .count()
                        <= 1
            }
        } else if pattern.contains('*') {
            // Simple glob matching (could be enhanced with regex)
            let pattern_parts: Vec<&str> = pattern.split('*').collect();
            if pattern_parts.len() == 2 {
                path_str.starts_with(pattern_parts[0]) && path_str.ends_with(pattern_parts[1])
            } else {
                false
            }
        } else {
            path_str == pattern || (recursive && path_str.starts_with(&format!("{}/", pattern)))
        }
    }

    fn record_violation(&mut self, violation: FilesystemViolation) {
        warn!(
            "Filesystem violation: {:?} access to '{}' - {:?}",
            violation.attempted_access,
            violation.path.display(),
            violation.violation_type
        );

        self.violations.push(violation);

        // Keep only the most recent violations
        if self.violations.len() > self.max_violations {
            self.violations.remove(0);
        }
    }
}
