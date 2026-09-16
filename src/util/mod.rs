// Utility functions for common operations across the ATTEST project

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// File system utilities
pub mod fs_utils {
    use super::*;

    /// Ensure a directory exists, creating it if necessary
    pub fn ensure_dir_exists<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if !path.exists() {
            fs::create_dir_all(path)?;
        } else if !path.is_dir() {
            return Err(anyhow!(
                "Path exists but is not a directory: {}",
                path.display()
            ));
        }
        Ok(())
    }

    /// Get file extension in lowercase
    pub fn get_file_extension<P: AsRef<Path>>(path: P) -> Option<String> {
        path.as_ref()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
    }

    /// Check if a file is readable
    pub fn is_file_readable<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();
        path.exists() && path.is_file() && fs::metadata(path).is_ok()
    }

    /// Get file size in bytes
    pub fn get_file_size<P: AsRef<Path>>(path: P) -> Result<u64> {
        let metadata = fs::metadata(path.as_ref())?;
        Ok(metadata.len())
    }

    /// Normalize path separators for cross-platform compatibility
    pub fn normalize_path<P: AsRef<Path>>(path: P) -> PathBuf {
        let path = path.as_ref();
        let path_str = path.to_string_lossy();
        PathBuf::from(path_str.replace('\\', "/"))
    }
}

/// String utilities
pub mod string_utils {

    /// Truncate string to maximum length with ellipsis
    pub fn truncate_string(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else if max_len <= 3 {
            "...".to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }

    /// Check if string contains any of the given patterns (case-insensitive)
    pub fn contains_any_ignore_case(text: &str, patterns: &[&str]) -> bool {
        let text_lower = text.to_lowercase();
        patterns
            .iter()
            .any(|pattern| text_lower.contains(&pattern.to_lowercase()))
    }

    /// Sanitize string for use in filenames
    pub fn sanitize_filename(name: &str) -> String {
        name.chars()
            .map(|c| match c {
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                c if c.is_control() => '_',
                c => c,
            })
            .collect()
    }

    /// Extract version from string (e.g., "v1.2.3" -> "1.2.3")
    pub fn extract_version(version_str: &str) -> Option<String> {
        let version_str = version_str.trim();
        if version_str.starts_with('v') || version_str.starts_with('V') {
            Some(version_str[1..].to_string())
        } else if version_str
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
        {
            Some(version_str.to_string())
        } else {
            None
        }
    }
}

/// Time utilities
pub mod time_utils {
    use super::*;

    /// Get current Unix timestamp in seconds
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get current Unix timestamp in milliseconds
    pub fn current_timestamp_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }

    /// Format duration as human-readable string
    pub fn format_duration(duration: Duration) -> String {
        let secs = duration.as_secs();
        let millis = duration.subsec_millis();

        if secs >= 3600 {
            format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
        } else if secs >= 60 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else if secs > 0 {
            format!("{}.{}s", secs, millis / 100)
        } else {
            format!("{}ms", millis)
        }
    }

    /// Check if timestamp is within the given age limit (in seconds)
    pub fn is_within_age_limit(timestamp: u64, max_age_seconds: u64) -> bool {
        let current = current_timestamp();
        current.saturating_sub(timestamp) <= max_age_seconds
    }
}

/// Hash utilities
pub mod hash_utils {
    use super::*;
    use blake3::Hasher;

    /// Generate Blake3 hash of a string
    pub fn hash_string(input: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(input.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Generate Blake3 hash of multiple strings combined
    pub fn hash_strings(inputs: &[&str]) -> String {
        let mut hasher = Hasher::new();
        for input in inputs {
            hasher.update(input.as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Generate Blake3 hash of a file
    pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<String> {
        let content = fs::read(path)?;
        let mut hasher = Hasher::new();
        hasher.update(&content);
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Generate short hash (first 8 characters)
    pub fn short_hash(input: &str) -> String {
        let full_hash = hash_string(input);
        full_hash.chars().take(8).collect()
    }
}

/// Environment utilities
pub mod env_utils {
    use super::*;

    /// Get environment variable with default value
    pub fn get_env_or_default(key: &str, default: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| default.to_string())
    }

    /// Check if running in CI environment
    pub fn is_ci_environment() -> bool {
        std::env::var("CI")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
            || std::env::var("GITHUB_ACTIONS").is_ok()
            || std::env::var("GITLAB_CI").is_ok()
            || std::env::var("JENKINS_URL").is_ok()
    }

    /// Get current user name or default
    pub fn get_current_user() -> String {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    }

    /// Sanitize environment variables for secure logging
    pub fn sanitize_env_vars(env_vars: &HashMap<String, String>) -> HashMap<String, String> {
        let sensitive_keys = ["PASSWORD", "SECRET", "TOKEN", "KEY", "PRIVATE"];

        env_vars
            .iter()
            .map(|(k, v)| {
                let key_upper = k.to_uppercase();
                let is_sensitive = sensitive_keys
                    .iter()
                    .any(|sensitive| key_upper.contains(sensitive));

                if is_sensitive {
                    (k.clone(), "***REDACTED***".to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect()
    }
}

/// Validation utilities
pub mod validation {

    /// Validate semantic version format
    pub fn is_valid_semver(version: &str) -> bool {
        // Simple semver validation without regex dependency
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        // Check if all parts are valid numbers
        for part in &parts {
            if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
            // Don't allow leading zeros except for "0"
            if part.len() > 1 && part.starts_with('0') {
                return false;
            }
        }

        true
    }

    /// Validate email format
    pub fn is_valid_email(email: &str) -> bool {
        // Simple email validation without regex dependency
        if email.is_empty() || !email.contains('@') {
            return false;
        }

        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return false;
        }

        let local = parts[0];
        let domain = parts[1];

        // Basic checks
        if local.is_empty() || domain.is_empty() || !domain.contains('.') {
            return false;
        }

        // Check for invalid characters
        if email.contains(' ') || email.contains('\t') || email.contains('\n') {
            return false;
        }

        true
    }

    /// Validate container image name format
    pub fn is_valid_container_image(image: &str) -> bool {
        // Basic validation for container image format
        !image.is_empty()
            && !image.starts_with('-')
            && !image.ends_with('-')
            && image
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '/' || c == ':')
    }

    /// Check if string is a valid identifier (alphanumeric + underscore/hyphen)
    pub fn is_valid_identifier(name: &str) -> bool {
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            && name
                .chars()
                .next()
                .expect("guarded by !name.is_empty() above")
                .is_alphabetic()
    }
}

/// Error utilities
pub mod error_utils {
    use super::*;

    /// Convert any error to a string representation
    pub fn error_to_string<E: std::fmt::Display>(error: E) -> String {
        error.to_string()
    }

    /// Create a standardized error message with context
    pub fn create_error_with_context(operation: &str, details: &str) -> anyhow::Error {
        anyhow!("Failed to {}: {}", operation, details)
    }

    /// Check if error is a specific type (by string matching)
    pub fn is_error_type(error: &anyhow::Error, error_type: &str) -> bool {
        error
            .to_string()
            .to_lowercase()
            .contains(&error_type.to_lowercase())
    }
}
