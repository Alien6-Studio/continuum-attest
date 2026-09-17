use super::{Pipeline, Step};
use std::collections::{HashMap, HashSet};

pub struct ValidationError {
    pub step: Option<String>,
    pub field: Option<String>,
    pub message: String,
    pub severity: ValidationSeverity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationError>,
    pub info: Vec<ValidationError>,
    pub is_valid: bool,
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            info: Vec::new(),
            is_valid: true,
        }
    }

    pub fn add_error(&mut self, step: Option<String>, field: Option<String>, message: String) {
        self.errors.push(ValidationError {
            step,
            field,
            message,
            severity: ValidationSeverity::Error,
        });
        self.is_valid = false;
    }

    pub fn add_warning(&mut self, step: Option<String>, field: Option<String>, message: String) {
        self.warnings.push(ValidationError {
            step,
            field,
            message,
            severity: ValidationSeverity::Warning,
        });
    }

    pub fn add_info(&mut self, step: Option<String>, field: Option<String>, message: String) {
        self.info.push(ValidationError {
            step,
            field,
            message,
            severity: ValidationSeverity::Info,
        });
    }
}

impl Pipeline {
    /// Comprehensive pipeline validation with detailed reporting
    pub fn validate_comprehensive(&self) -> ValidationResult {
        let mut result = ValidationResult::new();

        // Basic validation
        self.validate_basic(&mut result);

        // Attestation validation
        self.validate_attestation_config_detailed(&mut result);

        // Step validation
        self.validate_steps_detailed(&mut result);

        // Dependency validation
        self.validate_dependencies_detailed(&mut result);

        // Security validation
        self.validate_security(&mut result);

        // Performance validation
        self.validate_performance(&mut result);

        result
    }

    fn validate_basic(&self, result: &mut ValidationResult) {
        // Version validation
        if self.version.is_empty() {
            result.add_error(
                None,
                Some("version".to_string()),
                "Pipeline version is required".to_string(),
            );
        } else {
            // Validate version format
            if !self.version.chars().next().unwrap_or('0').is_ascii_digit() {
                result.add_warning(
                    None,
                    Some("version".to_string()),
                    "Version should start with a number (e.g., '0.1', '1.0')".to_string(),
                );
            }
        }

        // Name validation
        if let Some(name) = &self.name {
            if name.is_empty() {
                result.add_warning(
                    None,
                    Some("name".to_string()),
                    "Pipeline name is empty".to_string(),
                );
            } else if name.len() > 50 {
                result.add_warning(
                    None,
                    Some("name".to_string()),
                    "Pipeline name is very long (>50 characters)".to_string(),
                );
            }
        } else {
            result.add_info(
                None,
                Some("name".to_string()),
                "Consider adding a descriptive pipeline name".to_string(),
            );
        }

        // Steps validation
        if self.steps.is_empty() {
            result.add_error(
                None,
                Some("steps".to_string()),
                "Pipeline must contain at least one step".to_string(),
            );
        }
    }

    fn validate_steps_detailed(&self, result: &mut ValidationResult) {
        for (step_name, step) in &self.steps {
            self.validate_step_detailed(step_name, step, result);
        }

        // Check for duplicate step names (should not happen with HashMap, but good to verify)
        let unique_names: HashSet<_> = self.steps.keys().collect();
        if unique_names.len() != self.steps.len() {
            result.add_error(
                None,
                Some("steps".to_string()),
                "Duplicate step names detected".to_string(),
            );
        }
    }

    fn validate_step_detailed(&self, step_name: &str, step: &Step, result: &mut ValidationResult) {
        // Command validation
        if step.run.trim().is_empty() {
            result.add_error(
                Some(step_name.to_string()),
                Some("run".to_string()),
                "Step has empty run command".to_string(),
            );
        } else {
            // Check for potentially dangerous commands
            let dangerous_commands = ["rm -rf", "format", "del /f", "sudo rm", "chmod 777"];
            let run_lower = step.run.to_lowercase();
            for dangerous in &dangerous_commands {
                if run_lower.contains(dangerous) {
                    result.add_warning(
                        Some(step_name.to_string()),
                        Some("run".to_string()),
                        format!("Potentially dangerous command detected: {}", dangerous),
                    );
                }
            }

            // Check for hardcoded paths
            if step.run.contains("/usr/") || step.run.contains("C:\\") {
                result.add_warning(
                    Some(step_name.to_string()),
                    Some("run".to_string()),
                    "Hardcoded system paths detected - consider using environment variables"
                        .to_string(),
                );
            }
        }

        // Input/Output validation
        for input in &step.inputs {
            if input.is_absolute() {
                result.add_error(
                    Some(step_name.to_string()),
                    Some("inputs".to_string()),
                    format!("Absolute input path not allowed: {}", input.display()),
                );
            }
        }

        for output in &step.outputs {
            if output.is_absolute() {
                result.add_error(
                    Some(step_name.to_string()),
                    Some("outputs".to_string()),
                    format!("Absolute output path not allowed: {}", output.display()),
                );
            }
        }

        // Environment variables validation
        if let Some(env) = &step.env {
            for (key, value) in env {
                // Check for suspicious environment variables
                if key.to_lowercase().contains("password") || key.to_lowercase().contains("secret")
                {
                    result.add_warning(
                        Some(step_name.to_string()),
                        Some("env".to_string()),
                        format!("Sensitive environment variable name detected: {}", key),
                    );
                }

                // Check for hardcoded sensitive values
                if value.len() > 20
                    && (value.chars().all(|c| c.is_alphanumeric())
                        || value.starts_with("sk-")
                        || value.starts_with("ghp_"))
                {
                    result.add_warning(
                        Some(step_name.to_string()),
                        Some("env".to_string()),
                        format!(
                            "Potential hardcoded secret in environment variable: {}",
                            key
                        ),
                    );
                }
            }
        }

        // Timeout validation
        if let Some(timeout) = step.timeout_secs {
            if timeout > 86400 {
                // 24 hours
                result.add_warning(
                    Some(step_name.to_string()),
                    Some("timeout_secs".to_string()),
                    "Very long timeout detected (>24 hours)".to_string(),
                );
            } else if timeout < 5 {
                result.add_warning(
                    Some(step_name.to_string()),
                    Some("timeout_secs".to_string()),
                    "Very short timeout detected (<5 seconds)".to_string(),
                );
            }
        }

        // Container image validation
        if let Some(image) = &step.image {
            if image == "latest" || image.ends_with(":latest") {
                result.add_warning(
                    Some(step_name.to_string()),
                    Some("image".to_string()),
                    "Using 'latest' tag is not recommended for reproducible builds".to_string(),
                );
            }

            if !image.contains(':') {
                result.add_info(
                    Some(step_name.to_string()),
                    Some("image".to_string()),
                    "Consider specifying explicit image tag for reproducibility".to_string(),
                );
            }
        }
    }

    fn validate_dependencies_detailed(&self, result: &mut ValidationResult) {
        // Check for unknown dependencies
        for (step_name, step) in &self.steps {
            if let Some(needs) = &step.needs {
                for dep in needs {
                    if !self.steps.contains_key(dep) {
                        result.add_error(
                            Some(step_name.to_string()),
                            Some("needs".to_string()),
                            format!("Step depends on unknown step: {}", dep),
                        );
                    }
                }

                // Check for self-dependency
                if needs.contains(step_name) {
                    result.add_error(
                        Some(step_name.to_string()),
                        Some("needs".to_string()),
                        "Step cannot depend on itself".to_string(),
                    );
                }

                // Check for excessive dependencies
                if needs.len() > 10 {
                    result.add_warning(
                        Some(step_name.to_string()),
                        Some("needs".to_string()),
                        "Step has many dependencies - consider refactoring".to_string(),
                    );
                }
            }
        }

        // Analyze DAG structure
        if let Ok(dag) = super::dag::ExecutionDAG::build(self) {
            let analysis = dag.analyze();

            if analysis.max_depth > 20 {
                result.add_warning(
                    None,
                    Some("structure".to_string()),
                    format!(
                        "Very deep pipeline ({} levels) - consider parallelization",
                        analysis.max_depth
                    ),
                );
            }

            if analysis.is_linear && analysis.total_nodes > 5 {
                result.add_info(None, Some("structure".to_string()), 
                    "Linear pipeline detected - consider adding parallelization for better performance".to_string());
            }

            // Report parallelization opportunities
            let parallel_count: usize = analysis
                .parallelizable_groups
                .iter()
                .filter(|group| group.len() > 1)
                .map(|group| group.len())
                .sum();

            if parallel_count > 0 {
                result.add_info(
                    None,
                    Some("parallelization".to_string()),
                    format!("{} steps can be parallelized", parallel_count),
                );
            }
        }
    }

    fn validate_security(&self, result: &mut ValidationResult) {
        // Check for insecure practices
        for (step_name, step) in &self.steps {
            // Check for shell injection vulnerabilities
            if step.run.contains("$1") || step.run.contains("${") {
                result.add_warning(
                    Some(step_name.to_string()),
                    Some("run".to_string()),
                    "Potential shell injection vulnerability - validate all inputs".to_string(),
                );
            }

            // Check for network access without explicit declaration
            if step.run.contains("curl") || step.run.contains("wget") || step.run.contains("http") {
                result.add_info(
                    Some(step_name.to_string()),
                    Some("run".to_string()),
                    "Network access detected - ensure it's intentional and secure".to_string(),
                );
            }

            // Check for file system access
            if step.run.contains("chmod") || step.run.contains("chown") {
                result.add_warning(
                    Some(step_name.to_string()),
                    Some("run".to_string()),
                    "File permission changes detected - review for security implications"
                        .to_string(),
                );
            }
        }

        // Global environment validation
        for key in self.env.keys() {
            if key.to_uppercase().contains("TOKEN") || key.to_uppercase().contains("KEY") {
                result.add_warning(
                    None,
                    Some("env".to_string()),
                    format!("Sensitive global environment variable: {}", key),
                );
            }
        }
    }

    fn validate_performance(&self, result: &mut ValidationResult) {
        // Check for performance anti-patterns
        for (step_name, step) in &self.steps {
            // Check for inefficient commands
            if step.run.contains("find /") || step.run.contains("grep -r /") {
                result.add_info(
                    Some(step_name.to_string()),
                    Some("run".to_string()),
                    "System-wide search detected - consider limiting scope for better performance"
                        .to_string(),
                );
            }

            // Check cache settings
            if !step.cache && step.inputs.len() > 5 {
                result.add_info(Some(step_name.to_string()), Some("cache".to_string()), 
                    "Caching disabled for step with many inputs - consider enabling for better performance".to_string());
            }

            // Check for large output directories
            for output in &step.outputs {
                if output.to_string_lossy().contains("node_modules")
                    || output.to_string_lossy().contains("target")
                {
                    result.add_info(
                        Some(step_name.to_string()),
                        Some("outputs".to_string()),
                        "Large directory in outputs - consider excluding unnecessary files"
                            .to_string(),
                    );
                }
            }
        }
    }

    pub fn validate_attestation_config_detailed(&self, result: &mut ValidationResult) {
        let config = &self.attestation;

        // Validate global attestation settings
        if config.require_reproducible && !config.sign_all_steps {
            result.add_warning(
                None,
                Some("attestation".to_string()),
                "Requiring reproducible builds without signing may not provide full verification"
                    .to_string(),
            );
        }

        if config.verify_dependencies && self.steps.values().all(|step| step.needs.is_none()) {
            result.add_info(
                None,
                Some("attestation".to_string()),
                "Dependency verification enabled but no dependencies found".to_string(),
            );
        }

        // Validate step-level attestation settings
        let mut attestation_types = HashMap::new();
        for (step_name, step) in &self.steps {
            if let Some(attestation) = &step.attestation {
                // Track attestation types
                *attestation_types
                    .entry(&attestation.attestation_type)
                    .or_insert(0) += 1;

                // Validate reproducibility settings
                if attestation.reproducible && step.run.contains("date") {
                    result.add_warning(
                        Some(step_name.to_string()),
                        Some("attestation".to_string()),
                        "Step marked as reproducible but uses date command".to_string(),
                    );
                }

                // Validate SLSA generation
                if attestation.generate_slsa && step.outputs.is_empty() {
                    result.add_warning(
                        Some(step_name.to_string()),
                        Some("attestation".to_string()),
                        "SLSA generation enabled but no outputs declared".to_string(),
                    );
                }

                // Check for missing attestation types
                if attestation.attestation_type.is_empty() {
                    result.add_error(
                        Some(step_name.to_string()),
                        Some("attestation.type".to_string()),
                        "Attestation type is required".to_string(),
                    );
                }
            } else if config.sign_all_steps {
                result.add_info(
                    Some(step_name.to_string()),
                    Some("attestation".to_string()),
                    "Step will be signed but has no specific attestation configuration".to_string(),
                );
            }
        }

        // Report attestation type distribution
        for (att_type, count) in attestation_types {
            if count > 1 {
                result.add_info(
                    None,
                    Some("attestation".to_string()),
                    format!("Attestation type '{}' used by {} steps", att_type, count),
                );
            }
        }
    }
}
