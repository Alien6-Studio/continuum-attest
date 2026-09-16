use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

use super::dag::ExecutionDAG;
use super::exports::*;
use super::step::Step;

/// attest.yaml schema version understood by this binary. Bump only on a
/// breaking change to the configuration format; loading rejects files that
/// declare a newer schema with an explicit "upgrade attest" message.
pub const PIPELINE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pipeline {
    /// attest.yaml format version. Optional; absent means version 1.
    /// Distinct from `version`, which is the user's own pipeline version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    pub version: String,
    pub name: Option<String>,
    pub steps: HashMap<String, Step>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub attestation: AttestationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AttestationConfig {
    #[serde(default)]
    pub sign_all_steps: bool,
    #[serde(default)]
    pub verify_dependencies: bool,
    #[serde(default)]
    pub require_reproducible: bool,
}

impl Pipeline {
    pub async fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read pipeline file: {}", path))?;

        let pipeline: Pipeline = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse pipeline file: {}", path))?;

        pipeline.validate()?;
        Ok(pipeline)
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(v) = self.schema_version {
            if v > PIPELINE_SCHEMA_VERSION {
                anyhow::bail!(
                    "attest.yaml declares schema_version {} but this attest supports up to {}; upgrade attest to use this file",
                    v,
                    PIPELINE_SCHEMA_VERSION
                );
            }
        }

        if self.version.is_empty() {
            anyhow::bail!("Pipeline version is required");
        }

        if self.steps.is_empty() {
            anyhow::bail!("Pipeline must contain at least one step");
        }

        // Build DAG to check for cycles
        let _dag = ExecutionDAG::build(self)?;

        // Validate each step
        for (name, step) in &self.steps {
            step.validate(name)?;

            if let Some(needs) = &step.needs {
                for dep in needs {
                    if !self.steps.contains_key(dep) {
                        anyhow::bail!("Step '{}' depends on unknown step '{}'", name, dep);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn print_graph(&self) {
        println!("Pipeline DAG:");
        for (name, step) in &self.steps {
            print!("  {}", name);
            if let Some(needs) = &step.needs {
                if !needs.is_empty() {
                    print!(" <- [{}]", needs.join(", "));
                }
            }
            println!();
        }
    }

    pub fn print_dot(&self) {
        println!("digraph pipeline {{");
        println!("  rankdir=LR;");
        println!("  node [shape=box, style=rounded];");

        for name in self.steps.keys() {
            println!("  \"{}\";", name);
        }

        for (name, step) in &self.steps {
            if let Some(needs) = &step.needs {
                for dep in needs {
                    println!("  \"{}\" -> \"{}\";", dep, name);
                }
            }
        }

        println!("}}");
    }

    pub fn print_json(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        println!("{}", json);
        Ok(())
    }

    /// Export pipeline to Docker Compose format
    pub fn export_docker_compose(&self) -> Result<String> {
        let options = ExportOptions {
            format: ExportFormat::DockerCompose,
            output_file: None,
            template_dir: None,
            variables: std::collections::HashMap::new(),
            include_cache: false,
            include_signatures: false,
            target_environment: None,
        };
        MultiFormatExporter::export(self, options)
    }

    /// Export pipeline to GitLab CI format
    pub fn export_gitlab_ci(&self) -> Result<String> {
        let options = ExportOptions {
            format: ExportFormat::GitLabCI,
            output_file: None,
            template_dir: None,
            variables: std::collections::HashMap::new(),
            include_cache: false,
            include_signatures: false,
            target_environment: None,
        };
        MultiFormatExporter::export(self, options)
    }

    /// Export pipeline to GitHub Actions format
    pub fn export_github_actions(&self) -> Result<String> {
        let options = ExportOptions {
            format: ExportFormat::GitHubActions,
            output_file: None,
            template_dir: None,
            variables: std::collections::HashMap::new(),
            include_cache: false,
            include_signatures: false,
            target_environment: None,
        };
        MultiFormatExporter::export(self, options)
    }

    /// Export pipeline to Makefile format
    pub fn export_makefile(&self) -> Result<String> {
        let options = ExportOptions {
            format: ExportFormat::Makefile,
            output_file: None,
            template_dir: None,
            variables: std::collections::HashMap::new(),
            include_cache: false,
            include_signatures: false,
            target_environment: None,
        };
        MultiFormatExporter::export(self, options)
    }

    /// Export pipeline to Jenkins format
    pub fn export_jenkins(&self) -> Result<String> {
        let options = ExportOptions {
            format: ExportFormat::Jenkins,
            output_file: None,
            template_dir: None,
            variables: std::collections::HashMap::new(),
            include_cache: false,
            include_signatures: false,
            target_environment: None,
        };
        MultiFormatExporter::export(self, options)
    }
}
