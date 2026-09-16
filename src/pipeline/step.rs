use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A key `attest.yaml` does not define is rejected, not ignored. A typo
/// such as `ouputs:` would otherwise produce a receipt that silently says
/// nothing about that output — the exact class of quiet discrepancy this
/// tool exists to make impossible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub run: String,
    #[serde(default)]
    pub inputs: Vec<PathBuf>,
    #[serde(default)]
    pub outputs: Vec<PathBuf>,
    pub needs: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
    pub working_dir: Option<PathBuf>,

    #[serde(default)]
    pub image: Option<String>,
    /// Hermetic capsule to execute this step in: the name of
    /// a capsule under `.attest/capsules/`. The receipt records the
    /// capsule's manifest hash in `StepResult.capsule_hash`.
    #[serde(default)]
    pub capsule: Option<String>,
    #[serde(default = "default_true")]
    pub cache: bool,
    /// Wall-clock limit for the step's command. When it elapses the whole
    /// process group is killed and the step fails with exit code 124.
    #[serde(default)]
    pub timeout_secs: Option<u64>,

    #[serde(default)]
    pub attestation: Option<StepAttestation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepAttestation {
    #[serde(rename = "type")]
    pub attestation_type: String,
    #[serde(default)]
    pub reproducible: bool,
    #[serde(default)]
    pub generate_slsa: bool,
    #[serde(default)]
    pub verify_chain: bool,
}

fn default_true() -> bool {
    true
}

impl Step {
    pub fn validate(&self, step_name: &str) -> Result<()> {
        if self.run.trim().is_empty() {
            anyhow::bail!("Step '{}' has empty run command", step_name);
        }

        for input in &self.inputs {
            if input.is_absolute() {
                anyhow::bail!(
                    "Step '{}' has absolute input path: {}",
                    step_name,
                    input.display()
                );
            }
        }

        for output in &self.outputs {
            if output.is_absolute() {
                anyhow::bail!(
                    "Step '{}' has absolute output path: {}",
                    step_name,
                    output.display()
                );
            }
        }

        Ok(())
    }

    pub fn effective_env(&self, pipeline_env: &HashMap<String, String>) -> HashMap<String, String> {
        let mut env = pipeline_env.clone();

        if let Some(step_env) = &self.env {
            env.extend(step_env.clone());
        }

        env
    }
}
