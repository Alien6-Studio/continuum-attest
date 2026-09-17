use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    /// BTreeMap for the same reason as `Pipeline::steps`: a step's env is
    /// part of the pipeline's serialization, and therefore of its hash, so
    /// its ordering has to be canonical rather than per-process.
    pub env: Option<BTreeMap<String, String>>,
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

    /// Digest of everything about this step that shapes how it executes.
    ///
    /// Folded into the cache key. That key used to cover the command, the
    /// declared inputs and the environment, which left `working_dir` out: a
    /// step could be pointed at a different directory, read a different file
    /// of the same name, and be served the previous directory's result --
    /// then have that result signed into a receipt describing the new
    /// configuration. `image`, `capsule` and `timeout_secs` had the same
    /// hole.
    ///
    /// The whole step is hashed rather than a list of fields chosen by hand.
    /// Including a field that turns out not to affect execution costs a cache
    /// miss; omitting one that does costs a receipt that is wrong. Those are
    /// not comparable, so the safe direction is to include everything, and
    /// the next field someone adds is covered without their remembering to.
    pub fn execution_shape(&self) -> String {
        let canonical = serde_json::to_string(self).unwrap_or_default();
        blake3::hash(canonical.as_bytes()).to_hex().to_string()
    }

    pub fn effective_env(
        &self,
        pipeline_env: &BTreeMap<String, String>,
    ) -> BTreeMap<String, String> {
        let mut env = pipeline_env.clone();

        if let Some(step_env) = &self.env {
            env.extend(step_env.clone());
        }

        env
    }
}
