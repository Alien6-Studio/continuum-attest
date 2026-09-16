//! Hermetic capsule prototype (`attest capsule`).
//!
//! A capsule is ATTEST's hermetic execution unit (scientific note §3.1):
//! an OCI image pinned by digest plus a manifest that binds it to ATTEST
//! semantics — declared environment, a single read-write workspace mount,
//! and no network. The manifest lives at
//! `<workspace>/.attest/capsules/<name>/capsule.yaml` and is identified by
//! `capsule_hash` = blake3 of its canonical serialization (sorted env
//! keys, `capsule_hash` field excluded), so the same capsule declaration
//! hashes identically on every machine.
//!
//! Execution (`attest capsule run`) shells out to the detected container
//! runtime (Docker/Podman, same detection as `src/sandbox/`) with
//! `--network none`, a read-only root filesystem and an environment that
//! is exactly the manifest `env` plus the issue-#8 normalization set
//! ([`crate::executor::HERMETIC_ENV`]); ambient variables never leak in.
//! The wrapped command's exit code is propagated verbatim.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::executor::HERMETIC_ENV;

/// Format tag of capsule manifest v1.
pub const CAPSULE_FORMAT: &str = "attest-capsule/v1";

/// The only network mode supported by capsule v1.
pub const CAPSULE_NETWORK_NONE: &str = "none";

#[derive(Debug, thiserror::Error)]
pub enum CapsuleError {
    /// Image referenced by tag instead of digest — rejected with exit 2
    /// at `init` time and re-validated (refused) at `run` time.
    #[error("image '{0}' is not digest-pinned; use <repo>@sha256:<64 hex> (tag references are rejected)")]
    TagReference(String),
    #[error("capsule '{0}' not found (expected {1})")]
    NotFound(String, PathBuf),
    #[error("capsule '{name}': stored capsule_hash does not match the manifest (stored {stored}, recomputed {recomputed})")]
    HashMismatch {
        name: String,
        stored: String,
        recomputed: String,
    },
    #[error("capsule manifest invalid: {0}")]
    Invalid(String),
}

/// `capsule.yaml`, format `attest-capsule/v1`. Field order here IS the
/// canonical serialization order; `env` is a BTreeMap so keys are always
/// sorted. `capsule_hash` is excluded from the hashed form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleManifest {
    pub format: String,
    pub name: String,
    /// Digest-pinned OCI reference (`repo@sha256:<64 hex>`); tags rejected.
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub mounts: CapsuleMounts,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleMounts {
    /// Container path the workspace is bind-mounted at, read-write.
    /// Exactly one workspace mount exists in v1.
    pub workspace: PathBuf,
}

impl CapsuleManifest {
    /// Manifest for `attest capsule init` defaults: workspace at `/work`,
    /// no extra env, no entrypoint override, network none.
    pub fn new(name: &str, image: &str) -> Result<Self> {
        validate_image_ref(image)?;
        Ok(Self {
            format: CAPSULE_FORMAT.to_string(),
            name: name.to_string(),
            image: image.to_string(),
            entrypoint: None,
            env: BTreeMap::new(),
            mounts: CapsuleMounts {
                workspace: PathBuf::from("/work"),
            },
            network: CAPSULE_NETWORK_NONE.to_string(),
            capsule_hash: None,
        })
    }

    /// blake3 hex of the canonical serialization (capsule_hash excluded).
    pub fn compute_hash(&self) -> Result<String> {
        let mut canonical = self.clone();
        canonical.capsule_hash = None;
        let bytes = serde_yaml::to_string(&canonical)?;
        Ok(blake3::hash(bytes.as_bytes()).to_hex().to_string())
    }

    /// Structural validation shared by `init`, `load` and `run`.
    pub fn validate(&self) -> Result<()> {
        if self.format != CAPSULE_FORMAT {
            anyhow::bail!(CapsuleError::Invalid(format!(
                "unsupported format '{}' (expected {CAPSULE_FORMAT})",
                self.format
            )));
        }
        validate_image_ref(&self.image)?;
        if self.network != CAPSULE_NETWORK_NONE {
            anyhow::bail!(CapsuleError::Invalid(format!(
                "unsupported network '{}' (v1 supports only '{CAPSULE_NETWORK_NONE}')",
                self.network
            )));
        }
        if !self.mounts.workspace.is_absolute() {
            anyhow::bail!(CapsuleError::Invalid(format!(
                "workspace mount '{}' must be an absolute container path",
                self.mounts.workspace.display()
            )));
        }
        Ok(())
    }
}

/// Reject any image reference that is not digest-pinned
/// (`<repo>@sha256:<64 lowercase hex>`).
pub fn validate_image_ref(image: &str) -> Result<()> {
    let rejected = || anyhow::anyhow!(CapsuleError::TagReference(image.to_string()));
    let (repo, digest) = image.split_once("@sha256:").ok_or_else(rejected)?;
    if repo.is_empty()
        || digest.len() != 64
        || !digest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(rejected());
    }
    Ok(())
}

/// `<workspace>/.attest/capsules/<name>/capsule.yaml`.
pub fn manifest_path(workspace: &Path, name: &str) -> PathBuf {
    workspace
        .join(".attest")
        .join("capsules")
        .join(name)
        .join("capsule.yaml")
}

/// `attest capsule init`: write the manifest with its computed hash.
/// Fails if the capsule already exists (re-init must be explicit: delete
/// the directory first).
pub fn init(workspace: &Path, name: &str, image: &str) -> Result<PathBuf> {
    let mut manifest = CapsuleManifest::new(name, image)?;
    manifest.validate()?;
    manifest.capsule_hash = Some(manifest.compute_hash()?);

    let path = manifest_path(workspace, name);
    if path.exists() {
        anyhow::bail!("capsule '{name}' already exists at {}", path.display());
    }
    let dir = path.parent().expect("manifest path has a parent");
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    std::fs::write(&path, serde_yaml::to_string(&manifest)?)
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(path)
}

/// Load a manifest and verify: structure, digest pinning, and that the
/// stored `capsule_hash` matches the recomputed one.
pub fn load(workspace: &Path, name: &str) -> Result<CapsuleManifest> {
    let path = manifest_path(workspace, name);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!(CapsuleError::NotFound(name.to_string(), path.clone())))?;
    let manifest: CapsuleManifest = serde_yaml::from_str(&content)
        .map_err(|err| anyhow::anyhow!(CapsuleError::Invalid(err.to_string())))?;
    manifest.validate()?;
    let recomputed = manifest.compute_hash()?;
    match &manifest.capsule_hash {
        Some(stored) if *stored == recomputed => Ok(manifest),
        Some(stored) => Err(anyhow::anyhow!(CapsuleError::HashMismatch {
            name: name.to_string(),
            stored: stored.clone(),
            recomputed,
        })),
        None => Err(anyhow::anyhow!(CapsuleError::Invalid(
            "manifest has no capsule_hash field; re-run `attest capsule init`".to_string()
        ))),
    }
}

/// Container runtime binary used to execute capsules (same detection
/// order as `src/sandbox/`). v1 supports Docker and Podman.
pub fn runtime_binary() -> Option<&'static str> {
    match crate::sandbox::container::ContainerUtils::detect_runtime() {
        Some(crate::sandbox::ContainerRuntime::Docker) => Some("docker"),
        Some(crate::sandbox::ContainerRuntime::Podman) => Some("podman"),
        _ => None,
    }
}

/// Build the full `docker`/`podman` argument vector for a capsule run.
/// Split out of [`run`] so tests can assert the exact isolation flags
/// without a container runtime.
pub fn run_args(manifest: &CapsuleManifest, workspace: &Path, command: &[String]) -> Vec<String> {
    let mount = manifest.mounts.workspace.display().to_string();
    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "--network".into(),
        CAPSULE_NETWORK_NONE.into(),
        "--read-only".into(),
        "-v".into(),
        format!("{}:{}", workspace.display(), mount),
        "-w".into(),
        mount,
    ];
    // Environment = exactly the manifest env + the #8 normalization set;
    // normalization wins on conflict, ambient env never appears.
    let mut env = manifest.env.clone();
    for (key, value) in HERMETIC_ENV {
        env.insert(key.to_string(), value.to_string());
    }
    for (key, value) in &env {
        args.push("-e".into());
        args.push(format!("{key}={value}"));
    }
    match &manifest.entrypoint {
        Some(entrypoint) if !entrypoint.is_empty() => {
            args.push("--entrypoint".into());
            args.push(entrypoint[0].clone());
            args.push(manifest.image.clone());
            args.extend(entrypoint[1..].iter().cloned());
        }
        _ => args.push(manifest.image.clone()),
    }
    args.extend(command.iter().cloned());
    args
}

/// `attest capsule run`: execute `command` inside the capsule. The
/// manifest is re-validated (digest pinning included). Returns the
/// command's exit code; stdout/stderr are inherited.
pub fn run(workspace: &Path, name: &str, command: &[String]) -> Result<i32> {
    if command.is_empty() {
        anyhow::bail!("capsule run requires a command after `--`");
    }
    let manifest = load(workspace, name)?;
    let binary = runtime_binary()
        .context("no container runtime found (docker or podman required for capsule run)")?;
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("cannot resolve workspace {}", workspace.display()))?;
    let status = Command::new(binary)
        .args(run_args(&manifest, &workspace, command))
        .status()
        .with_context(|| format!("failed to execute {binary}"))?;
    Ok(status.code().unwrap_or(1))
}

/// Capsule execution with captured stdout/stderr, for pipeline steps
/// (`capsule:` in `attest.yaml`). Same isolation flags as [`run`].
pub fn run_captured(
    manifest: &CapsuleManifest,
    workspace: &Path,
    command: &[String],
) -> Result<std::process::Output> {
    let binary = runtime_binary()
        .context("no container runtime found (docker or podman required for capsule steps)")?;
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("cannot resolve workspace {}", workspace.display()))?;
    Command::new(binary)
        .args(run_args(manifest, &workspace, command))
        .output()
        .with_context(|| format!("failed to execute {binary}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_REF: &str = "docker.io/library/busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn tag_references_are_rejected() {
        assert!(validate_image_ref("rust:1.93").is_err());
        assert!(validate_image_ref("rust@sha256:abc").is_err());
        assert!(validate_image_ref(DIGEST_REF).is_ok());
    }

    #[test]
    fn hash_excludes_stored_hash_and_is_stable() {
        let mut manifest = CapsuleManifest::new("demo", DIGEST_REF).expect("manifest");
        let bare = manifest.compute_hash().expect("hash");
        manifest.capsule_hash = Some(bare.clone());
        assert_eq!(manifest.compute_hash().expect("hash"), bare);
    }

    #[test]
    fn run_args_enforce_isolation() {
        let manifest = CapsuleManifest::new("demo", DIGEST_REF).expect("manifest");
        let args = run_args(&manifest, Path::new("/ws"), &["true".to_string()]);
        assert!(args.contains(&"--read-only".to_string()));
        let net = args.iter().position(|a| a == "--network").expect("network");
        assert_eq!(args[net + 1], "none");
        assert!(args.contains(&"/ws:/work".to_string()));
        for (key, value) in HERMETIC_ENV {
            assert!(args.contains(&format!("{key}={value}")));
        }
    }

    #[test]
    fn entrypoint_precedes_image_and_command() {
        let mut manifest = CapsuleManifest::new("demo", DIGEST_REF).expect("manifest");
        manifest.entrypoint = Some(vec!["/bin/sh".to_string(), "-c".to_string()]);
        let args = run_args(&manifest, Path::new("/ws"), &["echo hi".to_string()]);
        let ep = args
            .iter()
            .position(|a| a == "--entrypoint")
            .expect("entrypoint");
        assert_eq!(args[ep + 1], "/bin/sh");
        assert_eq!(args[ep + 2], DIGEST_REF);
        assert_eq!(args[ep + 3], "-c");
        assert_eq!(args[ep + 4], "echo hi");
    }
}
