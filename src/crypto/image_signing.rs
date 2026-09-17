//! OCI image signing via cosign (`attest image sign`).
//!
//! Implements the signing half of the image supply-chain spec
//! (`docs/image-signing.md` in continuum-attest-www): IMG-2 (digest
//! references only), IMG-3 (KMS-backed keys), IMG-4 (revision
//! annotation), IMG-6 (clean-tree precondition), IMG-11 (signing
//! receipt) and IMG-12 (exit codes: 0 signed, 1 precondition failed,
//! 2 operational error).
//!
//! Signing shells out to the `cosign` binary, like
//! `image_verification::verify_with_cosign`. Minimum supported cosign
//! version: 2.2 (annotations + KMS providers), checked at runtime.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Minimum cosign (major, minor) supported for signing.
pub const MIN_COSIGN_VERSION: (u32, u32) = (2, 2);

/// Everything `attest image sign` needs to run. Field semantics follow
/// the documented CLI contract, referenced below by its IMG-n clauses.
#[derive(Debug, Clone)]
pub struct ImageSignRequest {
    /// Digest reference `registry/repo@sha256:<64 hex>` (IMG-2).
    pub image_ref: String,
    /// Key URI, normally `azurekms://…` (IMG-3).
    pub key_uri: String,
    /// Extra `key=value` annotations; `continuum.git.revision` is
    /// derived from the repository HEAD when not provided (IMG-4).
    pub annotations: Vec<(String, String)>,
    /// Escape hatch allowing a file-based private key (IMG-3).
    pub allow_file_key: bool,
    /// Refuse to sign on a dirty tree (IMG-6). Default on.
    pub require_clean_tree: bool,
    /// Paths for the clean-tree check; empty = whole repository.
    pub clean_paths: Vec<String>,
    /// Receipt output directory; default `.attest/receipts/`.
    pub receipt_dir: Option<PathBuf>,
    /// Sign the receipt with the local ATTEST key (same conventions as
    /// `attest run --sign`).
    pub sign_receipt: bool,
    /// ATTEST signing key id for the receipt (`attest keys list`).
    pub receipt_key: Option<String>,
}

/// Outcome of a completed signing operation (exit code 0).
#[derive(Debug)]
pub struct SignOutcome {
    pub receipt_path: PathBuf,
    pub revision: String,
}

/// Failure modes mapped to the IMG-12 exit-code convention.
#[derive(Debug)]
pub enum SignFailure {
    /// Exit 1: a precondition check failed (e.g. dirty tree).
    Precondition(String),
    /// Exit 2: operational error (bad reference, missing cosign, …).
    Operational(String),
}

impl SignFailure {
    pub fn exit_code(&self) -> i32 {
        match self {
            SignFailure::Precondition(_) => 1,
            SignFailure::Operational(_) => 2,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            SignFailure::Precondition(msg) | SignFailure::Operational(msg) => msg,
        }
    }
}

/// Validate a digest reference `repo@sha256:<64 lowercase hex>` (IMG-2).
/// A tag reference is rejected with the normative message; there is no
/// tag→digest auto-resolution.
pub fn validate_digest_ref(image_ref: &str) -> std::result::Result<(), SignFailure> {
    if let Some((repo, digest)) = image_ref.split_once('@') {
        let hex_ok = digest
            .strip_prefix("sha256:")
            .map(|h| {
                h.len() == 64
                    && h.chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            })
            .unwrap_or(false);
        if repo.is_empty() || !hex_ok {
            return Err(SignFailure::Operational(format!(
                "invalid digest reference '{image_ref}': expected repo@sha256:<64 lowercase hex>"
            )));
        }
        Ok(())
    } else {
        Err(SignFailure::Operational(format!(
            "signing requires a digest reference (repo@sha256:...), got tag '{image_ref}'"
        )))
    }
}

/// Enforce the KMS key policy (IMG-3): `azurekms://` URIs are accepted;
/// anything else is refused unless `--allow-file-key`.
pub fn validate_key_uri(
    key_uri: &str,
    allow_file_key: bool,
) -> std::result::Result<(), SignFailure> {
    if key_uri.starts_with("azurekms://") {
        return Ok(());
    }
    if allow_file_key {
        return Ok(());
    }
    Err(SignFailure::Operational(format!(
        "key '{key_uri}' is not a KMS URI (azurekms://...); file-based keys require --allow-file-key"
    )))
}

/// Validate a `continuum.git.revision` value (IMG-4): a full SHA-1 or
/// SHA-256 object id, i.e. `^[a-f0-9]{40,64}$`.
pub fn validate_revision(revision: &str) -> std::result::Result<(), SignFailure> {
    let len_ok = (40..=64).contains(&revision.len());
    let hex_ok = revision
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase());
    if len_ok && hex_ok {
        Ok(())
    } else {
        Err(SignFailure::Operational(format!(
            "invalid continuum.git.revision '{revision}': must match ^[a-f0-9]{{40,64}}$ (full object id)"
        )))
    }
}

pub const REVISION_ANNOTATION: &str = "continuum.git.revision";

/// Sign an OCI image per the request. Returns the outcome on success
/// (exit 0) or the classified failure (exit 1/2).
pub fn sign_image(
    workspace: &Path,
    request: &ImageSignRequest,
) -> std::result::Result<SignOutcome, SignFailure> {
    validate_digest_ref(&request.image_ref)?;
    validate_key_uri(&request.key_uri, request.allow_file_key)?;

    // IMG-4: derive the revision annotation from HEAD unless provided.
    let mut annotations = request.annotations.clone();
    let revision = match annotations
        .iter()
        .find(|(k, _)| k == REVISION_ANNOTATION)
        .map(|(_, v)| v.clone())
    {
        Some(explicit) => explicit,
        None => {
            let head = git_head(workspace).map_err(|e| {
                SignFailure::Operational(format!("cannot derive {REVISION_ANNOTATION}: {e:#}"))
            })?;
            annotations.push((REVISION_ANNOTATION.to_string(), head.clone()));
            head
        }
    };
    validate_revision(&revision)?;
    // Deterministic annotation order in argv and in the receipt manifest.
    annotations.sort();

    // IMG-6: clean-tree precondition.
    if request.require_clean_tree {
        let dirty = git_dirty_paths(workspace, &request.clean_paths)
            .map_err(|e| SignFailure::Operational(format!("clean-tree check failed: {e:#}")))?;
        if !dirty.is_empty() {
            return Err(SignFailure::Precondition(format!(
                "refusing to sign: working tree is dirty ({}); commit, stash, or pass --no-require-clean-tree",
                dirty.join(", ")
            )));
        }
    }

    // Locate cosign and enforce the version floor.
    let cosign = crate::crypto::image_verification::ImageVerifier::find_cosign_binary()
        .ok()
        .flatten()
        .ok_or_else(|| {
            SignFailure::Operational(
                "cosign binary not found; install it: https://docs.sigstore.dev/cosign/system_config/installation/"
                    .to_string(),
            )
        })?;
    check_cosign_version(&cosign)?;

    // IMG-2/IMG-4: cosign sign --yes --key <URI> -a k=v… <digest-ref>
    let mut cmd = Command::new(&cosign);
    cmd.arg("sign")
        .arg("--yes")
        .arg("--key")
        .arg(&request.key_uri);
    for (key, value) in &annotations {
        cmd.arg("-a").arg(format!("{key}={value}"));
    }
    cmd.arg(&request.image_ref);
    let output = cmd
        .output()
        .map_err(|e| SignFailure::Operational(format!("failed to execute cosign: {e}")))?;
    if !output.status.success() {
        return Err(SignFailure::Operational(format!(
            "cosign sign failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    // IMG-11: write the signing receipt.
    let receipt_path = write_signing_receipt(workspace, request, &annotations, &output.stdout)
        .map_err(|e| SignFailure::Operational(format!("cannot write signing receipt: {e:#}")))?;

    Ok(SignOutcome {
        receipt_path,
        revision,
    })
}

/// `HEAD` of the repository at `workspace`.
fn git_head(workspace: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(workspace)
        .output()
        .context("failed to execute git rev-parse")?;
    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Dirty paths per `git status --porcelain --untracked-files=all`,
/// restricted to `paths` when non-empty (IMG-6).
fn git_dirty_paths(workspace: &Path, paths: &[String]) -> Result<Vec<String>> {
    let mut cmd = Command::new("git");
    cmd.args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(workspace);
    if !paths.is_empty() {
        cmd.arg("--");
        cmd.args(paths);
    }
    let output = cmd.output().context("failed to execute git status")?;
    if !output.status.success() {
        anyhow::bail!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.get(3..).map(str::to_string))
        .collect())
}

/// Enforce [`MIN_COSIGN_VERSION`] by parsing `cosign version` output
/// (`GitVersion: vX.Y.Z`). An unparsable version is operational: better
/// to fail loudly than to sign with an unknown cosign.
fn check_cosign_version(cosign: &str) -> std::result::Result<(), SignFailure> {
    let output = Command::new(cosign)
        .arg("version")
        .output()
        .map_err(|e| SignFailure::Operational(format!("failed to execute cosign version: {e}")))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let version = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("GitVersion:"))
        .map(|v| v.trim().trim_start_matches('v').to_string())
        .ok_or_else(|| {
            SignFailure::Operational(format!(
                "cannot determine cosign version (need >= {}.{})",
                MIN_COSIGN_VERSION.0, MIN_COSIGN_VERSION.1
            ))
        })?;
    let mut parts = version.split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    if (major, minor) < MIN_COSIGN_VERSION {
        return Err(SignFailure::Operational(format!(
            "cosign {version} is too old: signing requires >= {}.{}",
            MIN_COSIGN_VERSION.0, MIN_COSIGN_VERSION.1
        )));
    }
    Ok(())
}

/// Canonical input manifest for the signing receipt (IMG-11):
/// blake3 over image digest, key URI and sorted annotations.
fn signing_input_manifest(request: &ImageSignRequest, annotations: &[(String, String)]) -> String {
    let mut manifest = String::from("attest-image-sign/v1\n");
    manifest.push_str(&format!("image:{}\n", request.image_ref));
    manifest.push_str(&format!("key:{}\n", request.key_uri));
    if request.allow_file_key {
        manifest.push_str("allow-file-key:true\n");
    }
    for (key, value) in annotations {
        manifest.push_str(&format!("annotation:{key}={value}\n"));
    }
    manifest
}

/// Build, optionally sign, and persist the signing receipt (IMG-11).
///
/// `input_hash` is the blake3 of the canonical manifest; `output_hash`
/// is the blake3 of cosign's reported signing output (the payload
/// digest cosign prints on success).
fn write_signing_receipt(
    workspace: &Path,
    request: &ImageSignRequest,
    annotations: &[(String, String)],
    cosign_stdout: &[u8],
) -> Result<PathBuf> {
    let manifest = signing_input_manifest(request, annotations);
    let input_hash = blake3::hash(manifest.as_bytes()).to_hex().to_string();
    let output_hash = blake3::hash(cosign_stdout).to_hex().to_string();

    let step = crate::storage::StepResult {
        name: "image-sign".to_string(),
        input_hash: input_hash.clone(),
        output_hash,
        duration_secs: 0,
        exit_code: 0,
        cache_hit: false,
        stdout: String::from_utf8_lossy(cosign_stdout).to_string(),
        stderr: String::new(),
        capsule_hash: None,
    };

    let mut receipt = crate::storage::Receipt {
        schema_version: Some(crate::storage::RECEIPT_SCHEMA_VERSION),
        pipeline_hash: input_hash,
        steps: vec![step],
        timestamp: chrono::Utc::now(),
        total_duration_secs: 0,
        signature: None,
        signer_public_key: None,
        attest_version: "0.1.0".to_string(),
        causal_events: vec![],
        causal_chain_hash: None,
        reproducibility: None,
        provenance: None,
        timestamp_token: None,
    };

    if request.sign_receipt {
        let mut storage = crate::storage::Storage::new(workspace)?;
        let store = crate::keys::KeyStore::new(workspace);
        match store.select_signing_key(request.receipt_key.as_deref())? {
            Some(signing_key) => storage.set_keypair(
                crate::crypto::sign::AttestKeypair::from_signing_key(signing_key),
            ),
            None => storage.load_keypair(true)?,
        }
        receipt = storage.sign_receipt(&receipt)?;
    }

    let receipts_dir = request
        .receipt_dir
        .clone()
        .unwrap_or_else(|| workspace.join(".attest").join("receipts"));
    std::fs::create_dir_all(&receipts_dir)
        .with_context(|| format!("cannot create {}", receipts_dir.display()))?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    crate::storage::write_receipt_unique(
        &receipts_dir,
        &stamp,
        Some("image-sign"),
        &serde_yaml::to_string(&receipt)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "registry.example/repo@sha256:8f3c1a2b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";

    #[test]
    fn digest_ref_accepted() {
        assert!(validate_digest_ref(DIGEST).is_ok());
    }

    #[test]
    fn tag_ref_rejected_with_normative_message() {
        let err = validate_digest_ref("registry.example/repo:v1.2.3").unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert_eq!(
            err.message(),
            "signing requires a digest reference (repo@sha256:...), got tag 'registry.example/repo:v1.2.3'"
        );
    }

    #[test]
    fn malformed_digest_rejected() {
        for bad in [
            "repo@sha256:abc",                                                          // short
            "repo@sha512:0000", // wrong algo
            "@sha256:8f3c1a2b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8", // no repo
        ] {
            let err = validate_digest_ref(bad).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{bad}");
        }
        let upper = format!(
            "repo@sha256:{}",
            "8F3C1A2B4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8"
        );
        assert_eq!(validate_digest_ref(&upper).unwrap_err().exit_code(), 2);
    }

    #[test]
    fn kms_uri_accepted_file_key_gated() {
        assert!(validate_key_uri("azurekms://vault.vault.azure.net/keys/k/1", false).is_ok());
        assert_eq!(
            validate_key_uri("./cosign.key", false)
                .unwrap_err()
                .exit_code(),
            2
        );
        assert!(validate_key_uri("./cosign.key", true).is_ok());
    }

    #[test]
    fn revision_regex_enforced() {
        assert!(validate_revision(&"a".repeat(40)).is_ok());
        assert!(validate_revision(&"0".repeat(64)).is_ok());
        for bad in [
            "deadbeef",
            &"a".repeat(39),
            &"g".repeat(40),
            &"A".repeat(40),
            &"a".repeat(65),
        ] {
            assert_eq!(validate_revision(bad).unwrap_err().exit_code(), 2, "{bad}");
        }
    }

    #[test]
    fn manifest_is_canonical() {
        let request = ImageSignRequest {
            image_ref: DIGEST.to_string(),
            key_uri: "azurekms://v/keys/k/1".to_string(),
            annotations: vec![],
            allow_file_key: false,
            require_clean_tree: true,
            clean_paths: vec![],
            receipt_dir: None,
            sign_receipt: false,
            receipt_key: None,
        };
        let annotations = vec![
            ("a".to_string(), "1".to_string()),
            ("continuum.git.revision".to_string(), "b".repeat(40)),
        ];
        let manifest = signing_input_manifest(&request, &annotations);
        assert!(manifest.starts_with("attest-image-sign/v1\n"));
        assert!(manifest.contains(&format!("image:{DIGEST}\n")));
        assert!(manifest.contains("annotation:a=1\n"));
        assert!(!manifest.contains("allow-file-key"));
    }
}
