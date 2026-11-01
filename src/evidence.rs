//! Release handoff: a signed receipt, its output bytes, and optionally a
//! Sigstore workflow bundle. Verification never extracts archive paths or
//! imports trust from the sender. Referenced capsule manifests and causal
//! events are included without depending on the producer's workspace.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::archive::{ArchiveEntry, ArchiveLimits};
use crate::storage::{ArtifactInfo, Receipt};
use crate::verify::{Check, CheckStatus, Policy, ReceiptVerdict, Requirement, VerifyOptions};

mod proofs;

pub const EVIDENCE_FORMAT: &str = "attest-evidence/v2";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
}

fn safe_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.contains(['\\', ':', '\n', '\r', '\0'])
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && Path::new(path)
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
        "unsafe artifact path: {path:?}"
    );
    Ok(())
}

/// Read only the declared file or link, refusing symlinked ancestors.
pub(crate) fn artifact_bytes(root: &Path, artifact: &ArtifactInfo) -> Result<Vec<u8>> {
    safe_path(&artifact.path)?;
    let mut current = root.to_path_buf();
    let parts: Vec<_> = Path::new(&artifact.path).components().collect();
    for (index, part) in parts.iter().enumerate() {
        current.push(part.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("cannot read artifact {}", artifact.path))?;
        if index + 1 < parts.len() {
            ensure!(
                metadata.is_dir() && !metadata.is_symlink(),
                "symlink or non-directory artifact ancestor: {}",
                current.display()
            );
        } else {
            return match artifact.kind.as_str() {
                "file" if metadata.is_file() && !metadata.is_symlink() => {
                    crate::verify::read_bounded(
                        &current,
                        ArchiveLimits::default().entry,
                        "artifact",
                    )
                }
                "symlink" if metadata.is_symlink() => {
                    let target = std::fs::read_link(&current)?;
                    let target = target
                        .to_str()
                        .context("artifact link target is not UTF-8")?;
                    Ok(target.as_bytes().to_vec())
                }
                _ => bail!("artifact kind changed or is unsupported: {}", artifact.path),
            };
        }
    }
    bail!("empty artifact path")
}

fn artifacts(receipt: &Receipt) -> Result<&[ArtifactInfo]> {
    let provenance = receipt
        .provenance
        .as_ref()
        .context("receipt has no artifact provenance")?;
    ensure!(
        !provenance.artifacts.is_empty(),
        "receipt declares no artifact files"
    );
    Ok(&provenance.artifacts)
}

/// Validate the signed inventory against every step's output manifest, not
/// merely each listed digest: omitting an artifact must also be detected.
pub(crate) fn inventory(receipt: &Receipt) -> Result<()> {
    let mut manifests: BTreeMap<&str, BTreeMap<&str, &ArtifactInfo>> = BTreeMap::new();
    let step_names: BTreeSet<_> = receipt.steps.iter().map(|s| s.name.as_str()).collect();
    ensure!(
        step_names.len() == receipt.steps.len(),
        "duplicate step names"
    );
    for artifact in artifacts(receipt)? {
        safe_path(&artifact.path)?;
        ensure!(
            step_names.contains(artifact.step.as_str()),
            "artifact names an unknown step"
        );
        ensure!(
            artifact.algorithm == "blake3",
            "unsupported artifact digest algorithm"
        );
        ensure!(
            matches!(artifact.kind.as_str(), "file" | "symlink"),
            "unsupported artifact kind"
        );
        ensure!(
            artifact.digest.len() == 64
                && artifact
                    .digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid artifact digest"
        );
        ensure!(
            manifests
                .entry(&artifact.step)
                .or_default()
                .insert(&artifact.path, artifact)
                .is_none(),
            "duplicate artifact in step"
        );
    }
    for step in &receipt.steps {
        let mut manifest = format!("{}\n", crate::hashing::MANIFEST_HEADER);
        if let Some(entries) = manifests.get(step.name.as_str()) {
            for (path, artifact) in entries {
                let kind = if artifact.kind == "file" { 'f' } else { 'l' };
                manifest.push_str(&format!("{kind}:{} {path}\n", artifact.digest));
            }
        }
        ensure!(
            blake3::hash(manifest.as_bytes()).to_hex().as_str() == step.output_hash,
            "artifact inventory does not match output hash for {}",
            step.name
        );
    }
    Ok(())
}

fn check_digest(artifact: &ArtifactInfo, bytes: &[u8]) -> Result<()> {
    ensure!(
        blake3::hash(bytes).to_hex().as_str() == artifact.digest,
        "artifact digest mismatch: {}",
        artifact.path
    );
    Ok(())
}

pub fn pack(
    receipt_path: &Path,
    workspace: &Path,
    output: &Path,
    identity_bundle: Option<&Path>,
) -> Result<()> {
    pack_with_capsules(receipt_path, workspace, output, identity_bundle, &[])
}

pub fn pack_with_capsules(
    receipt_path: &Path,
    workspace: &Path,
    output: &Path,
    identity_bundle: Option<&Path>,
    capsules: &[std::path::PathBuf],
) -> Result<()> {
    let bytes =
        crate::verify::read_bounded(receipt_path, crate::verify::MAX_RECEIPT_BYTES, "receipt")?;
    let receipt: Receipt = serde_yaml::from_slice(&bytes).context("invalid receipt")?;
    ensure!(
        receipt.schema_version.unwrap_or(1) <= crate::storage::RECEIPT_SCHEMA_VERSION,
        "unsupported receipt schema"
    );
    let key = receipt
        .signer_public_key
        .as_deref()
        .context("evidence needs a signed receipt")?;
    let signature = receipt
        .signature
        .as_deref()
        .context("evidence needs a signed receipt")?;
    ensure!(
        crate::crypto::sign::verify_with_public_key(
            key,
            crate::storage::receipt_signing_bytes(&receipt)?.as_bytes(),
            signature
        )?,
        "invalid receipt signature"
    );
    inventory(&receipt)?;
    let mut files = proofs::collect(&receipt, workspace, capsules)?;
    let mut size = bytes.len() as u64 + files.values().map(|bytes| bytes.len() as u64).sum::<u64>();
    for artifact in artifacts(&receipt)? {
        let bytes = artifact_bytes(workspace, artifact)?;
        check_digest(artifact, &bytes)?;
        let path = format!("artifacts/{}", artifact.path);
        if let Some(previous) = files.get(&path) {
            ensure!(
                previous == &bytes,
                "steps disagree on artifact {}",
                artifact.path
            );
        } else {
            size += bytes.len() as u64;
            ensure!(
                size <= ArchiveLimits::default().decompressed / 2,
                "evidence payload exceeds 256 MiB"
            );
            files.insert(path, bytes);
        }
    }
    files.insert("receipt.yaml".into(), bytes);
    files.insert(
        "manifest.json".into(),
        serde_json::to_vec(&Manifest {
            format: EVIDENCE_FORMAT.into(),
        })?,
    );
    if let Some(bundle) = identity_bundle {
        files.insert(
            "identity.sigstore.json".into(),
            crate::verify::read_bounded(
                bundle,
                crate::identity::MAX_IDENTITY_BYTES,
                "identity bundle",
            )?,
        );
    }
    ensure!(
        files.len() <= ArchiveLimits::default().entries,
        "too many evidence entries"
    );
    // Stage beside the destination: never leave a partial archive behind, and
    // verify our own resource limits before making it visible to a recipient.
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staged = tempfile::NamedTempFile::new_in(parent)?;
    crate::archive::write_archive(
        files
            .into_iter()
            .map(|(path, bytes)| ArchiveEntry { path, bytes })
            .collect(),
        staged.path(),
    )?;
    crate::archive::read_archive(staged.path())?;
    staged.persist(output).map_err(|error| error.error)?;
    Ok(())
}

/// Signature and successful execution are always required for release
/// evidence. The optional identity policy is supplied independently by the
/// recipient; a bundled certificate or public key cannot authorize itself.
pub fn verify(
    archive: &Path,
    trust_store: &Path,
    identity_policy: Option<&crate::identity::IdentityPolicy>,
    artifact_root: Option<&Path>,
) -> Result<ReceiptVerdict> {
    verify_with_policy(
        archive,
        trust_store,
        identity_policy,
        artifact_root,
        &default_policy(),
    )
}

/// Required checks come from the recipient. A sender cannot downgrade
/// completeness by setting an archive flag or omitting its proof entries.
pub fn default_policy() -> Policy {
    Policy {
        required: vec![
            Requirement::Signature,
            Requirement::Success,
            Requirement::Artifacts,
            Requirement::Capsule,
            Requirement::Linkage,
        ],
    }
}

pub fn verify_with_policy(
    archive: &Path,
    trust_store: &Path,
    identity_policy: Option<&crate::identity::IdentityPolicy>,
    artifact_root: Option<&Path>,
    policy: &Policy,
) -> Result<ReceiptVerdict> {
    let entries = crate::archive::read_archive(archive)?;
    let files: BTreeMap<_, _> = entries
        .iter()
        .map(|e| (e.path.as_str(), e.bytes.as_slice()))
        .collect();
    let manifest: Manifest = serde_json::from_slice(
        files
            .get("manifest.json")
            .context("missing evidence manifest")?,
    )?;
    ensure!(
        manifest.format == EVIDENCE_FORMAT || manifest.format == "attest-evidence/v1",
        "unsupported evidence format {}",
        manifest.format
    );
    let receipt_bytes = *files.get("receipt.yaml").context("missing receipt.yaml")?;
    ensure!(
        receipt_bytes.len() as u64 <= crate::verify::MAX_RECEIPT_BYTES,
        "receipt exceeds size limit"
    );
    let mut required = policy.required.clone();
    // These are the minimum acceptance contract of a release handoff.
    for requirement in [
        Requirement::Signature,
        Requirement::Success,
        Requirement::Artifacts,
    ] {
        if !required.contains(&requirement) {
            required.push(requirement);
        }
    }
    if identity_policy.is_some() && !required.contains(&Requirement::Identity) {
        required.push(Requirement::Identity);
    }
    let options = VerifyOptions {
        check_signatures: true,
        recompute: false,
        workspace: std::env::current_dir()?,
        trust_store: Some(trust_store.to_path_buf()),
        trust_receipt_timestamp: false,
        policy: Policy { required },
    };
    let mut verdict = crate::verify::verify_receipt_bytes(
        receipt_bytes,
        &archive.display().to_string(),
        &options,
    )?;
    let checked = (|| -> Result<()> {
        let receipt: Receipt = serde_yaml::from_slice(receipt_bytes)?;
        inventory(&receipt)?;
        let mut expected: BTreeSet<String> = ["manifest.json", "receipt.yaml"]
            .into_iter()
            .map(String::from)
            .collect();
        if files.contains_key("identity.sigstore.json") {
            expected.insert("identity.sigstore.json".into());
        }
        expected.extend(proofs::paths(&receipt)?);
        for artifact in artifacts(&receipt)? {
            let path = format!("artifacts/{}", artifact.path);
            let bytes = files
                .get(path.as_str())
                .with_context(|| format!("missing artifact {}", artifact.path))?;
            check_digest(artifact, bytes)?;
            if let Some(root) = artifact_root {
                check_digest(artifact, &artifact_bytes(root, artifact)?)?;
            }
            expected.insert(path);
        }
        ensure!(
            files.keys().all(|path| expected.contains(*path)),
            "archive contains unaccounted files"
        );
        Ok(())
    })();
    verdict.checks.push(match checked {
        Ok(()) => Check {
            name: "artifacts".into(),
            status: CheckStatus::Pass,
            detail: "all artifact bytes match the signed output manifests".into(),
        },
        Err(error) => Check {
            name: "artifacts".into(),
            status: CheckStatus::Fail,
            detail: format!("{error:#}"),
        },
    });
    if let Ok(receipt) = serde_yaml::from_slice::<Receipt>(receipt_bytes) {
        verdict.checks.extend(proofs::assess(&receipt, &files));
    }
    verdict.identity = Some(crate::identity::IdentityOutcome {
        required: identity_policy.cloned(),
        verified: None,
        principals: crate::identity::IdentityPrincipals {
            evidence_producer: verdict.signed_by.clone(),
            workflow: None,
            artifact_signer: None,
        },
    });
    if let Some(policy) = identity_policy {
        let checked = (|| -> Result<crate::identity::IdentityVerification> {
            let bundle = files
                .get("identity.sigstore.json")
                .context("required workflow identity evidence is missing")?;
            ensure!(
                bundle.len() as u64 <= crate::identity::MAX_IDENTITY_BYTES,
                "identity bundle exceeds size limit"
            );
            let temp = tempfile::tempdir()?;
            let receipt_path = temp.path().join("receipt.yaml");
            let bundle_path = temp.path().join("identity.sigstore.json");
            std::fs::write(&receipt_path, receipt_bytes)?;
            std::fs::write(&bundle_path, bundle)?;
            crate::identity::verify_receipt_identity(&receipt_path, &bundle_path, policy)
        })();
        verdict.checks.push(match checked {
            Ok(verified) => {
                if let Some(identity) = &mut verdict.identity {
                    identity.principals.workflow = Some(verified.workflow.clone());
                    identity.verified = Some(verified);
                }
                Check {
                    name: "identity".into(),
                    status: CheckStatus::Pass,
                    detail:
                        "workflow issuer, repository, workflow and revision match recipient policy"
                            .into(),
                }
            }
            Err(error) => Check {
                name: "identity".into(),
                status: CheckStatus::Fail,
                detail: format!("{error:#}"),
            },
        });
    } else {
        verdict.checks.push(Check {
            name: "identity".into(),
            status: CheckStatus::Skipped,
            detail: "no workflow identity policy supplied by recipient".into(),
        });
    }
    crate::verify::apply_policy(&mut verdict, &options.policy);
    Ok(verdict)
}
