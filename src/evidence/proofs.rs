//! Conditional proofs are selected by signed references, never by a sender's
//! claim that its archive is complete. Missing material remains visible even
//! when a recipient chooses not to require it.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

use crate::archive::ArchiveLimits;
use crate::capsule::CapsuleManifest;
use crate::storage::causal_ledger::CausalEvent;
use crate::storage::Receipt;
use crate::verify::{Check, CheckStatus};

fn fields(value: &serde_json::Value, allowed: &[&str]) -> Result<()> {
    let object = value.as_object().context("proof must be an object")?;
    ensure!(
        object.keys().all(|key| allowed.contains(&key.as_str())),
        "proof contains an unauthenticated unknown field"
    );
    Ok(())
}

fn capsule(bytes: &[u8]) -> Result<CapsuleManifest> {
    let value: serde_json::Value = serde_yaml::from_slice(bytes)?;
    fields(
        &value,
        &[
            "format",
            "name",
            "image",
            "entrypoint",
            "env",
            "mounts",
            "network",
            "capsule_hash",
        ],
    )?;
    fields(&value["mounts"], &["workspace"])?;
    serde_json::from_value(value).context("invalid capsule manifest")
}

fn event(bytes: &[u8]) -> Result<CausalEvent> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    fields(
        &value,
        &[
            "event_id",
            "step_name",
            "causal_parents",
            "input_hash",
            "output_hash",
            "timestamp",
            "exit_code",
            "pipeline_hash",
            "environment_hash",
            "signer_public_key",
            "signature",
            "metadata",
        ],
    )?;
    serde_json::from_value(value).context("invalid causal event")
}

fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid proof reference digest"
    );
    Ok(())
}

fn capsule_hashes(receipt: &Receipt) -> Result<BTreeSet<&str>> {
    let mut hashes = BTreeSet::new();
    for hash in receipt
        .steps
        .iter()
        .filter_map(|step| step.capsule_hash.as_deref())
    {
        digest(hash)?;
        hashes.insert(hash);
    }
    Ok(hashes)
}

pub(super) fn paths(receipt: &Receipt) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    for hash in capsule_hashes(receipt)? {
        paths.insert(format!("capsules/{hash}.yaml"));
    }
    for id in &receipt.causal_events {
        digest(id)?;
        ensure!(
            paths.insert(format!("events/{id}.json")),
            "duplicate causal reference"
        );
    }
    Ok(paths)
}

pub(super) fn collect(
    receipt: &Receipt,
    workspace: &Path,
    capsules: &[PathBuf],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let expected = capsule_hashes(receipt)?;
    for path in capsules {
        let bytes =
            crate::verify::read_bounded(path, ArchiveLimits::default().entry, "capsule manifest")?;
        let manifest = capsule(&bytes)?;
        manifest.validate()?;
        let hash = manifest.compute_hash()?;
        ensure!(
            manifest.capsule_hash.as_deref() == Some(hash.as_str()),
            "capsule's stored hash differs from its content"
        );
        ensure!(
            expected.contains(hash.as_str()),
            "capsule is not referenced by this receipt"
        );
        ensure!(
            files
                .insert(format!("capsules/{hash}.yaml"), bytes)
                .is_none(),
            "duplicate capsule proof"
        );
        ensure!(
            files.values().map(|v| v.len() as u64).sum::<u64>()
                <= ArchiveLimits::default().decompressed / 2,
            "proof payload exceeds 256 MiB"
        );
    }
    // Event identifiers are validated before constructing paths. The file
    // reader also refuses symlinked ancestors, including .attest itself.
    for id in &receipt.causal_events {
        digest(id)?;
        let path = format!(".attest/causal_ledger/events/{id}.json");
        let artifact = crate::storage::ArtifactInfo {
            step: String::new(),
            path,
            kind: "file".into(),
            algorithm: "blake3".into(),
            digest: String::new(),
        };
        match super::artifact_bytes(workspace, &artifact) {
            Ok(bytes) => {
                let mut event = event(&bytes)?;
                // Legacy event metadata is outside its ID, root and signature.
                // Preserve only authenticated claims in the v2 proof projection.
                event.metadata.clear();
                files.insert(format!("events/{id}.json"), serde_json::to_vec(&event)?);
            }
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
                }) => {}
            Err(error) => return Err(error),
        }
        ensure!(
            files.values().map(|v| v.len() as u64).sum::<u64>()
                <= ArchiveLimits::default().decompressed / 2,
            "proof payload exceeds 256 MiB"
        );
    }
    paths(receipt)?;
    Ok(files)
}

fn result(name: &str, checked: Result<Option<String>>) -> Check {
    match checked {
        Ok(None) => Check {
            name: name.into(),
            status: CheckStatus::Pass,
            detail: "all referenced proofs are present and bound to the signed receipt".into(),
        },
        Ok(Some(detail)) => Check {
            name: name.into(),
            status: CheckStatus::Skipped,
            detail,
        },
        Err(error) => Check {
            name: name.into(),
            status: CheckStatus::Fail,
            detail: format!("{error:#}"),
        },
    }
}

pub(super) fn assess(receipt: &Receipt, files: &BTreeMap<&str, &[u8]>) -> Vec<Check> {
    let capsules = (|| -> Result<Option<String>> {
        let mut missing = Vec::new();
        for hash in capsule_hashes(receipt)? {
            let path = format!("capsules/{hash}.yaml");
            let Some(bytes) = files.get(path.as_str()) else {
                missing.push(hash);
                continue;
            };
            let manifest = capsule(bytes)?;
            manifest.validate()?;
            ensure!(
                manifest.compute_hash()? == hash && manifest.capsule_hash.as_deref() == Some(hash),
                "capsule manifest does not match signed capsule hash"
            );
        }
        Ok((!missing.is_empty()).then(|| {
            format!(
                "incomplete capsule evidence; missing manifests: {}",
                missing.join(", ")
            )
        }))
    })();
    let causal = (|| -> Result<Option<String>> {
        let mut events = HashMap::<String, CausalEvent>::new();
        let expected: BTreeSet<_> = receipt.causal_events.iter().collect();
        ensure!(
            expected.len() == receipt.causal_events.len(),
            "duplicate causal references"
        );
        if expected.is_empty() {
            ensure!(
                receipt.causal_chain_hash.is_none(),
                "causal chain root has no event references"
            );
            return Ok(None);
        }
        let mut missing = Vec::new();
        for id in &receipt.causal_events {
            digest(id)?;
            let path = format!("events/{id}.json");
            let Some(bytes) = files.get(path.as_str()) else {
                missing.push(id.as_str());
                continue;
            };
            let event = event(bytes)?;
            ensure!(
                event.metadata.is_empty(),
                "causal proof contains unauthenticated metadata"
            );
            ensure!(
                event.event_id == *id,
                "causal entry name differs from event identity"
            );
            ensure!(
                crate::storage::causal_ledger::CausalLedger::event_id_is_authentic(&event),
                "causal event content differs from its identity"
            );
            ensure!(
                crate::storage::causal_ledger::CausalLedger::event_signature_holds(&event)
                    != Some(false),
                "invalid causal event signature"
            );
            ensure!(
                event
                    .causal_parents
                    .iter()
                    .all(|parent| expected.contains(parent)),
                "causal event refers to an unrecorded parent"
            );
            events.insert(id.clone(), event);
        }
        if !missing.is_empty() {
            return Ok(Some(format!(
                "incomplete causal evidence; missing events: {}",
                missing.join(", ")
            )));
        }
        let checked = crate::archive::chain_linkage(receipt, &events, false);
        ensure!(checked.status == CheckStatus::Pass, "{}", checked.detail);
        Ok(None)
    })();
    vec![result("capsule", capsules), result("chain-linkage", causal)]
}
