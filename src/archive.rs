//! Self-contained attestation archives (`attest causal export` /
//! `attest verify --archive`).
//!
//! Archive format `attest-archive/v1`: a zstd-compressed tar containing
//! `manifest.json`, `receipt.yaml` (byte-identical to the original),
//! `events/<id>.json` — the causal-ledger events the receipt references —
//! and `pubkeys/<key-id>.pub` convenience copies. The tar is reproducible: entries sorted by path,
//! mtime 0, uid/gid 0 — exporting the same receipt twice yields
//! byte-identical archives.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::storage::Receipt;
use crate::verify::{Check, CheckStatus, ReceiptVerdict, VerifyOptions};

pub const ARCHIVE_FORMAT: &str = "attest-archive/v1";

#[derive(Debug, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub format: String,
    /// Taken from the receipt's own timestamp, not the export wall clock.
    /// Archives must be reproducible, so nothing here may change between
    /// two exports of the same receipt.
    pub created: String,
    pub attest_version: String,
    #[serde(default)]
    pub partial: bool,
}

/// One file inside an archive.
pub struct ArchiveEntry {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Write entries as a reproducible tar.zst: paths sorted, mtime 0,
/// uid/gid 0, mode 0644.
pub fn write_archive(mut entries: Vec<ArchiveEntry>, output: &Path) -> Result<()> {
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let mut builder = tar::Builder::new(Vec::new());
    for entry in &entries {
        let mut header = tar::Header::new_ustar();
        header.set_size(entry.bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append_data(&mut header, &entry.path, entry.bytes.as_slice())
            .with_context(|| format!("cannot append {} to archive", entry.path))?;
    }
    let tar_bytes = builder.into_inner().context("cannot finalize tar")?;

    let compressed =
        zstd::encode_all(tar_bytes.as_slice(), 0).context("cannot compress archive")?;
    std::fs::write(output, compressed)
        .with_context(|| format!("cannot write {}", output.display()))?;
    Ok(())
}

/// Read every file entry of a tar.zst archive.
pub fn read_archive(path: &Path) -> Result<Vec<ArchiveEntry>> {
    let compressed =
        std::fs::read(path).with_context(|| format!("cannot read archive {}", path.display()))?;
    let tar_bytes = zstd::decode_all(compressed.as_slice())
        .with_context(|| format!("{} is not a zstd archive", path.display()))?;

    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    let mut entries = Vec::new();
    for entry in archive.entries().context("cannot list archive entries")? {
        let mut entry = entry.context("corrupt archive entry")?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        entries.push(ArchiveEntry { path, bytes });
    }
    Ok(entries)
}

/// Outcome of an export attempt.
pub enum ExportOutcome {
    /// The archive was written; `partial` mirrors the manifest flag.
    Written { partial: bool },
    /// Causal references could not be resolved and `allow_partial` was not
    /// set; nothing was written. The CLI maps this to exit 1 — an
    /// incomplete chain is a verification-meaningful condition, not an
    /// operational error.
    IncompleteChain { missing: Vec<String> },
}

/// Export a receipt as a self-contained archive.
///
/// The ledger events the receipt references are resolved from
/// `.attest/causal_ledger/events/<event-id>.json` and carried as
/// `events/<event-id>.json`. That is what makes the archive self-contained:
/// with them, a verifier can recompute `causal_chain_hash` without the
/// repository the receipt came from.
///
/// A reference that cannot be resolved is a gap. Without `allow_partial` a
/// gap aborts the export; with it, the manifest records `"partial": true`.
pub fn export_archive(
    receipt_path: &Path,
    output: &Path,
    allow_partial: bool,
) -> Result<ExportOutcome> {
    let receipt_bytes = std::fs::read(receipt_path)
        .with_context(|| format!("cannot read receipt {}", receipt_path.display()))?;
    let receipt: Receipt = serde_yaml::from_slice(&receipt_bytes)
        .with_context(|| format!("{} is not a valid receipt", receipt_path.display()))?;

    let mut entries: Vec<ArchiveEntry> = Vec::new();
    let mut partial = false;

    // events/ — the ledger events the receipt references.
    //
    // Receipts live in `<workspace>/.attest/receipts/`, so the ledger is two
    // levels up from the receipt file.
    let events_dir = receipt_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("."))
        .join("causal_ledger")
        .join("events");
    let mut missing: Vec<String> = Vec::new();
    for event_id in &receipt.causal_events {
        let candidate = events_dir.join(format!("{}.json", event_id));
        if candidate.is_file() {
            entries.push(ArchiveEntry {
                path: format!("events/{}.json", event_id),
                bytes: std::fs::read(&candidate)?,
            });
        } else {
            missing.push(event_id.clone());
        }
    }
    if !missing.is_empty() {
        if !allow_partial {
            return Ok(ExportOutcome::IncompleteChain { missing });
        }
        partial = true;
    }

    // pubkeys/ — convenience copy of every signer key.
    let mut signer_keys: HashSet<String> = HashSet::new();
    if let Some(key) = &receipt.signer_public_key {
        signer_keys.insert(key.clone());
    }
    for entry in &entries {
        if let Ok(chain_receipt) = serde_yaml::from_slice::<Receipt>(&entry.bytes) {
            if let Some(key) = &chain_receipt.signer_public_key {
                signer_keys.insert(key.clone());
            }
        }
    }
    for key_hex in &signer_keys {
        if let Ok((id, pem)) = public_key_pem_from_hex(key_hex) {
            entries.push(ArchiveEntry {
                path: format!("pubkeys/{}.pub", id),
                bytes: pem.into_bytes(),
            });
        }
    }

    let manifest = ArchiveManifest {
        format: ARCHIVE_FORMAT.to_string(),
        created: receipt.timestamp.to_rfc3339(),
        attest_version: receipt.attest_version.clone(),
        partial,
    };
    entries.push(ArchiveEntry {
        path: "manifest.json".to_string(),
        bytes: serde_json::to_vec_pretty(&manifest)?,
    });
    entries.push(ArchiveEntry {
        path: "receipt.yaml".to_string(),
        bytes: receipt_bytes,
    });

    write_archive(entries, output)?;
    Ok(ExportOutcome::Written { partial })
}

/// Every referenced event must be present, and together they must recompute
/// to the root the receipt was signed over.
///
/// Presence alone would be weak: an archive could carry a different set of
/// events than the one the signature commits to. Recomputing the root is
/// what ties the two together, and it is possible offline precisely because
/// the root is a pure function of the events in the order the receipt lists
/// them.
fn chain_linkage(
    receipt: &Receipt,
    events: &std::collections::HashMap<String, crate::storage::causal_ledger::CausalEvent>,
    partial: bool,
) -> Check {
    let named = |name: &str, status: CheckStatus, detail: String| Check {
        name: name.to_string(),
        status,
        detail,
    };

    if receipt.causal_events.is_empty() {
        return named(
            "chain-linkage",
            CheckStatus::Skipped,
            "receipt references no causal events".to_string(),
        );
    }

    let missing: Vec<&str> = receipt
        .causal_events
        .iter()
        .filter(|id| !events.contains_key(*id))
        .map(String::as_str)
        .collect();

    if !missing.is_empty() {
        let detail = format!("unresolved causal references: {}", missing.join(", "));
        return if partial {
            named(
                "chain-linkage",
                CheckStatus::Skipped,
                format!("partial archive: {detail}"),
            )
        } else {
            named("chain-linkage", CheckStatus::Fail, detail)
        };
    }

    let ordered: Vec<crate::storage::causal_ledger::CausalEvent> = receipt
        .causal_events
        .iter()
        .filter_map(|id| events.get(id).cloned())
        .collect();

    // An event's id has to follow from its contents, or the archive is a set
    // of files that merely agree with each other. Checked before the chain
    // root, so a rewritten event is named as such rather than surfacing as a
    // root mismatch with no indication of which event moved.
    let forged: Vec<&str> = ordered
        .iter()
        .filter(|event| !crate::storage::causal_ledger::CausalLedger::event_id_is_authentic(event))
        .map(|event| event.event_id.as_str())
        .collect();
    if !forged.is_empty() {
        return named(
            "chain-linkage",
            CheckStatus::Fail,
            format!(
                "causal event contents do not match their recorded ids: {}",
                forged.join(", ")
            ),
        );
    }

    // An event that carries a signature has to carry one that holds. Events
    // used to be signed with the producing machine's key and checked against
    // that same local key, which meant nobody else could check them at all;
    // the signer's public key is recorded now, so this works from an archive
    // alone. Unsigned events are not an error here -- a run without a signing
    // key produces them -- but a signature that does not verify is.
    let unverifiable: Vec<&str> = ordered
        .iter()
        .filter(|event| {
            crate::storage::causal_ledger::CausalLedger::event_signature_holds(event) == Some(false)
        })
        .map(|event| event.event_id.as_str())
        .collect();
    if !unverifiable.is_empty() {
        return named(
            "chain-linkage",
            CheckStatus::Fail,
            format!(
                "causal events carry signatures that do not verify: {}",
                unverifiable.join(", ")
            ),
        );
    }

    let recomputed = crate::storage::causal_ledger::CausalLedger::chain_hash(&ordered);

    match &receipt.causal_chain_hash {
        Some(expected) if *expected == recomputed => named(
            "chain-linkage",
            CheckStatus::Pass,
            format!(
                "{} events recompute to the signed chain root",
                ordered.len()
            ),
        ),
        Some(expected) => named(
            "chain-linkage",
            CheckStatus::Fail,
            format!("events recompute to {recomputed}, receipt claims {expected}"),
        ),
        None => named(
            "chain-linkage",
            CheckStatus::Fail,
            "receipt lists causal events but records no chain root".to_string(),
        ),
    }
}

fn public_key_pem_from_hex(key_hex: &str) -> Result<(String, String)> {
    let bytes = hex::decode(key_hex).context("invalid public key hex")?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
    let key = VerifyingKey::from_bytes(&array).map_err(|e| anyhow::anyhow!("{}", e))?;
    let pem = key
        .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .context("cannot encode public key PEM")?;
    Ok((crate::keys::key_id(&key), pem))
}

/// Outcome of verifying an archive: per-receipt verdicts plus the
/// archive-level metadata.
pub struct ArchiveVerdict {
    pub receipts: Vec<ReceiptVerdict>,
    pub partial: bool,
}

impl ArchiveVerdict {
    pub fn passed(&self) -> bool {
        self.receipts.iter().all(|r| r.passed())
    }
}

/// Verify an archive fully offline: the receipt's own checks, plus
/// `chain-linkage` — every id in `causal_events` is present as an event,
/// and the events recompute to the `causal_chain_hash` the receipt is
/// signed over.
///
/// `Err` is operational (unreadable/absent archive, bad manifest) → exit 2.
pub fn verify_archive(path: &Path, opts: &VerifyOptions) -> Result<ArchiveVerdict> {
    let entries = read_archive(path)?;

    let manifest_entry = entries
        .iter()
        .find(|e| e.path == "manifest.json")
        .with_context(|| format!("{}: archive has no manifest.json", path.display()))?;
    let manifest: ArchiveManifest =
        serde_json::from_slice(&manifest_entry.bytes).context("invalid manifest.json")?;
    if manifest.format != ARCHIVE_FORMAT {
        bail!(
            "unsupported archive format '{}' (expected {})",
            manifest.format,
            ARCHIVE_FORMAT
        );
    }

    let events: std::collections::HashMap<String, crate::storage::causal_ledger::CausalEvent> =
        entries
            .iter()
            .filter_map(|e| {
                let id = e.path.strip_prefix("events/")?.strip_suffix(".json")?;
                let event = serde_json::from_slice(&e.bytes).ok()?;
                Some((id.to_string(), event))
            })
            .collect();

    let mut receipts = Vec::new();
    for entry in &entries {
        if entry.path != "receipt.yaml" {
            continue;
        }

        let label = format!("{}:{}", path.display(), entry.path);
        let mut verdict = crate::verify::verify_receipt_bytes(&entry.bytes, &label, opts)?;

        let linkage = match serde_yaml::from_slice::<Receipt>(&entry.bytes) {
            Ok(receipt) => chain_linkage(&receipt, &events, manifest.partial),
            Err(err) => Check {
                name: "chain-linkage".to_string(),
                status: CheckStatus::Fail,
                detail: format!("receipt is unreadable: {err}"),
            },
        };
        if linkage.status == CheckStatus::Fail {
            verdict.verdict = "fail".to_string();
        }
        verdict.checks.push(linkage);
        receipts.push(verdict);
    }

    if receipts.is_empty() {
        bail!("{}: archive contains no receipt.yaml", path.display());
    }

    Ok(ArchiveVerdict {
        receipts,
        partial: manifest.partial,
    })
}
