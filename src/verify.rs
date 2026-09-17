//! Full receipt verification (`attest verify`).
//!
//! Checks run in order — schema, consistency, signature, recompute — and are
//! reported independently. All checks are local; no network I/O is performed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::storage::{receipt_signing_bytes, Receipt};

/// Options for a verification run, mapped 1:1 from the CLI flags.
pub struct VerifyOptions {
    pub check_signatures: bool,
    pub recompute: bool,
    pub workspace: PathBuf,
    pub trust_store: Option<PathBuf>,
    /// Accept a revoked key's signature on the strength of the receipt's own
    /// timestamp, with no independent proof of when it was signed.
    ///
    /// Off by default, and that default is the point: the receipt's
    /// timestamp is written by the signer and covered by the signer's
    /// signature, so whoever steals a key can date a receipt before the
    /// revocation meant to stop them. Kept as an opt-in because receipts
    /// written before timestamping existed cannot acquire a token now.
    pub trust_receipt_timestamp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct ReceiptVerdict {
    pub receipt: String,
    pub verdict: String,
    pub checks: Vec<Check>,
    pub signed_by: Option<String>,
    /// Non-fatal notices (e.g. a signature by a key revoked after signing).
    pub warnings: Vec<String>,
}

impl ReceiptVerdict {
    pub fn passed(&self) -> bool {
        self.verdict == "pass"
    }
}

fn check(name: &str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_string(),
        status,
        detail: detail.into(),
    }
}

/// Verify a single receipt file.
///
/// `Err` is reserved for operational problems (unreadable file, YAML that is
/// not YAML at all) and maps to exit code 2 in the CLI. Every verification
/// failure — including a receipt that does not match the schema — is a
/// `fail` check inside the returned verdict (exit code 1).
pub fn verify_receipt_file(path: &Path, opts: &VerifyOptions) -> Result<ReceiptVerdict> {
    let display_path = path.display().to_string();
    let content = std::fs::read(path)
        .with_context(|| format!("cannot read receipt file: {}", display_path))?;
    verify_receipt_bytes(&content, &display_path, opts)
}

/// Verify a receipt already held in memory (e.g. an archive entry).
/// Same contract as [`verify_receipt_file`]; `label` names the receipt in
/// the verdict.
pub fn verify_receipt_bytes(
    content: &[u8],
    label: &str,
    opts: &VerifyOptions,
) -> Result<ReceiptVerdict> {
    let display_path = label.to_string();
    let value: serde_yaml::Value = serde_yaml::from_slice(content)
        .with_context(|| format!("unreadable YAML in {}", display_path))?;

    let mut checks: Vec<Check> = Vec::new();
    let mut signed_by: Option<String> = None;
    let mut warnings: Vec<String> = Vec::new();

    // 1. schema — strict: receipts are a security document, unknown fields
    //    are rejected (deny_unknown_fields on Receipt/StepResult).
    //    Checked on the raw YAML before the strict parse: a future-version
    //    receipt would otherwise fail with an opaque unknown-field error
    //    instead of telling the user to upgrade.
    if let Some(v) = value.get("schema_version").and_then(|v| v.as_u64()) {
        if v > crate::storage::RECEIPT_SCHEMA_VERSION as u64 {
            checks.push(check(
                "schema",
                CheckStatus::Fail,
                format!(
                    "receipt schema_version {} is newer than the latest supported version ({}); upgrade attest to verify this receipt",
                    v,
                    crate::storage::RECEIPT_SCHEMA_VERSION
                ),
            ));
            for name in ["consistency", "signature", "timestamp", "recompute"] {
                checks.push(check(name, CheckStatus::Skipped, "schema check failed"));
            }
            return Ok(ReceiptVerdict {
                receipt: display_path,
                verdict: "fail".to_string(),
                checks,
                signed_by,
                warnings,
            });
        }
    }
    let receipt: Option<Receipt> = match serde_yaml::from_value(value) {
        Ok(receipt) => {
            checks.push(check("schema", CheckStatus::Pass, "receipt matches schema"));
            Some(receipt)
        }
        Err(err) => {
            checks.push(check("schema", CheckStatus::Fail, err.to_string()));
            None
        }
    };

    if let Some(receipt) = &receipt {
        checks.push(consistency_check(receipt));

        // The timestamp is resolved first because the signature check
        // needs it: revocation must be judged against a time the signer
        // did not choose, when one is available.
        let (ts_check, trusted_time) = timestamp_check(receipt, opts);

        if opts.check_signatures {
            let (sig_check, key_id) = signature_check(receipt, opts, trusted_time, &mut warnings);
            checks.push(sig_check);
            signed_by = key_id;
        } else {
            checks.push(check(
                "signature",
                CheckStatus::Skipped,
                "disabled by --no-check-signatures",
            ));
        }
        checks.push(ts_check);

        if opts.recompute {
            checks.push(recompute_check(receipt, &opts.workspace));
        } else {
            checks.push(check(
                "recompute",
                CheckStatus::Skipped,
                "enable with --recompute",
            ));
        }
    } else {
        for name in ["consistency", "signature", "timestamp", "recompute"] {
            checks.push(check(name, CheckStatus::Skipped, "schema check failed"));
        }
    }

    let verdict = if checks.iter().any(|c| c.status == CheckStatus::Fail) {
        "fail"
    } else {
        "pass"
    };

    Ok(ReceiptVerdict {
        receipt: display_path,
        verdict: verdict.to_string(),
        checks,
        signed_by,
        warnings,
    })
}

/// Internal-coherence checks on the parsed receipt.
fn consistency_check(receipt: &Receipt) -> Check {
    let mut problems: Vec<String> = Vec::new();

    if receipt.attest_version.is_empty() {
        problems.push("attest_version is empty".to_string());
    }
    if receipt.pipeline_hash.len() != 64 || !is_lower_hex(&receipt.pipeline_hash) {
        problems.push("pipeline_hash is not a 64-char lowercase hex digest".to_string());
    }
    if receipt.steps.is_empty() {
        problems.push("receipt has no steps".to_string());
    }
    for step in &receipt.steps {
        if step.input_hash.len() != 64 || !is_lower_hex(&step.input_hash) {
            problems.push(format!(
                "step '{}': input_hash is not a 64-char lowercase hex digest",
                step.name
            ));
        }
        if step.output_hash.len() != 64 || !is_lower_hex(&step.output_hash) {
            problems.push(format!(
                "step '{}': output_hash is not a 64-char lowercase hex digest",
                step.name
            ));
        }
    }

    if problems.is_empty() {
        check("consistency", CheckStatus::Pass, "receipt is coherent")
    } else {
        check("consistency", CheckStatus::Fail, problems.join("; "))
    }
}

/// Verify the RFC 3161 timestamp token, if the receipt carries one.
///
/// Returns the instant the authority attested, which the signature check
/// then uses to judge revocation. A receipt without a token is not a
/// failure — timestamping is opt-in — but it does mean nothing independent
/// says when it was signed.
fn timestamp_check(
    receipt: &Receipt,
    opts: &VerifyOptions,
) -> (Check, Option<chrono::DateTime<chrono::Utc>>) {
    use base64::Engine as _;

    let Some(encoded) = &receipt.timestamp_token else {
        return (
            check(
                "timestamp",
                CheckStatus::Skipped,
                "receipt carries no timestamp token",
            ),
            None,
        );
    };

    let Some(signature_hex) = &receipt.signature else {
        return (
            check(
                "timestamp",
                CheckStatus::Fail,
                "receipt has a timestamp token but no signature for it to cover",
            ),
            None,
        );
    };

    let token = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(der) => der,
        Err(_) => {
            return (
                check(
                    "timestamp",
                    CheckStatus::Fail,
                    "timestamp token is not valid base64",
                ),
                None,
            )
        }
    };

    let imprint = match crate::crypto::timestamp::signature_imprint(signature_hex) {
        Ok(imprint) => imprint,
        Err(err) => return (check("timestamp", CheckStatus::Fail, err.to_string()), None),
    };

    let store = opts
        .trust_store
        .clone()
        .unwrap_or_else(|| opts.workspace.join(".attest").join("trust"));
    let issuers = crate::keys::tsa_issuers(&store);
    if issuers.is_empty() {
        return (
            check(
                "timestamp",
                CheckStatus::Fail,
                format!(
                    "no pinned timestamp authority in {}; add the issuing CA certificate to verify this token",
                    store.join("tsa").display()
                ),
            ),
            None,
        );
    }

    match crate::crypto::timestamp::verify_token(&token, &imprint, &issuers) {
        Ok(verified) => {
            let detail = format!(
                "signature timestamped {} by {}",
                verified.info.gen_time.to_rfc3339(),
                verified.signer
            );
            (
                check("timestamp", CheckStatus::Pass, detail),
                Some(verified.info.gen_time),
            )
        }
        Err(err) => (check("timestamp", CheckStatus::Fail, err.to_string()), None),
    }
}

/// Verify the Ed25519 signature over the canonical signing bytes, then
/// check the signer key against the trust store (semantics:
/// revoked keys fail for receipts signed after `revoked_at`, and pass with
/// a warning for receipts signed before).
fn signature_check(
    receipt: &Receipt,
    opts: &VerifyOptions,
    trusted_time: Option<chrono::DateTime<chrono::Utc>>,
    warnings: &mut Vec<String>,
) -> (Check, Option<String>) {
    let (signature, public_key_hex) = match (&receipt.signature, &receipt.signer_public_key) {
        (Some(sig), Some(key)) => (sig, key),
        _ => {
            return (
                check("signature", CheckStatus::Fail, "receipt is unsigned"),
                None,
            )
        }
    };

    let signing_bytes = match receipt_signing_bytes(receipt) {
        Ok(bytes) => bytes,
        Err(err) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("cannot canonicalize receipt: {}", err),
                ),
                None,
            )
        }
    };

    match crate::crypto::sign::verify_with_public_key(
        public_key_hex,
        signing_bytes.as_bytes(),
        signature,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    "Ed25519 signature does not verify against signer_public_key",
                ),
                None,
            )
        }
        Err(err) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("malformed signature material: {}", err),
                ),
                None,
            )
        }
    }

    match key_trust_status(opts, public_key_hex) {
        Err(err) => (
            check(
                "signature",
                CheckStatus::Fail,
                format!("cannot load trust store: {}", err),
            ),
            None,
        ),
        Ok(KeyTrust::Unknown) => {
            let key_id = crate::keys::key_id_from_hex(public_key_hex)
                .unwrap_or_else(|_| public_key_hex.clone());
            (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("valid signature but signed by untrusted key {}", key_id),
                ),
                None,
            )
        }
        Ok(KeyTrust::Trusted) => (
            check(
                "signature",
                CheckStatus::Pass,
                format!("valid signature by trusted key {}", public_key_hex),
            ),
            Some(public_key_hex.clone()),
        ),
        Ok(KeyTrust::Revoked(revoked_at)) => {
            // Which clock decides whether this signature predates the
            // revocation. A timestamp token is a third party's word; the
            // receipt's own field is the signer's, and whoever stole the
            // key can set it to anything they like.
            let signed_at = match trusted_time {
                Some(attested) => attested,
                None if opts.trust_receipt_timestamp => {
                    warnings.push(format!(
                        "key {} is revoked and this receipt carries no timestamp token; \
                         --trust-receipt-timestamp was given, so the revocation check \
                         falls back to the receipt's own timestamp, which whoever holds \
                         the key controls",
                        public_key_hex
                    ));
                    receipt.timestamp
                }
                None => {
                    // Falling back here silently would hand back exactly what
                    // revocation exists to take away: the thief writes the
                    // date. Refuse, and say what would make it verifiable.
                    return (
                        check(
                            "signature",
                            CheckStatus::Fail,
                            format!(
                                "signed by revoked key {} and carrying no timestamp token, \
                                 so there is no evidence the signature predates the \
                                 revocation at {}; re-verify with a timestamped receipt, \
                                 or pass --trust-receipt-timestamp to accept the signer's \
                                 own word for when it was signed",
                                public_key_hex, revoked_at
                            ),
                        ),
                        None,
                    );
                }
            };
            if signed_at > revoked_at {
                (
                    check(
                        "signature",
                        CheckStatus::Fail,
                        format!(
                            "signed by key {} after its revocation at {}",
                            public_key_hex, revoked_at
                        ),
                    ),
                    None,
                )
            } else {
                warnings.push(format!(
                    "signed by key revoked later ({} revoked at {})",
                    public_key_hex, revoked_at
                ));
                (
                    check(
                        "signature",
                        CheckStatus::Pass,
                        "valid signature; signed by key revoked later",
                    ),
                    Some(public_key_hex.clone()),
                )
            }
        }
    }
}

enum KeyTrust {
    Trusted,
    Revoked(chrono::DateTime<chrono::Utc>),
    Unknown,
}

/// Resolve the trust status of a hex-encoded public key.
///
/// Sources, in order: the explicit `--trust-store` dir, else `.attest/trust/`
/// (managed `.pub` PEM files + `trust.toml` policy, plus legacy loose raw-32
/// or hex-64 key files, treated as trusted), else fall back to the local
/// signing key `.attest/keys/public.key` so a repository can verify its own
/// receipts without a trust store.
fn key_trust_status(opts: &VerifyOptions, public_key_hex: &str) -> Result<KeyTrust> {
    let store = opts
        .trust_store
        .clone()
        .unwrap_or_else(|| opts.workspace.join(".attest").join("trust"));

    if store.is_dir() {
        let policy = crate::keys::TrustPolicy::load(&store)?;
        let managed = crate::keys::trust_dir_public_keys(&store)?;

        for (id, key_hex) in &managed {
            if key_hex != public_key_hex {
                continue;
            }
            return Ok(match policy.entry(id) {
                Some(entry) if entry.status == "revoked" => match entry.revoked_at {
                    Some(at) => KeyTrust::Revoked(at),
                    // revoked without a date: treat as always revoked
                    None => KeyTrust::Revoked(chrono::DateTime::<chrono::Utc>::MIN_UTC),
                },
                // present as .pub but no policy entry, or entry trusted
                _ => KeyTrust::Trusted,
            });
        }

        // Legacy loose files: raw 32-byte or hex-64 content, always trusted.
        for entry in std::fs::read_dir(&store)? {
            let path = entry?.path();
            if !path.is_file()
                || path.extension().map(|e| e == "pub").unwrap_or(false)
                || path.file_name().map(|n| n == "trust.toml").unwrap_or(false)
            {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let key_hex = if bytes.len() == 32 {
                Some(hex::encode(&bytes))
            } else {
                String::from_utf8(bytes).ok().and_then(|text| {
                    let text = text.trim().to_lowercase();
                    (text.len() == 64 && is_lower_hex(&text)).then_some(text)
                })
            };
            if key_hex.as_deref() == Some(public_key_hex) {
                return Ok(KeyTrust::Trusted);
            }
        }
        return Ok(KeyTrust::Unknown);
    }

    let local_key = opts
        .workspace
        .join(".attest")
        .join("keys")
        .join("public.key");
    if local_key.is_file() {
        let bytes = std::fs::read(&local_key)?;
        if bytes.len() == 32 && hex::encode(&bytes) == public_key_hex {
            return Ok(KeyTrust::Trusted);
        }
    }
    Ok(KeyTrust::Unknown)
}

/// Recompute every step's input hash from the workspace's pipeline
/// declaration and compare byte-for-byte with the receipt.
fn recompute_check(receipt: &Receipt, workspace: &Path) -> Check {
    let pipeline_path = workspace.join("attest.yaml");
    let content = match std::fs::read_to_string(&pipeline_path) {
        Ok(content) => content,
        Err(err) => {
            return check(
                "recompute",
                CheckStatus::Fail,
                format!("cannot read {}: {}", pipeline_path.display(), err),
            )
        }
    };
    let pipeline: crate::pipeline::Pipeline = match serde_yaml::from_str(&content) {
        Ok(pipeline) => pipeline,
        Err(err) => {
            return check(
                "recompute",
                CheckStatus::Fail,
                format!("cannot parse {}: {}", pipeline_path.display(), err),
            )
        }
    };

    let mut problems: Vec<String> = Vec::new();

    // The pipeline as a whole, not only the steps the receipt happens to
    // mention. Without this, adding a step or changing an env var left the
    // old receipt accepted: every step it named still matched, and the ones
    // it did not name were never looked for.
    match serde_yaml::to_string(&pipeline) {
        Ok(serialized) => {
            let recomputed = blake3::hash(serialized.as_bytes()).to_hex().to_string();
            if recomputed != receipt.pipeline_hash {
                problems.push(format!(
                    "pipeline hash mismatch (receipt {}, workspace {})",
                    receipt.pipeline_hash, recomputed
                ));
            }
        }
        Err(err) => problems.push(format!("cannot re-serialize the workspace pipeline: {err}")),
    }

    // A step present in the workspace but absent from the receipt means the
    // receipt describes a smaller build than the one the pipeline defines.
    let attested: std::collections::BTreeSet<&str> =
        receipt.steps.iter().map(|s| s.name.as_str()).collect();
    for name in pipeline.steps.keys() {
        if !attested.contains(name.as_str()) {
            problems.push(format!(
                "step '{}' is declared in the workspace pipeline but absent from the receipt",
                name
            ));
        }
    }

    for step_result in &receipt.steps {
        let step = match pipeline.steps.get(&step_result.name) {
            Some(step) => step,
            None => {
                problems.push(format!(
                    "step '{}' is not declared in the workspace pipeline",
                    step_result.name
                ));
                continue;
            }
        };
        // Capsule steps: recompute the capsule manifest hash
        // from .attest/capsules/ and compare with the receipt.
        match (&step.capsule, &step_result.capsule_hash) {
            (Some(name), Some(recorded)) => match crate::capsule::load(workspace, name) {
                Ok(manifest) => {
                    let recomputed = manifest.capsule_hash.unwrap_or_default();
                    if recomputed != *recorded {
                        problems.push(format!(
                            "step '{}': capsule hash mismatch (receipt {}, workspace {})",
                            step_result.name, recorded, recomputed
                        ));
                    }
                }
                Err(err) => problems.push(format!(
                    "step '{}': capsule '{}': {}",
                    step_result.name, name, err
                )),
            },
            (Some(name), None) => problems.push(format!(
                "step '{}' declares capsule '{}' but the receipt records no capsule_hash",
                step_result.name, name
            )),
            (None, Some(_)) => problems.push(format!(
                "step '{}' records a capsule_hash but the workspace pipeline declares no capsule",
                step_result.name
            )),
            (None, None) => {}
        }
        match crate::hashing::hash_inputs(workspace, &step_result.name, &step.run, &step.inputs) {
            Ok(recomputed) => {
                if recomputed != step_result.input_hash {
                    problems.push(format!(
                        "step '{}': input hash mismatch (receipt {}, workspace {})",
                        step_result.name, step_result.input_hash, recomputed
                    ));
                }
            }
            Err(err) => problems.push(format!("step '{}': {}", step_result.name, err)),
        }

        // Inputs alone say the build started from the right source. Outputs
        // are what someone actually ships, and checking one without the
        // other let an artifact be replaced while the receipt still passed.
        match crate::hashing::hash_outputs(workspace, &step_result.name, &step.outputs) {
            Ok(recomputed) => {
                if recomputed != step_result.output_hash {
                    problems.push(format!(
                        "step '{}': output hash mismatch (receipt {}, workspace {})",
                        step_result.name, step_result.output_hash, recomputed
                    ));
                }
            }
            Err(err) => problems.push(format!("step '{}': {}", step_result.name, err)),
        }
    }

    if problems.is_empty() {
        check(
            "recompute",
            CheckStatus::Pass,
            "pipeline, step inputs and step outputs match the workspace",
        )
    } else {
        check("recompute", CheckStatus::Fail, problems.join("; "))
    }
}

fn is_lower_hex(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}
