//! in-toto Statement v1 / SLSA Provenance v1 export and import.
//!
//! `attest export --format in-toto` maps a persisted receipt
//! ([`crate::storage::Receipt`]) to an in-toto Statement v1 carrying the
//! SLSA Provenance v1 predicate, wrapped in a DSSE envelope
//! (`application/vnd.dsse.envelope.v1+json`). `attest import --format
//! in-toto` verifies such an envelope against the local trust store and
//! reports in the same format as `attest verify`.
//!
//! Serialization is deterministic: every struct below declares its fields
//! in byte-lexicographic order of their JSON names and is emitted as
//! compact JSON, so the exported envelope is byte-for-byte reproducible
//! for a given receipt and signing key (Ed25519 signatures are
//! deterministic).
//!
//! Deviations from the issue-#13 mapping table (which was written against
//! the legacy `src/storage/receipt.rs` schema) are documented inline: the
//! persisted receipt has no `id` (invocationId is derived from the
//! canonical receipt content hash) and a single completion `timestamp`
//! (startedOn is derived by subtracting `total_duration_secs`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::storage::{receipt_signing_bytes, Receipt};
use crate::verify::{Check, CheckStatus, ReceiptVerdict};

pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
pub const BUILD_TYPE: &str = "https://alien6.com/attest/pipeline/v1";

// ---------------------------------------------------------------------------
// Wire format. Field declaration order == byte-lexicographic order of the
// serialized JSON names, which makes derived serialization canonical
// without relying on serde_json map-ordering features.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub predicate: Predicate,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub subject: Vec<ResourceDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    pub digest: Digest,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Predicate {
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildDefinition {
    #[serde(rename = "buildType")]
    pub build_type: String,
    #[serde(rename = "externalParameters")]
    pub external_parameters: ExternalParameters,
    #[serde(rename = "resolvedDependencies")]
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalParameters {
    #[serde(rename = "pipelineHash")]
    pub pipeline_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDetails {
    pub builder: Builder,
    pub metadata: RunMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Builder {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    #[serde(rename = "finishedOn")]
    pub finished_on: String,
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    #[serde(rename = "startedOn")]
    pub started_on: String,
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Export an unsigned receipt (or a signed one with no local private
    /// key) as a DSSE envelope with an empty `signatures` array.
    pub allow_unsigned: bool,
    /// Signing key id for the DSSE envelope (see `attest keys list`).
    pub key: Option<String>,
    /// Workspace root holding `.attest/keys`.
    pub workspace: PathBuf,
}

/// Outcome of an export attempt. Preconditions that must fail the command
/// with exit code 1 are explicit variants; operational problems are `Err`.
#[derive(Debug)]
pub enum ExportOutcome {
    Written {
        json: String,
        warnings: Vec<String>,
    },
    /// The receipt is unsigned and `--allow-unsigned` was not given.
    UnsignedReceipt,
    /// The receipt carries a signature that does not verify; refusing to
    /// launder a tampered receipt into a standard format.
    InvalidReceiptSignature(String),
    /// No local private key can sign the DSSE envelope and
    /// `--allow-unsigned` was not given.
    NoSigningKey(String),
}

/// Map a persisted receipt to the in-toto/SLSA statement.
pub fn statement_from_receipt(receipt: &Receipt) -> Result<Statement> {
    let mut steps: Vec<&crate::storage::StepResult> = receipt.steps.iter().collect();
    steps.sort_by(|a, b| a.name.cmp(&b.name));

    let subject = steps
        .iter()
        .map(|step| ResourceDescriptor {
            digest: Digest {
                blake3: step.output_hash.clone(),
            },
            name: step.name.clone(),
        })
        .collect();
    let resolved_dependencies = steps
        .iter()
        .map(|step| ResourceDescriptor {
            digest: Digest {
                blake3: step.input_hash.clone(),
            },
            name: step.name.clone(),
        })
        .collect();

    // The persisted receipt has no `id`; the invocation id is the blake3
    // hash of the canonical signing bytes, i.e. content-derived and stable.
    let invocation_id = blake3::hash(receipt_signing_bytes(receipt)?.as_bytes())
        .to_hex()
        .to_string();

    // `timestamp` records completion; startedOn is derived.
    let finished = receipt.timestamp;
    let started = finished
        - chrono::Duration::try_seconds(receipt.total_duration_secs as i64)
            .context("total_duration_secs out of range")?;

    Ok(Statement {
        type_: STATEMENT_TYPE.to_string(),
        predicate: Predicate {
            build_definition: BuildDefinition {
                build_type: BUILD_TYPE.to_string(),
                external_parameters: ExternalParameters {
                    pipeline_hash: receipt.pipeline_hash.clone(),
                },
                resolved_dependencies,
            },
            run_details: RunDetails {
                builder: Builder {
                    id: format!("https://alien6.com/attest@v{}", receipt.attest_version),
                },
                metadata: RunMetadata {
                    finished_on: rfc3339(finished),
                    invocation_id,
                    started_on: rfc3339(started),
                },
            },
        },
        predicate_type: PREDICATE_TYPE.to_string(),
        subject,
    })
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// DSSE Pre-Authentication Encoding (v1).
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Export one receipt file as a signed DSSE envelope.
pub fn export_receipt_file(receipt_path: &Path, options: &ExportOptions) -> Result<ExportOutcome> {
    let content = std::fs::read_to_string(receipt_path)
        .with_context(|| format!("cannot read receipt file: {}", receipt_path.display()))?;
    let receipt: Receipt = serde_yaml::from_str(&content)
        .with_context(|| format!("invalid receipt: {}", receipt_path.display()))?;

    // Never export a receipt whose own signature is broken.
    let receipt_signed = receipt.signature.is_some() && receipt.signer_public_key.is_some();
    if let (Some(signature), Some(public_key)) = (&receipt.signature, &receipt.signer_public_key) {
        let signing_bytes = receipt_signing_bytes(&receipt)?;
        match crate::crypto::sign::verify_with_public_key(
            public_key,
            signing_bytes.as_bytes(),
            signature,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return Ok(ExportOutcome::InvalidReceiptSignature(
                    "receipt signature does not verify against signer_public_key".to_string(),
                ))
            }
            Err(err) => {
                return Ok(ExportOutcome::InvalidReceiptSignature(format!(
                    "malformed receipt signature material: {}",
                    err
                )))
            }
        }
    } else if !options.allow_unsigned {
        return Ok(ExportOutcome::UnsignedReceipt);
    }

    let mut warnings: Vec<String> = Vec::new();
    let statement = statement_from_receipt(&receipt)?;
    if statement.subject.is_empty() {
        warnings.push("receipt declares no step outputs; exported subject is empty".to_string());
    }

    let payload = serde_json::to_string(&statement).context("cannot serialize statement")?;

    // An unsigned receipt exports as an unsigned envelope: an envelope
    // signature would claim an authenticity the receipt never had.
    let signing_key = if receipt_signed {
        // Pick the envelope signing key: an explicit --key, else the key
        // that signed the receipt (if its private half is local), else the
        // single local signing key.
        let store = crate::keys::KeyStore::new(&options.workspace);
        let requested = match (&options.key, &receipt.signer_public_key) {
            (Some(id), _) => Some(id.clone()),
            (None, Some(public_key)) => {
                let id = crate::keys::key_id_from_hex(public_key)?;
                store
                    .keys_dir()
                    .join(format!("{}.key", id))
                    .is_file()
                    .then_some(id)
            }
            (None, None) => None,
        };
        store.select_signing_key(requested.as_deref())?
    } else {
        warnings.push("receipt is unsigned; DSSE envelope carries no signatures".to_string());
        None
    };

    let signatures = match signing_key {
        Some(signing_key) => {
            let verifying_key = signing_key.verifying_key();
            let keyid = crate::keys::key_id(&verifying_key);
            if let Some(receipt_key) = &receipt.signer_public_key {
                if hex::encode(verifying_key.to_bytes()) != *receipt_key {
                    warnings.push(format!(
                        "DSSE envelope signed by local key {} but the receipt was signed by key {}",
                        keyid,
                        crate::keys::key_id_from_hex(receipt_key)
                            .unwrap_or_else(|_| receipt_key.clone())
                    ));
                }
            }
            use ed25519_dalek::Signer;
            let signature = signing_key.sign(&pae(DSSE_PAYLOAD_TYPE, payload.as_bytes()));
            vec![EnvelopeSignature {
                keyid,
                sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            }]
        }
        None if !receipt_signed || options.allow_unsigned => {
            if receipt_signed {
                warnings
                    .push("no local signing key; DSSE envelope carries no signatures".to_string());
            }
            Vec::new()
        }
        None => {
            return Ok(ExportOutcome::NoSigningKey(
                "no local private key to sign the DSSE envelope (generate one with \
                 'attest keys generate' or pass --allow-unsigned)"
                    .to_string(),
            ))
        }
    };

    let envelope = Envelope {
        payload: base64::engine::general_purpose::STANDARD.encode(payload.as_bytes()),
        payload_type: DSSE_PAYLOAD_TYPE.to_string(),
        signatures,
    };
    let mut json = serde_json::to_string(&envelope).context("cannot serialize envelope")?;
    json.push('\n');
    Ok(ExportOutcome::Written { json, warnings })
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// Workspace root; the trust store defaults to `<workspace>/.attest/trust`.
    pub workspace: PathBuf,
    pub trust_store: Option<PathBuf>,
}

fn check(name: &str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_string(),
        status,
        detail: detail.into(),
    }
}

/// Verify a DSSE-wrapped in-toto statement file and report in the same
/// shape as `attest verify`. `Err` is reserved for operational problems
/// (unreadable file, content that is not JSON at all) and maps to exit
/// code 2; every verification failure is a failed check (exit code 1).
pub fn import_statement_file(path: &Path, options: &ImportOptions) -> Result<ReceiptVerdict> {
    let display_path = path.display().to_string();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read statement file: {}", display_path))?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("unreadable JSON in {}", display_path))?;

    let mut checks: Vec<Check> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut signed_by: Option<String> = None;

    // 1. schema — envelope shape, payload decoding, statement shape.
    let parsed = parse_envelope(&value);
    match &parsed {
        Ok(_) => checks.push(check(
            "schema",
            CheckStatus::Pass,
            "DSSE envelope and in-toto statement match schema",
        )),
        Err(detail) => checks.push(check("schema", CheckStatus::Fail, detail.clone())),
    }

    if let Ok((envelope, payload, statement)) = parsed {
        // 2. consistency — mapped fields are well-formed.
        checks.push(consistency_check(&statement));

        // 3. signature — DSSE signature against the #6 trust store.
        let (sig_check, key) =
            signature_check(&envelope, &payload, &statement, options, &mut warnings);
        checks.push(sig_check);
        signed_by = key;
    } else {
        for name in ["consistency", "signature"] {
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

/// Parse the envelope and its payload; any shape problem is a schema-check
/// failure message, not an operational error.
fn parse_envelope(value: &serde_json::Value) -> Result<(Envelope, Vec<u8>, Statement), String> {
    let envelope: Envelope = serde_json::from_value(value.clone())
        .map_err(|err| format!("not a DSSE envelope: {}", err))?;
    if envelope.payload_type != DSSE_PAYLOAD_TYPE {
        return Err(format!(
            "unsupported payloadType '{}' (expected {})",
            envelope.payload_type, DSSE_PAYLOAD_TYPE
        ));
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .map_err(|err| format!("payload is not valid base64: {}", err))?;
    let statement: Statement = serde_json::from_slice(&payload)
        .map_err(|err| format!("payload is not an in-toto statement: {}", err))?;
    if statement.type_ != STATEMENT_TYPE {
        return Err(format!(
            "unsupported statement _type '{}' (expected {})",
            statement.type_, STATEMENT_TYPE
        ));
    }
    if statement.predicate_type != PREDICATE_TYPE {
        return Err(format!(
            "unsupported predicateType '{}' (expected {})",
            statement.predicate_type, PREDICATE_TYPE
        ));
    }
    Ok((envelope, payload, statement))
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn consistency_check(statement: &Statement) -> Check {
    let mut problems: Vec<String> = Vec::new();
    let predicate = &statement.predicate;

    if predicate.build_definition.build_type != BUILD_TYPE {
        problems.push(format!(
            "buildType '{}' is not the ATTEST pipeline buildType",
            predicate.build_definition.build_type
        ));
    }
    if !is_lower_hex64(&predicate.build_definition.external_parameters.pipeline_hash) {
        problems.push("pipelineHash is not a 64-char lowercase hex digest".to_string());
    }
    for descriptor in statement
        .subject
        .iter()
        .chain(&predicate.build_definition.resolved_dependencies)
    {
        if !is_lower_hex64(&descriptor.digest.blake3) {
            problems.push(format!(
                "'{}': blake3 digest is not a 64-char lowercase hex digest",
                descriptor.name
            ));
        }
    }
    if !is_lower_hex64(&predicate.run_details.metadata.invocation_id) {
        problems.push("invocationId is not a 64-char lowercase hex digest".to_string());
    }
    for (name, stamp) in [
        ("startedOn", &predicate.run_details.metadata.started_on),
        ("finishedOn", &predicate.run_details.metadata.finished_on),
    ] {
        if chrono::DateTime::parse_from_rfc3339(stamp).is_err() {
            problems.push(format!("{} is not an RFC 3339 timestamp", name));
        }
    }
    if !predicate
        .run_details
        .builder
        .id
        .starts_with("https://alien6.com/attest@v")
    {
        problems.push(format!(
            "builder.id '{}' is not an ATTEST builder",
            predicate.run_details.builder.id
        ));
    }
    if statement.subject.is_empty() {
        problems.push("statement has an empty subject".to_string());
    }

    if problems.is_empty() {
        check("consistency", CheckStatus::Pass, "statement is coherent")
    } else {
        check("consistency", CheckStatus::Fail, problems.join("; "))
    }
}

/// Verify `signatures[0]` over the DSSE PAE against the trust store
/// (issue-#6 semantics: unknown keys fail; revoked keys fail for
/// statements finished after `revoked_at` and warn otherwise).
fn signature_check(
    envelope: &Envelope,
    payload: &[u8],
    statement: &Statement,
    options: &ImportOptions,
    warnings: &mut Vec<String>,
) -> (Check, Option<String>) {
    let signature = match envelope.signatures.first() {
        Some(signature) => signature,
        None => {
            return (
                check("signature", CheckStatus::Fail, "envelope is unsigned"),
                None,
            )
        }
    };

    let trust_dir = options
        .trust_store
        .clone()
        .unwrap_or_else(|| options.workspace.join(".attest").join("trust"));
    let trusted = match crate::keys::trust_dir_public_keys(&trust_dir) {
        Ok(map) => map,
        Err(err) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("cannot load trust store: {}", err),
                ),
                None,
            )
        }
    };
    let public_key_hex = match trusted.get(&signature.keyid) {
        Some(key) => key.clone(),
        None => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("keyid {} is not in the trust store", signature.keyid),
                ),
                None,
            )
        }
    };

    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&signature.sig) {
        Ok(bytes) => bytes,
        Err(err) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("signature is not valid base64: {}", err),
                ),
                None,
            )
        }
    };
    let message = pae(&envelope.payload_type, payload);
    match crate::crypto::sign::verify_with_public_key(
        &public_key_hex,
        &message,
        &hex::encode(&signature_bytes),
    ) {
        Ok(true) => {}
        Ok(false) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    "DSSE signature does not verify against the trusted key",
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

    // Revocation policy: same semantics as `attest verify`, keyed on the
    // statement's completion time.
    let policy = match crate::keys::TrustPolicy::load(&trust_dir) {
        Ok(policy) => policy,
        Err(err) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("cannot load trust policy: {}", err),
                ),
                None,
            )
        }
    };
    if let Some(entry) = policy.entry(&signature.keyid) {
        if entry.status == "revoked" {
            let revoked_at = entry
                .revoked_at
                .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
            let finished = chrono::DateTime::parse_from_rfc3339(
                &statement.predicate.run_details.metadata.finished_on,
            )
            .map(|t| t.with_timezone(&chrono::Utc))
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC);
            if finished > revoked_at {
                return (
                    check(
                        "signature",
                        CheckStatus::Fail,
                        format!(
                            "signed by key {} after its revocation at {}",
                            signature.keyid, revoked_at
                        ),
                    ),
                    None,
                );
            }
            warnings.push(format!(
                "signed by key revoked later ({} revoked at {})",
                signature.keyid, revoked_at
            ));
        }
    }

    (
        check(
            "signature",
            CheckStatus::Pass,
            format!("valid DSSE signature by trusted key {}", signature.keyid),
        ),
        Some(public_key_hex),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StepResult;

    fn sample_receipt() -> Receipt {
        Receipt {
            schema_version: Some(crate::storage::RECEIPT_SCHEMA_VERSION),
            pipeline_hash: "a".repeat(64),
            steps: vec![
                StepResult {
                    name: "build".to_string(),
                    input_hash: "b".repeat(64),
                    output_hash: "c".repeat(64),
                    duration_secs: 5,
                    exit_code: 0,
                    cache_hit: false,
                    stdout: "built".to_string(),
                    stderr: String::new(),
                    capsule_hash: None,
                },
                StepResult {
                    name: "audit".to_string(),
                    input_hash: "d".repeat(64),
                    output_hash: "e".repeat(64),
                    duration_secs: 2,
                    exit_code: 0,
                    cache_hit: false,
                    stdout: String::new(),
                    stderr: String::new(),
                    capsule_hash: None,
                },
            ],
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-08-27T10:00:30Z")
                .expect("valid timestamp")
                .with_timezone(&chrono::Utc),
            total_duration_secs: 30,
            signature: None,
            signer_public_key: None,
            attest_version: "0.1.0".to_string(),
            causal_events: vec![],
            causal_chain_hash: None,
            reproducibility: None,
            provenance: None,
            timestamp_token: None,
        }
    }

    #[test]
    fn statement_mapping_is_deterministic_and_sorted() {
        let receipt = sample_receipt();
        let statement = statement_from_receipt(&receipt).expect("statement");

        // Steps sorted by name: audit before build.
        assert_eq!(statement.subject[0].name, "audit");
        assert_eq!(statement.subject[1].name, "build");
        assert_eq!(statement.subject[1].digest.blake3, "c".repeat(64));
        assert_eq!(
            statement.predicate.build_definition.resolved_dependencies[0]
                .digest
                .blake3,
            "d".repeat(64)
        );
        assert_eq!(
            statement.predicate.run_details.metadata.started_on,
            "2026-08-27T10:00:00Z"
        );
        assert_eq!(
            statement.predicate.run_details.metadata.finished_on,
            "2026-08-27T10:00:30Z"
        );
        assert_eq!(
            statement.predicate.run_details.builder.id,
            "https://alien6.com/attest@v0.1.0"
        );

        let first = serde_json::to_string(&statement).expect("json");
        let second = serde_json::to_string(&statement_from_receipt(&receipt).expect("statement"))
            .expect("json");
        assert_eq!(first, second);
        // Canonical key order in the serialized payload.
        assert!(first.starts_with("{\"_type\":\"https://in-toto.io/Statement/v1\",\"predicate\":"));
    }

    #[test]
    fn invocation_id_ignores_signature_fields() {
        let unsigned = sample_receipt();
        let mut signed = sample_receipt();
        signed.signature = Some("00".repeat(64));
        signed.signer_public_key = Some("11".repeat(32));
        let a = statement_from_receipt(&unsigned).expect("statement");
        let b = statement_from_receipt(&signed).expect("statement");
        assert_eq!(
            a.predicate.run_details.metadata.invocation_id,
            b.predicate.run_details.metadata.invocation_id
        );
    }

    #[test]
    fn pae_matches_dsse_spec() {
        assert_eq!(
            pae("application/vnd.in-toto+json", b"hi"),
            b"DSSEv1 28 application/vnd.in-toto+json 2 hi".to_vec()
        );
    }
}
