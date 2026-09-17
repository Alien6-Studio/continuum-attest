//! Shared receipt wire types and exact CLI signing bytes.
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Receipt schema version written by this binary. Bump only on a breaking
/// change to the receipt format; verification rejects receipts newer than
/// this with an explicit "upgrade attest" message.
pub const RECEIPT_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Receipt format version. Absent on receipts written before schema
    /// versioning existed — those are version 1. Kept optional and skipped
    /// when `None` so pre-versioning receipts and their signatures stay
    /// byte-identical (same pattern as `capsule_hash`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    pub pipeline_hash: String,
    pub steps: Vec<StepResult>,
    pub timestamp: DateTime<Utc>,
    pub total_duration_secs: u64,
    pub signature: Option<String>,
    pub signer_public_key: Option<String>,
    pub attest_version: String,
    /// Causal events recorded during pipeline execution
    pub causal_events: Vec<String>, // Event IDs
    /// Root hash of causal chain for this execution
    pub causal_chain_hash: Option<String>,
    /// Reproducibility verdict from `attest run --check-reproducibility`.
    /// Absent = not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproducibility: Option<ReproducibilityInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ExecutionProvenance>,
    /// RFC 3161 timestamp token over the signature, base64 DER. Absent when
    /// the run did not request one.
    ///
    /// Deliberately outside the signed bytes: the token is issued *after*
    /// the signature exists, over that signature. Including it would be
    /// circular. Its integrity comes from the timestamp authority's own
    /// signature, not from ours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_token: Option<String>,
}

/// Result of a double-build reproducibility check attached to a receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproducibilityInfo {
    pub verified: bool,
    pub runs: u32,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    pub public_key: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepResult {
    pub name: String,
    pub input_hash: String,
    pub output_hash: String,
    pub duration_secs: u64,
    pub exit_code: i32,
    pub cache_hit: bool,
    pub stdout: String,
    pub stderr: String,
    /// Capsule the step ran in: blake3 of the capsule
    /// manifest's canonical serialization. Absent for non-capsule steps;
    /// skipped when serializing so pre-capsule receipts and signatures
    /// stay byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_hash: Option<String>,
}

/// Canonical byte representation of a receipt for signing/verification.
///
/// This is the exact payload signed by `attest run --sign`: the receipt with
/// `signature`, `signer_public_key` and `timestamp_token` set to null, steps
/// sorted by name, causal events sorted, serialized as JSON in struct field
/// order.
///
/// The three cleared fields are the ones that only exist once signing has
/// happened. Clearing them is what lets a receipt be signed, then
/// timestamped, and still verify: adding the token does not disturb the
/// bytes the signature covers.
pub fn receipt_signing_bytes(receipt: &Receipt) -> Result<String> {
    let mut signing_receipt = receipt.clone();
    signing_receipt.signature = None;
    signing_receipt.signer_public_key = None;
    signing_receipt.timestamp_token = None;
    signing_receipt.steps.sort_by(|a, b| a.name.cmp(&b.name));
    signing_receipt.causal_events.sort();
    serde_json::to_string(&signing_receipt).context("Failed to serialize receipt for signing")
}

/// Signed runner observations. These are not independent evidence of runner integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProvenance {
    pub invocation_id: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub pipeline_name: Option<String>,
    pub source: Option<SourceInfo>,
    pub runner_os: String,
    pub runner_arch: String,
    pub ci: Option<CiInfo>,
    pub steps: Vec<StepProvenance>,
    pub artifacts: Vec<ArtifactInfo>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInfo {
    pub repository: Option<String>,
    pub commit: String,
    pub branch: Option<String>,
    pub tracked_dirty: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiInfo {
    pub provider: String,
    pub run_id: Option<String>,
    pub job_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepProvenance {
    pub name: String,
    pub needs: Vec<String>,
    pub command_hash: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInfo {
    pub step: String,
    pub path: String,
    pub kind: String,
    pub digest: String,
    pub algorithm: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign::{verify_with_public_key, AttestKeypair};

    fn receipt() -> Receipt {
        Receipt {
            schema_version: Some(RECEIPT_SCHEMA_VERSION),
            pipeline_hash: "a".repeat(64),
            steps: vec![StepResult {
                name: "build".to_string(),
                input_hash: "b".repeat(64),
                output_hash: "c".repeat(64),
                duration_secs: 1,
                exit_code: 0,
                cache_hit: false,
                stdout: String::new(),
                stderr: String::new(),
                capsule_hash: None,
            }],
            timestamp: Utc::now(),
            total_duration_secs: 1,
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

    /// The property the whole timestamping design rests on.
    ///
    /// A receipt is signed first, then handed to a timestamp authority,
    /// then stored with the token attached. If the token were inside the
    /// signed bytes that order would be impossible — the signature would
    /// have to cover something that does not exist yet.
    #[test]
    fn attaching_a_token_leaves_the_signature_valid() {
        let keypair = AttestKeypair::generate();
        let mut signed = receipt();
        signed.signer_public_key = Some(keypair.public_key_hex());
        let bytes = receipt_signing_bytes(&signed).expect("canonicalizes");
        signed.signature = Some(keypair.sign(bytes.as_bytes()));

        // The token arrives after the fact, as it does in a real run.
        let mut timestamped = signed.clone();
        timestamped.timestamp_token = Some("MIIBogYJKoZIhvcNAQcCoIIBkz==".to_string());

        let rebuilt = receipt_signing_bytes(&timestamped).expect("canonicalizes");
        assert_eq!(
            rebuilt, bytes,
            "attaching a token changed the bytes the signature covers"
        );
        assert!(verify_with_public_key(
            timestamped.signer_public_key.as_ref().expect("key"),
            rebuilt.as_bytes(),
            timestamped.signature.as_ref().expect("signature"),
        )
        .expect("verification runs"));
    }

    /// Tampering must still be caught: excluding the token from the signed
    /// bytes is a narrow exception, not a hole.
    #[test]
    fn altering_a_recorded_fact_still_breaks_the_signature() {
        let keypair = AttestKeypair::generate();
        let mut signed = receipt();
        signed.signer_public_key = Some(keypair.public_key_hex());
        let bytes = receipt_signing_bytes(&signed).expect("canonicalizes");
        signed.signature = Some(keypair.sign(bytes.as_bytes()));

        signed.steps[0].output_hash = "d".repeat(64);

        let rebuilt = receipt_signing_bytes(&signed).expect("canonicalizes");
        assert!(!verify_with_public_key(
            signed.signer_public_key.as_ref().expect("key"),
            rebuilt.as_bytes(),
            signed.signature.as_ref().expect("signature"),
        )
        .expect("verification runs"));
    }
}
