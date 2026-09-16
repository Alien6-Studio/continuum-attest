//! The attack RFC 3161 timestamping was added to stop.
//!
//! Revocation compares the signing time against `revoked_at`. Without a
//! timestamp token the only available signing time is the one written
//! *inside* the receipt — a field the signer controls and the signer's own
//! signature covers. Whoever steals a key can therefore set it to any
//! moment before the revocation, re-sign, and walk straight past the rule
//! that exists to stop them. The receipt stays internally consistent,
//! because they hold the key that makes it consistent.
//!
//! A timestamp token removes the choice: the time comes from a third party,
//! over the signature, after it existed. This test runs the attack twice on
//! the same receipt, once without the token and once with, and shows the
//! token is what makes the difference.
//!
//! Needs the network: the token has to be a real one, issued over the real
//! signature. A token minted here would only prove this test can mint
//! tokens.

use std::time::Duration;

use attest::crypto::timestamp::{request_token, signature_imprint, DEFAULT_TSA_URL};
use attest::keys::{KeyStore, TrustPolicy};
use attest::storage::{receipt_signing_bytes, Receipt, StepResult};
use attest::verify::{verify_receipt_bytes, VerifyOptions};
use attest::AttestKeypair;
use chrono::{DateTime, TimeZone, Utc};

fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
}

#[test]
#[ignore = "requires network access to a timestamp authority"]
fn a_timestamp_token_defeats_a_backdated_receipt() {
    let workspace = tempfile::tempdir().unwrap();
    let store = KeyStore::new(workspace.path());
    let key_id = store.generate("stolen").expect("key generated");
    let signing_key = store
        .select_signing_key(Some(&key_id))
        .expect("key selectable")
        .expect("key present");
    let keypair = AttestKeypair::from_signing_key(signing_key);

    // The attacker's claim: this was signed in January, long before anyone
    // revoked anything.
    let mut receipt = Receipt {
        schema_version: Some(3),
        pipeline_hash: "0".repeat(64),
        steps: vec![StepResult {
            name: "build".to_string(),
            input_hash: "1".repeat(64),
            output_hash: "2".repeat(64),
            duration_secs: 1,
            exit_code: 0,
            cache_hit: false,
            stdout: String::new(),
            stderr: String::new(),
            capsule_hash: None,
        }],
        timestamp: at(2026, 1, 1),
        total_duration_secs: 0,
        signature: None,
        signer_public_key: None,
        attest_version: env!("CARGO_PKG_VERSION").to_string(),
        causal_events: Vec::new(),
        causal_chain_hash: None,
        reproducibility: None,
        provenance: None,
        timestamp_token: None,
    };

    // They hold the key, so the backdated receipt is perfectly self
    // consistent. That is the whole problem.
    let signing_bytes = receipt_signing_bytes(&receipt).expect("canonical bytes");
    let signature_hex = keypair.sign(signing_bytes.as_bytes());
    receipt.signature = Some(signature_hex.clone());
    receipt.signer_public_key = Some(keypair.public_key_hex());

    // A real authority stamps the real signature, now.
    let imprint = signature_imprint(&signature_hex).expect("imprint");
    let token = request_token(DEFAULT_TSA_URL, &imprint, Duration::from_secs(30))
        .expect("the timestamp authority answered");

    // Pin that authority, and revoke the key at a date that sits between
    // the receipt's claim and the moment the signature demonstrably existed.
    store
        .trust_tsa(
            std::path::Path::new(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/timestamp/digicert-tsa-ca.der"
            )),
            "digicert",
        )
        .expect("authority pinned");

    let trust_dir = store.trust_dir();
    let mut policy = TrustPolicy::load(&trust_dir).expect("policy loads");
    let entry = policy
        .keys
        .iter_mut()
        .find(|k| k.id == key_id)
        .expect("the key is in the trust store");
    entry.status = "revoked".to_string();
    entry.revoked_at = Some(at(2026, 6, 1));
    policy.save(&trust_dir).expect("policy saved");

    let opts = VerifyOptions {
        check_signatures: true,
        recompute: false,
        workspace: workspace.path().to_path_buf(),
        trust_store: Some(trust_dir.clone()),
    };

    // 1. Without the token the attack works: the receipt's own claim of
    //    January is the only signing time available, and January precedes
    //    the June revocation.
    let without = serde_yaml::to_string(&receipt).expect("serialises");
    let verdict = verify_receipt_bytes(without.as_bytes(), "backdated", &opts).expect("verifies");
    assert!(
        verdict.passed(),
        "expected the backdated receipt to pass without a token, got {}: {:#?}",
        verdict.verdict,
        verdict.checks
    );
    assert!(
        verdict
            .warnings
            .iter()
            .any(|w| w.contains("whoever holds the key controls")),
        "the residual risk must be stated, got: {:?}",
        verdict.warnings
    );

    // 2. With the token attached the attack fails. Attaching it does not
    //    disturb the signed bytes, so the signature is still the same one.
    use base64::Engine as _;
    receipt.timestamp_token = Some(base64::engine::general_purpose::STANDARD.encode(&token));
    let with = serde_yaml::to_string(&receipt).expect("serialises");
    let verdict =
        verify_receipt_bytes(with.as_bytes(), "backdated+token", &opts).expect("verifies");

    let signature_check = verdict
        .checks
        .iter()
        .find(|c| c.name == "signature")
        .expect("signature check reported");
    let timestamp_check = verdict
        .checks
        .iter()
        .find(|c| c.name == "timestamp")
        .expect("timestamp check reported");

    assert!(
        timestamp_check.detail.contains("timestamped"),
        "the token should verify, got: {}",
        timestamp_check.detail
    );
    assert!(
        !verdict.passed(),
        "a token proving the signature is younger than the revocation must \
         fail the receipt, got {}: {:#?}",
        verdict.verdict,
        verdict.checks
    );
    assert!(
        signature_check.detail.contains("revocation"),
        "the failure should name the revocation, got: {}",
        signature_check.detail
    );
}
