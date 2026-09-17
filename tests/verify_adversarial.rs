//! Adversarial tests for the timestamp arm of receipt verification.
//!
//! `src/verify.rs` decides whether to trust a receipt, and the timestamp
//! check is the part that decides *when* a signature existed. That answer
//! overrides the receipt's own timestamp for the revocation rule, so a
//! verifier that accepts a token too readily hands an attacker back exactly
//! what timestamping was added to take away.
//!
//! Every case here runs offline against the committed DigiCert token. The
//! fixture's imprint is the SHA-256 of `attest timestamp fixture`, so a
//! receipt whose `signature` field holds those bytes in hex is one the real
//! token genuinely covers. That is what makes the trust path reachable
//! without a network or a private key.

use std::path::{Path, PathBuf};

use attest::verify::{verify_receipt_bytes, CheckStatus, VerifyOptions};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/timestamp/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The bytes the fixture token was issued over, as the hex a receipt's
/// `signature` field carries.
fn covered_signature_hex() -> String {
    hex::encode(b"attest timestamp fixture")
}

fn token_b64() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(fixture("digicert-token.der"))
}

/// A trust store holding `issuer_fixture` as the only pinned authority, or
/// no authority at all when given `None`.
fn trust_store(dir: &Path, issuer_fixture: Option<&str>) -> PathBuf {
    let trust = dir.join("trust");
    std::fs::create_dir_all(trust.join("tsa")).unwrap();
    std::fs::write(trust.join("trust.toml"), "version = 1\n").unwrap();
    if let Some(name) = issuer_fixture {
        std::fs::write(trust.join("tsa").join("pinned.crt"), fixture(name)).unwrap();
    }
    trust
}

fn receipt_yaml(signature: Option<&str>, token: Option<&str>) -> String {
    let mut yaml = String::from(
        "schema_version: 3\n\
         pipeline_hash: 0000000000000000000000000000000000000000000000000000000000000000\n\
         steps: []\n\
         timestamp: 2026-01-01T00:00:00Z\n\
         total_duration_secs: 0\n\
         attest_version: 0.1.0\n\
         causal_events: []\n\
         causal_chain_hash: null\n\
         signer_public_key: null\n",
    );
    match signature {
        Some(s) => yaml.push_str(&format!("signature: {s}\n")),
        None => yaml.push_str("signature: null\n"),
    }
    if let Some(t) = token {
        yaml.push_str(&format!("timestamp_token: {t}\n"));
    }
    yaml
}

/// Run the verifier and return the timestamp check's status and detail.
fn timestamp_check(dir: &Path, yaml: &str, issuer: Option<&str>) -> (CheckStatus, String) {
    let opts = VerifyOptions {
        check_signatures: true,
        recompute: false,
        workspace: dir.to_path_buf(),
        trust_store: Some(trust_store(dir, issuer)),
        trust_receipt_timestamp: false,
    };
    let verdict = verify_receipt_bytes(yaml.as_bytes(), "case", &opts).expect("verifier runs");
    let check = verdict
        .checks
        .iter()
        .find(|c| c.name == "timestamp")
        .expect("a timestamp check is always reported");
    (check.status, check.detail.clone())
}

#[test]
fn the_authentic_token_is_accepted_and_reports_the_stated_time() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = receipt_yaml(Some(&covered_signature_hex()), Some(&token_b64()));
    let (status, detail) = timestamp_check(dir.path(), &yaml, Some("digicert-tsa-ca.der"));
    assert_eq!(status, CheckStatus::Pass, "{detail}");
    // Cross-checked against `openssl ts -reply -text` on this fixture.
    assert!(
        detail.contains("2026-09-16T13:37:32"),
        "should report the authority's time, got: {detail}"
    );
}

/// The attack this check exists to stop: lifting a valid token off one
/// receipt and attaching it to another. The token names the signature it
/// covers, so it must not vouch for a different one.
#[test]
fn a_token_lifted_onto_a_different_signature_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut other = covered_signature_hex();
    other.replace_range(0..2, "ff");
    let yaml = receipt_yaml(Some(&other), Some(&token_b64()));
    let (status, detail) = timestamp_check(dir.path(), &yaml, Some("digicert-tsa-ca.der"));
    assert_eq!(status, CheckStatus::Fail, "{detail}");
}

/// A token from an authority nobody pinned proves nothing: anyone can run a
/// timestamp service and stamp whatever they like.
#[test]
fn a_token_from_an_unpinned_authority_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = receipt_yaml(Some(&covered_signature_hex()), Some(&token_b64()));
    let (status, detail) = timestamp_check(dir.path(), &yaml, Some("unrelated-root.der"));
    assert_eq!(status, CheckStatus::Fail, "{detail}");
    assert!(detail.contains("pinned"), "got: {detail}");
}

/// With nothing pinned at all the verifier must refuse rather than shrug:
/// silently skipping would let an unverifiable token read as a verified one.
#[test]
fn a_token_with_no_pinned_authority_at_all_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = receipt_yaml(Some(&covered_signature_hex()), Some(&token_b64()));
    let (status, detail) = timestamp_check(dir.path(), &yaml, None);
    assert_eq!(status, CheckStatus::Fail, "{detail}");
    assert!(
        detail.contains("no pinned timestamp authority"),
        "got: {detail}"
    );
}

#[test]
fn a_token_with_no_signature_to_cover_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = receipt_yaml(None, Some(&token_b64()));
    let (status, detail) = timestamp_check(dir.path(), &yaml, Some("digicert-tsa-ca.der"));
    assert_eq!(status, CheckStatus::Fail, "{detail}");
}

#[test]
fn a_token_that_is_not_base64_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = receipt_yaml(Some(&covered_signature_hex()), Some("\"not base64 !!\""));
    let (status, detail) = timestamp_check(dir.path(), &yaml, Some("digicert-tsa-ca.der"));
    assert_eq!(status, CheckStatus::Fail, "{detail}");
}

#[test]
fn a_receipt_with_no_token_reports_skipped_rather_than_passed() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = receipt_yaml(Some(&covered_signature_hex()), None);
    let (status, _) = timestamp_check(dir.path(), &yaml, Some("digicert-tsa-ca.der"));
    assert_eq!(status, CheckStatus::Skipped);
}

/// No prefix of a real token may verify. Truncation is the cheapest attack
/// there is, and a reader that trusts a length field over the bytes it
/// actually has is the classic way to fall for it.
#[test]
fn no_truncation_of_a_real_token_ever_verifies() {
    use base64::Engine as _;
    let dir = tempfile::tempdir().unwrap();
    let der = fixture("digicert-token.der");
    let trust = trust_store(dir.path(), Some("digicert-tsa-ca.der"));

    // Every 32nd prefix: enough to cross every structural boundary without
    // running the whole suite for a minute.
    for cut in (1..der.len()).step_by(32) {
        let truncated = base64::engine::general_purpose::STANDARD.encode(&der[..cut]);
        let yaml = receipt_yaml(Some(&covered_signature_hex()), Some(&truncated));
        let opts = VerifyOptions {
            check_signatures: true,
            recompute: false,
            workspace: dir.path().to_path_buf(),
            trust_store: Some(trust.clone()),
            trust_receipt_timestamp: false,
        };
        let verdict = verify_receipt_bytes(yaml.as_bytes(), "case", &opts).expect("verifier runs");
        let check = verdict
            .checks
            .iter()
            .find(|c| c.name == "timestamp")
            .expect("timestamp check reported");
        assert_eq!(
            check.status,
            CheckStatus::Fail,
            "a {cut}-byte prefix of the token verified: {}",
            check.detail
        );
    }
}
