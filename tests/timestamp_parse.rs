//! Offline tests of the RFC 3161 token parser, against a token a real
//! authority actually issued.
//!
//! The fixture under `tests/fixtures/timestamp/` was obtained from
//! DigiCert's public timestamp service over the SHA-256 of the string
//! `attest timestamp fixture`. Keeping a real token rather than a
//! hand-built one is the point: it is the shape of the thing in the wild,
//! including the parts of CMS we skip over, that the parser has to survive.
//! No network is needed to run this.

use attest::crypto::timestamp::{parse_token, TimestampError, TimestampInfo};

fn token() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/timestamp/digicert-token.der"
    ))
    .expect("token fixture is readable")
}

fn imprint() -> [u8; 32] {
    let hex = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/timestamp/fixture-imprint.txt"
    ))
    .expect("imprint fixture is readable");
    let bytes = hex::decode(hex.trim()).expect("imprint is hex");
    bytes.try_into().expect("imprint is 32 bytes")
}

fn parsed() -> TimestampInfo {
    parse_token(&token(), &imprint()).expect("a real token parses")
}

#[test]
fn a_real_token_yields_the_time_the_authority_stated() {
    let info = parsed();

    // Cross-checked against `openssl ts -reply -text`, which reported
    // "Sep 16 13:37:32 2026 GMT" for this token.
    assert_eq!(
        info.gen_time.format("%Y-%m-%d %H:%M:%S").to_string(),
        "2026-09-16 13:37:32"
    );
}

#[test]
fn the_policy_oid_is_digicerts() {
    // 2.16.840.1.114412.7.1 — DigiCert's timestamping policy. Decoding it
    // exercises the multi-byte arc path, which a short OID would not.
    assert_eq!(parsed().policy, "2.16.840.1.114412.7.1");
}

#[test]
fn the_serial_is_carried_whole() {
    let serial = parsed().serial;
    assert!(!serial.is_empty());
    assert!(serial.chars().all(|c| c.is_ascii_hexdigit()));
    // DigiCert issues serials well beyond 64 bits; narrowing one to a
    // number would silently corrupt it.
    assert!(
        serial.len() > 16,
        "serial looks truncated to 64 bits: {serial}"
    );
}

/// The binding that makes the token mean anything.
#[test]
fn a_token_for_other_data_is_refused() {
    let mut wrong = imprint();
    wrong[0] ^= 0x01;

    let err = parse_token(&token(), &wrong).expect_err("imprint mismatch");
    assert!(
        matches!(err, TimestampError::ImprintMismatch),
        "expected an imprint mismatch, got {err:?}"
    );
}

/// A parser that panics on malformed input is a denial of service in the
/// one code path a verifier cannot avoid running on attacker-supplied data.
#[test]
fn no_truncation_of_a_real_token_panics() {
    let full = token();
    let expected = imprint();
    for cut in 0..full.len() {
        let _ = parse_token(&full[..cut], &expected);
    }
}

#[test]
fn no_single_byte_corruption_panics() {
    let full = token();
    let expected = imprint();
    // Every byte, flipped one bit. Exhaustive over positions rather than
    // sampled: the cost is trivial and the guarantee is total.
    for i in 0..full.len() {
        let mut corrupted = full.clone();
        corrupted[i] ^= 0x80;
        let _ = parse_token(&corrupted, &expected);
    }
}

// ---------------------------------------------------------------------------
// Signature verification.
//
// The pinned issuer is DigiCert's "Trusted G4 TimeStamping RSA4096 SHA256
// 2025 CA1", the certificate that issued the responder which signed the
// fixture. The unrelated root is "DigiCert Trusted Root G4" — a real
// DigiCert certificate, and one level further up the same chain, which
// makes it a sharper negative than a random certificate would be.
// ---------------------------------------------------------------------------

use attest::crypto::timestamp::verify_token;

fn pinned_ca() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/timestamp/digicert-tsa-ca.der"
    ))
    .expect("CA fixture is readable")
}

fn unrelated_root() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/timestamp/unrelated-root.der"
    ))
    .expect("root fixture is readable")
}

#[test]
fn a_real_token_verifies_against_its_pinned_issuer() {
    let verified = verify_token(&token(), &imprint(), &[pinned_ca()])
        .expect("the authority's signature checks out");

    assert_eq!(
        verified
            .info
            .gen_time
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        "2026-09-16 13:37:32"
    );
    assert!(
        verified.signer.contains("Timestamp Responder"),
        "unexpected signer: {}",
        verified.signer
    );
}

#[test]
fn no_pinned_issuer_means_no_trust() {
    let err = verify_token(&token(), &imprint(), &[]).expect_err("nothing is pinned");
    assert!(matches!(err, TimestampError::UntrustedAuthority));
}

/// The negative that matters: a genuine certificate from the same vendor,
/// one level up the very chain this token uses, must still be refused. It
/// did not issue the responder, so it proves nothing about it.
#[test]
fn a_certificate_that_did_not_issue_the_signer_is_refused() {
    let err = verify_token(&token(), &imprint(), &[unrelated_root()]).expect_err("wrong issuer");
    assert!(
        matches!(err, TimestampError::UntrustedAuthority),
        "expected an untrusted authority, got {err:?}"
    );
}

#[test]
fn a_token_for_other_data_fails_before_any_signature_work() {
    let mut wrong = imprint();
    wrong[31] ^= 0xff;
    let err = verify_token(&token(), &wrong, &[pinned_ca()]).expect_err("imprint mismatch");
    assert!(matches!(err, TimestampError::ImprintMismatch));
}

/// Every byte of the token, one bit flipped, against a pinned issuer.
///
/// The invariant is not that every corruption fails — roughly half the
/// token is certificates this verifier never reads. A DigiCert token
/// carries four: the responder, the CA that issued it, the Trusted Root G4
/// and a cross-certificate. Only the responder matters, and the CA we check
/// against is the *pinned* copy, not the embedded one. Bytes that carry no
/// meaning for the assertion may change without changing the assertion, and
/// that is correct.
///
/// What must hold is stronger and narrower: a corrupted token must never
/// make the verifier assert something false. Either it is rejected, or it
/// yields exactly the same time and the same binding as the original.
#[test]
fn no_corruption_can_change_what_the_verifier_asserts() {
    let full = token();
    let expected = imprint();
    let pinned = [pinned_ca()];
    let truth = verify_token(&full, &expected, &pinned).expect("the pristine token verifies");

    let mut altered_but_accepted = 0usize;
    for i in 0..full.len() {
        let mut corrupted = full.clone();
        corrupted[i] ^= 0x80;
        if let Ok(verdict) = verify_token(&corrupted, &expected, &pinned) {
            altered_but_accepted += 1;
            assert_eq!(
                verdict.info, truth.info,
                "a token corrupted at byte {i} verified with a different assertion"
            );
        }
    }

    // Recorded rather than asserted exactly: the figure moves with the
    // authority's chain. A sudden collapse towards zero would mean the
    // verifier started rejecting valid tokens; a jump towards the full
    // length would mean it stopped checking.
    assert!(
        (2000..5000).contains(&altered_but_accepted),
        "unexpected share of inert bytes: {altered_but_accepted} of {}",
        full.len()
    );
}
