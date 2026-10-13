//! Issue #59: the YAML parser changed; not one signed byte may have.
//!
//! Receipts written by earlier versions, committed under
//! tests/fixtures/receipts, are parsed by the current library, re-signed
//! in the sense that their canonical signing bytes are recomputed, and
//! held to the signatures they carry. A parser that read a field
//! differently would produce different bytes and a signature that no
//! longer verifies.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

fn fixtures() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/receipts");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("fixtures/receipts exists")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no receipt fixtures to hold the parser to"
    );
    paths
}

/// Every fixture's signature still verifies over the bytes the current
/// parser produces for it, and a round trip through the current writer
/// produces the same bytes again.
#[test]
fn committed_receipts_keep_their_signatures_through_the_parser() {
    use attest::crypto::sign::verify_with_public_key;
    use attest::storage::{receipt_signing_bytes, Receipt};

    for path in fixtures() {
        let text = std::fs::read_to_string(&path).unwrap();
        let receipt: Receipt = serde_yaml::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: does not parse: {e}", path.display()));
        let signature = receipt
            .signature
            .clone()
            .unwrap_or_else(|| panic!("{}: fixture must be signed", path.display()));
        let signer = receipt.signer_public_key.clone().unwrap();
        let bytes = receipt_signing_bytes(&receipt).unwrap();
        assert!(
            verify_with_public_key(&signer, bytes.as_bytes(), &signature).unwrap(),
            "{}: signature no longer verifies over the parsed receipt",
            path.display()
        );

        let rewritten = serde_yaml::to_string(&receipt).unwrap();
        let reparsed: Receipt = serde_yaml::from_str(&rewritten).unwrap();
        assert_eq!(
            receipt_signing_bytes(&reparsed).unwrap(),
            bytes,
            "{}: a round trip through the writer changed the signed bytes",
            path.display()
        );
    }
}

/// The 0.1 release's own receipt, signed by the release key the
/// repository trusts, verifies with the CLI exactly as it did then.
#[test]
fn the_release_receipt_from_0_1_still_verifies_with_the_cli() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let receipt = repo.join("tests/fixtures/receipts/v0.1-attest-ci-release-2026.yaml");
    Command::cargo_bin("attest")
        .unwrap()
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--trust-store",
            repo.join(".attest/trust").to_str().unwrap(),
            "--require",
            "signature",
            "--workspace",
            repo.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicates::str::contains(
            "valid signature by trusted key d5daff5527b274a1e7812a35ab46b4c6871c5c00bc0335091f18ea0f99ecaf81",
        ));
}
