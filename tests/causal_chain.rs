//! A run must record what it did into the causal ledger, and the receipt
//! must carry that record.
//!
//! Until this was written, `Storage::record_causal_event` existed and no
//! caller reached it: `causal_events` was always empty, `causal_chain_hash`
//! always null, and every `attest causal` subcommand queried a store that
//! nothing ever wrote to.

use assert_cmd::Command;
use attest::storage::Receipt;
use tempfile::TempDir;

/// Two steps, the second depending on the first, so the recorded parentage
/// is observable rather than trivially empty.
const PIPELINE: &str = r#"version: "0.1"
name: chain
steps:
  one:
    run: "true"
    inputs: ["src/"]
    outputs: []
  two:
    run: "true"
    inputs: ["src/"]
    outputs: []
    needs: ["one"]
"#;

fn run_pipeline() -> (TempDir, Receipt) {
    let temp = TempDir::new().expect("temp dir");
    let workspace = temp.path();
    std::fs::create_dir_all(workspace.join("src")).expect("src");
    std::fs::write(workspace.join("src/a.txt"), "data").expect("input");
    std::fs::write(workspace.join("attest.yaml"), PIPELINE).expect("pipeline");

    Command::cargo_bin("attest")
        .unwrap()
        .current_dir(workspace)
        .arg("init")
        .assert()
        .success();
    Command::cargo_bin("attest")
        .unwrap()
        .current_dir(workspace)
        .arg("run")
        .timeout(std::time::Duration::from_secs(120))
        .assert()
        .success();

    let receipt_path = std::fs::read_dir(workspace.join(".attest/receipts"))
        .expect("receipts dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "yaml"))
        .expect("a receipt was written");
    let text = std::fs::read_to_string(receipt_path).expect("receipt readable");
    let receipt: Receipt = serde_yaml::from_str(&text).expect("receipt parses");
    (temp, receipt)
}

#[test]
fn a_run_records_one_event_per_step_and_a_chain_root() {
    let (_temp, receipt) = run_pipeline();

    assert_eq!(
        receipt.causal_events.len(),
        2,
        "expected one event per executed step, got {:?}",
        receipt.causal_events
    );
    for id in &receipt.causal_events {
        assert_eq!(id.len(), 64, "event id is not a blake3 hex digest: {id}");
    }
    assert!(
        receipt.causal_chain_hash.is_some(),
        "no chain root recorded"
    );
}

/// The chain belongs to the signed bytes. If it did not, a receipt could be
/// re-pointed at a different history without breaking its signature.
#[test]
fn the_chain_is_covered_by_the_signature() {
    let (_temp, receipt) = run_pipeline();

    let original = attest::storage::receipt_signing_bytes(&receipt).expect("canonicalizes");

    let mut altered = receipt.clone();
    altered.causal_chain_hash = Some("0".repeat(64));
    let tampered = attest::storage::receipt_signing_bytes(&altered).expect("canonicalizes");
    assert_ne!(
        original, tampered,
        "changing the chain root left the signed bytes untouched"
    );

    let mut altered = receipt;
    altered.causal_events.clear();
    let tampered = attest::storage::receipt_signing_bytes(&altered).expect("canonicalizes");
    assert_ne!(
        original, tampered,
        "dropping the event ids left the signed bytes untouched"
    );
}
