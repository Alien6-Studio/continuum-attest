//! Issue #5 acceptance criteria: `attest verify` performs full receipt
//! verification (schema, consistency, signature, recompute) via the built
//! binary, with the 0/1/2 exit-code convention.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

fn attest() -> Command {
    Command::cargo_bin("attest").expect("attest binary builds")
}

const TOY_PIPELINE: &str = r#"
version: "1.0"
name: toy
steps:
  copy:
    run: "cat in.txt > out.txt"
    inputs: ["in.txt"]
    outputs: ["out.txt"]
    cache: false
"#;

/// Initialize a workspace and produce one receipt (optionally signed).
/// Returns the receipt path.
fn produce_receipt(dir: &Path, sign: bool) -> PathBuf {
    attest().arg("init").current_dir(dir).assert().success();
    std::fs::write(dir.join("attest.yaml"), TOY_PIPELINE).unwrap();
    std::fs::write(dir.join("in.txt"), "payload").unwrap();

    let mut cmd = attest();
    cmd.arg("run");
    if sign {
        cmd.arg("--sign");
    }
    cmd.current_dir(dir).assert().success();

    let receipts: Vec<PathBuf> = std::fs::read_dir(dir.join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "yaml").unwrap_or(false))
        .collect();
    assert_eq!(receipts.len(), 1, "exactly one receipt expected");
    receipts.into_iter().next().unwrap()
}

fn load_yaml(path: &Path) -> serde_yaml::Value {
    serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn save_yaml(path: &Path, value: &serde_yaml::Value) {
    std::fs::write(path, serde_yaml::to_string(value).unwrap()).unwrap();
}

/// Criterion 1: a freshly signed receipt verifies (exit 0), trusting the
/// local signing key.
#[test]
fn signed_receipt_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), true);

    attest()
        .args(["verify", receipt.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("pass"));
}

/// Criterion 2: flipping one byte of the signature makes verification fail
/// (exit 1) with the signature check reported as the culprit.
#[test]
fn flipped_signature_byte_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), true);

    let mut value = load_yaml(&receipt);
    let sig = value["signature"].as_str().unwrap().to_string();
    let flipped_char = if sig.starts_with('0') { "1" } else { "0" };
    let tampered = format!("{}{}", flipped_char, &sig[1..]);
    value["signature"] = serde_yaml::Value::String(tampered);
    save_yaml(&receipt, &value);

    attest()
        .args(["verify", receipt.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("signature"))
        .stdout(predicates::str::contains("FAIL"));
}

/// Criterion 3: editing a step's output_hash invalidates the signature over
/// the canonical bytes (exit 1).
#[test]
fn edited_output_hash_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), true);

    let mut value = load_yaml(&receipt);
    value["steps"][0]["output_hash"] = serde_yaml::Value::String("a".repeat(64));
    save_yaml(&receipt, &value);

    attest()
        .args(["verify", receipt.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(1);
}

/// Criterion 4: a nonexistent receipt file is an operational error (exit 2)
/// with nothing on stdout.
#[test]
fn nonexistent_file_exits_two() {
    let tmp = tempfile::tempdir().unwrap();

    attest()
        .args(["verify", "does-not-exist.yaml"])
        .current_dir(tmp.path())
        .assert()
        .code(2)
        .stdout(predicates::str::is_empty());
}

/// Criterion 5: --format json emits NDJSON — one JSON object per receipt
/// with the documented fields.
#[test]
fn json_format_parses() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), true);

    let output = attest()
        .args(["verify", "--format", "json", receipt.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "one NDJSON line per receipt");
    let obj: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(obj["verdict"], "pass");
    assert!(obj["receipt"].as_str().unwrap().ends_with(".yaml"));
    assert!(obj["checks"].as_array().unwrap().len() >= 3);
    assert_eq!(obj["signed_by"].as_str().unwrap().len(), 64);
    for check in obj["checks"].as_array().unwrap() {
        assert!(check["name"].is_string());
        assert!(matches!(
            check["status"].as_str().unwrap(),
            "pass" | "fail" | "skipped"
        ));
    }
}

/// Criterion 6: --offline succeeds — every check is local.
#[test]
fn offline_verification_passes() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), true);

    attest()
        .args(["verify", "--offline", receipt.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(0);
}

/// Criterion 7 (adapted — the executor receipt has no status/time fields):
/// an internally incoherent receipt (non-hex pipeline_hash) fails the
/// consistency check even with signature checking disabled.
#[test]
fn consistency_failure_exits_one() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), false);

    let mut value = load_yaml(&receipt);
    value["pipeline_hash"] = serde_yaml::Value::String("not-a-hash".to_string());
    save_yaml(&receipt, &value);

    attest()
        .args([
            "verify",
            "--check-signatures",
            "false",
            receipt.to_str().unwrap(),
        ])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("consistency"))
        .stdout(predicates::str::contains("FAIL"));
}

/// Bonus: --recompute passes when the workspace matches the receipt, and
/// fails after a declared input changes.
#[test]
fn recompute_detects_workspace_drift() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), true);

    attest()
        .args(["verify", "--recompute", receipt.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(0);

    std::fs::write(tmp.path().join("in.txt"), "tampered").unwrap();

    attest()
        .args(["verify", "--recompute", receipt.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("recompute"))
        .stdout(predicates::str::contains("FAIL"));
}

/// Issue #30: a freshly produced receipt declares the current schema version.
#[test]
fn fresh_receipt_carries_schema_version() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), false);

    let value = load_yaml(&receipt);
    assert_eq!(
        value["schema_version"].as_u64(),
        Some(attest::storage::RECEIPT_SCHEMA_VERSION as u64),
        "new receipts must declare the current schema version"
    );
}

/// Issue #30: a receipt from a future attest (schema_version > supported)
/// fails verification with an explicit upgrade message instead of an opaque
/// parse error.
#[test]
fn future_schema_version_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), false);

    let mut value = load_yaml(&receipt);
    value["schema_version"] = serde_yaml::Value::Number(99.into());
    save_yaml(&receipt, &value);

    attest()
        .args(["verify", receipt.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("schema_version 99"))
        .stdout(predicates::str::contains("upgrade attest"));
}

/// Issue #30: receipts written before schema versioning existed (no
/// schema_version field) still verify — absent means version 1.
#[test]
fn pre_versioning_receipt_still_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let receipt = produce_receipt(tmp.path(), false);

    let mut value = load_yaml(&receipt);
    value.as_mapping_mut().unwrap().remove("schema_version");
    save_yaml(&receipt, &value);

    attest()
        .args([
            "verify",
            "--check-signatures",
            "false",
            receipt.to_str().unwrap(),
        ])
        .current_dir(tmp.path())
        .assert()
        .code(0);
}
