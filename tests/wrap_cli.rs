//! Integration tests for `attest run --wrap`: manifest hashes,
//! exit-code propagation, unsigned warnings and signing.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn attest_cmd() -> Command {
    Command::cargo_bin("attest").expect("attest binary")
}

fn wrap_args(workspace: &Path) -> Vec<String> {
    vec![
        "run".to_string(),
        "--wrap".to_string(),
        "--workspace".to_string(),
        workspace.to_str().expect("path").to_string(),
    ]
}

fn only_receipt(workspace: &Path) -> attest::storage::Receipt {
    let receipts_dir = workspace.join(".attest").join("receipts");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&receipts_dir)
        .expect("receipts dir")
        .map(|e| e.expect("entry").path())
        .collect();
    assert_eq!(entries.len(), 1, "expected exactly one receipt");
    let path = entries.pop().expect("receipt path");
    serde_yaml::from_str(&std::fs::read_to_string(path).expect("read receipt"))
        .expect("receipt YAML")
}

/// Acceptance criterion 1 (first half): declared input/output hashes in
/// the receipt match the canonical manifest algorithm.
#[test]
fn wrap_records_manifest_hashes() {
    let workspace = tempfile::tempdir().expect("tempdir");
    std::fs::write(workspace.path().join("in.txt"), "wrapped content").expect("write input");

    let mut args = wrap_args(workspace.path());
    args.extend(
        [
            "--name",
            "copy",
            "--input",
            "in.txt",
            "--output",
            "out.txt",
            "--",
            "sh",
            "-c",
            "cat in.txt > out.txt",
        ]
        .map(String::from),
    );
    attest_cmd()
        .args(&args)
        .current_dir(workspace.path())
        .assert()
        .success();

    let receipt = only_receipt(workspace.path());
    assert_eq!(receipt.steps.len(), 1);
    let step = &receipt.steps[0];
    assert_eq!(step.name, "copy");
    assert_eq!(step.exit_code, 0);

    // The argument vector is recorded as JSON, not space-joined: joining
    // lost the boundaries, so `-c "cat in.txt > out.txt"` and three separate
    // words hashed identically while running different commands.
    let run_string = r#"["sh","-c","cat in.txt > out.txt"]"#;
    let expected_input = attest::hashing::hash_inputs(
        workspace.path(),
        "copy",
        run_string,
        &[PathBuf::from("in.txt")],
    )
    .expect("input hash");
    let expected_output =
        attest::hashing::hash_outputs(workspace.path(), "copy", &[PathBuf::from("out.txt")])
            .expect("output hash");
    assert_eq!(step.input_hash, expected_input);
    assert_eq!(step.output_hash, expected_output);
    assert!(receipt.signature.is_none());
}

/// Acceptance criterion 1 (second half): wrapped command exit 3 →
/// `attest` exits 3 and the receipt records `exit_code: 3`.
#[test]
fn wrap_propagates_wrapped_exit_code() {
    let workspace = tempfile::tempdir().expect("tempdir");
    std::fs::write(workspace.path().join("in.txt"), "x").expect("write input");

    let mut args = wrap_args(workspace.path());
    args.extend(
        [
            "--name",
            "flaky",
            "--input",
            "in.txt",
            "--output",
            "out.txt",
            "--",
            "sh",
            "-c",
            "cp in.txt out.txt; exit 3",
        ]
        .map(String::from),
    );
    let output = attest_cmd()
        .args(&args)
        .current_dir(workspace.path())
        .output()
        .expect("run wrap");
    assert_eq!(output.status.code(), Some(3));

    let receipt = only_receipt(workspace.path());
    assert_eq!(receipt.steps[0].exit_code, 3);
}

/// Rule: attestation failure while the command succeeded → exit 1 with a
/// distinct message (missing declared output).
#[test]
fn wrap_missing_output_fails_attestation() {
    let workspace = tempfile::tempdir().expect("tempdir");

    let mut args = wrap_args(workspace.path());
    args.extend(
        [
            "--name",
            "noop",
            "--output",
            "never-created.txt",
            "--",
            "true",
        ]
        .map(String::from),
    );
    let output = attest_cmd()
        .args(&args)
        .current_dir(workspace.path())
        .output()
        .expect("run wrap");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("attestation failed"),
        "unexpected stderr: {stderr}"
    );
    assert!(!workspace.path().join(".attest").join("receipts").exists());
}

/// Rule: a failed command with missing outputs keeps its own exit code
/// (attestation never masks the command's failure).
#[test]
fn wrap_failed_command_keeps_exit_code_over_attestation() {
    let workspace = tempfile::tempdir().expect("tempdir");

    let mut args = wrap_args(workspace.path());
    args.extend(
        [
            "--name",
            "broken",
            "--output",
            "never-created.txt",
            "--",
            "sh",
            "-c",
            "exit 5",
        ]
        .map(String::from),
    );
    let output = attest_cmd()
        .args(&args)
        .current_dir(workspace.path())
        .output()
        .expect("run wrap");
    assert_eq!(output.status.code(), Some(5));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("attestation incomplete"),
        "unexpected stderr: {stderr}"
    );
}

/// Rule: no declared inputs → warning that attestation covers the command
/// string only, receipt still written.
#[test]
fn wrap_without_inputs_warns() {
    let workspace = tempfile::tempdir().expect("tempdir");

    let mut args = wrap_args(workspace.path());
    args.extend(["--name", "hello", "--", "echo", "hi"].map(String::from));
    let output = attest_cmd()
        .args(&args)
        .current_dir(workspace.path())
        .output()
        .expect("run wrap");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no inputs declared; attestation covers command string only"),
        "unexpected stderr: {stderr}"
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hi\n");

    let receipt = only_receipt(workspace.path());
    assert_eq!(receipt.steps[0].stdout, "hi\n");
}

/// `--sign` produces a receipt whose signature verifies against the
/// workspace trust store.
#[test]
fn wrap_sign_produces_verifiable_signature() {
    let workspace = tempfile::tempdir().expect("tempdir");
    std::fs::write(workspace.path().join("in.txt"), "x").expect("write input");
    let store = attest::keys::KeyStore::new(workspace.path());
    store.generate("wrap-test").expect("generate key");

    let mut args = wrap_args(workspace.path());
    args.extend(
        [
            "--name",
            "signed",
            "--sign",
            "--input",
            "in.txt",
            "--output",
            "out.txt",
            "--",
            "sh",
            "-c",
            "cat in.txt > out.txt",
        ]
        .map(String::from),
    );
    attest_cmd()
        .args(&args)
        .current_dir(workspace.path())
        .assert()
        .success();

    let receipt = only_receipt(workspace.path());
    let signature = receipt.signature.clone().expect("signature");
    let public_key = receipt.signer_public_key.clone().expect("public key");
    let signing_bytes = attest::storage::receipt_signing_bytes(&receipt).expect("signing bytes");
    assert!(attest::crypto::sign::verify_with_public_key(
        &public_key,
        signing_bytes.as_bytes(),
        &signature,
    )
    .expect("verification runs"));
}

/// CLI hygiene: --wrap without --name or command exits 2; wrap-only flags
/// without --wrap exit 2.
#[test]
fn wrap_flag_validation() {
    let workspace = tempfile::tempdir().expect("tempdir");

    let mut args = wrap_args(workspace.path());
    args.extend(["--", "true"].map(String::from));
    attest_cmd()
        .args(&args)
        .current_dir(workspace.path())
        .assert()
        .code(2);

    let output = attest_cmd()
        .args(["run", "--name", "x"])
        .current_dir(workspace.path())
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
}
