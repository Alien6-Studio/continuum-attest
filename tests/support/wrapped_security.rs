//! Forgery tests for wrapped execution; included by security_invariants.rs.
use assert_cmd::Command;
use attest::storage::{ExecutionDescriptor, Receipt};
use std::path::{Path, PathBuf};

fn attest() -> Command {
    Command::cargo_bin("attest").unwrap()
}

fn produced() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("in.txt"), "original\n").unwrap();
    attest()
        .current_dir(dir.path())
        .args([
            "run",
            "--wrap",
            "--name",
            "copy",
            "--input",
            "in.txt",
            "--output",
            "out.txt",
            "--",
            "sh",
            "-c",
            "cp in.txt out.txt",
        ])
        .assert()
        .success();
    let receipt = std::fs::read_dir(dir.path().join(".attest/receipts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    verify(dir.path(), &receipt, 0);
    (dir, receipt)
}

fn verify(workspace: &Path, receipt: &Path, code: i32) -> serde_json::Value {
    // Disable signature checks deliberately: each invariant tests the
    // independent recomputation rather than letting a signature mask it.
    let output = attest()
        .current_dir(workspace)
        .arg("verify")
        .arg(receipt)
        .args([
            "--check-signatures",
            "false",
            "--recompute",
            "--require",
            "recompute",
            "--format",
            "json",
        ])
        .assert()
        .code(code)
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    result["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "recompute")
        .unwrap()
        .clone()
}

fn change_receipt(path: &Path, change: impl FnOnce(&mut Receipt)) {
    let mut receipt: Receipt = serde_yaml::from_slice(&std::fs::read(path).unwrap()).unwrap();
    change(&mut receipt);
    std::fs::write(path, serde_yaml::to_string(&receipt).unwrap()).unwrap();
}

#[test]
fn forging_wrapped_inputs_after_transfer_is_refused() {
    let (dir, receipt) = produced();
    std::fs::write(dir.path().join("in.txt"), "substituted input").unwrap();
    let check = verify(dir.path(), &receipt, 1);
    assert!(check["detail"]
        .as_str()
        .unwrap()
        .contains("wrapped input hash mismatch"));
}

#[test]
fn forging_wrapped_outputs_after_transfer_is_refused() {
    let (dir, receipt) = produced();
    // cp can preserve the source's temporary read-only mode. An attacker
    // owning the delivery can replace the output regardless of those bits.
    std::fs::remove_file(dir.path().join("out.txt")).unwrap();
    std::fs::write(dir.path().join("out.txt"), "substituted output").unwrap();
    let check = verify(dir.path(), &receipt, 1);
    assert!(check["detail"]
        .as_str()
        .unwrap()
        .contains("wrapped output hash mismatch"));
}

#[test]
fn forging_wrapped_command_identity_is_refused() {
    let (dir, path) = produced();
    change_receipt(&path, |receipt| {
        let command = vec![
            "sh".to_string(),
            "-c".into(),
            "printf substituted > out.txt".into(),
        ];
        let canonical = serde_json::to_string(&command).unwrap();
        let provenance = receipt.provenance.as_mut().unwrap();
        provenance.execution = Some(ExecutionDescriptor::Wrapped { command });
        provenance.steps[0].command_hash = blake3::hash(canonical.as_bytes()).to_hex().to_string();
        receipt.steps[0].input_hash = attest::hashing::hash_inputs(
            dir.path(),
            "copy",
            &canonical,
            &[PathBuf::from("in.txt")],
        )
        .unwrap();
        // The new command and input manifest agree with one another, but
        // not with the original execution identity the receipt committed to.
    });
    let check = verify(dir.path(), &path, 1);
    assert!(check["detail"]
        .as_str()
        .unwrap()
        .contains("does not match pipeline hash"));
}

#[test]
fn forging_wrapped_command_hash_is_refused() {
    let (dir, receipt) = produced();
    change_receipt(&receipt, |receipt| {
        receipt.provenance.as_mut().unwrap().steps[0].command_hash = "0".repeat(64);
    });
    let check = verify(dir.path(), &receipt, 1);
    assert!(check["detail"]
        .as_str()
        .unwrap()
        .contains("does not match command hash"));
}

#[test]
fn forging_wrapped_declarations_for_another_step_is_refused() {
    let (dir, receipt) = produced();
    change_receipt(&receipt, |receipt| {
        receipt.provenance.as_mut().unwrap().steps[0].name = "another-build".into();
    });
    let check = verify(dir.path(), &receipt, 1);
    assert!(check["detail"]
        .as_str()
        .unwrap()
        .contains("do not describe the recorded step"));
}

#[test]
fn forging_a_capsule_claim_for_wrapped_execution_is_refused() {
    let (dir, receipt) = produced();
    change_receipt(&receipt, |receipt| {
        receipt.steps[0].capsule_hash = Some("a".repeat(64))
    });
    let check = verify(dir.path(), &receipt, 1);
    assert!(check["detail"]
        .as_str()
        .unwrap()
        .contains("cannot claim a capsule"));
}

#[test]
fn forging_wrapped_inputs_during_execution_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("input"), "original").unwrap();
    attest()
        .current_dir(dir.path())
        .args([
            "run",
            "--wrap",
            "--name",
            "rewrite",
            "--input",
            "input",
            "--output",
            "output",
            "--",
            "sh",
            "-c",
            "chmod u+w input; printf forged > input; cp input output",
        ])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "modified its own declared inputs",
        ));
    assert!(!dir.path().join(".attest/receipts").exists());
}

#[cfg(unix)]
#[test]
fn forging_a_wrapped_input_through_a_plain_transient_write_is_refused() {
    // Root can ignore permission bits; the receipt reports that limit.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("in.txt"), "original\n").unwrap();
    attest().current_dir(dir.path())
        .args(["run", "--wrap", "--name", "try-write", "--input", "in.txt", "--output", "out.txt",
            "--", "sh", "-c", "if printf 'forged\\n' > in.txt; then cp in.txt out.txt; printf 'original\\n' > in.txt; else cp in.txt out.txt; fi"])
        .assert().success();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out.txt")).unwrap(),
        "original\n"
    );
}
