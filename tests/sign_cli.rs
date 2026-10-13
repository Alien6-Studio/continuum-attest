//! Issue #40: producing evidence and signing it are different trust
//! operations. `attest sign` signs a receipt in a process that ran no
//! project command, and `attest run --sign` does not hold the key while
//! steps run.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

fn attest() -> Command {
    Command::cargo_bin("attest").expect("attest binary builds")
}

const TOY: &str = r#"
version: "1.0"
name: toy
steps:
  copy:
    run: "cat in.txt > out.txt"
    inputs: ["in.txt"]
    outputs: ["out.txt"]
    cache: false
"#;

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success();
    std::fs::write(dir.path().join("attest.yaml"), TOY).unwrap();
    std::fs::write(dir.path().join("in.txt"), "payload").unwrap();
    dir
}

fn generate(dir: &Path, name: &str) -> String {
    let out = attest()
        .args(["keys", "generate", "--name", name])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn receipt_in(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir.join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "yaml"))
        .expect("a receipt")
}

/// An unsigned receipt from one process is signed by another, verifies,
/// and is not signed twice.
#[test]
fn sign_signs_an_unsigned_receipt_once() {
    let dir = workspace();
    let key = generate(dir.path(), "release");
    attest()
        .arg("run")
        .current_dir(dir.path())
        .assert()
        .success();
    let receipt = receipt_in(dir.path());
    assert!(!std::fs::read_to_string(&receipt)
        .unwrap()
        .contains("signer_public_key: \""));

    attest()
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--require",
            "signature",
        ])
        .current_dir(dir.path())
        .assert()
        .code(1);

    attest()
        .args(["sign", receipt.to_str().unwrap(), "--key", &key])
        .current_dir(dir.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains(
            receipt.file_name().unwrap().to_str().unwrap(),
        ));
    attest()
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--require",
            "signature",
        ])
        .current_dir(dir.path())
        .assert()
        .code(0);

    attest()
        .args(["sign", receipt.to_str().unwrap(), "--key", &key])
        .current_dir(dir.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("already signed"));

    // --output leaves the original alone.
    attest()
        .arg("run")
        .current_dir(dir.path())
        .assert()
        .success();
    let fresh = std::fs::read_dir(dir.path().join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p != &receipt && p.extension().is_some_and(|e| e == "yaml"))
        .next()
        .unwrap();
    let signed = dir.path().join("signed.yaml");
    attest()
        .args([
            "sign",
            fresh.to_str().unwrap(),
            "--key",
            &key,
            "--output",
            signed.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .assert()
        .code(0);
    assert!(!std::fs::read_to_string(&fresh)
        .unwrap()
        .contains("signer_public_key: \""));
    attest()
        .args(["verify", signed.to_str().unwrap(), "--require", "signature"])
        .current_dir(dir.path())
        .assert()
        .code(0);
}

/// The key can live outside the workspace, where no build step can read
/// it, and both `run --sign` and `sign` find it there.
#[test]
fn keys_outside_the_workspace_are_used_when_pointed_at() {
    let dir = workspace();
    let key = generate(dir.path(), "release");
    let vault = tempfile::tempdir().unwrap();
    let private = format!("{key}.key");
    std::fs::rename(
        dir.path().join(".attest/keys").join(&private),
        vault.path().join(&private),
    )
    .unwrap();

    // Without the pointer the key is gone from the workspace.
    attest()
        .args(["run", "--sign", "--key", &key])
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("no private key"));

    attest()
        .args(["run", "--sign", "--key", &key])
        .env("ATTEST_KEYS_DIR", vault.path())
        .current_dir(dir.path())
        .assert()
        .success();
    let receipt = receipt_in(dir.path());
    attest()
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--require",
            "signature",
        ])
        .current_dir(dir.path())
        .assert()
        .code(0);
}

/// Usage errors are refused before anything is read.
#[test]
fn sign_refuses_a_tsa_without_a_timestamp() {
    let dir = workspace();
    attest()
        .args(["sign", "nothing.yaml", "--tsa", "https://tsa.example"])
        .current_dir(dir.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--tsa requires --timestamp"));
}
