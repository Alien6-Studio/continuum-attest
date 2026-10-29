//! CLI boundary tests. The executable shim checks invocation and secret handling;
//! real cryptographic verification is covered by identity::tests::real_sigstore_verification.
#![cfg(unix)]

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn fixture(script: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("cosign");
    std::fs::write(&program, script).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        dir.path().join("receipt.yaml"),
        include_bytes!("fixtures/interop/receipt.yaml"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("cosign.bundle"),
        include_bytes!("fixtures/identity/github.sigstore.json"),
    )
    .unwrap();
    dir
}

fn command(dir: &Path) -> assert_cmd::Command {
    let mut cmd = cargo_bin_cmd!("attest");
    cmd.current_dir(dir)
        .env(
            "PATH",
            std::env::join_paths([dir, Path::new("/usr/bin"), Path::new("/bin")]).unwrap(),
        )
        .env_remove("SIGSTORE_ID_TOKEN");
    cmd
}

const SIGNER: &str = r#"#!/bin/sh
if [ "$1" = version ]; then echo 'GitVersion: v3.1.4'; exit 0; fi
printf '%s\n' "$@" > "$0.args"
printf '%s' "${SIGSTORE_ID_TOKEN-}" > "$0.token"
previous=''
for arg do
  if [ "$previous" = '--bundle' ]; then bundle="$arg"; fi
  previous="$arg"
done
cp "$previous" "$0.signed"
cp "$0.bundle" "$bundle"
"#;

#[test]
fn signing_binds_exact_receipt_bytes_and_passes_token_outside_argv() {
    let dir = fixture(SIGNER);
    command(dir.path())
        .env("TEST_JOB_TOKEN", "test-only-token")
        .args([
            "identity",
            "sign",
            "receipt.yaml",
            "--bundle",
            "proof.json",
            "--identity-token-env",
            "TEST_JOB_TOKEN",
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read(dir.path().join("receipt.yaml")).unwrap(),
        std::fs::read(dir.path().join("cosign.signed")).unwrap()
    );
    let args = std::fs::read_to_string(dir.path().join("cosign.args")).unwrap();
    assert!(args.contains("sign-blob\n"));
    assert!(args.contains("--tlog-upload=true\n"));
    assert!(!args.contains("test-only-token"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("cosign.token")).unwrap(),
        "test-only-token"
    );
    assert_eq!(
        std::fs::read(dir.path().join("proof.json")).unwrap(),
        std::fs::read(dir.path().join("cosign.bundle")).unwrap()
    );
}

#[test]
fn signing_failure_never_exposes_token_or_leaves_a_bundle() {
    let dir = fixture(
        r#"#!/bin/sh
if [ "$1" = version ]; then echo 'GitVersion: v3.1.4'; exit 0; fi
echo "$SIGSTORE_ID_TOKEN" >&2
exit 42
"#,
    );
    command(dir.path())
        .env("TEST_JOB_TOKEN", "secret-from-provider")
        .args([
            "identity",
            "sign",
            "receipt.yaml",
            "--bundle",
            "proof.json",
            "--identity-token-env",
            "TEST_JOB_TOKEN",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("workflow signing failed"))
        .stderr(predicate::str::contains("secret-from-provider").not());
    assert!(!dir.path().join("proof.json").exists());
}

#[test]
fn signing_refuses_old_cosign_and_preserves_existing_evidence() {
    let dir = fixture("#!/bin/sh\necho 'GitVersion: v2.6.1'\n");
    command(dir.path())
        .args(["identity", "sign", "receipt.yaml", "--bundle", "proof.json"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cosign 3"));
    assert!(!dir.path().join("proof.json").exists());
    std::fs::write(dir.path().join("cosign"), SIGNER).unwrap();
    std::fs::write(dir.path().join("proof.json"), "existing evidence").unwrap();
    command(dir.path())
        .args(["identity", "sign", "receipt.yaml", "--bundle", "proof.json"])
        .assert()
        .code(2);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("proof.json")).unwrap(),
        "existing evidence"
    );
}

#[test]
fn empty_explicit_identity_token_is_refused() {
    let dir = fixture(SIGNER);
    command(dir.path())
        .env("TEST_JOB_TOKEN", " ")
        .args([
            "identity",
            "sign",
            "receipt.yaml",
            "--bundle",
            "proof.json",
            "--identity-token-env",
            "TEST_JOB_TOKEN",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("token is empty"));
    assert!(!dir.path().join("cosign.args").exists());
}
