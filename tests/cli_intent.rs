//! Security-sensitive option dependencies are refused before anything runs.
//!
//! Each case asks for a guarantee the selected mode cannot produce, and
//! checks two things: exit code 2 with a diagnostic naming the missing
//! prerequisite, and no side effect -- the step did not run, no receipt was
//! written. Discovering the mistake after the build is the failure these
//! tests exist to prevent.

use assert_cmd::Command;
use std::path::Path;

fn attest() -> Command {
    Command::cargo_bin("attest").expect("attest binary builds")
}

/// A pipeline whose only step leaves a marker, so "did not run" is a
/// statement about the filesystem rather than about output.
const MARKER_PIPELINE: &str = r#"
version: "1.0"
name: intent
steps:
  mark:
    run: "touch ran.marker"
    inputs: []
    outputs: ["ran.marker"]
    cache: false
"#;

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success();
    std::fs::write(dir.path().join("attest.yaml"), MARKER_PIPELINE).unwrap();
    dir
}

fn nothing_ran(dir: &Path) {
    assert!(
        !dir.join("ran.marker").exists(),
        "the step ran before the usage error was reported"
    );
    let receipts = std::fs::read_dir(dir.join(".attest/receipts"))
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0);
    assert_eq!(receipts, 0, "a receipt was written for a refused run");
}

/// Run with the given arguments in a fresh workspace; require exit 2, the
/// named prerequisite in the diagnostic, and no side effect.
fn refused(args: &[&str], names: &str) {
    let dir = workspace();
    attest()
        .args(args)
        .current_dir(dir.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("requires"))
        .stderr(predicates::str::contains(names));
    nothing_ran(dir.path());
}

#[test]
fn timestamp_without_sign_is_refused_before_the_pipeline_runs() {
    refused(&["run", "--timestamp"], "--sign");
}

#[test]
fn key_without_sign_is_refused_before_the_pipeline_runs() {
    refused(&["run", "--key", "0123"], "--sign");
}

#[test]
fn tsa_without_timestamp_is_refused_before_the_pipeline_runs() {
    refused(&["run", "--tsa", "https://tsa.example"], "--timestamp");
}

#[test]
fn wrap_only_options_are_refused_without_wrap() {
    refused(&["run", "--name", "x"], "--wrap");
    refused(&["run", "--input", "a"], "--wrap");
    refused(&["run", "--output", "a"], "--wrap");
    refused(&["run", "--workspace", "."], "--wrap");
    refused(&["run", "--", "touch", "ran.marker"], "--wrap");
}

#[test]
fn wrap_without_its_own_prerequisites_is_refused() {
    refused(&["run", "--wrap", "--", "touch", "ran.marker"], "--name");
    refused(&["run", "--wrap", "--name", "x"], "a command after");
}

#[test]
fn pipeline_only_options_are_refused_with_wrap() {
    let wrapped = ["run", "--wrap", "--name", "x"];
    for extra in [
        &["--check-reproducibility"][..],
        &["--pipeline", "attest.yaml"][..],
        &["--verify"][..],
    ] {
        let mut args: Vec<&str> = wrapped.to_vec();
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--", "touch", "ran.marker"]);
        refused(&args, "not --wrap");
    }
}

/// The same rule holds on the wrap path and on the reproducibility path:
/// one table, checked before either branch is taken.
#[test]
fn timestamp_without_sign_is_refused_in_every_mode() {
    refused(
        &[
            "run",
            "--wrap",
            "--name",
            "x",
            "--timestamp",
            "--",
            "touch",
            "ran.marker",
        ],
        "--sign",
    );
    refused(&["run", "--check-reproducibility", "--timestamp"], "--sign");
}

/// Image commands have the same shape: naming a receipt key without asking
/// for a signed receipt is refused before cosign is even looked for.
#[test]
fn image_receipt_key_without_signing_is_refused() {
    let dir = workspace();
    attest()
        .args([
            "image",
            "sign",
            "registry.example/repo@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "--key",
            "azurekms://vault.example/key",
            "--receipt-key",
            "0123",
        ])
        .current_dir(dir.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--receipt-key requires --sign"));
    attest()
        .args([
            "image",
            "verify",
            "registry.example/repo@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "--receipt-key",
            "0123",
        ])
        .current_dir(dir.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--receipt-key requires --sign-receipt"));
    nothing_ran(dir.path());
}

/// A valid combination still runs, so the table refuses and nothing more.
#[test]
fn a_valid_combination_still_runs() {
    let dir = workspace();
    attest()
        .args(["run"])
        .current_dir(dir.path())
        .assert()
        .success();
    assert!(dir.path().join("ran.marker").exists());
}
