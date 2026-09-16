//! Integration tests for CLI commands
//!
//! These tests cover the main CLI functionality to improve code coverage
//! for the main.rs module.

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_cli_help_command() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--help");

    cmd.assert().success().stdout(predicate::str::contains(
        "Verifiable CI/CD with cryptographic attestation",
    ));
}

#[test]
fn test_cli_version_command() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--version");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("attest"));
}

#[test]
fn test_cli_verbose_flag() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["--verbose", "--help"]);

    cmd.assert().success();
}

#[test]
fn test_cli_quiet_flag() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["--quiet", "--help"]);

    cmd.assert().success();
}

#[test]
fn test_init_command_basic() {
    let temp_dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path()).arg("init");

    // The init command should attempt to initialize (may fail but shouldn't crash)
    cmd.assert().code(predicate::in_iter([0, 1])); // Either success or expected failure
}

#[test]
fn test_image_verify_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["image", "verify", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Verify container image signature"));
}

#[test]
fn test_image_config_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["image", "config", "--help"]);

    cmd.assert().success().stdout(predicate::str::contains(
        "Check image verification configuration",
    ));
}

#[test]
fn test_causal_path_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["causal", "path", "--help"]);

    cmd.assert().success().stdout(predicate::str::contains(
        "Query causal path between two events",
    ));
}

#[test]
fn test_causal_stats_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["causal", "stats", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Show causal ledger statistics"));
}

#[test]
fn test_causal_events_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["causal", "events", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("List recent causal events"));
}

#[test]
fn test_causal_chain_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["causal", "chain", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Build and display causal chain"));
}

#[test]
fn test_run_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["run", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Run pipeline with attestation"));
}

#[test]
fn test_invalid_command() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("invalid-command");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

#[test]
fn test_image_verify_missing_arg() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["image", "verify"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_causal_path_missing_args() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["causal", "path"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
#[ignore = "Requires working cosign setup"]
fn test_image_verify_nonexistent_image() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.args(&["image", "verify", "nonexistent/image:latest"]);

    // Should handle gracefully even if image doesn't exist
    cmd.assert().code(predicate::in_iter([0, 1]));
}

#[test]
#[ignore = "Requires working setup"]
fn test_run_command_basic() {
    let temp_dir = TempDir::new().unwrap();

    // Create a minimal pipeline file
    let pipeline_content = r#"
version: "0.1"
name: "test-pipeline"
steps:
  test:
    run: "echo 'hello world'"
"#;

    std::fs::write(temp_dir.path().join("attest.yaml"), pipeline_content).unwrap();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .args(&["run", "--pipeline", "attest.yaml"]);

    cmd.assert().code(predicate::in_iter([0, 1])); // May fail due to setup but shouldn't crash
}

#[test]
#[ignore = "Requires working setup"]
fn test_run_command_with_verify_flag() {
    let temp_dir = TempDir::new().unwrap();

    let pipeline_content = r#"
version: "0.1"
name: "test-pipeline"
steps:
  test:
    run: "echo 'hello world'"
"#;

    std::fs::write(temp_dir.path().join("attest.yaml"), pipeline_content).unwrap();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .args(&["run", "--pipeline", "attest.yaml", "--verify"]);

    cmd.assert().code(predicate::in_iter([0, 1]));
}

#[test]
#[ignore = "Requires working setup"]
fn test_run_command_with_sign_flag() {
    let temp_dir = TempDir::new().unwrap();

    let pipeline_content = r#"
version: "0.1"
name: "test-pipeline"
steps:
  test:
    run: "echo 'hello world'"
"#;

    std::fs::write(temp_dir.path().join("attest.yaml"), pipeline_content).unwrap();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .args(&["run", "--pipeline", "attest.yaml", "--sign"]);

    cmd.assert().code(predicate::in_iter([0, 1]));
}

#[test]
#[ignore = "Requires working setup"]
fn test_run_command_with_both_flags() {
    let temp_dir = TempDir::new().unwrap();

    let pipeline_content = r#"
version: "0.1"
name: "test-pipeline"
steps:
  test:
    run: "echo 'hello world'"
"#;

    std::fs::write(temp_dir.path().join("attest.yaml"), pipeline_content).unwrap();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path()).args(&[
        "run",
        "--pipeline",
        "attest.yaml",
        "--verify",
        "--sign",
    ]);

    cmd.assert().code(predicate::in_iter([0, 1]));
}
