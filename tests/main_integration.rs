//! Integration tests for the main CLI application
//!
//! These tests cover the command-line interface parsing, subcommand dispatch,
//! and main application flow to improve code coverage.

use assert_cmd::Command;
use tempfile::TempDir;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Verifiable CI/CD with cryptographic attestation",
        ));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("0.1.0"));
}

#[test]
fn test_cli_verbose_flag() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--verbose").arg("--help").assert().success();
}

#[test]
fn test_cli_quiet_flag() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--quiet").arg("--help").assert().success();
}

#[test]
fn test_init_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("init")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Initialize ATTEST repository"));
}

#[test]
fn test_run_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("run")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Run pipeline with attestation"));
}

#[test]
fn test_image_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Image signature verification"));
}

#[test]
fn test_image_verify_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("verify")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Verify container image signature",
        ));
}

#[test]
fn test_image_config_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("config")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Check image verification configuration",
        ));
}

#[test]
fn test_causal_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("causal")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Causal ledger operations"));
}

#[test]
fn test_causal_path_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("causal")
        .arg("path")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Query causal path between two events",
        ));
}

#[test]
fn test_causal_stats_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("causal")
        .arg("stats")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Show causal ledger statistics"));
}

#[test]
fn test_causal_events_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("causal")
        .arg("events")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("List recent causal events"));
}

#[test]
fn test_causal_chain_command_help() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("causal")
        .arg("chain")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Build and display causal chain"));
}

#[test]
fn test_init_command_in_temp_dir() {
    let temp_dir = TempDir::new().unwrap();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // NOTE: `AttestCore::init` (src/core.rs) currently only logs mode info -
    // it does not create a `.attest` directory or any other files on disk -
    // so this test only checks that the `init` subcommand runs to completion
    // successfully, rather than checking for filesystem side effects that
    // the current implementation does not have.
}

#[test]
fn test_run_command_with_flags() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Create a simple pipeline file
    let pipeline_content = r#"
version: "0.1"
name: "test-pipeline"
steps:
  test:
    run: "echo 'Hello from test'"
    inputs: []
    outputs: []
"#;
    std::fs::write(temp_dir.path().join("attest.yaml"), pipeline_content).unwrap();

    // Test run command with verify and sign flags
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("run")
        .arg("--verify")
        .arg("--sign")
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success();
}

#[test]
fn test_run_command_with_pipeline_flag() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Create a custom pipeline file
    let pipeline_content = r#"
version: "0.1"
name: "custom-pipeline"
steps:
  echo:
    run: "echo 'Custom pipeline test'"
    inputs: []
    outputs: []
"#;
    let custom_pipeline = temp_dir.path().join("custom.yaml");
    std::fs::write(&custom_pipeline, pipeline_content).unwrap();

    // Test run command with specific pipeline file
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("run")
        .arg("--pipeline")
        .arg(custom_pipeline.to_str().unwrap())
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success();
}

/// `attest image verify` hard-fails when the cosign binary is missing, so
/// these tests can only run where cosign is installed (not on CI runners).
fn cosign_available() -> bool {
    std::process::Command::new("cosign")
        .arg("version")
        .output()
        .is_ok()
}

#[test]
fn test_image_verify_command() {
    if !cosign_available() {
        eprintln!("Skipping test_image_verify_command: cosign not installed");
        return;
    }
    // Test image verification with a common image
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("verify")
        .arg("alpine:latest")
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stdout(predicates::str::contains("Verifying container image"));
}

#[test]
fn test_image_verify_command_detailed() {
    if !cosign_available() {
        eprintln!("Skipping test_image_verify_command_detailed: cosign not installed");
        return;
    }
    // Test image verification with detailed flag
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("verify")
        .arg("alpine:latest")
        .arg("--detailed")
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Detailed Verification Information",
        ));
}

#[test]
fn test_image_config_show() {
    // Test image config show
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("config")
        .arg("--show")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Current Image Verification Configuration",
        ));
}

#[test]
fn test_image_config_test_cosign() {
    // Test cosign availability check
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("config")
        .arg("--test-cosign")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains("Testing cosign availability"));
}

#[test]
fn test_image_config_show_and_test() {
    // Test both show and test flags together
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("config")
        .arg("--show")
        .arg("--test-cosign")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Current Image Verification Configuration",
        ))
        .stdout(predicates::str::contains("Testing cosign availability"));
}

#[test]
fn test_causal_stats_command() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize to create storage
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Test causal stats
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("stats")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains("Causal Ledger Statistics"));
}

#[test]
fn test_causal_stats_detailed() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Test detailed causal stats
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("stats")
        .arg("--detailed")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains("Average chain length"));
}

#[test]
fn test_causal_events_command() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // A freshly initialised workspace has no events, and the command must
    // say so. It used to print a "Recent causal events" header and a count
    // whatever the ledger held, and never list an event at all — which is
    // what this assertion was pinning.
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("events")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains("no causal events recorded"));
}

#[test]
fn test_causal_events_with_limit() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // `--limit` is accepted and, with nothing to list, changes nothing.
    // Asserting that it echoes itself would test the message, not the
    // behaviour; the behaviour is exercised in causal_events_lists_real_events.
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("events")
        .arg("--limit")
        .arg("5")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains("no causal events recorded"));
}

/// The command must actually list events, and honour `--limit`.
///
/// This was written while runs recorded nothing: the executor set
/// `causal_events: vec![]` and no caller ever reached the ledger, so every
/// `attest causal` subcommand operated on an empty store. It is the test
/// that made that visible.
#[test]
fn causal_events_lists_real_events() {
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path();

    Command::cargo_bin("attest")
        .unwrap()
        .current_dir(workspace)
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/a.txt"), "data").unwrap();
    std::fs::write(
        workspace.join("attest.yaml"),
        r#"version: "0.1"
name: events
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
"#,
    )
    .unwrap();

    Command::cargo_bin("attest")
        .unwrap()
        .current_dir(workspace)
        .arg("run")
        .timeout(std::time::Duration::from_secs(120))
        .assert()
        .success();

    let listed = Command::cargo_bin("attest")
        .unwrap()
        .current_dir(workspace)
        .args(["causal", "events"])
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();
    let out = String::from_utf8(listed.get_output().stdout.clone()).unwrap();
    assert!(out.contains("one"), "step 'one' not listed: {out}");
    assert!(out.contains("two"), "step 'two' not listed: {out}");

    // One event, plus the note saying the rest were withheld.
    let limited = Command::cargo_bin("attest")
        .unwrap()
        .current_dir(workspace)
        .args(["causal", "events", "--limit", "1"])
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();
    let out = String::from_utf8(limited.get_output().stdout.clone()).unwrap();
    assert!(
        out.contains("showing 1 of"),
        "--limit did not truncate: {out}"
    );
}

#[test]
fn test_causal_events_with_step_filter() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Test causal events with step filter
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("events")
        .arg("--step")
        .arg("build")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Recent causal events for step 'build'",
        ));
}

#[test]
fn test_causal_path_command() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Test causal path query (expecting no path found)
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("path")
        .arg("event1")
        .arg("event2")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains("Querying causal path"));
}

#[test]
fn test_causal_path_detailed() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Test causal path with detailed flag
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("path")
        .arg("event1")
        .arg("event2")
        .arg("--detailed")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains("Querying causal path"));
}

#[test]
fn test_causal_chain_empty_events() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Test causal chain with no event IDs (should show error)
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("chain")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains("No event IDs provided"));
}

#[test]
fn test_causal_chain_with_events() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Test causal chain with event IDs
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("chain")
        .arg("event1")
        .arg("event2")
        .arg("event3")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Building causal chain from 3 events",
        ));
}

#[test]
fn test_causal_chain_with_save() {
    let temp_dir = TempDir::new().unwrap();

    // First initialize
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Test causal chain with save flag
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("causal")
        .arg("chain")
        .arg("event1")
        .arg("--save")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicates::str::contains("Chain saved to ledger storage"));
}

#[test]
fn test_invalid_command() {
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("invalid-command").assert().failure();
}

#[test]
fn test_run_without_init() {
    let temp_dir = TempDir::new().unwrap();

    // Running outside an ATTEST repository is an operational error (exit 2).
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("run")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .code(2)
        .stderr(predicates::str::contains("not an ATTEST repository"));
}

#[test]
fn test_global_flags_work_with_subcommands() {
    // Test that global flags work with subcommands
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--verbose")
        .arg("image")
        .arg("config")
        .arg("--show")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--quiet")
        .arg("image")
        .arg("config")
        .arg("--show")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();
}

#[test]
fn test_logging_levels_setup() {
    // Test that different verbosity levels work
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--verbose").arg("--help").assert().success();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("--quiet").arg("--help").assert().success();
}

#[test]
fn test_complex_command_combinations() {
    let temp_dir = TempDir::new().unwrap();

    // Initialize first
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Test combining global flags with complex subcommands
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("--verbose")
        .arg("causal")
        .arg("events")
        .arg("--limit")
        .arg("20")
        .arg("--step")
        .arg("test-step")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();
}

// Additional tests to ensure full coverage of CLI parsing logic
#[test]
fn test_all_image_subcommands() {
    // Test that all image subcommands parse correctly
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("verify")
        .arg("--help")
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("image")
        .arg("config")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn test_all_causal_subcommands() {
    // Test that all causal subcommands parse correctly
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("causal")
        .arg("path")
        .arg("--help")
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("causal")
        .arg("stats")
        .arg("--help")
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("causal")
        .arg("events")
        .arg("--help")
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.arg("causal")
        .arg("chain")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn test_run_command_flag_combinations() {
    let temp_dir = TempDir::new().unwrap();

    // Initialize first
    let mut init_cmd = Command::cargo_bin("attest").unwrap();
    init_cmd
        .current_dir(temp_dir.path())
        .arg("init")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success();

    // Create a pipeline file
    let pipeline_content = r#"
version: "0.1"
name: "flag-test-pipeline"
steps:
  test:
    run: "echo 'Testing flags'"
    inputs: []
    outputs: []
"#;
    std::fs::write(temp_dir.path().join("attest.yaml"), pipeline_content).unwrap();

    // Test just verify flag
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("run")
        .arg("--verify")
        .timeout(std::time::Duration::from_secs(20))
        .assert()
        .success();

    // Test just sign flag
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("run")
        .arg("--sign")
        .timeout(std::time::Duration::from_secs(20))
        .assert()
        .success();
}
