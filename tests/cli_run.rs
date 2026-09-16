//! Issue #17 acceptance criteria: `attest init` and `attest run` drive the
//! real executor end to end, via the built binary.

use assert_cmd::Command;
use std::path::Path;

fn attest() -> Command {
    Command::cargo_bin("attest").expect("attest binary builds")
}

fn write_pipeline(dir: &Path, yaml: &str) {
    std::fs::write(dir.join("attest.yaml"), yaml).unwrap();
}

fn receipt_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let receipts = dir.join(".attest").join("receipts");
    if !receipts.is_dir() {
        return vec![];
    }
    std::fs::read_dir(receipts)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "yaml").unwrap_or(false))
        .collect()
}

fn load_receipt(path: &Path) -> serde_yaml::Value {
    serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
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

/// Criterion 1: init creates the layout; re-running changes nothing and exits 0.
#[test]
fn init_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();

    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();

    assert!(tmp.path().join(".attest/receipts").is_dir());
    assert!(tmp.path().join(".attest/cache").is_dir());
    assert!(tmp.path().join("attest.yaml").is_file());
    let gitignore = std::fs::read_to_string(tmp.path().join(".gitignore")).unwrap();
    assert!(gitignore.lines().any(|l| l.trim() == ".attest/keys/"));

    let starter_before = std::fs::read_to_string(tmp.path().join("attest.yaml")).unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    let starter_after = std::fs::read_to_string(tmp.path().join("attest.yaml")).unwrap();
    assert_eq!(starter_before, starter_after);
    let gitignore_after = std::fs::read_to_string(tmp.path().join(".gitignore")).unwrap();
    assert_eq!(gitignore, gitignore_after);
}

/// Criterion 2: run executes the step, writes the output and a receipt with
/// non-empty manifest-v1 hashes.
#[test]
fn run_executes_and_writes_receipt() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(tmp.path(), TOY_PIPELINE);
    std::fs::write(tmp.path().join("in.txt"), "payload").unwrap();

    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .success();

    assert_eq!(
        std::fs::read_to_string(tmp.path().join("out.txt")).unwrap(),
        "payload"
    );

    let receipts = receipt_files(tmp.path());
    assert_eq!(receipts.len(), 1, "exactly one receipt expected");
    let receipt = load_receipt(&receipts[0]);
    let step = &receipt["steps"][0];
    assert_eq!(step["name"].as_str().unwrap(), "copy");
    assert_eq!(step["exit_code"].as_i64().unwrap(), 0);
    // blake3 hex digests over attest-manifest/v1 documents
    assert_eq!(step["input_hash"].as_str().unwrap().len(), 64);
    assert_eq!(step["output_hash"].as_str().unwrap().len(), 64);
}

/// Criterion 3: --sign produces a signed receipt.
#[test]
fn run_sign_produces_signed_receipt() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(tmp.path(), TOY_PIPELINE);
    std::fs::write(tmp.path().join("in.txt"), "payload").unwrap();

    attest()
        .args(["run", "--sign"])
        .current_dir(tmp.path())
        .assert()
        .success();

    let receipts = receipt_files(tmp.path());
    assert_eq!(receipts.len(), 1);
    let receipt = load_receipt(&receipts[0]);
    assert!(
        receipt["signature"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "signature must be set, got: {:?}",
        receipt["signature"]
    );
    assert!(
        receipt["signer_public_key"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "signer_public_key must be set"
    );
}

/// Criterion 4: a failing step yields CLI exit 1 with the failure recorded
/// in a written receipt.
#[test]
fn failing_step_exits_one_with_receipt() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(
        tmp.path(),
        r#"
version: "1.0"
name: failing
steps:
  boom:
    run: "exit 3"
    inputs: []
    outputs: []
    cache: false
"#,
    );

    attest().arg("run").current_dir(tmp.path()).assert().code(1);

    let receipts = receipt_files(tmp.path());
    assert_eq!(
        receipts.len(),
        1,
        "receipt must still be written on failure"
    );
    let receipt = load_receipt(&receipts[0]);
    assert_eq!(receipt["steps"][0]["exit_code"].as_i64().unwrap(), 3);
}

/// Criterion 5: run without init is an operational error (exit 2) with the
/// exact message.
#[test]
fn run_without_init_exits_two() {
    let tmp = tempfile::tempdir().unwrap();
    write_pipeline(tmp.path(), TOY_PIPELINE);
    std::fs::write(tmp.path().join("in.txt"), "payload").unwrap();

    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains(
            "not an ATTEST repository (run 'attest init')",
        ));
}

/// Criterion 6: a missing declared input surfaces the manifest MissingInput
/// error as a verification failure (exit 1).
#[test]
fn missing_declared_input_exits_one() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(tmp.path(), TOY_PIPELINE);
    // in.txt deliberately not created

    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("declared input not found"))
        .stderr(predicates::str::contains("in.txt"));
}

/// Issue #24: a failing step must name itself on stderr with its exit code
/// and the tail of its captured output, not just flip the process exit code.
#[test]
fn failing_step_reports_name_exit_code_and_output() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(
        tmp.path(),
        r#"
version: "1.0"
name: failing
steps:
  boom:
    run: "echo the_actual_error_detail >&2; exit 3"
    inputs: []
    outputs: []
    cache: false
"#,
    );

    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "step 'boom' failed with exit code 3",
        ))
        .stderr(predicates::str::contains("the_actual_error_detail"));
}

/// Issue #26: a step whose dependency failed must not execute; it is
/// reported as skipped and left out of the receipt.
#[test]
fn dependent_of_failed_step_is_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(
        tmp.path(),
        r#"
version: "1.0"
name: failing-chain
steps:
  boom:
    run: "exit 3"
    inputs: []
    outputs: []
    cache: false
  after:
    run: "touch after_ran.txt"
    needs: ["boom"]
    inputs: []
    outputs: []
    cache: false
  transitive:
    run: "touch transitive_ran.txt"
    needs: ["after"]
    inputs: []
    outputs: []
    cache: false
"#,
    );

    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "step 'after' skipped: a dependency did not succeed",
        ))
        .stderr(predicates::str::contains(
            "step 'transitive' skipped: a dependency did not succeed",
        ));

    assert!(
        !tmp.path().join("after_ran.txt").exists(),
        "dependent step must not run after its dependency failed"
    );
    assert!(
        !tmp.path().join("transitive_ran.txt").exists(),
        "transitively dependent step must not run either"
    );

    let receipts = receipt_files(tmp.path());
    assert_eq!(receipts.len(), 1);
    let receipt = load_receipt(&receipts[0]);
    let steps = receipt["steps"].as_sequence().unwrap();
    assert_eq!(
        steps.len(),
        1,
        "only the executed step belongs in the receipt"
    );
    assert_eq!(steps[0]["name"].as_str().unwrap(), "boom");
}

/// Issue #25: failed results must not be cached — rerunning after a failure
/// executes the step again instead of replaying the failure from cache.
#[test]
fn failed_step_result_is_not_cached() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(
        tmp.path(),
        r#"
version: "1.0"
name: flaky
steps:
  flaky:
    run: "echo ran >> attempts.txt; exit 3"
    inputs: []
    outputs: []
    cache: true
"#,
    );

    attest().arg("run").current_dir(tmp.path()).assert().code(1);
    attest().arg("run").current_dir(tmp.path()).assert().code(1);

    let attempts = std::fs::read_to_string(tmp.path().join("attempts.txt")).unwrap();
    assert_eq!(
        attempts.lines().count(),
        2,
        "a failed step must execute again on the next run, not replay from cache"
    );
}

/// A successful `cache: true` step is served from cache on the second run,
/// while `cache: false` steps are executed every time.
#[test]
fn cache_flag_controls_step_caching() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(
        tmp.path(),
        r#"
version: "1.0"
name: caching
steps:
  cached:
    run: "echo ran >> cached_attempts.txt"
    inputs: []
    outputs: []
    cache: true
  uncached:
    run: "echo ran >> uncached_attempts.txt"
    inputs: []
    outputs: []
    cache: false
"#,
    );

    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .success();
    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .success();

    let cached = std::fs::read_to_string(tmp.path().join("cached_attempts.txt")).unwrap();
    assert_eq!(
        cached.lines().count(),
        1,
        "a successful cache:true step must be served from cache on rerun"
    );
    let uncached = std::fs::read_to_string(tmp.path().join("uncached_attempts.txt")).unwrap();
    assert_eq!(
        uncached.lines().count(),
        2,
        "a cache:false step must execute on every run"
    );
}

/// Issue #27: `timeout_secs` is enforced — the step is killed once the
/// timeout elapses and fails with exit code 124, like GNU timeout.
#[test]
fn step_timeout_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(
        tmp.path(),
        r#"
version: "1.0"
name: slow
steps:
  slow:
    run: "sleep 30; touch survived.txt"
    inputs: []
    outputs: []
    cache: false
    timeout_secs: 1
"#,
    );

    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "step 'slow' failed with exit code 124",
        ))
        .stderr(predicates::str::contains("timed out after 1s"));

    assert!(
        !tmp.path().join("survived.txt").exists(),
        "the command must be killed, not left running past the timeout"
    );

    let receipts = receipt_files(tmp.path());
    assert_eq!(receipts.len(), 1);
    let receipt = load_receipt(&receipts[0]);
    assert_eq!(receipt["steps"][0]["exit_code"].as_i64().unwrap(), 124);
}

/// Bonus: a parse error in the pipeline file is an operational error (exit 2).
#[test]
fn invalid_pipeline_exits_two() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    write_pipeline(tmp.path(), "version: \"1.0\"\nsteps: {}\n");

    attest().arg("run").current_dir(tmp.path()).assert().code(2);
}

/// Issue #30: an attest.yaml declaring a newer schema than this binary
/// supports is rejected with an explicit upgrade message, and a supported
/// declaration is accepted.
#[test]
fn pipeline_schema_version_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    std::fs::write(tmp.path().join("in.txt"), "payload").unwrap();

    write_pipeline(tmp.path(), &format!("schema_version: 99\n{}", TOY_PIPELINE));
    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("schema_version 99"))
        .stderr(predicates::str::contains("upgrade attest"));

    write_pipeline(tmp.path(), &format!("schema_version: 1\n{}", TOY_PIPELINE));
    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .success();
}
