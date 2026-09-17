//! Issue #8 acceptance criteria: `attest run --check-reproducibility`
//! executes the pipeline twice in fresh hermetic workspaces and compares
//! per-step output hashes.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

use attest::storage::Receipt;

fn attest() -> Command {
    Command::cargo_bin("attest").expect("attest binary builds")
}

fn init_workspace(dir: &Path, pipeline: &str) {
    attest().arg("init").current_dir(dir).assert().success();
    std::fs::write(dir.join("attest.yaml"), pipeline).unwrap();
}

fn last_receipt(stdout: &[u8]) -> Receipt {
    let stdout = String::from_utf8_lossy(stdout);
    let path = stdout
        .lines()
        .rev()
        .find(|l| l.trim_end().ends_with(".yaml"))
        .expect("receipt path on stdout")
        .trim();
    serde_yaml::from_str(&std::fs::read_to_string(PathBuf::from(path)).unwrap()).unwrap()
}

/// Criterion 1: a deterministic pipeline passes with a
/// `reproducibility: {verified: true, runs: 2, method: double-build/v1}`
/// block on the receipt.
#[test]
fn deterministic_pipeline_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(
        tmp.path(),
        r#"
version: "1.0"
name: det
steps:
  hello:
    run: "printf hello > out.txt"
    inputs: []
    outputs: ["out.txt"]
    cache: false
"#,
    );

    let output = attest()
        .args(["run", "--check-reproducibility"])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let receipt = last_receipt(&output);
    let repro = receipt.reproducibility.expect("reproducibility block");
    assert!(repro.verified);
    assert_eq!(repro.runs, 2);
    assert_eq!(repro.method, "double-build/v1");
}

/// Criterion 2: a nondeterministic step fails with exit 1 and the diff
/// report names the divergent output. The spec's `date +%s%N` is not
/// portable (BSD date prints a literal `N`, and same-second runs collide);
/// /dev/urandom diverges unconditionally.
#[test]
fn nondeterministic_step_diverges() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(
        tmp.path(),
        r#"
version: "1.0"
name: nondet
steps:
  roll:
    run: "head -c 8 /dev/urandom > out.txt"
    inputs: []
    outputs: ["out.txt"]
    cache: false
"#,
    );

    let output = attest()
        .args(["run", "--check-reproducibility"])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .get_output()
        .clone();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("step roll"), "stderr was: {stderr}");
    assert!(stderr.contains("out.txt"), "stderr was: {stderr}");

    // The written receipt records the failed verification.
    let receipt = last_receipt(&output.stdout);
    let repro = receipt.reproducibility.expect("reproducibility block");
    assert!(!repro.verified);
}

/// Criterion 3: a build that embeds its absolute build path diverges,
/// because the two runs deliberately use different workspace paths.
#[test]
fn path_leak_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(
        tmp.path(),
        r#"
version: "1.0"
name: pathleak
steps:
  leak:
    run: "pwd > out.txt"
    inputs: []
    outputs: ["out.txt"]
    cache: false
"#,
    );

    attest()
        .args(["run", "--check-reproducibility"])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("out.txt"));
}

/// Criterion 4: a pre-seeded cache must not short-circuit either run.
/// Both runs start from fresh workspaces with empty caches, so the run-1
/// receipt must report cache_hit false even when the original workspace
/// has a warm cache for the same step.
#[test]
fn cache_is_bypassed() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(
        tmp.path(),
        r#"
version: "1.0"
name: cached
steps:
  build:
    run: "printf hello > out.txt"
    inputs: []
    outputs: ["out.txt"]
    cache: true
"#,
    );

    // Seed the original workspace's cache with a normal run.
    attest().arg("run").current_dir(tmp.path()).assert().code(0);

    let output = attest()
        .args(["run", "--check-reproducibility"])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let receipt = last_receipt(&output);
    assert!(receipt.steps.iter().all(|s| !s.cache_hit));
    assert!(receipt.reproducibility.expect("block").verified);
}

/// Criterion 5: the normalized environment is injected — the step observes
/// SOURCE_DATE_EPOCH=1704067200 in both runs (the step itself fails if the
/// value is wrong, which is stronger than only comparing the two runs).
#[test]
fn source_date_epoch_is_normalized() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(
        tmp.path(),
        r#"
version: "1.0"
name: env
steps:
  stamp:
    run: "[ \"$SOURCE_DATE_EPOCH\" = \"1704067200\" ] && printf \"$SOURCE_DATE_EPOCH\" > out.txt"
    inputs: []
    outputs: ["out.txt"]
    cache: false
"#,
    );

    let output = attest()
        .args(["run", "--check-reproducibility"])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let receipt = last_receipt(&output);
    assert!(receipt.reproducibility.expect("block").verified);
    assert!(receipt.steps.iter().all(|s| s.exit_code == 0));
}
