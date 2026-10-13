//! Issue #19: a verdict says what it checked, and refuses when it could not.
//!
//! `--require` names the properties the caller needs established. A
//! requirement is met only by a check that ran and passed: skipped is not
//! passed, missing evidence is not passed, and the refusal names the
//! requirement and the reason, in text and in the JSON contract.

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

const FAILING_PIPELINE: &str = r#"
version: "1.0"
name: failing
steps:
  boom:
    run: "exit 3"
    inputs: []
    outputs: []
    cache: false
"#;

fn receipt_in(dir: &Path) -> PathBuf {
    let mut receipts: Vec<PathBuf> = std::fs::read_dir(dir.join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    receipts.sort();
    receipts.pop().expect("a receipt was written")
}

/// A workspace with one receipt; signed when `sign`, from a pipeline that
/// fails when `failing`.
fn workspace(sign: bool, failing: bool) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success();
    std::fs::write(
        dir.path().join("attest.yaml"),
        if failing {
            FAILING_PIPELINE
        } else {
            TOY_PIPELINE
        },
    )
    .unwrap();
    std::fs::write(dir.path().join("in.txt"), "payload").unwrap();
    let mut run = attest();
    run.arg("run");
    if sign {
        attest()
            .args(["keys", "generate", "--name", "signer"])
            .current_dir(dir.path())
            .assert()
            .success();
        run.arg("--sign");
    }
    let out = run.current_dir(dir.path()).output().unwrap();
    assert_eq!(out.status.success(), !failing, "run outcome");
    let receipt = receipt_in(dir.path());
    (dir, receipt)
}

fn verify(dir: &Path, receipt: &Path, extra: &[&str]) -> (i32, String, serde_json::Value) {
    let mut args = vec!["verify", receipt.to_str().unwrap()];
    args.extend_from_slice(extra);
    let text = attest().args(&args).current_dir(dir).output().unwrap();
    let mut json_args = args.clone();
    json_args.extend_from_slice(&["--format", "json"]);
    let json = attest().args(&json_args).current_dir(dir).output().unwrap();
    let record: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&json.stdout).trim()).unwrap();
    assert_eq!(text.status.code(), json.status.code());
    (
        text.status.code().unwrap(),
        String::from_utf8(text.stdout).unwrap(),
        record,
    )
}

fn unmet(record: &serde_json::Value) -> Vec<String> {
    record["policy"]["unmet"]
        .as_array()
        .map(|u| {
            u.iter()
                .map(|x| x["requirement"].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Without a policy, a verdict passes when no check failed and says what
/// it skipped. With one, the same evidence is refused, and the refusal
/// names the requirement.
#[test]
fn a_skipped_check_never_satisfies_an_explicit_requirement() {
    let (dir, receipt) = workspace(true, false);

    let (code, text, record) = verify(dir.path(), &receipt, &[]);
    assert_eq!(code, 0);
    assert!(text.contains("recompute    skipped"), "{text}");
    assert_eq!(record["policy"]["required"], serde_json::json!([]));
    assert_eq!(unmet(&record), Vec::<String>::new());

    let (code, text, record) = verify(dir.path(), &receipt, &["--require", "recompute"]);
    assert_eq!(code, 1);
    assert!(
        text.contains("REFUSED: requirement 'recompute' not met: recompute check not performed"),
        "{text}"
    );
    assert_eq!(record["verdict"], "fail");
    assert_eq!(
        record["policy"]["required"],
        serde_json::json!(["recompute"])
    );
    assert_eq!(unmet(&record), vec!["recompute"]);

    // The same requirement, with the check actually performed, is met.
    let (code, _, record) = verify(
        dir.path(),
        &receipt,
        &["--require", "recompute", "--recompute"],
    );
    assert_eq!(code, 0);
    assert_eq!(unmet(&record), Vec::<String>::new());
}

/// Evidence that is absent is not evidence: a receipt without a timestamp
/// token cannot meet `timestamp`, and a signature check that was disabled
/// cannot meet `signature`, however valid the signature would have been.
#[test]
fn missing_evidence_and_disabled_checks_are_refused_when_required() {
    let (dir, receipt) = workspace(true, false);

    let (code, text, record) = verify(dir.path(), &receipt, &["--require", "timestamp"]);
    assert_eq!(code, 1);
    assert!(text.contains("requirement 'timestamp' not met"), "{text}");
    assert_eq!(unmet(&record), vec!["timestamp"]);

    let (code, _, record) = verify(
        dir.path(),
        &receipt,
        &["--require", "signature", "--check-signatures", "false"],
    );
    assert_eq!(code, 1);
    assert_eq!(unmet(&record), vec!["signature"]);

    let (code, _, record) = verify(dir.path(), &receipt, &["--require", "signature"]);
    assert_eq!(code, 0);
    assert_eq!(unmet(&record), Vec::<String>::new());

    // Several at once, in one flag or several: every unmet one is named.
    let (code, _, record) = verify(
        dir.path(),
        &receipt,
        &["--require", "signature,timestamp", "--require", "trust"],
    );
    assert_eq!(code, 1);
    assert_eq!(unmet(&record), vec!["timestamp", "trust"]);
}

/// Evidence validity and execution outcome are separate questions. A
/// receipt of a failed build is valid evidence of a failed build; it only
/// becomes a refusal when the caller requires success.
#[test]
fn execution_outcome_is_reported_apart_from_evidence_validity() {
    let (dir, receipt) = workspace(false, true);

    let (code, text, record) = verify(dir.path(), &receipt, &["--check-signatures", "false"]);
    assert_eq!(code, 0, "valid evidence of a failed build passes");
    assert!(
        text.contains("execution: failure (1 failed step(s))"),
        "{text}"
    );
    assert_eq!(record["execution"]["outcome"], "failure");
    assert_eq!(record["execution"]["failed_steps"], 1);

    let (code, text, record) = verify(
        dir.path(),
        &receipt,
        &["--check-signatures", "false", "--require", "success"],
    );
    assert_eq!(code, 1);
    assert!(text.contains("requirement 'success' not met"), "{text}");
    assert_eq!(unmet(&record), vec!["success"]);

    let (dir, receipt) = workspace(false, false);
    let (code, _, record) = verify(
        dir.path(),
        &receipt,
        &["--check-signatures", "false", "--require", "success"],
    );
    assert_eq!(code, 0);
    assert_eq!(record["execution"]["outcome"], "success");
}

/// A name the verifier does not know is a usage error, before anything
/// is read: a typo must not become a weaker policy.
#[test]
fn an_unknown_requirement_is_a_usage_error() {
    let (dir, receipt) = workspace(true, false);
    attest()
        .args(["verify", receipt.to_str().unwrap(), "--require", "signatur"])
        .current_dir(dir.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("unknown requirement 'signatur'"));
}

/// Every verdict, refused or not, validates against the published
/// contract, with the policy and execution fields in it.
#[test]
fn refusals_fit_the_json_contract() {
    let schema: serde_json::Value =
        serde_json::from_str(attest::verify::VERDICT_JSON_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let (dir, receipt) = workspace(true, false);
    for extra in [
        &[][..],
        &["--require", "signature"][..],
        &["--require", "timestamp,recompute,trust,success"][..],
    ] {
        let (_, _, record) = verify(dir.path(), &receipt, extra);
        assert!(validator.is_valid(&record), "{record}");
    }
}

/// An archive that is partial cannot choose a weaker policy for itself.
/// A gap in the causal chain makes linkage "not performed" by the
/// archive's own admission, which is honest without a policy and a
/// refusal under one: the caller required linkage, and a partial archive
/// does not have it.
#[test]
fn a_partial_archive_does_not_meet_a_linkage_requirement() {
    let (dir, receipt) = workspace(true, false);
    let complete = dir.path().join("complete.attest.tar.zst");
    attest()
        .args([
            "causal",
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--output",
            complete.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .assert()
        .success();
    attest()
        .args([
            "verify",
            "--archive",
            complete.to_str().unwrap(),
            "--require",
            "linkage,signature",
        ])
        .current_dir(dir.path())
        .assert()
        .code(0);

    // A reference nothing resolves: exportable only as partial. Editing
    // the receipt breaks its signature, so that check is disabled here
    // and the question is linkage alone.
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&receipt).unwrap()).unwrap();
    value["causal_events"] =
        serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("evt-missing".into())]);
    std::fs::write(&receipt, serde_yaml::to_string(&value).unwrap()).unwrap();
    let partial = dir.path().join("partial.attest.tar.zst");
    attest()
        .args([
            "causal",
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--output",
            partial.to_str().unwrap(),
            "--allow-partial",
        ])
        .current_dir(dir.path())
        .assert()
        .success();

    attest()
        .args([
            "verify",
            "--archive",
            partial.to_str().unwrap(),
            "--check-signatures",
            "false",
        ])
        .current_dir(dir.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("(partial)"));
    attest()
        .args([
            "verify",
            "--archive",
            partial.to_str().unwrap(),
            "--check-signatures",
            "false",
            "--require",
            "linkage",
        ])
        .current_dir(dir.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("requirement 'linkage' not met"));
}

/// The same names, the same semantics, on the in-toto import path.
#[test]
fn import_applies_the_same_policy_names() {
    let (dir, receipt) = workspace(true, false);
    let statement = dir.path().join("statement.json");
    attest()
        .args([
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--format",
            "in-toto",
            "--output",
            statement.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .assert()
        .success();
    attest()
        .args([
            "import",
            "--format",
            "in-toto",
            statement.to_str().unwrap(),
            "--require",
            "signature",
        ])
        .current_dir(dir.path())
        .assert()
        .code(0);
    // A property this surface cannot establish is unmet, not ignored.
    attest()
        .args([
            "import",
            "--format",
            "in-toto",
            statement.to_str().unwrap(),
            "--require",
            "recompute",
        ])
        .current_dir(dir.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("requirement 'recompute' not met"));
}
