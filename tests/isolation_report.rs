//! Issue #39: a receipt says which isolation controls were in force,
//! control by control, instead of implying them from a mode's name.

use assert_cmd::Command;
use std::path::Path;

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

fn receipt(dir: &Path) -> serde_yaml::Value {
    let path = std::fs::read_dir(dir.join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "yaml"))
        .unwrap();
    serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn control<'a>(isolation: &'a serde_yaml::Value, name: &str) -> &'a serde_yaml::Value {
    isolation["controls"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name} control"))
}

/// Without --verify there is no sandbox, and the receipt says so for
/// every control rather than staying silent.
#[test]
fn a_plain_run_reports_no_isolation_at_all() {
    let dir = workspace();
    attest()
        .arg("run")
        .current_dir(dir.path())
        .assert()
        .success();
    let isolation = &receipt(dir.path())["isolation"];
    assert_eq!(isolation["mode"], "none");
    assert_eq!(isolation["platform"], std::env::consts::OS);
    for name in [
        "network",
        "filesystem",
        "capabilities",
        "environment",
        "memory",
        "open-files",
        "cpu",
        "timeout",
    ] {
        assert_eq!(
            control(isolation, name)["status"],
            "not-enforced",
            "{name} under no isolation"
        );
    }
}

/// --verify is process isolation: the receipt names what that enforces,
/// the open-file limit here, and what it does not, network and filesystem
/// first of all, with the reason.
#[test]
fn process_isolation_reports_exactly_what_it_enforces() {
    let dir = workspace();
    attest()
        .args(["run", "--verify"])
        .current_dir(dir.path())
        .assert()
        .success();
    let isolation = &receipt(dir.path())["isolation"];
    assert_eq!(isolation["mode"], "process");

    let network = control(isolation, "network");
    assert_eq!(network["status"], "not-enforced");
    assert!(network["detail"]
        .as_str()
        .unwrap()
        .contains("steps can reach the network"));
    assert_eq!(control(isolation, "filesystem")["status"], "not-enforced");
    assert_eq!(control(isolation, "capabilities")["status"], "not-enforced");

    let files = control(isolation, "open-files");
    let memory = control(isolation, "memory");
    if cfg!(unix) {
        assert_eq!(files["status"], "enforced", "{files:?}");
        assert!(files["detail"].as_str().unwrap().contains("RLIMIT_NOFILE"));
        assert_eq!(
            memory["status"], "not-enforced",
            "no memory limit by default"
        );
    } else {
        assert_eq!(files["status"], "not-available");
        assert_eq!(memory["status"], "not-available");
    }
    assert_eq!(control(isolation, "timeout")["status"], "not-enforced");
    assert!(
        isolation.get("capsule_steps").is_none(),
        "no capsule steps to list"
    );
}

/// The isolation block sits inside the signed bytes: a receipt whose
/// isolation claims were edited after signing no longer verifies.
#[test]
fn the_isolation_claims_are_covered_by_the_signature() {
    let dir = workspace();
    attest()
        .args(["keys", "generate", "--name", "k"])
        .current_dir(dir.path())
        .assert()
        .success();
    attest()
        .args(["run", "--verify", "--sign"])
        .current_dir(dir.path())
        .assert()
        .success();
    let path = std::fs::read_dir(dir.path().join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "yaml"))
        .unwrap();
    attest()
        .args(["verify", path.to_str().unwrap()])
        .current_dir(dir.path())
        .assert()
        .code(0);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("status: not-enforced"), "{text}");
    let forged = text.replacen("status: not-enforced", "status: enforced", 1);
    std::fs::write(&path, forged).unwrap();
    attest()
        .args(["verify", path.to_str().unwrap()])
        .current_dir(dir.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("signature"));
}
