//! Issue #7 acceptance criteria: `attest causal export` produces
//! reproducible self-contained archives and `attest verify --archive`
//! checks them fully offline.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

use attest::archive::{read_archive, write_archive};

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

fn init_workspace(dir: &Path) {
    attest().arg("init").current_dir(dir).assert().success();
    std::fs::write(dir.join("attest.yaml"), TOY_PIPELINE).unwrap();
    std::fs::write(dir.join("in.txt"), "payload").unwrap();
}

fn generate_key(dir: &Path, name: &str) -> String {
    let output = attest()
        .args(["keys", "generate", "--name", name])
        .current_dir(dir)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).unwrap().trim().to_string()
}

fn run_signed(dir: &Path, key_id: &str) -> PathBuf {
    attest()
        .args(["run", "--sign", "--key", key_id])
        .current_dir(dir)
        .assert()
        .success();
    let mut receipts: Vec<PathBuf> = std::fs::read_dir(dir.join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "yaml").unwrap_or(false))
        .collect();
    receipts.sort();
    receipts.pop().unwrap()
}

fn export(dir: &Path, receipt: &Path, output: &Path) {
    attest()
        .args([
            "causal",
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .current_dir(dir)
        .assert()
        .code(0);
}

/// Give a receipt a fabricated causal reference (the executor writes an
/// empty ledger today). Editing the YAML invalidates its signature, so
/// tests using this verify with --check-signatures false.
fn add_causal_event(receipt: &Path, event_id: &str) {
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(receipt).unwrap()).unwrap();
    value["causal_events"] =
        serde_yaml::Value::Sequence(vec![serde_yaml::Value::String(event_id.to_string())]);
    std::fs::write(receipt, serde_yaml::to_string(&value).unwrap()).unwrap();
}

/// Criterion 1: end-to-end — build and export on machine A, delete A's
/// workspace, verify the archive on auditor machine B that trusts A's key.
#[test]
fn export_then_offline_verify_on_other_machine() {
    let machine_a = tempfile::tempdir().unwrap();
    let machine_b = tempfile::tempdir().unwrap();
    init_workspace(machine_a.path());
    init_workspace(machine_b.path());

    let id = generate_key(machine_a.path(), "builder-a");

    // Auditor B imports A's public key before A disappears.
    let pem_file = machine_b.path().join("builder-a.pem");
    attest()
        .args([
            "keys",
            "export",
            &id,
            "--output",
            pem_file.to_str().unwrap(),
        ])
        .current_dir(machine_a.path())
        .assert()
        .code(0);
    attest()
        .args([
            "keys",
            "import",
            pem_file.to_str().unwrap(),
            "--name",
            "builder-a",
        ])
        .current_dir(machine_b.path())
        .assert()
        .code(0);

    let receipt = run_signed(machine_a.path(), &id);
    let archive = machine_b.path().join("build.attest.tar.zst");
    export(machine_a.path(), &receipt, &archive);

    // Machine A is gone: the archive must be self-sufficient.
    drop(machine_a);

    attest()
        .args([
            "verify",
            "--archive",
            archive.to_str().unwrap(),
            "--trust-store",
            machine_b.path().join(".attest/trust").to_str().unwrap(),
        ])
        .current_dir(machine_b.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("receipt.yaml"))
        .stdout(predicates::str::contains("pass"));
}

/// Criterion 2 (rule 1): exporting the same receipt twice yields
/// byte-identical archives.
#[test]
fn export_is_reproducible() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(tmp.path());
    let id = generate_key(tmp.path(), "repro");
    let receipt = run_signed(tmp.path(), &id);

    let first = tmp.path().join("first.attest.tar.zst");
    let second = tmp.path().join("second.attest.tar.zst");
    export(tmp.path(), &receipt, &first);
    export(tmp.path(), &receipt, &second);

    let first_bytes = std::fs::read(&first).unwrap();
    let second_bytes = std::fs::read(&second).unwrap();
    assert!(!first_bytes.is_empty());
    assert_eq!(
        first_bytes, second_bytes,
        "two exports of the same receipt must be byte-identical"
    );
}

/// Criterion 3: tampering with a chain member inside the archive is
/// detected and the verdict names the tampered entry.
#[test]
fn a_tampered_event_breaks_the_chain_root() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(tmp.path());
    let id = generate_key(tmp.path(), "chain");
    let receipt = run_signed(tmp.path(), &id);

    let archive = tmp.path().join("chain.attest.tar.zst");
    export(tmp.path(), &receipt, &archive);

    // Alter one event's recorded output. The receipt is untouched and its
    // signature still verifies — which is the point: only recomputing the
    // chain root from the events can catch this.
    let mut entries = read_archive(&archive).unwrap();
    let event = entries
        .iter_mut()
        .find(|e| e.path.starts_with("events/"))
        .expect("the archive carries the events the receipt references");
    let mut value: serde_json::Value = serde_json::from_slice(&event.bytes).unwrap();
    value["output_hash"] = serde_json::Value::String("0".repeat(64));
    event.bytes = serde_json::to_vec(&value).unwrap();
    write_archive(entries, &archive).unwrap();

    attest()
        .args([
            "verify",
            "--archive",
            archive.to_str().unwrap(),
            "--check-signatures",
            "false",
        ])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("chain-linkage"))
        .stdout(predicates::str::contains("FAIL"));
}

/// Criterion 4: a valid signature by a key the auditor does not trust
/// fails with the key id named.
#[test]
fn untrusted_key_fails_with_key_id() {
    let machine_a = tempfile::tempdir().unwrap();
    let machine_b = tempfile::tempdir().unwrap();
    init_workspace(machine_a.path());
    init_workspace(machine_b.path());

    let id = generate_key(machine_a.path(), "stranger");
    let receipt = run_signed(machine_a.path(), &id);
    let archive = machine_b.path().join("stranger.attest.tar.zst");
    export(machine_a.path(), &receipt, &archive);

    // Machine B never imported the key.
    attest()
        .args(["verify", "--archive", archive.to_str().unwrap()])
        .current_dir(machine_b.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("signed by untrusted key"))
        .stdout(predicates::str::contains(&id));
}

/// Criterion 5: a causal reference that cannot be resolved locally aborts
/// the export (exit 1); --allow-partial exports anyway and the archive
/// verdict carries partial=true.
#[test]
fn unresolved_chain_requires_allow_partial() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(tmp.path());
    let id = generate_key(tmp.path(), "gappy");
    let receipt = run_signed(tmp.path(), &id);
    add_causal_event(&receipt, "evt-missing");

    let archive = tmp.path().join("partial.attest.tar.zst");
    attest()
        .args([
            "causal",
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
        ])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("evt-missing"));
    assert!(!archive.exists(), "no archive on refused export");

    attest()
        .args([
            "causal",
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--allow-partial",
        ])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .stderr(predicates::str::contains("partial"));

    // Editing causal_events broke the signature; check the rest offline.
    let output = attest()
        .args([
            "verify",
            "--archive",
            archive.to_str().unwrap(),
            "--check-signatures",
            "false",
            "--format",
            "json",
        ])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let summary = lines.last().expect("archive summary line");
    assert_eq!(summary["verdict"], "pass");
    assert_eq!(summary["partial"], true);
}
