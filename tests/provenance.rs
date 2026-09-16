use assert_cmd::Command;
use attest::storage::Receipt;
#[test]
fn run_binds_git_artifacts_and_provenance_to_signature() {
    let tmp = tempfile::tempdir().unwrap();
    Command::cargo_bin("attest")
        .unwrap()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    std::fs::write(tmp.path().join("input.txt"), "provenance payload").unwrap();
    std::fs::write(tmp.path().join("attest.yaml"),"version: '1.0'\nname: provenance-test\nsteps:\n  build:\n    run: 'sleep 1; cat input.txt > output.txt'\n    inputs: [input.txt]\n    outputs: [output.txt]\n    cache: false\n").unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["add", "attest.yaml", "input.txt", ".gitignore"],
        vec![
            "-c",
            "user.name=Receipt Test",
            "-c",
            "user.email=test@example.test",
            "commit",
            "-qm",
            "fixture",
        ],
        vec![
            "remote",
            "add",
            "origin",
            "https://user:fake-secret@example.test/team/repo.git?token=fake-secret",
        ],
    ] {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert!(output.status.success());
    }
    Command::cargo_bin("attest")
        .unwrap()
        .args(["run", "--sign"])
        .current_dir(tmp.path())
        .assert()
        .success();
    let path = std::fs::read_dir(tmp.path().join(".attest/receipts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = std::fs::read(&path).unwrap();
    let mut receipt: Receipt = serde_yaml::from_slice(&bytes).unwrap();
    let provenance = receipt.provenance.as_ref().unwrap();
    // A literal on purpose, not RECEIPT_SCHEMA_VERSION: this assertion
    // exists so that bumping the constant is a deliberate act with a test to
    // update, rather than something a receipt silently follows.
    assert_eq!(receipt.schema_version, Some(3));
    assert_eq!(provenance.pipeline_name.as_deref(), Some("provenance-test"));
    assert!(provenance.invocation_id.is_some());
    let source = provenance.source.as_ref().unwrap();
    assert!(!source.tracked_dirty);
    assert_eq!(
        source.repository.as_deref(),
        Some("https://example.test/team/repo.git")
    );
    assert!(!String::from_utf8_lossy(&bytes).contains("fake-secret"));
    let artifact = &provenance.artifacts[0];
    assert_eq!(artifact.path, "output.txt");
    assert_eq!(
        artifact.digest,
        blake3::hash(b"provenance payload").to_hex().to_string()
    );
    assert!(
        receipt.steps[0].duration_secs >= 1,
        "Measure time after execution"
    );
    Command::cargo_bin("attest")
        .unwrap()
        .args(["verify", path.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .success();
    receipt.provenance.as_mut().unwrap().artifacts[0].path = "forged.txt".into();
    std::fs::write(&path, serde_yaml::to_string(&receipt).unwrap()).unwrap();
    Command::cargo_bin("attest")
        .unwrap()
        .args(["verify", path.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(1);
}
