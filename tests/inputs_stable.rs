//! Issue #38: a step executes against a stable view of its declared inputs.
//! The inputs are unwritable while the step runs, the receipt says whether
//! that was in force, and the permission bits come back afterwards.

use assert_cmd::Command;
use std::path::Path;

fn attest() -> Command {
    Command::cargo_bin("attest").expect("attest binary builds")
}

fn workspace(pipeline: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success();
    std::fs::write(dir.path().join("attest.yaml"), pipeline).unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/a.txt"), "source\n").unwrap();
    std::fs::write(dir.path().join("in.txt"), "input\n").unwrap();
    dir
}

fn receipt(dir: &Path) -> Option<serde_yaml::Value> {
    let path = std::fs::read_dir(dir.join(".attest/receipts"))
        .ok()?
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "yaml"))?;
    Some(serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap())
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A step that writes a declared input fails at the write; the input is
/// untouched, the run reports the failed step, and the receipt records
/// the control as enforced.
#[cfg(unix)]
#[test]
fn a_step_cannot_write_a_declared_input_file() {
    let dir = workspace(
        "version: \"1.0\"\nname: rewrite\nsteps:\n  rewrite:\n    run: \"echo tampered > in.txt\"\n    inputs: [\"in.txt\"]\n    outputs: []\n    cache: false\n",
    );
    let before = mode(&dir.path().join("in.txt"));
    attest()
        .arg("run")
        .current_dir(dir.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("step 'rewrite' failed"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("in.txt")).unwrap(),
        "input\n"
    );
    assert_eq!(
        mode(&dir.path().join("in.txt")),
        before,
        "permissions restored"
    );
    let receipt = receipt(dir.path()).expect("a receipt of the failed step");
    let inputs = receipt["isolation"]["controls"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "inputs")
        .unwrap();
    // Permission bits refuse a plain write; they are not a guarantee, and
    // the receipt must not call them one.
    assert_eq!(inputs["status"], "not-enforced", "{inputs:?}");
    assert!(inputs["detail"]
        .as_str()
        .unwrap()
        .contains("Only a capsule enforces"));
}

/// The limit of permission bits, stated rather than hidden: a step that
/// puts the write bit back, changes an input, uses it and restores it
/// before it ends is not caught, and the receipt's inputs row says so.
#[cfg(unix)]
#[test]
fn a_step_that_restores_its_input_is_not_caught_and_the_receipt_says_so() {
    let dir = workspace(
        "version: \"1.0\"\nname: revert\nsteps:\n  revert:\n    run: \"chmod u+w in.txt && cp in.txt .keep && echo tampered > in.txt && cat in.txt > out.txt && cp .keep in.txt\"\n    inputs: [\"in.txt\"]\n    outputs: [\"out.txt\"]\n    cache: false\n",
    );
    attest()
        .arg("run")
        .current_dir(dir.path())
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out.txt")).unwrap(),
        "tampered\n"
    );
    let receipt = receipt(dir.path()).unwrap();
    let inputs = receipt["isolation"]["controls"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "inputs")
        .unwrap();
    assert_eq!(inputs["status"], "not-enforced");
    assert!(inputs["detail"]
        .as_str()
        .unwrap()
        .contains("changes undone before it ends are not"));
}

/// A link among the inputs is attested as a link; the bytes it leads to
/// are attested only if its target is declared too. A link to an
/// undeclared file is refused, a link to a declared one is accepted.
#[cfg(unix)]
#[test]
fn a_symlink_to_an_undeclared_file_is_refused_as_an_input() {
    let dir = workspace(
        "version: \"1.0\"\nname: link\nsteps:\n  read:\n    run: \"cat link > out.txt\"\n    inputs: [\"link\"]\n    outputs: [\"out.txt\"]\n    cache: false\n",
    );
    std::fs::write(dir.path().join("hidden.txt"), "unattested\n").unwrap();
    std::os::unix::fs::symlink("hidden.txt", dir.path().join("link")).unwrap();
    attest()
        .arg("run")
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("not under any declared path"));

    // Declared alongside, the same link is fine, and its target is held.
    std::fs::write(
        dir.path().join("attest.yaml"),
        "version: \"1.0\"\nname: link\nsteps:\n  read:\n    run: \"cat link > out.txt\"\n    inputs: [\"link\", \"hidden.txt\"]\n    outputs: [\"out.txt\"]\n    cache: false\n",
    )
    .unwrap();
    attest()
        .arg("run")
        .current_dir(dir.path())
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out.txt")).unwrap(),
        "unattested\n"
    );
}

/// A declared input directory is held still as a whole: nothing inside it
/// can be created, removed or changed by the step.
#[cfg(unix)]
#[test]
fn a_step_cannot_add_to_or_change_a_declared_input_directory() {
    let dir = workspace(
        "version: \"1.0\"\nname: dirs\nsteps:\n  add:\n    run: \"touch src/new.txt\"\n    inputs: [\"src\"]\n    outputs: []\n    cache: false\n  change:\n    run: \"echo x >> src/a.txt\"\n    inputs: [\"src\"]\n    outputs: []\n    cache: false\n",
    );
    let dir_mode = mode(&dir.path().join("src"));
    let file_mode = mode(&dir.path().join("src/a.txt"));
    attest().arg("run").current_dir(dir.path()).assert().code(1);
    assert!(!dir.path().join("src/new.txt").exists());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("src/a.txt")).unwrap(),
        "source\n"
    );
    assert_eq!(mode(&dir.path().join("src")), dir_mode);
    assert_eq!(mode(&dir.path().join("src/a.txt")), file_mode);
}

/// Outputs and scratch space stay writable: only the declared inputs are
/// held, and a step that writes where it should succeeds.
#[test]
fn outputs_and_scratch_remain_writable() {
    let dir = workspace(
        "version: \"1.0\"\nname: ok\nsteps:\n  build:\n    run: \"cat in.txt src/a.txt > out.txt && mkdir -p scratch && echo tmp > scratch/t\"\n    inputs: [\"in.txt\", \"src\"]\n    outputs: [\"out.txt\"]\n    cache: false\n",
    );
    attest()
        .arg("run")
        .current_dir(dir.path())
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out.txt")).unwrap(),
        "input\nsource\n"
    );
}

/// A symbolic link among the inputs is recorded as a link and never
/// followed; one that points outside the workspace is refused outright.
#[cfg(unix)]
#[test]
fn a_symlink_escaping_the_workspace_is_refused_as_an_input() {
    let dir = workspace(
        "version: \"1.0\"\nname: link\nsteps:\n  read:\n    run: \"true\"\n    inputs: [\"escape\"]\n    outputs: []\n    cache: false\n",
    );
    std::os::unix::fs::symlink("/etc/hosts", dir.path().join("escape")).unwrap();
    attest()
        .arg("run")
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("escape"));
    assert!(
        receipt(dir.path()).is_none(),
        "no receipt for a refused input"
    );
}

/// A capsule mounts each declared input read-only over the workspace
/// mount, so the runtime refuses the write whatever the step runs as.
#[test]
fn a_capsule_mounts_declared_inputs_read_only() {
    let dir = workspace("version: \"1.0\"\nname: x\nsteps: {}\n");
    let manifest = attest::capsule::CapsuleManifest {
        format: "attest-capsule/v1".to_string(),
        name: "c".to_string(),
        image: "registry.example/img@sha256:".to_string() + &"0".repeat(64),
        entrypoint: None,
        env: Default::default(),
        mounts: attest::capsule::CapsuleMounts {
            workspace: "/ws".into(),
        },
        network: attest::capsule::CAPSULE_NETWORK_NONE.to_string(),
        capsule_hash: None,
    };
    let args = attest::capsule::run_args(
        &manifest,
        dir.path(),
        &["src".into(), "in.txt".into(), "missing".into()],
        &["true".to_string()],
    );
    let joined = args.join(" ");
    assert!(
        joined.contains(&format!("{}/in.txt:/ws/in.txt:ro", dir.path().display())),
        "{joined}"
    );
    assert!(
        joined.contains(&format!("{}/src:/ws/src:ro", dir.path().display())),
        "{joined}"
    );
    assert!(
        !joined.contains("missing"),
        "absent inputs are left to hashing to report"
    );
}
