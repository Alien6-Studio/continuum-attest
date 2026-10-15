//! Integration tests for hermetic capsules (`attest capsule`).
//!
//! Runtime-free tests (init/hash/verify semantics) always run. Tests that
//! execute a container self-skip with a message when neither Docker nor
//! Podman is available or the pinned test image cannot be pulled.

use std::path::Path;
use std::process::Command as StdCommand;

use assert_cmd::Command;

use attest::capsule;
use attest::storage::{Receipt, StepResult};

const DIGEST_REF: &str = "docker.io/library/busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Golden hash of the default manifest for `demo` + [`DIGEST_REF`]. Any
/// change to the canonical serialization (field order, YAML style, env
/// sorting) breaks every capsule_hash in existing receipts and must show
/// up here first.
const GOLDEN_HASH: &str = "61919b228bee2e45121638469e727a6c052c05d8efd0acb92e822193630deaeb";

fn attest_cmd() -> Command {
    Command::cargo_bin("attest").expect("attest binary")
}

fn ws_arg(dir: &Path) -> String {
    dir.to_str().expect("utf-8 path").to_string()
}

/// Acceptance criterion 1a: `init` with a tag reference exits 2 and
/// writes nothing.
#[test]
fn init_rejects_tag_reference_with_exit_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    attest_cmd()
        .args([
            "capsule",
            "init",
            "--image",
            "rust:1.93",
            "--name",
            "demo",
            "--workspace",
            &ws_arg(dir.path()),
        ])
        .assert()
        .code(2);
    assert!(!capsule::manifest_path(dir.path(), "demo").exists());
}

/// Acceptance criterion 1b: `init` with a digest reference writes
/// `capsule.yaml` and `hash` is idempotent across invocations.
#[test]
fn init_writes_manifest_and_hash_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    attest_cmd()
        .args([
            "capsule",
            "init",
            "--image",
            DIGEST_REF,
            "--name",
            "demo",
            "--workspace",
            &ws_arg(dir.path()),
        ])
        .assert()
        .success();
    assert!(capsule::manifest_path(dir.path(), "demo").exists());

    let hash_once = || {
        let output = attest_cmd()
            .args([
                "capsule",
                "hash",
                "demo",
                "--workspace",
                &ws_arg(dir.path()),
            ])
            .output()
            .expect("run hash");
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .expect("utf-8")
            .trim()
            .to_string()
    };
    let first = hash_once();
    assert_eq!(first, hash_once(), "hash must be idempotent");
    assert_eq!(first.len(), 64);
    assert_eq!(
        first, GOLDEN_HASH,
        "canonical capsule serialization changed — this breaks capsule_hash in existing receipts"
    );
}

/// `run` without a command after `--` is an operational error (exit 2),
/// even before any runtime lookup.
#[test]
fn run_without_command_exits_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    capsule::init(dir.path(), "demo", DIGEST_REF).expect("init");
    attest_cmd()
        .args(["capsule", "run", "demo", "--workspace", &ws_arg(dir.path())])
        .assert()
        .code(2);
}

/// Editing the manifest without re-running `init` invalidates the stored
/// hash: `hash` and `load` both refuse.
#[test]
fn edited_manifest_fails_hash_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    capsule::init(dir.path(), "demo", DIGEST_REF).expect("init");
    let path = capsule::manifest_path(dir.path(), "demo");
    // Swap the pinned digest for another valid one: the manifest stays
    // parseable and structurally valid, but the stored hash no longer
    // matches.
    let tampered = std::fs::read_to_string(&path)
        .expect("read manifest")
        .replace("sha256:00000000", "sha256:11111111");
    std::fs::write(&path, tampered).expect("write manifest");
    attest_cmd()
        .args([
            "capsule",
            "hash",
            "demo",
            "--workspace",
            &ws_arg(dir.path()),
        ])
        .assert()
        .code(1);
    assert!(capsule::load(dir.path(), "demo").is_err());
}

/// Build a workspace with a one-step pipeline bound to capsule `demo`
/// and a receipt whose hashes match it, then return the receipt path.
fn pipeline_workspace_with_receipt(dir: &Path) -> std::path::PathBuf {
    capsule::init(dir, "demo", DIGEST_REF).expect("init capsule");
    let manifest = capsule::load(dir, "demo").expect("load capsule");
    let capsule_hash = manifest.capsule_hash.clone().expect("stored hash");

    let run = "echo hermetic".to_string();
    std::fs::write(
        dir.join("attest.yaml"),
        format!(
            "version: '1'\nname: capsule-demo\nsteps:\n  build:\n    run: {run}\n    capsule: demo\n"
        ),
    )
    .expect("write pipeline");

    let input_hash = attest::hashing::hash_inputs(dir, "build", &run, &[]).expect("input hash");
    // Real hashes, not placeholders. `verify --recompute` now checks the
    // pipeline hash and the step outputs as well as the inputs, and a fixture
    // that could not satisfy those checks was only ever testing the two it
    // happened to cover.
    let pipeline: attest::pipeline::Pipeline =
        serde_yaml::from_str(&std::fs::read_to_string(dir.join("attest.yaml")).expect("read"))
            .expect("the fixture pipeline parses");
    let pipeline_hash = blake3::hash(
        serde_yaml::to_string(&pipeline)
            .expect("re-serialize")
            .as_bytes(),
    )
    .to_hex()
    .to_string();
    let output_hash = attest::hashing::hash_outputs(dir, "build", &[]).expect("output hash");

    let receipt = Receipt {
        schema_version: Some(1),
        pipeline_hash,
        steps: vec![StepResult {
            name: "build".to_string(),
            input_hash,
            output_hash,
            duration_secs: 1,
            exit_code: 0,
            cache_hit: false,
            stdout: String::new(),
            stderr: String::new(),
            capsule_hash: Some(capsule_hash),
        }],
        timestamp: chrono::DateTime::parse_from_rfc3339("2026-08-27T10:00:00Z")
            .expect("timestamp")
            .with_timezone(&chrono::Utc),
        total_duration_secs: 1,
        signature: None,
        signer_public_key: None,
        attest_version: "0.1.0".to_string(),
        causal_events: vec![],
        causal_chain_hash: None,
        reproducibility: None,
        provenance: None,
        timestamp_token: None,
        isolation: None,
    };
    let receipt_path = dir.join("receipt.yaml");
    std::fs::write(
        &receipt_path,
        serde_yaml::to_string(&receipt).expect("yaml"),
    )
    .expect("write receipt");
    receipt_path
}

/// Acceptance criterion 5a: a receipt recording the capsule's hash passes
/// `verify --recompute` against the workspace.
#[test]
fn verify_recompute_passes_with_matching_capsule() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receipt_path = pipeline_workspace_with_receipt(dir.path());
    attest_cmd()
        .args([
            "verify",
            receipt_path.to_str().expect("path"),
            "--check-signatures",
            "false",
            "--recompute",
            "--workspace",
            &ws_arg(dir.path()),
        ])
        .assert()
        .success();
}

/// Acceptance criterion 5b: tampering with `capsule.yaml` after the run
/// makes `verify --recompute` exit 1.
#[test]
fn verify_recompute_fails_after_capsule_tamper() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receipt_path = pipeline_workspace_with_receipt(dir.path());

    // Replace the capsule with a re-inited one pointing at a different
    // digest: internally consistent (load succeeds), but its hash no
    // longer matches the receipt.
    let capsule_dir = capsule::manifest_path(dir.path(), "demo");
    std::fs::remove_dir_all(capsule_dir.parent().expect("dir")).expect("remove capsule");
    let other_ref = DIGEST_REF.replace("00000000", "11111111");
    capsule::init(dir.path(), "demo", &other_ref).expect("re-init");

    let output = attest_cmd()
        .args([
            "verify",
            receipt_path.to_str().expect("path"),
            "--check-signatures",
            "false",
            "--recompute",
            "--workspace",
            &ws_arg(dir.path()),
        ])
        .output()
        .expect("run verify");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("capsule hash mismatch"),
        "expected capsule hash mismatch in: {stdout}"
    );
}

/// A receipt with a capsule_hash verified against a pipeline whose step
/// declares no capsule fails: the binding is two-way.
#[test]
fn verify_recompute_fails_when_pipeline_drops_capsule() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receipt_path = pipeline_workspace_with_receipt(dir.path());
    std::fs::write(
        dir.path().join("attest.yaml"),
        "version: '1'\nname: capsule-demo\nsteps:\n  build:\n    run: echo hermetic\n",
    )
    .expect("rewrite pipeline");
    attest_cmd()
        .args([
            "verify",
            receipt_path.to_str().expect("path"),
            "--check-signatures",
            "false",
            "--recompute",
            "--workspace",
            &ws_arg(dir.path()),
        ])
        .assert()
        .code(1);
}

// ---------------------------------------------------------------------------
// Container-runtime-gated tests (criteria 2, 3 and 4). Self-skip when no
// Docker/Podman runtime is available or the test image cannot be pulled.
// ---------------------------------------------------------------------------

/// Pull busybox and return its digest-pinned reference, or None (skip).
fn pulled_busybox_ref() -> Option<String> {
    let binary = capsule::runtime_binary()?;
    if let Ok(image) = std::env::var("ATTEST_TEST_CAPSULE_IMAGE") {
        capsule::validate_image_ref(&image).expect("digest-pinned test image");
        let inspect = StdCommand::new(binary)
            .args(["image", "inspect", &image])
            .output()
            .expect("inspect local test image");
        assert!(
            inspect.status.success(),
            "configured capsule test image is not available locally"
        );
        return Some(image);
    }
    let pull = StdCommand::new(binary)
        .args(["pull", "-q", "docker.io/library/busybox:latest"])
        .output()
        .ok()?;
    if !pull.status.success() {
        eprintln!("skipping: cannot pull busybox with {binary}");
        return None;
    }
    let inspect = StdCommand::new(binary)
        .args([
            "image",
            "inspect",
            "--format",
            "{{index .RepoDigests 0}}",
            "docker.io/library/busybox:latest",
        ])
        .output()
        .ok()?;
    if !inspect.status.success() {
        return None;
    }
    let image = String::from_utf8(inspect.stdout).ok()?.trim().to_string();
    capsule::validate_image_ref(&image).ok()?;
    Some(image)
}

/// Acceptance criterion 2: network is unreachable inside a capsule.
#[test]
fn capsule_network_is_none() {
    let Some(image) = pulled_busybox_ref() else {
        eprintln!("skipping capsule_network_is_none: no container runtime");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    capsule::init(dir.path(), "netless", &image).expect("init");
    let manifest = capsule::load(dir.path(), "netless").expect("load");
    let output = capsule::run_captured(
        &manifest,
        dir.path(),
        &attest::capsule::InputMounts::none(),
        &[
            "sh".to_string(),
            "-c".to_string(),
            "wget -T 3 -q -O /dev/null http://example.com".to_string(),
        ],
    )
    .expect("run");
    assert!(
        !output.status.success(),
        "network access should fail inside a capsule"
    );
}

/// Acceptance criterion 3: environment is exactly manifest env + the
/// normalization set; ambient variables never leak in.
#[test]
fn capsule_env_is_declared_only() {
    let Some(image) = pulled_busybox_ref() else {
        eprintln!("skipping capsule_env_is_declared_only: no container runtime");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    capsule::init(dir.path(), "envtest", &image).expect("init");
    let manifest = capsule::load(dir.path(), "envtest").expect("load");
    std::env::set_var("ATTEST_TEST_LEAK", "leaked");
    let output = capsule::run_captured(
        &manifest,
        dir.path(),
        &attest::capsule::InputMounts::none(),
        &[
            "sh".to_string(),
            "-c".to_string(),
            "echo leak=[$ATTEST_TEST_LEAK] epoch=[$SOURCE_DATE_EPOCH] tz=[$TZ]".to_string(),
        ],
    )
    .expect("run");
    std::env::remove_var("ATTEST_TEST_LEAK");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("leak=[]"), "ambient env leaked: {stdout}");
    assert!(
        stdout.contains("epoch=[1704067200]") && stdout.contains("tz=[UTC]"),
        "normalization env missing: {stdout}"
    );
}

/// Acceptance criterion 4: the same command in the same capsule produces
/// the same output-manifest hash on two consecutive runs.
#[test]
fn capsule_runs_are_deterministic() {
    let Some(image) = pulled_busybox_ref() else {
        eprintln!("skipping capsule_runs_are_deterministic: no container runtime");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    capsule::init(dir.path(), "determ", &image).expect("init");
    let manifest = capsule::load(dir.path(), "determ").expect("load");
    let out_file = std::path::PathBuf::from("out.txt");
    let mut hashes = Vec::new();
    for _ in 0..2 {
        let output = capsule::run_captured(
            &manifest,
            dir.path(),
            &attest::capsule::InputMounts::none(),
            &[
                "sh".to_string(),
                "-c".to_string(),
                "printf 'build %s\\n' \"$SOURCE_DATE_EPOCH\" > out.txt".to_string(),
            ],
        )
        .expect("run");
        assert!(
            output.status.success(),
            "capsule run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        hashes.push(
            attest::hashing::hash_outputs(dir.path(), "determ", std::slice::from_ref(&out_file))
                .expect("output hash"),
        );
    }
    assert_eq!(hashes[0], hashes[1], "output hash must be deterministic");
}

/// Issue #38, the capsule half: the step reads its declared inputs from a
/// snapshot taken when they were hashed. A process on the host changes
/// the input while the step runs and puts it back before the step ends;
/// the step must have read the original, the run must pass, and the
/// receipt must say the inputs were enforced.
#[test]
fn capsule_step_reads_a_frozen_copy_of_its_inputs() {
    let Some(image) = pulled_busybox_ref() else {
        eprintln!("skipping capsule_step_reads_a_frozen_copy_of_its_inputs: no container runtime");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    Command::cargo_bin("attest")
        .unwrap()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success();
    capsule::init(dir.path(), "frozen", &image).expect("init");
    std::fs::write(dir.path().join("in.txt"), "original\n").unwrap();
    std::fs::write(
        dir.path().join("attest.yaml"),
        "version: \"1.0\"\nname: frozen\nsteps:\n  read:\n    run: \"touch started && sleep 2 && cat in.txt > out.txt && touch consumed && sleep 2\"\n    inputs: [\"in.txt\"]\n    outputs: [\"out.txt\"]\n    capsule: frozen\n    cache: false\n",
    )
    .unwrap();

    // Open before InputGuard drops the write bits, as a concurrent editor
    // could. A write through this descriptor really changes the host file;
    // ignoring permission errors would never exercise the snapshot.
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.path().join("in.txt"))
        .unwrap();
    let input = dir.path().join("in.txt");
    let started = dir.path().join("started");
    let consumed = dir.path().join("consumed");
    let tamper = std::thread::spawn(move || {
        use std::io::{Seek, SeekFrom, Write};
        let wait_for = |path: &Path| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while !path.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "capsule did not create {}",
                    path.display()
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        wait_for(&started);
        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.write_all(b"tampered\n").unwrap();
        writer.sync_all().unwrap();
        assert_eq!(std::fs::read_to_string(&input).unwrap(), "tampered\n");
        wait_for(&consumed);
        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.write_all(b"original\n").unwrap();
        writer.sync_all().unwrap();
    });
    let run = Command::cargo_bin("attest")
        .unwrap()
        .arg("run")
        .current_dir(dir.path())
        .output()
        .unwrap();
    tamper.join().unwrap();
    assert!(
        run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out.txt")).unwrap(),
        "original\n",
        "the step must have read the snapshot, not the host file"
    );
    let receipt_path = std::fs::read_dir(dir.path().join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "yaml"))
        .unwrap();
    let receipt: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(receipt_path).unwrap()).unwrap();
    let inputs = receipt["isolation"]["controls"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "inputs")
        .unwrap();
    assert_eq!(inputs["status"], "enforced", "{inputs:?}");
    let leftover = std::fs::read_dir(dir.path().join(".attest/snapshots"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(leftover, 0, "snapshot cleaned up");
}

/// A read-only bind mount is ineffective if the same backing files are
/// reachable through the writable workspace. Attempt the old alias from
/// inside a real capsule, then require both the original output and a
/// signed, recomputed receipt.
#[test]
fn capsule_cannot_rewrite_inputs_through_a_workspace_snapshot_alias() {
    let Some(image) = pulled_busybox_ref() else {
        eprintln!("skipping snapshot alias test: no container runtime");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    attest_cmd()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success();
    attest_cmd()
        .args(["keys", "generate", "--name", "test"])
        .current_dir(dir.path())
        .assert()
        .success();
    capsule::init(dir.path(), "frozen", &image).unwrap();
    std::fs::write(dir.path().join("in.txt"), "original\n").unwrap();
    let command = "for input in .attest/snapshots/*/in.txt; do if [ -f \"$input\" ]; then printf 'tampered\\n' > \"$input\"; fi; done; cat in.txt > out.txt";
    let pipeline = format!(
        "version: \"1.0\"\nname: alias\nsteps:\n  read:\n    run: {}\n    inputs: [\"in.txt\"]\n    outputs: [\"out.txt\"]\n    capsule: frozen\n    cache: false\n",
        serde_json::to_string(command).unwrap()
    );
    std::fs::write(dir.path().join("attest.yaml"), pipeline).unwrap();
    attest_cmd()
        .args(["run", "--sign"])
        .current_dir(dir.path())
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out.txt")).unwrap(),
        "original\n"
    );
    let receipt = std::fs::read_dir(dir.path().join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "yaml"))
        .unwrap();
    attest_cmd()
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--recompute",
            "--require",
            "signature,recompute,success",
        ])
        .current_dir(dir.path())
        .assert()
        .success();
}

/// Issue #39: the receipt declares a capsule's filesystem control as
/// enforced, so the control has to be shown to bite. The root filesystem
/// of a capsule is read-only: a write anywhere outside the workspace
/// mount fails, while the workspace itself stays writable for outputs.
#[test]
fn capsule_root_filesystem_is_read_only() {
    let Some(image) = pulled_busybox_ref() else {
        eprintln!("skipping capsule_root_filesystem_is_read_only: no container runtime");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    capsule::init(dir.path(), "rofs", &image).expect("init");
    let manifest = capsule::load(dir.path(), "rofs").expect("load");
    let output = capsule::run_captured(
        &manifest,
        dir.path(),
        &attest::capsule::InputMounts::none(),
        &[
            "sh".to_string(),
            "-c".to_string(),
            "touch /etc/planted 2>/dev/null || touch /usr/planted 2>/dev/null".to_string(),
        ],
    )
    .expect("run");
    assert!(
        !output.status.success(),
        "a write outside the workspace must fail in a capsule"
    );
    let output = capsule::run_captured(
        &manifest,
        dir.path(),
        &attest::capsule::InputMounts::none(),
        &[
            "sh".to_string(),
            "-c".to_string(),
            "echo out > out.txt".to_string(),
        ],
    )
    .expect("run");
    assert!(
        output.status.success(),
        "the workspace mount stays writable"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out.txt")).unwrap(),
        "out\n"
    );
}

/// A nested input's parent directory is a mount point inside the capsule,
/// so it cannot be moved aside and replaced. The attack renames `src`,
/// plants a substitute and reads it; the rename must fail, the step must
/// fail, and no output may carry the substituted bytes.
#[test]
fn capsule_cannot_substitute_a_nested_input_by_renaming_its_parent() {
    let Some(image) = pulled_busybox_ref() else {
        eprintln!("skipping capsule_cannot_substitute_a_nested_input_by_renaming_its_parent: no container runtime");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    attest_cmd()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success();
    capsule::init(dir.path(), "frozen", &image).unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/in.txt"), "original\n").unwrap();
    let command = "mv src src.orig && mkdir src && echo substituted > src/in.txt && cat src/in.txt > out.txt && rm -r src && mv src.orig src";
    let pipeline = format!(
        "version: \"1.0\"\nname: rename\nsteps:\n  read:\n    run: {}\n    inputs: [\"src/in.txt\"]\n    outputs: [\"out.txt\"]\n    capsule: frozen\n    cache: false\n",
        serde_json::to_string(command).unwrap()
    );
    std::fs::write(dir.path().join("attest.yaml"), pipeline).unwrap();
    let run = attest_cmd()
        .arg("run")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        !run.status.success(),
        "the rename must have failed the step"
    );
    assert!(
        !dir.path().join("out.txt").exists()
            || std::fs::read_to_string(dir.path().join("out.txt")).unwrap() != "substituted\n",
        "an output must never carry substituted input bytes"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("src/in.txt")).unwrap(),
        "original\n"
    );
}
