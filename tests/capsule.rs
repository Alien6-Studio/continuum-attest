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
