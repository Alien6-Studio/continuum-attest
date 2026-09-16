//! Issue #10 acceptance criteria: `attest image sign` drives cosign with
//! the exact normative argv, enforces the digest-only and clean-tree
//! preconditions, and writes a verifiable signing receipt.
//!
//! cosign is replaced by a shell shim on PATH that answers `version`
//! with `GitVersion: v2.4.0` and records the argv of every other call.

use assert_cmd::Command;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const DIGEST: &str =
    "registry.example/repo@sha256:8f3c1a2b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";

struct SignFixture {
    /// Owns the workspace and shim directories for the test's lifetime.
    _tmp: tempfile::TempDir,
    repo: PathBuf,
    shim_path: String,
    argv_file: PathBuf,
}

/// `attest` command with PATH restricted to the cosign shim plus the
/// system dirs (for `git`), so `which("cosign")` resolves to the shim.
fn attest(fixture: &SignFixture) -> Command {
    let mut cmd = Command::cargo_bin("attest").expect("attest binary builds");
    cmd.current_dir(&fixture.repo)
        .env("PATH", &fixture.shim_path);
    cmd
}

fn git(repo: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {:?} failed", args);
}

fn git_head(repo: &Path) -> String {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .expect("git rev-parse runs");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Build a committed git repo with `attest init` layout and a cosign
/// shim (GitVersion v2.4.0, argv capture) first on PATH.
fn fixture() -> SignFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    let shim_dir = tmp.path().join("shim");
    std::fs::create_dir_all(&repo).expect("repo dir");
    std::fs::create_dir_all(&shim_dir).expect("shim dir");

    let argv_file = tmp.path().join("cosign-argv.txt");
    let shim = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = version ]; then\n\
         \techo 'GitVersion:    v2.4.0'\n\
         \texit 0\n\
         fi\n\
         printf '%s\\n' \"$@\" >> '{}'\n\
         echo 'tlog entry created with index: 42'\n",
        argv_file.display()
    );
    let cosign = shim_dir.join("cosign");
    std::fs::write(&cosign, shim).expect("write shim");
    std::fs::set_permissions(&cosign, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");

    git(&repo, &["init", "--quiet"]);
    git(&repo, &["config", "user.email", "test@example.com"]);
    git(&repo, &["config", "user.name", "Test"]);

    let fixture = SignFixture {
        shim_path: format!("{}:/usr/bin:/bin", shim_dir.display()),
        _tmp: tmp,
        repo: repo.clone(),
        argv_file,
    };
    attest(&fixture).arg("init").assert().success();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "--quiet", "-m", "initial"]);
    fixture
}

fn recorded_argv(fixture: &SignFixture) -> Vec<String> {
    std::fs::read_to_string(&fixture.argv_file)
        .expect("cosign argv recorded")
        .lines()
        .map(str::to_string)
        .collect()
}

/// Criterion 1+2: signing runs cosign with the exact normative argv,
/// deriving `continuum.git.revision` from HEAD, and exits 0.
#[test]
fn sign_invokes_cosign_with_normative_argv() {
    let fixture = fixture();
    let head = git_head(&fixture.repo);

    attest(&fixture)
        .args([
            "image",
            "sign",
            DIGEST,
            "--key",
            "azurekms://vault.vault.azure.net/keys/signing/1",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains(format!(
            "signed {DIGEST} (revision {head})"
        )));

    assert_eq!(
        recorded_argv(&fixture),
        vec![
            "sign".to_string(),
            "--yes".to_string(),
            "--key".to_string(),
            "azurekms://vault.vault.azure.net/keys/signing/1".to_string(),
            "-a".to_string(),
            format!("continuum.git.revision={head}"),
            DIGEST.to_string(),
        ]
    );
}

/// Extra annotations are passed sorted, before the digest reference.
#[test]
fn extra_annotations_are_sorted_into_argv() {
    let fixture = fixture();
    let head = git_head(&fixture.repo);

    attest(&fixture)
        .args([
            "image",
            "sign",
            DIGEST,
            "--key",
            "azurekms://v/keys/k/1",
            "--annotation",
            "org.opencontainers.image.source=https://example.com",
            "--annotation",
            "app=demo",
        ])
        .assert()
        .success();

    assert_eq!(
        recorded_argv(&fixture),
        vec![
            "sign".to_string(),
            "--yes".to_string(),
            "--key".to_string(),
            "azurekms://v/keys/k/1".to_string(),
            "-a".to_string(),
            "app=demo".to_string(),
            "-a".to_string(),
            format!("continuum.git.revision={head}"),
            "-a".to_string(),
            "org.opencontainers.image.source=https://example.com".to_string(),
            DIGEST.to_string(),
        ]
    );
}

/// Criterion 3 (IMG-2): a tag reference is an operational error (exit 2)
/// with the normative message, and cosign is never invoked.
#[test]
fn tag_reference_exits_two_without_calling_cosign() {
    let fixture = fixture();

    attest(&fixture)
        .args([
            "image",
            "sign",
            "registry.example/repo:v1.2.3",
            "--key",
            "azurekms://v/keys/k/1",
        ])
        .assert()
        .code(2)
        .stderr(predicates::str::contains(
            "signing requires a digest reference (repo@sha256:...), got tag 'registry.example/repo:v1.2.3'",
        ));

    assert!(!fixture.argv_file.exists(), "cosign must not be invoked");
}

/// Criterion 4 (IMG-6): a dirty tree is a precondition failure (exit 1)
/// naming the dirty paths; `--no-require-clean-tree` overrides it.
#[test]
fn dirty_tree_exits_one_naming_paths() {
    let fixture = fixture();
    std::fs::write(fixture.repo.join("scratch.txt"), "wip").expect("write");

    attest(&fixture)
        .args(["image", "sign", DIGEST, "--key", "azurekms://v/keys/k/1"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("refusing to sign"))
        .stderr(predicates::str::contains("scratch.txt"))
        .stderr(predicates::str::contains("--no-require-clean-tree"));
    assert!(!fixture.argv_file.exists(), "cosign must not be invoked");

    attest(&fixture)
        .args([
            "image",
            "sign",
            DIGEST,
            "--key",
            "azurekms://v/keys/k/1",
            "--no-require-clean-tree",
        ])
        .assert()
        .success();
    assert!(fixture.argv_file.exists());
}

/// `--clean-paths` restricts the dirty check to the given paths.
#[test]
fn clean_paths_scope_the_dirty_check() {
    let fixture = fixture();
    std::fs::write(fixture.repo.join("scratch.txt"), "wip").expect("write");

    attest(&fixture)
        .args([
            "image",
            "sign",
            DIGEST,
            "--key",
            "azurekms://v/keys/k/1",
            "--clean-paths",
            "src",
        ])
        .assert()
        .success();
}

/// A non-KMS key URI is refused without `--allow-file-key` (IMG-3).
#[test]
fn file_key_requires_escape_hatch() {
    let fixture = fixture();

    attest(&fixture)
        .args(["image", "sign", DIGEST, "--key", "./cosign.key"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--allow-file-key"));

    attest(&fixture)
        .args([
            "image",
            "sign",
            DIGEST,
            "--key",
            "./cosign.key",
            "--allow-file-key",
        ])
        .assert()
        .success();
}

/// Criterion 5 (IMG-11): a signed receipt is written and passes
/// `attest verify`.
#[test]
fn signed_receipt_passes_attest_verify() {
    let fixture = fixture();

    let output = attest(&fixture)
        .args([
            "image",
            "sign",
            DIGEST,
            "--key",
            "azurekms://v/keys/k/1",
            "--sign",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);
    let receipt_path = stdout
        .lines()
        .last()
        .expect("receipt path printed")
        .trim()
        .to_string();
    assert!(
        Path::new(&receipt_path).is_file(),
        "receipt not found at {receipt_path}"
    );

    let receipt: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&receipt_path).expect("read receipt"))
            .expect("receipt parses");
    assert_eq!(receipt["steps"][0]["name"].as_str(), Some("image-sign"));
    assert_eq!(receipt["steps"][0]["exit_code"].as_i64(), Some(0));
    assert!(
        receipt["signature"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "receipt must be signed"
    );

    attest(&fixture)
        .args(["verify", &receipt_path])
        .assert()
        .success();
}

/// A cosign older than the 2.2 floor is refused (exit 2).
#[test]
fn old_cosign_is_refused() {
    let fixture = fixture();
    // Overwrite the shim with an old version.
    let shim_dir = PathBuf::from(
        fixture
            .shim_path
            .split(':')
            .next()
            .expect("shim dir on PATH"),
    );
    std::fs::write(
        shim_dir.join("cosign"),
        "#!/bin/sh\necho 'GitVersion:    v2.1.9'\n",
    )
    .expect("rewrite shim");

    attest(&fixture)
        .args(["image", "sign", DIGEST, "--key", "azurekms://v/keys/k/1"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("too old"));
}
