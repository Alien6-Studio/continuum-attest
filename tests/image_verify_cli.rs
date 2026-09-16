//! Issue #11 acceptance criteria: enriched `attest image verify` drives
//! `docker buildx imagetools inspect` and `cosign` with the exact
//! normative argv, enforces IMG-7..IMG-10, and reports per IMG-12.
//!
//! `docker` and `cosign` are replaced by shell shims on PATH that
//! record their argv and replay committed fixture JSON.

use assert_cmd::Command;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const DIGEST: &str =
    "registry.example/gateway@sha256:8f3c1a2b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";
/// Revision recorded in `tests/fixtures/imagetools/provenance_slsa_v1.json`.
const FIXTURE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const KMS_URI: &str = "azurekms://vault.vault.azure.net/keys/signing/1";

struct VerifyFixture {
    _tmp: tempfile::TempDir,
    shim_path: String,
    docker_argv: PathBuf,
    cosign_argv: PathBuf,
    sbom_fixture: PathBuf,
    provenance_fixture: PathBuf,
    kms_export_empty: bool,
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/imagetools")
        .join(name)
}

fn write_shim(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write shim");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
}

/// Shims for docker (fixture replay) and cosign (public-key export +
/// verify), both recording argv invocation-by-invocation.
fn fixture() -> VerifyFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let shim_dir = tmp.path().join("shim");
    std::fs::create_dir_all(&shim_dir).expect("shim dir");

    let docker_argv = tmp.path().join("docker-argv.txt");
    let cosign_argv = tmp.path().join("cosign-argv.txt");

    write_shim(
        &shim_dir,
        "docker",
        &format!(
            "#!/bin/sh\n\
             {{ printf '%s\\n' \"$@\"; echo '===='; }} >> '{}'\n\
             case \"$6\" in\n\
             *SBOM*) cat \"$SBOM_FIXTURE\" ;;\n\
             *Provenance*) cat \"$PROVENANCE_FIXTURE\" ;;\n\
             *) echo 'unexpected docker argv' >&2; exit 64 ;;\n\
             esac\n",
            docker_argv.display()
        ),
    );
    write_shim(
        &shim_dir,
        "cosign",
        &format!(
            "#!/bin/sh\n\
             {{ printf '%s\\n' \"$@\"; echo '===='; }} >> '{}'\n\
             if [ \"$1\" = public-key ]; then\n\
             \tif [ \"${{KMS_EXPORT_EMPTY:-0}}\" = 1 ]; then exit 0; fi\n\
             \tprintf -- '-----BEGIN PUBLIC KEY-----\\nMFkw\\n-----END PUBLIC KEY-----\\n' > \"$5\"\n\
             fi\n\
             exit 0\n",
            cosign_argv.display()
        ),
    );

    VerifyFixture {
        shim_path: format!("{}:/usr/bin:/bin", shim_dir.display()),
        _tmp: tmp,
        docker_argv,
        cosign_argv,
        sbom_fixture: fixture_path("sbom_single.json"),
        provenance_fixture: fixture_path("provenance_slsa_v1.json"),
        kms_export_empty: false,
    }
}

fn attest(fixture: &VerifyFixture) -> Command {
    let mut cmd = Command::cargo_bin("attest").expect("attest binary builds");
    cmd.env("PATH", &fixture.shim_path)
        .env("SBOM_FIXTURE", &fixture.sbom_fixture)
        .env("PROVENANCE_FIXTURE", &fixture.provenance_fixture)
        .env(
            "KMS_EXPORT_EMPTY",
            if fixture.kms_export_empty { "1" } else { "0" },
        );
    cmd
}

/// Recorded invocations: one Vec<String> of argv per call.
fn recorded(argv_file: &Path) -> Vec<Vec<String>> {
    let Ok(text) = std::fs::read_to_string(argv_file) else {
        return vec![];
    };
    let mut calls = vec![];
    let mut current = vec![];
    for line in text.lines() {
        if line == "====" {
            calls.push(std::mem::take(&mut current));
        } else {
            current.push(line.to_string());
        }
    }
    calls
}

/// Criteria 1+2: a fully enforced verification passes end to end and
/// every external call carries the exact normative argv.
#[test]
fn full_verification_records_exact_argv() {
    let fixture = fixture();

    let output = attest(&fixture)
        .args([
            "image",
            "verify",
            DIGEST,
            "--require-sbom",
            "--require-provenance",
            "--expected-revision",
            FIXTURE_REVISION,
            "--key",
            KMS_URI,
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let report: serde_json::Value = serde_json::from_slice(&output).expect("json report on stdout");
    assert_eq!(report["image"].as_str(), Some(DIGEST));
    assert_eq!(report["verdict"].as_str(), Some("pass"));
    let checks = report["checks"].as_array().expect("checks array");
    assert_eq!(checks.len(), 4);
    for name in ["sbom", "provenance", "revision", "signature"] {
        let check = checks
            .iter()
            .find(|c| c["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("check {name} missing"));
        assert_eq!(check["status"].as_str(), Some("pass"), "{name}");
    }

    // Exact inspect argv (IMG-7/IMG-8).
    let docker_calls = recorded(&fixture.docker_argv);
    assert_eq!(
        docker_calls,
        vec![
            vec![
                "buildx".to_string(),
                "imagetools".to_string(),
                "inspect".to_string(),
                DIGEST.to_string(),
                "--format".to_string(),
                "{{json .SBOM}}".to_string(),
            ],
            vec![
                "buildx".to_string(),
                "imagetools".to_string(),
                "inspect".to_string(),
                DIGEST.to_string(),
                "--format".to_string(),
                "{{json .Provenance}}".to_string(),
            ],
        ]
    );

    // Exact cosign argv: KMS export (IMG-10) then verify with the
    // revision annotation (IMG-9).
    let cosign_calls = recorded(&fixture.cosign_argv);
    assert_eq!(cosign_calls.len(), 2);
    let export = &cosign_calls[0];
    assert_eq!(export[0..4], ["public-key", "--key", KMS_URI, "--outfile"]);
    assert!(export[4].ends_with("cosign.pub"), "{export:?}");
    let verify = &cosign_calls[1];
    assert_eq!(verify[0], "verify");
    assert_eq!(verify[1], "--key");
    assert_eq!(verify[2], export[4], "verify must use the exported key");
    assert_eq!(
        verify[3..],
        [
            "-a".to_string(),
            format!("continuum.git.revision={FIXTURE_REVISION}"),
            DIGEST.to_string(),
        ]
    );
}

/// Criterion 3: an expected-revision mismatch against SLSA v1 is exit 1
/// with the `revision` check failing and both revisions named.
#[test]
fn revision_mismatch_exits_one_naming_both() {
    let fixture = fixture();
    let other = "f".repeat(40);

    let output = attest(&fixture)
        .args([
            "image",
            "verify",
            DIGEST,
            "--expected-revision",
            &other,
            "--format",
            "json",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let report: serde_json::Value = serde_json::from_slice(&output).expect("json report on stdout");
    assert_eq!(report["verdict"].as_str(), Some("fail"));
    let revision = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["name"].as_str() == Some("revision"))
        .expect("revision check present")
        .clone();
    assert_eq!(revision["status"].as_str(), Some("fail"));
    let detail = revision["detail"].as_str().expect("detail");
    assert!(detail.contains(&other), "{detail}");
    assert!(detail.contains(FIXTURE_REVISION), "{detail}");
}

/// Criterion 4: a tag reference with any supply-chain flag is an
/// operational error (exit 2) before any external call.
#[test]
fn tag_ref_with_require_sbom_exits_two() {
    let fixture = fixture();

    attest(&fixture)
        .args([
            "image",
            "verify",
            "registry.example/gateway:v1.2.3",
            "--require-sbom",
        ])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("digest reference"));

    assert!(!fixture.docker_argv.exists(), "docker must not be invoked");
    assert!(!fixture.cosign_argv.exists(), "cosign must not be invoked");
}

/// A malformed --expected-revision is an operational error (exit 2).
#[test]
fn malformed_expected_revision_exits_two() {
    let fixture = fixture();

    attest(&fixture)
        .args(["image", "verify", DIGEST, "--expected-revision", "deadbeef"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("continuum.git.revision"));
}

/// IMG-10: an empty KMS public-key export is an operational error.
#[test]
fn empty_kms_export_exits_two() {
    let mut fixture = fixture();
    fixture.kms_export_empty = true;

    attest(&fixture)
        .args(["image", "verify", DIGEST, "--key", KMS_URI])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("did not export a public key"));
}

/// A file-based public key is used directly: no public-key export call.
#[test]
fn file_key_skips_kms_export() {
    let fixture = fixture();
    let public_key = fixture._tmp.path().join("verifier.pub");
    std::fs::write(&public_key, "-----BEGIN PUBLIC KEY-----\n").expect("write key");

    attest(&fixture)
        .args([
            "image",
            "verify",
            DIGEST,
            "--key",
            public_key.to_str().expect("utf8 path"),
        ])
        .assert()
        .success();

    let cosign_calls = recorded(&fixture.cosign_argv);
    assert_eq!(cosign_calls.len(), 1);
    assert_eq!(
        cosign_calls[0],
        vec![
            "verify".to_string(),
            "--key".to_string(),
            public_key.to_string_lossy().to_string(),
            DIGEST.to_string(),
        ]
    );
}

/// A structurally broken SBOM fails the sbom check (exit 1) with the
/// violated clause in the detail.
#[test]
fn broken_sbom_fails_check() {
    let mut fixture = fixture();
    let broken = fixture._tmp.path().join("broken_sbom.json");
    let mut sbom: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture_path("sbom_single.json")).expect("fixture"),
    )
    .expect("fixture parses");
    sbom["SPDX"]["packages"] = serde_json::json!("not-an-array");
    std::fs::write(&broken, serde_json::to_string(&sbom).expect("serialize")).expect("write");
    fixture.sbom_fixture = broken;

    attest(&fixture)
        .args([
            "image",
            "verify",
            DIGEST,
            "--require-sbom",
            "--format",
            "json",
        ])
        .assert()
        .code(1)
        .stdout(predicates::str::contains("packages is not an array"));
}

/// Issue #12 criterion 4: `--sign-receipt` writes a signed verification
/// receipt under `.attest/receipts/` that passes `attest verify`.
#[test]
fn signed_verification_receipt_passes_attest_verify() {
    let fixture = fixture();

    // Attest workspace with a local receipt-signing key.
    let repo = fixture._tmp.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo dir");
    attest(&fixture)
        .current_dir(&repo)
        .arg("init")
        .assert()
        .success();

    let output = attest(&fixture)
        .current_dir(&repo)
        .args([
            "image",
            "verify",
            DIGEST,
            "--require-sbom",
            "--require-provenance",
            "--expected-revision",
            FIXTURE_REVISION,
            "--key",
            KMS_URI,
            "--sign-receipt",
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
        receipt_path.contains(".attest") && receipt_path.contains("image-verify"),
        "unexpected receipt path {receipt_path}"
    );
    assert!(
        Path::new(&receipt_path).is_file(),
        "receipt not found at {receipt_path}"
    );

    let receipt: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&receipt_path).expect("read receipt"))
            .expect("receipt parses");
    assert_eq!(receipt["steps"][0]["name"].as_str(), Some("image-verify"));
    assert_eq!(receipt["steps"][0]["exit_code"].as_i64(), Some(0));
    assert!(
        receipt["signature"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "receipt must be signed"
    );

    attest(&fixture)
        .current_dir(&repo)
        .args(["verify", &receipt_path])
        .assert()
        .success();
}
