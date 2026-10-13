//! Issue #15: the trust store as something you can hand to someone else.
//! `attest trust bundle` signs it; `attest trust show` says who issued it,
//! over what period it is valid, and whether anything in it was altered.

use assert_cmd::Command;
use std::path::Path;

fn attest() -> Command {
    Command::cargo_bin("attest").expect("attest binary builds")
}

fn init(dir: &Path) {
    attest().arg("init").current_dir(dir).assert().success();
}

fn generate(dir: &Path, name: &str) -> String {
    let out = attest()
        .args(["keys", "generate", "--name", name])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn bundle(dir: &Path, extra: &[&str]) -> std::path::PathBuf {
    let path = dir.join("bundle.json");
    let mut args = vec!["trust", "bundle", "--output", path.to_str().unwrap()];
    args.extend_from_slice(extra);
    attest().args(&args).current_dir(dir).assert().success();
    path
}

fn show_json(dir: &Path, path: &Path) -> (i32, serde_json::Value) {
    let out = attest()
        .args(["trust", "show", path.to_str().unwrap(), "--format", "json"])
        .current_dir(dir)
        .output()
        .unwrap();
    let report = serde_json::from_slice(&out.stdout).expect("show --format json is JSON");
    (out.status.code().unwrap(), report)
}

/// A recipient learns who issued the bundle, over what period, and which
/// keys it vouches for or revokes, each revocation dated.
#[test]
fn bundle_says_who_issued_it_until_when_and_what_it_covers() {
    let tmp = tempfile::tempdir().unwrap();
    init(tmp.path());
    let issuer = generate(tmp.path(), "release");
    let doomed = generate(tmp.path(), "ci-runner");
    attest()
        .args(["keys", "revoke", &doomed])
        .current_dir(tmp.path())
        .assert()
        .success();

    let path = bundle(tmp.path(), &["--key", &issuer, "--valid-for", "30"]);

    attest()
        .args(["trust", "show", path.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains(": pass"))
        .stdout(predicates::str::contains(&issuer))
        .stdout(predicates::str::contains("ci-runner"))
        .stdout(predicates::str::contains("revoked at"))
        .stdout(predicates::str::contains("valid signature by issuer"));

    let (code, report) = show_json(tmp.path(), &path);
    assert_eq!(code, 0);
    assert_eq!(report["verdict"], "pass");
    assert_eq!(report["issuer"]["key_id"], issuer);
    assert_eq!(report["keys"].as_array().unwrap().len(), 2);
    let revoked = report["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == doomed)
        .expect("the revoked key is in the bundle");
    assert_eq!(revoked["status"], "revoked");
    assert!(
        revoked["revoked_at"].is_string(),
        "a revocation carries its moment"
    );
    let issued =
        chrono::DateTime::parse_from_rfc3339(report["issued_at"].as_str().unwrap()).unwrap();
    let until =
        chrono::DateTime::parse_from_rfc3339(report["valid_until"].as_str().unwrap()).unwrap();
    assert_eq!((until - issued).num_days(), 30);
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["passed"] == true));
}

/// The signature is not decoration: a bundle edited after signing is
/// reported as altered, with the verdict and the exit code to match.
#[test]
fn an_altered_bundle_is_reported_as_such() {
    let tmp = tempfile::tempdir().unwrap();
    init(tmp.path());
    let _issuer = generate(tmp.path(), "release");
    let path = bundle(tmp.path(), &[]);

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"name\": \"release\""));
    std::fs::write(
        &path,
        text.replace("\"name\": \"release\"", "\"name\": \"renamed\""),
    )
    .unwrap();

    attest()
        .args(["trust", "show", path.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains(": fail"))
        .stdout(predicates::str::contains("altered after signing"));
}

/// Validity is a window, and `show` says where `now` stands relative to it.
#[test]
fn an_expired_bundle_is_reported_as_expired() {
    let tmp = tempfile::tempdir().unwrap();
    init(tmp.path());
    let _issuer = generate(tmp.path(), "release");
    let path = bundle(tmp.path(), &["--valid-for", "0"]);
    std::thread::sleep(std::time::Duration::from_millis(50));

    attest()
        .args(["trust", "show", path.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("expired at"))
        // Everything else still holds; expiry is the one failed check.
        .stdout(predicates::str::contains("valid signature by issuer"));
}

/// A bundle from a version this reader does not know is refused, not
/// guessed at.
#[test]
fn an_unknown_schema_version_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    init(tmp.path());
    let _issuer = generate(tmp.path(), "release");
    let path = bundle(tmp.path(), &[]);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replace("\"schema_version\": 1", "\"schema_version\": 2"),
    )
    .unwrap();

    attest()
        .args(["trust", "show", path.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("unsupported bundle schema 2"));
}

/// A revoked key cannot issue a bundle, and a store with nothing in it
/// has nothing to bundle.
#[test]
fn producing_a_bundle_needs_a_trusted_issuer() {
    let tmp = tempfile::tempdir().unwrap();
    init(tmp.path());
    attest()
        .args(["trust", "bundle", "--output", "b.json"])
        .current_dir(tmp.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("no managed signing key"));

    let key = generate(tmp.path(), "release");
    attest()
        .args(["keys", "revoke", &key])
        .current_dir(tmp.path())
        .assert()
        .success();
    attest()
        .args(["trust", "bundle", "--output", "b.json", "--key", &key])
        .current_dir(tmp.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("revoked"));
    assert!(!tmp.path().join("b.json").exists());
}

/// The existing trust store is untouched by bundling: same files, same
/// bytes, before and after.
#[test]
fn bundling_leaves_the_trust_store_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    init(tmp.path());
    let _issuer = generate(tmp.path(), "release");
    let before = std::fs::read_to_string(tmp.path().join(".attest/trust/trust.toml")).unwrap();
    bundle(tmp.path(), &[]);
    let after = std::fs::read_to_string(tmp.path().join(".attest/trust/trust.toml")).unwrap();
    assert_eq!(before, after);
}
