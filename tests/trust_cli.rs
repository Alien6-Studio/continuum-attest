//! Issue #15: the trust store as something you can hand to someone else.
//! `attest trust bundle` signs it; `attest trust show` says who issued it,
//! over what period it is valid, and whether anything in it was altered.

use assert_cmd::Command;
use predicates::prelude::*;
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

// ---------------------------------------------------------------------------
// Issue #16: trust material moves between machines as a file, never online.
// ---------------------------------------------------------------------------

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

fn producer_with_signed_receipt() -> (tempfile::TempDir, String, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    init(dir.path());
    std::fs::write(dir.path().join("attest.yaml"), TOY_PIPELINE).unwrap();
    std::fs::write(dir.path().join("in.txt"), "payload").unwrap();
    let key = generate(dir.path(), "builder");
    attest()
        .args(["run", "--sign", "--key", &key])
        .current_dir(dir.path())
        .assert()
        .success();
    let receipt = std::fs::read_dir(dir.path().join(".attest/receipts"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "yaml"))
        .unwrap();
    (dir, key, receipt)
}

fn bundle_to(dir: &Path, file: &str, extra: &[&str]) -> std::path::PathBuf {
    let path = dir.join(file);
    let mut args = vec!["trust", "bundle", "--output", path.to_str().unwrap()];
    args.extend_from_slice(extra);
    attest().args(&args).current_dir(dir).assert().success();
    path
}

fn verify_with(producer: &Path, receipt: &Path, trust: &Path) -> i32 {
    attest()
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--trust-store",
            trust.to_str().unwrap(),
        ])
        .current_dir(producer)
        .output()
        .unwrap()
        .status
        .code()
        .unwrap()
}

/// Export on machine A, import on machine B, verify on B; then revoke on
/// A, refresh B from the newer bundle, and B refuses what A revoked. B
/// never had a network, and B learns what each import changed.
#[test]
fn a_bundle_carries_trust_and_then_revocation_to_another_machine() {
    let (producer, key, receipt) = producer_with_signed_receipt();
    let first = bundle_to(producer.path(), "b1.json", &[]);

    let recipient = tempfile::tempdir().unwrap();
    init(recipient.path());
    let trust = recipient.path().join(".attest/trust");

    // The first bundle from an issuer is accepted only against an issuer
    // the recipient already expects.
    attest()
        .args(["trust", "import", first.to_str().unwrap()])
        .current_dir(recipient.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("name the issuer you expect"));
    attest()
        .args([
            "trust",
            "import",
            first.to_str().unwrap(),
            "--issuer",
            "00000000000000000000000000000000",
        ])
        .current_dir(recipient.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("but you expected"));
    assert_eq!(verify_with(producer.path(), &receipt, &trust), 1);

    attest()
        .args(["trust", "import", first.to_str().unwrap(), "--issuer", &key])
        .current_dir(recipient.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("added"))
        .stdout(predicates::str::contains("builder"))
        .stdout(predicates::str::contains("1 added, 0 revoked"));
    assert_eq!(verify_with(producer.path(), &receipt, &trust), 0);

    // Revoke on A, refresh B. Sequence is issued_at in seconds, so a
    // newer bundle needs a later second.
    attest()
        .args(["keys", "revoke", &key])
        .current_dir(producer.path())
        .assert()
        .success();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // A revoked key cannot issue; a second, trusted key signs the update.
    let successor = generate(producer.path(), "builder-2");
    let second = bundle_to(producer.path(), "b2.json", &["--key", &successor]);
    // ...which B has not pinned: refused, whatever it contains.
    attest()
        .args(["trust", "refresh", second.to_str().unwrap()])
        .current_dir(recipient.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("name the issuer you expect"));
    attest()
        .args([
            "trust",
            "refresh",
            second.to_str().unwrap(),
            "--issuer",
            &successor,
        ])
        .current_dir(recipient.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("revoked"))
        .stdout(predicates::str::contains("builder-2"));
    assert_eq!(
        verify_with(producer.path(), &receipt, &trust),
        1,
        "the revocation arrived and the receipt is now refused"
    );
    attest()
        .args(["keys", "list"])
        .current_dir(recipient.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("revoked"))
        .stdout(predicates::str::contains("public only"));

    // The same bundle again is a no-op, not an error.
    attest()
        .args(["trust", "import", second.to_str().unwrap()])
        .current_dir(recipient.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("already current"));
}

/// Stale trust material is reported, not used, and never fetched.
#[test]
fn an_expired_bundle_is_not_imported() {
    let tmp = tempfile::tempdir().unwrap();
    init(tmp.path());
    let key = generate(tmp.path(), "release");
    let path = bundle(tmp.path(), &["--valid-for", "0"]);
    std::thread::sleep(std::time::Duration::from_millis(50));

    let recipient = tempfile::tempdir().unwrap();
    init(recipient.path());
    attest()
        .args(["trust", "import", path.to_str().unwrap(), "--issuer", &key])
        .current_dir(recipient.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("expired"));
    assert!(!recipient
        .path()
        .join(".attest/trust")
        .join(format!("{key}.pub"))
        .exists());
}

/// A revocation decided locally is not undone by a bundle that still
/// trusts the key. The recipient is told, and the key stays revoked.
#[test]
fn a_bundle_does_not_unrevoke_a_local_decision() {
    let tmp = tempfile::tempdir().unwrap();
    init(tmp.path());
    let issuer = generate(tmp.path(), "release");
    let worker = generate(tmp.path(), "worker");
    let first = bundle_to(tmp.path(), "b1.json", &["--key", &issuer]);

    let recipient = tempfile::tempdir().unwrap();
    init(recipient.path());
    attest()
        .args([
            "trust",
            "import",
            first.to_str().unwrap(),
            "--issuer",
            &issuer,
        ])
        .current_dir(recipient.path())
        .assert()
        .code(0);
    attest()
        .args(["keys", "revoke", &worker])
        .current_dir(recipient.path())
        .assert()
        .success();

    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second = bundle_to(tmp.path(), "b2.json", &["--key", &issuer]);
    attest()
        .args(["trust", "import", second.to_str().unwrap()])
        .current_dir(recipient.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("kept"))
        .stdout(predicates::str::contains("does not un-revoke"));
    attest()
        .args(["keys", "list"])
        .current_dir(recipient.path())
        .assert()
        .stdout(predicates::str::contains(&worker).and(predicates::str::contains("revoked")));
}

// ---------------------------------------------------------------------------
// Issue #17: pin who you trust, and make replacing them a deliberate act.
// ---------------------------------------------------------------------------

/// The authority stepping down names its successor in its own signed
/// bundle. The recipient, who pinned the old authority, accepts the new
/// one's first bundle on that basis and is told a handover happened. A
/// stranger with a well-formed bundle is still a stranger. And a key
/// rotated out keeps the signatures it made while it was trusted.
#[test]
fn a_handover_is_declared_by_the_outgoing_authority() {
    let (producer, old, receipt) = producer_with_signed_receipt();
    let new = generate(producer.path(), "builder-next");

    // A successor has to be a key the store already trusts.
    attest()
        .args([
            "trust",
            "bundle",
            "--output",
            "x.json",
            "--key",
            &old,
            "--successor",
            "00000000000000000000000000000000",
        ])
        .current_dir(producer.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("not in the trust store"));

    let first = bundle_to(
        producer.path(),
        "b1.json",
        &["--key", &old, "--successor", &new],
    );
    attest()
        .args(["trust", "show", first.to_str().unwrap()])
        .current_dir(producer.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains(format!("successor    {new}")))
        .stdout(predicates::str::contains("hands over to"));

    let recipient = tempfile::tempdir().unwrap();
    init(recipient.path());
    let trust = recipient.path().join(".attest/trust");
    attest()
        .args(["trust", "import", first.to_str().unwrap(), "--issuer", &old])
        .current_dir(recipient.path())
        .assert()
        .code(0);
    assert_eq!(verify_with(producer.path(), &receipt, &trust), 0);

    // The old authority retires: revoked, and the successor issues.
    attest()
        .args(["keys", "revoke", &old])
        .current_dir(producer.path())
        .assert()
        .success();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second = bundle_to(producer.path(), "b2.json", &["--key", &new]);
    attest()
        .args(["trust", "import", second.to_str().unwrap()])
        .current_dir(recipient.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains(format!(
            "handover: {old} named {new}"
        )))
        .stdout(predicates::str::contains("revoked"));

    // Rotation did not invalidate what the old key signed while trusted:
    // the receipt is judged on its own merits, exactly as any revocation.
    assert_eq!(verify_with(producer.path(), &receipt, &trust), 1);
    attest()
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--trust-store",
            trust.to_str().unwrap(),
            "--trust-receipt-timestamp",
        ])
        .current_dir(producer.path())
        .assert()
        .code(0)
        .stderr(predicates::str::contains("signed by key revoked later"));

    // A stranger: well-formed, self-vouching, never pinned, never named.
    let stranger = tempfile::tempdir().unwrap();
    init(stranger.path());
    let _z = generate(stranger.path(), "stranger");
    let theirs = bundle_to(stranger.path(), "z.json", &[]);
    attest()
        .args(["trust", "import", theirs.to_str().unwrap()])
        .current_dir(recipient.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("name the issuer you expect"));
}

// ---------------------------------------------------------------------------
// Issue #18: a verdict says how old its trust material is.
// ---------------------------------------------------------------------------

/// The verdict states the bundle its revocations are current up to, judged
/// by the local clock and saying so; an expired bundle turns into a
/// warning, not a failure, and a store with no bundle on record says that
/// too. Nothing here is fetched.
#[test]
fn a_verdict_states_the_period_its_trust_material_covers() {
    let (producer, key, receipt) = producer_with_signed_receipt();
    let first = bundle_to(producer.path(), "b1.json", &["--valid-for", "30"]);
    let recipient = tempfile::tempdir().unwrap();
    init(recipient.path());
    let trust = recipient.path().join(".attest/trust");

    let verdict = |extra: &[&str]| -> (i32, String, String) {
        let mut args = vec![
            "verify",
            receipt.to_str().unwrap(),
            "--trust-store",
            trust.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        let out = attest()
            .args(&args)
            .current_dir(producer.path())
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    };

    // Nothing on record yet: said plainly, in text and in the contract.
    let (_, text, _) = verdict(&[]);
    assert!(
        text.contains("trust material: no bundle on record"),
        "{text}"
    );
    let (_, json, _) = verdict(&["--format", "json"]);
    let record: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
    assert_eq!(record["trust_material"]["state"], "none");
    assert_eq!(record["trust_material"]["judged_by"], "local clock");

    attest()
        .args(["trust", "import", first.to_str().unwrap(), "--issuer", &key])
        .current_dir(recipient.path())
        .assert()
        .success();
    let (code, text, stderr) = verdict(&[]);
    assert_eq!(code, 0);
    assert!(text.contains(&format!("trust material: bundle")), "{text}");
    assert!(
        text.contains(&key) && text.contains("valid until"),
        "{text}"
    );
    assert!(!stderr.contains("expired"), "{stderr}");
    let (_, json, _) = verdict(&["--format", "json"]);
    let record: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
    assert_eq!(record["trust_material"]["state"], "current");
    assert_eq!(record["trust_material"]["issuer"], key);
    assert!(record["trust_material"]["sequence"].is_u64());
    assert!(record["trust_material"]["valid_until"].is_string());

    // Time passes: the accepted bundle is local state, like trust.toml, so
    // its window can be moved into the past the way a test moves a clock.
    let accepted = trust.join("bundles").join(format!("{key}.json"));
    let mut stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&accepted).unwrap()).unwrap();
    stored["valid_until"] = serde_json::Value::String("2020-01-01T00:00:00Z".into());
    std::fs::write(&accepted, serde_json::to_string(&stored).unwrap()).unwrap();

    let (code, text, stderr) = verdict(&[]);
    assert_eq!(code, 0, "expiry is a warning for policy, not a failure");
    assert!(text.contains("expired at 2020-01-01"), "{text}");
    assert!(
        stderr.contains("expired at 2020-01-01")
            && stderr.contains("revocations issued after bundle"),
        "{stderr}"
    );
    let (_, json, _) = verdict(&["--format", "json"]);
    let record: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
    assert_eq!(record["trust_material"]["state"], "expired");
}
