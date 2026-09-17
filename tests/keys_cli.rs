//! Issue #6 acceptance criteria: `attest keys` key lifecycle and trust
//! store, exercised via the built binary.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

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

fn generate(dir: &Path, name: &str) -> String {
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

/// Criterion 1: generate creates key material with the right modes, list
/// shows the entry, and the key id matches the blake3 derivation.
#[test]
fn generate_creates_key_with_derived_id() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(tmp.path());

    let id = generate(tmp.path(), "ci-master");
    assert_eq!(id.len(), 32, "key id is hex of 16 bytes");

    let private = tmp.path().join(".attest/keys").join(format!("{}.key", id));
    let public = tmp.path().join(".attest/trust").join(format!("{}.pub", id));
    assert!(private.is_file());
    assert!(public.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let private_mode = std::fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        let public_mode = std::fs::metadata(&public).unwrap().permissions().mode() & 0o777;
        assert_eq!(private_mode, 0o600, "private key must be 0600");
        assert_eq!(public_mode, 0o644, "public key must be 0644");
    }

    let private_pem = std::fs::read_to_string(&private).unwrap();
    assert!(private_pem.contains("BEGIN PRIVATE KEY"));
    let public_pem = std::fs::read_to_string(&public).unwrap();
    assert!(public_pem.contains("BEGIN PUBLIC KEY"));

    // key-id must equal hex(blake3(raw pubkey)[..16]) — recomputed here
    // through the library derivation from the on-disk PEM.
    assert_eq!(attest::keys::key_id_from_pem(&public_pem).unwrap(), id);

    attest()
        .args(["keys", "list"])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains(&id))
        .stdout(predicates::str::contains("ci-master"))
        .stdout(predicates::str::contains("trusted"))
        .stdout(predicates::str::contains("private+public"));
}

/// Criterion 2: full round-trip — generate and sign on machine A, export,
/// import and verify on machine B.
#[test]
fn export_import_round_trip_verifies() {
    let machine_a = tempfile::tempdir().unwrap();
    let machine_b = tempfile::tempdir().unwrap();
    init_workspace(machine_a.path());
    init_workspace(machine_b.path());

    let id = generate(machine_a.path(), "builder-a");

    let pem_file = machine_a.path().join("builder-a.pub.pem");
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
    let pem = std::fs::read_to_string(&pem_file).unwrap();
    assert!(pem.contains("BEGIN PUBLIC KEY"));
    assert!(
        !pem.contains("PRIVATE"),
        "export must never emit private material"
    );

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
        .code(0)
        .stdout(predicates::str::contains(&id));

    let receipt = run_signed(machine_a.path(), &id);

    // Machine B trusts builder-a via its own trust store; the receipt's
    // workspace is irrelevant here (no --recompute).
    attest()
        .args([
            "verify",
            "--trust-store",
            machine_b.path().join(".attest/trust").to_str().unwrap(),
            receipt.to_str().unwrap(),
        ])
        .current_dir(machine_b.path())
        .assert()
        .code(0);
}

/// Criterion 3: a revoked key's signature is refused unless something
/// independent says when it was signed.
///
/// This used to pass on the receipt's own timestamp alone, which is written
/// by the signer and covered by the signer's signature -- so whoever stole
/// the key chose the date and walked past the revocation. Accepting that now
/// requires asking for it explicitly.
#[test]
fn revocation_semantics() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(tmp.path());
    let id = generate(tmp.path(), "to-revoke");

    // Signed BEFORE revocation.
    let receipt_before = run_signed(tmp.path(), &id);

    attest()
        .args(["keys", "revoke", &id])
        .current_dir(tmp.path())
        .assert()
        .code(0);

    // No timestamp token, so there is no evidence the signature predates the
    // revocation: refused by default.
    attest()
        .args(["verify", receipt_before.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("carrying no timestamp token"));

    // The old behaviour remains reachable, but has to be asked for: receipts
    // written before timestamping existed cannot acquire a token now.
    attest()
        .args([
            "verify",
            receipt_before.to_str().unwrap(),
            "--trust-receipt-timestamp",
        ])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .stderr(predicates::str::contains("signed by key revoked later"));

    // Signed AFTER revocation (new receipt, timestamp > revoked_at).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(tmp.path().join("in.txt"), "payload v2").unwrap();
    let receipt_after = run_signed(tmp.path(), &id);
    assert_ne!(receipt_before, receipt_after);

    attest()
        .args([
            "verify",
            receipt_after.to_str().unwrap(),
            "--trust-receipt-timestamp",
        ])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stdout(predicates::str::contains("after its revocation"));

    // Revoking an unknown id is a verification-meaningful failure (exit 1).
    attest()
        .args(["keys", "revoke", "00000000000000000000000000000000"])
        .current_dir(tmp.path())
        .assert()
        .code(1);
}

/// Criterion 4: importing the same key twice is idempotent.
#[test]
fn import_is_idempotent() {
    let machine_a = tempfile::tempdir().unwrap();
    let machine_b = tempfile::tempdir().unwrap();
    init_workspace(machine_a.path());
    init_workspace(machine_b.path());

    let id = generate(machine_a.path(), "dup");
    let pem_file = machine_a.path().join("dup.pem");
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

    for _ in 0..2 {
        attest()
            .args([
                "keys",
                "import",
                pem_file.to_str().unwrap(),
                "--name",
                "dup",
            ])
            .current_dir(machine_b.path())
            .assert()
            .code(0);
    }

    let output = attest()
        .args(["keys", "list", "--format", "json"])
        .current_dir(machine_b.path())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    let entries: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(entries.len(), 1, "no duplicate trust entries");
    assert_eq!(entries[0]["id"], id.as_str());
    assert_eq!(entries[0]["private_key_present"], false);
}

/// Criterion 5: generating twice with the same name yields two distinct
/// key ids, both listed; run --sign without --key then requires the flag.
#[test]
fn same_name_twice_yields_distinct_ids() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(tmp.path());

    let id1 = generate(tmp.path(), "ci");
    let id2 = generate(tmp.path(), "ci");
    assert_ne!(id1, id2);

    attest()
        .args(["keys", "list"])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .stdout(predicates::str::contains(&id1))
        .stdout(predicates::str::contains(&id2));

    // Rule 5: two private keys and no --key is an operational error.
    attest()
        .args(["run", "--sign"])
        .current_dir(tmp.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains(
            "multiple private keys, use --key",
        ));
}

/// Rule 2: export must be incapable of emitting private material, and an
/// unknown id is an operational error.
#[test]
fn export_never_emits_private_material() {
    let tmp = tempfile::tempdir().unwrap();
    init_workspace(tmp.path());
    let id = generate(tmp.path(), "safe");

    let output = attest()
        .args(["keys", "export", &id])
        .current_dir(tmp.path())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let pem = String::from_utf8(output).unwrap();
    assert!(pem.contains("BEGIN PUBLIC KEY"));
    assert!(!pem.contains("PRIVATE"));

    attest()
        .args(["keys", "export", "ffffffffffffffffffffffffffffffff"])
        .current_dir(tmp.path())
        .assert()
        .code(2);
}
