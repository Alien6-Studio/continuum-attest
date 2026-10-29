//! Release packaging and recipient interoperability. Forgery cases whose
//! protection is removed by the mutation gate live in security_invariants.rs.

use attest::archive::{read_archive, ArchiveEntry};
use attest::keys::KeyStore;
use attest::storage::Receipt;

#[path = "support/release.rs"]
mod release_fixture;
use release_fixture::{check, verify, Release};

#[test]
fn recipient_verifies_reproducible_evidence_without_producer_workspace() {
    let release = Release::new(0);
    let first = std::fs::read(&release.archive).unwrap();
    release.pack().assert().success();
    assert_eq!(first, std::fs::read(&release.archive).unwrap());
    let entries = read_archive(&release.archive).unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path == "receipt.yaml")
            .unwrap()
            .bytes,
        std::fs::read(&release.receipt).unwrap()
    );
    let Release {
        producer,
        recipient,
        archive,
        ..
    } = release;
    producer.close().unwrap();
    let result = verify(
        recipient.path(),
        &archive,
        &recipient.path().join(".attest/trust"),
        &[],
        0,
    );
    assert_eq!(result["verdict"], "pass");
    assert_eq!(check(&result, "signature")["status"], "pass");
    assert_eq!(check(&result, "artifacts")["status"], "pass");
    assert_eq!(check(&result, "identity")["status"], "skipped");
    assert!(!recipient.path().join(".attest/keys").exists());
}

#[test]
fn separately_distributed_artifact_is_bound_to_the_receipt() {
    let release = Release::new(0);
    let root = release.recipient.path().join("download");
    std::fs::create_dir_all(root.join("dist")).unwrap();
    std::fs::write(root.join("dist/program"), "release payload\n").unwrap();
    std::fs::write(root.join("dist/metadata"), "manifest").unwrap();
    release.verify(&["--artifact-root", root.to_str().unwrap()], 0);
    std::fs::write(root.join("dist/program"), "replaced after download").unwrap();
    let result = release.verify(&["--artifact-root", root.to_str().unwrap()], 1);
    assert_eq!(check(&result, "artifacts")["status"], "fail");
}

#[test]
fn missing_or_unaccounted_archive_files_are_rejected() {
    let release = Release::new(0);
    release
        .mutate_archive(|entries| entries.retain(|entry| entry.path != "artifacts/dist/metadata"));
    assert_eq!(
        check(&release.verify(&[], 1), "artifacts")["status"],
        "fail"
    );
    release.pack().assert().success();
    release.mutate_archive(|entries| {
        entries.push(ArchiveEntry {
            path: "artifacts/unclaimed-program".into(),
            bytes: b"not signed".to_vec(),
        })
    });
    assert_eq!(
        check(&release.verify(&[], 1), "artifacts")["status"],
        "fail"
    );
}

#[test]
fn changing_receipt_claims_invalidates_the_signature() {
    let release = Release::new(0);
    release.mutate_archive(|entries| {
        let entry = entries
            .iter_mut()
            .find(|entry| entry.path == "receipt.yaml")
            .unwrap();
        let mut receipt: Receipt = serde_yaml::from_slice(&entry.bytes).unwrap();
        receipt.provenance.as_mut().unwrap().runner_os = "forged-runner".into();
        entry.bytes = serde_yaml::to_string(&receipt).unwrap().into_bytes();
    });
    assert_eq!(
        check(&release.verify(&[], 1), "signature")["status"],
        "fail"
    );
}

#[test]
fn packing_an_unsigned_or_invalidly_signed_receipt_preserves_existing_archive() {
    let release = Release::new(0);
    let original = std::fs::read(&release.archive).unwrap();
    let mut receipt: Receipt =
        serde_yaml::from_slice(&std::fs::read(&release.receipt).unwrap()).unwrap();
    for signature in [None, Some("00".repeat(64))] {
        receipt.signature = signature;
        std::fs::write(&release.receipt, serde_yaml::to_string(&receipt).unwrap()).unwrap();
        release.pack().assert().code(2);
        assert_eq!(std::fs::read(&release.archive).unwrap(), original);
    }
}

#[test]
fn embedded_signing_key_does_not_establish_recipient_trust() {
    let release = Release::new(0);
    let unconfigured = tempfile::tempdir().unwrap();
    let result = verify(
        unconfigured.path(),
        &release.archive,
        &unconfigured.path().join("trust"),
        &[],
        1,
    );
    assert_eq!(check(&result, "signature")["status"], "fail");
    assert!(!unconfigured.path().join("trust").exists());
    assert!(KeyStore::new(release.recipient.path())
        .revoke(&release.key)
        .unwrap());
    assert_eq!(
        check(&release.verify(&[], 1), "signature")["status"],
        "fail"
    );
}

#[cfg(unix)]
#[test]
fn matching_bytes_through_symlinked_ancestor_are_refused() {
    let release = Release::new(0);
    let moved = release.producer.path().join("elsewhere");
    std::fs::rename(release.producer.path().join("dist"), &moved).unwrap();
    std::os::unix::fs::symlink(&moved, release.producer.path().join("dist")).unwrap();
    release
        .pack()
        .assert()
        .code(2)
        .stderr(predicates::str::contains("artifact ancestor"));
    assert_eq!(
        check(
            &release.verify(
                &["--artifact-root", release.producer.path().to_str().unwrap()],
                1
            ),
            "artifacts"
        )["status"],
        "fail"
    );
}

#[test]
fn duplicate_tar_entries_are_operational_errors() {
    let release = Release::new(0);
    release.mutate_archive(|entries| {
        entries.push(ArchiveEntry {
            path: "receipt.yaml".into(),
            bytes: b"a: 1\n".to_vec(),
        })
    });
    let result = release.verify(&[], 2);
    assert_eq!(result["verdict"], "error");
    assert_eq!(result["error"], "operational");
}
