//! Recipient decisions on real signed receipts and independently pinned log keys.
use attest::publication::{entry_for_root, note::LogConfig, record::*};
use attest::storage::Receipt;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use ring::digest::{digest, SHA256};
use serde_json::Value;

#[path = "support/release.rs"]
mod release_fixture;
use release_fixture::{check, Release};

fn sha(bytes: &[u8]) -> Vec<u8> {
    digest(&SHA256, bytes).as_ref().to_vec()
}

struct Delivery {
    release: Release,
    trust: std::path::PathBuf,
    record: std::path::PathBuf,
}

impl Delivery {
    fn new() -> Self {
        let release = Release::new(0);
        let receipt: Receipt =
            serde_yaml::from_slice(&std::fs::read(&release.receipt).unwrap()).unwrap();
        assert_eq!(receipt.causal_events.len(), 1);
        let root = receipt.causal_chain_hash.unwrap();
        let opening = "23".repeat(32);
        let entry = entry_for_root(&root, &opening).unwrap();
        // Synthetic log signer used only by this fixture. The Go vectors in
        // publication_protocol independently check this note/Merkle profile.
        let key = SigningKey::from_bytes(&[0x65; 32]);
        let material = [vec![1], key.verifying_key().as_bytes().to_vec()].concat();
        let key_id = sha(&[b"recipient-test\n".as_slice(), &material].concat())[..4].to_vec();
        let config = LogConfig {
            format: "attest-log/v1".into(),
            origin: "recipient-test".into(),
            verifier_key: format!(
                "recipient-test+{}+{}",
                hex::encode(&key_id),
                STANDARD.encode(&material)
            ),
            read_url: None,
            submit_url: None,
            tls_ca: None,
        };
        let body = format!(
            "recipient-test\n1\n{}\n",
            STANDARD.encode(sha(&[vec![0], entry.clone()].concat()))
        );
        let signature = [key_id, key.sign(body.as_bytes()).to_bytes().to_vec()].concat();
        let checkpoint = format!("{body}\n— recipient-test {}\n", STANDARD.encode(signature));
        let publication = PublicationRecord {
            format: RECORD_FORMAT.into(),
            causal_root: root,
            opening_nonce: opening,
            entry: hex::encode(entry),
            log_id: config.log_id().unwrap(),
            submit_url: "https://log.test/add".into(),
            created_at: "2026-11-01T00:00:00Z".parse().unwrap(),
            submissions: vec![],
            outcome: PublicationState::Confirmed {
                leaf_index: 0,
                checkpoint,
                inclusion_path: vec![],
            },
        };
        let trust = release.recipient.path().join("log.json");
        std::fs::write(&trust, serde_json::to_vec(&config).unwrap()).unwrap();
        let record = release.producer.path().join("publication.json");
        std::fs::write(&record, serde_json::to_vec(&publication).unwrap()).unwrap();
        release
            .pack()
            .arg("--publication")
            .arg(&record)
            .assert()
            .success();
        Self {
            release,
            trust,
            record,
        }
    }

    fn verify(&self, extra: &[&str], code: i32) -> Value {
        let mut flags = vec!["--log-trust", self.trust.to_str().unwrap()];
        flags.extend(extra);
        self.release.verify(&flags, code)
    }

    fn alter(&self, change: impl FnOnce(&mut Value)) {
        self.release.mutate_archive(|entries| {
            let entry = entries
                .iter_mut()
                .find(|entry| entry.path == "publication.json")
                .unwrap();
            let mut value: Value = serde_json::from_slice(&entry.bytes).unwrap();
            change(&mut value);
            entry.bytes = serde_json::to_vec(&value).unwrap();
        });
    }
}

#[test]
fn publication_is_checked_offline_after_the_producer_is_removed() {
    let delivery = Delivery::new();
    let entries = attest::archive::read_archive(&delivery.release.archive).unwrap();
    let manifest: Value = serde_json::from_slice(
        &entries
            .iter()
            .find(|e| e.path == "manifest.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert_eq!(manifest["format"], "attest-evidence/v3");
    let receipt_trust = delivery.release.recipient.path().join(".attest/trust");
    let publication: Value =
        serde_json::from_slice(&std::fs::read(&delivery.record).unwrap()).unwrap();
    let checkpoint = delivery.release.recipient.path().join("reference.note");
    std::fs::write(
        &checkpoint,
        publication["outcome"]["checkpoint"].as_str().unwrap(),
    )
    .unwrap();
    let Delivery { release, trust, .. } = delivery;
    let Release {
        producer,
        recipient,
        archive,
        ..
    } = release;
    producer.close().unwrap();
    let result = release_fixture::verify(
        recipient.path(),
        &archive,
        &receipt_trust,
        &[
            "--log-trust",
            trust.to_str().unwrap(),
            "--log-checkpoint",
            checkpoint.to_str().unwrap(),
            "--require",
            "signature,artifacts,linkage,log-inclusion,log-consistency",
        ],
        0,
    );
    assert_eq!(check(&result, "log-inclusion")["status"], "pass");
    assert_eq!(check(&result, "log-consistency")["status"], "pass");
    assert!(!recipient.path().join(".attest/keys").exists());
}

#[test]
fn missing_log_trust_or_missing_confirmation_cannot_satisfy_recipient_policy() {
    let delivery = Delivery::new();
    let result = delivery.release.verify(&["--require", "log-inclusion"], 1);
    assert_eq!(check(&result, "log-inclusion")["status"], "skipped");
    delivery.alter(|value| {
        value["outcome"] = serde_json::json!({"status":"unconfirmed", "reason":"deadline"})
    });
    assert_eq!(
        check(&delivery.verify(&[], 0), "log-inclusion")["status"],
        "skipped"
    );
    assert_eq!(
        check(
            &delivery.verify(&["--require", "log-inclusion"], 1),
            "log-inclusion"
        )["status"],
        "skipped"
    );
}

#[test]
fn altered_opening_checkpoint_index_and_extra_nodes_are_refused() {
    for field in [
        "opening",
        "opening-entry",
        "checkpoint",
        "index",
        "path",
        "log",
    ] {
        let delivery = Delivery::new();
        delivery.alter(|value| match field {
            "opening" => value["opening_nonce"] = "24".repeat(32).into(),
            "opening-entry" => {
                value["opening_nonce"] = "24".repeat(32).into();
                value["entry"] = hex::encode(
                    entry_for_root(
                        value["causal_root"].as_str().unwrap(),
                        value["opening_nonce"].as_str().unwrap(),
                    )
                    .unwrap(),
                )
                .into();
            }
            "checkpoint" => {
                let note = value["outcome"]["checkpoint"]
                    .as_str()
                    .unwrap()
                    .replace("\n1\n", "\n2\n");
                value["outcome"]["checkpoint"] = note.into();
            }
            "index" => value["outcome"]["leaf_index"] = 1.into(),
            "path" => value["outcome"]["inclusion_path"] = serde_json::json!(["00".repeat(32)]),
            "log" => value["log_id"] = "00".repeat(32).into(),
            _ => unreachable!(),
        });
        assert_eq!(
            check(&delivery.verify(&[], 1), "log-inclusion")["status"],
            "fail",
            "{field}"
        );
    }
}

#[test]
fn v3_requires_its_publication_file_and_v2_cannot_smuggle_one() {
    for missing in [true, false] {
        let delivery = Delivery::new();
        delivery.release.mutate_archive(|entries| {
            if missing {
                entries.retain(|entry| entry.path != "publication.json");
            } else {
                entries
                    .iter_mut()
                    .find(|entry| entry.path == "manifest.json")
                    .unwrap()
                    .bytes = br#"{"format":"attest-evidence/v2"}"#.to_vec();
            }
        });
        assert_eq!(
            check(&delivery.verify(&[], 1), "artifacts")["status"],
            "fail"
        );
    }
}

#[test]
fn a_missing_reference_is_distinct_from_verified_consistency() {
    let delivery = Delivery::new();
    let result = delivery.verify(&["--require", "log-consistency"], 1);
    assert_eq!(check(&result, "log-inclusion")["status"], "pass");
    assert_eq!(check(&result, "log-consistency")["status"], "skipped");
}

#[test]
fn valid_log_inclusion_does_not_authorize_a_revoked_receipt_signer() {
    let delivery = Delivery::new();
    assert!(
        attest::keys::KeyStore::new(delivery.release.recipient.path())
            .revoke(&delivery.release.key)
            .unwrap()
    );
    let result = delivery.verify(&["--require", "log-inclusion"], 1);
    assert_eq!(check(&result, "signature")["status"], "fail");
    assert_eq!(check(&result, "log-inclusion")["status"], "pass");
}
