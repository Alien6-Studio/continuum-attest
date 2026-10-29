use crate::release_fixture::Release;
use attest::capsule::CapsuleManifest;
use attest::crypto::sign::AttestKeypair;
use attest::keys::KeyStore;
use attest::storage::causal_ledger::{CausalEvent, CausalLedger};
use attest::storage::{receipt_signing_bytes, Receipt};

pub(super) struct ProofRelease {
    pub release: Release,
    pub capsule: std::path::PathBuf,
}

impl ProofRelease {
    pub fn new() -> Self {
        let release = Release::new(0);
        let mut receipt: Receipt =
            serde_yaml::from_slice(&std::fs::read(&release.receipt).unwrap()).unwrap();
        let mut manifest = CapsuleManifest::new(
            "builder",
            &format!("example/build@sha256:{}", "a".repeat(64)),
        )
        .unwrap();
        manifest.capsule_hash = Some(manifest.compute_hash().unwrap());
        receipt.steps[0].capsule_hash = manifest.capsule_hash.clone();
        let capsule = release.producer.path().join("capsule.yaml");
        std::fs::write(&capsule, serde_yaml::to_string(&manifest).unwrap()).unwrap();
        let mut event = CausalEvent {
            event_id: String::new(),
            step_name: receipt.steps[0].name.clone(),
            causal_parents: vec![],
            input_hash: receipt.steps[0].input_hash.clone(),
            output_hash: receipt.steps[0].output_hash.clone(),
            timestamp: chrono::Utc::now(),
            exit_code: 0,
            pipeline_hash: receipt.pipeline_hash.clone(),
            environment_hash: "b".repeat(64),
            signer_public_key: None,
            signature: None,
            metadata: [("duration_secs".to_string(), "1".to_string())]
                .into_iter()
                .collect(),
        };
        event.event_id = CausalLedger::event_id_of(&event);
        receipt.causal_events = vec![event.event_id.clone()];
        receipt.causal_chain_hash = Some(CausalLedger::chain_hash(&[event.clone()]));
        let events = release.producer.path().join(".attest/causal_ledger/events");
        std::fs::create_dir_all(&events).unwrap();
        std::fs::write(
            events.join(format!("{}.json", event.event_id)),
            serde_json::to_vec(&event).unwrap(),
        )
        .unwrap();
        let key = KeyStore::new(release.producer.path())
            .select_signing_key(Some(&release.key))
            .unwrap()
            .unwrap();
        let key = AttestKeypair::from_signing_key(key);
        receipt.signature = Some(key.sign(receipt_signing_bytes(&receipt).unwrap().as_bytes()));
        std::fs::write(&release.receipt, serde_yaml::to_string(&receipt).unwrap()).unwrap();
        let fixture = Self { release, capsule };
        fixture.pack();
        fixture
    }

    pub fn pack(&self) {
        self.release
            .pack()
            .arg("--capsule-manifest")
            .arg(&self.capsule)
            .assert()
            .success();
    }
}
