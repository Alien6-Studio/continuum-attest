//! Security invariants for projections; shared with the mutation gate.
use attest::interop::{
    export_receipt_file, import_statement_file, ExportOptions, ExportOutcome, ImportOptions,
};
use attest::keys::KeyStore;
use attest::storage::{receipt_signing_bytes, ArtifactInfo, Receipt, StepResult};
use attest::verify::{CheckStatus, Policy, ReceiptVerdict};
use base64::Engine;
use std::path::{Path, PathBuf};

pub(crate) struct Fixture {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) original_key: String,
    pub(crate) envelope_key: String,
    pub(crate) receipt: PathBuf,
    pub(crate) envelope: PathBuf,
}
impl Fixture {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::new(dir.path());
        let original_key = store.generate("original").unwrap();
        let envelope_key = store.generate("exporter").unwrap();
        let key = attest::AttestKeypair::from_signing_key(
            store
                .select_signing_key(Some(&original_key))
                .unwrap()
                .unwrap(),
        );
        let content = b"the actual released artifact\n";
        std::fs::write(dir.path().join("artifact.bin"), content).unwrap();
        let digest = blake3::hash(content).to_hex().to_string();
        let manifest = format!(
            "{}\nf:{digest} artifact.bin\n",
            attest::hashing::MANIFEST_HEADER
        );
        let mut receipt: Receipt =
            serde_yaml::from_str(include_str!("../fixtures/interop/receipt.yaml")).unwrap();
        receipt.schema_version = Some(3);
        receipt.steps = vec![StepResult {
            name: "build".into(),
            input_hash: "1".repeat(64),
            output_hash: blake3::hash(manifest.as_bytes()).to_hex().to_string(),
            duration_secs: 1,
            exit_code: 0,
            cache_hit: false,
            stdout: String::new(),
            stderr: String::new(),
            capsule_hash: None,
        }];
        let mut provenance = attest::provenance::collect(dir.path(), None, true);
        provenance.artifacts = vec![ArtifactInfo {
            step: "build".into(),
            path: "artifact.bin".into(),
            kind: "file".into(),
            algorithm: "blake3".into(),
            digest,
        }];
        receipt.provenance = Some(provenance);
        receipt.signature = Some(key.sign(receipt_signing_bytes(&receipt).unwrap().as_bytes()));
        receipt.signer_public_key = Some(key.public_key_hex());
        let path = dir.path().join("receipt.yaml");
        std::fs::write(
            &path,
            format!(
                "{}\n# Preserve even comments in the original bytes.\n",
                serde_yaml::to_string(&receipt).unwrap()
            ),
        )
        .unwrap();
        let envelope = dir.path().join("statement.json");
        Self {
            dir,
            original_key,
            envelope_key,
            receipt: path,
            envelope,
        }
    }
    pub(crate) fn export(&self) -> anyhow::Result<String> {
        match export_receipt_file(
            &self.receipt,
            &ExportOptions {
                workspace: self.dir.path().into(),
                key: Some(self.envelope_key.clone()),
                ..Default::default()
            },
        )? {
            ExportOutcome::Written { json, .. } => {
                std::fs::write(&self.envelope, &json)?;
                Ok(json)
            }
            other => anyhow::bail!("unexpected export result: {other:?}"),
        }
    }
    pub(crate) fn import(&self, workspace: &Path, artifacts: bool) -> ReceiptVerdict {
        import_statement_file(
            &self.envelope,
            &ImportOptions {
                workspace: workspace.into(),
                trust_store: None,
                trust_statement_time: false,
                policy: Policy::default(),
                identity_policy: None,
                artifact_root: artifacts.then(|| self.dir.path().into()),
            },
        )
        .unwrap()
    }
    fn rewrite(&self, change: impl FnOnce(&mut serde_json::Value)) {
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&self.envelope).unwrap()).unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(envelope["payload"].as_str().unwrap())
            .unwrap();
        let mut payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        change(&mut payload);
        let bytes = serde_json::to_vec(&payload).unwrap();
        let store = KeyStore::new(self.dir.path());
        let key = store
            .select_signing_key(Some(&self.envelope_key))
            .unwrap()
            .unwrap();
        use ed25519_dalek::Signer;
        let sig = key.sign(&attest::interop::pae(
            attest::interop::DSSE_PAYLOAD_TYPE,
            &bytes,
        ));
        envelope["payload"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(bytes));
        envelope["signatures"][0]["sig"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()));
        std::fs::write(&self.envelope, serde_json::to_vec(&envelope).unwrap()).unwrap();
    }
}
fn status(verdict: &ReceiptVerdict, name: &str) -> CheckStatus {
    verdict
        .checks
        .iter()
        .find(|check| check.name == name)
        .unwrap()
        .status
}
pub(crate) fn payload(json: &str) -> serde_json::Value {
    let envelope: serde_json::Value = serde_json::from_str(json).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(envelope["payload"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn resigning_cannot_authorize_the_untrusted_original_receipt() {
    let fixture = Fixture::new();
    fixture.export().unwrap();
    assert!(fixture.import(fixture.dir.path(), false).passed());
    let recipient = tempfile::tempdir().unwrap();
    let public = fixture
        .dir
        .path()
        .join(".attest/trust")
        .join(format!("{}.pub", fixture.envelope_key));
    KeyStore::new(recipient.path())
        .import(&public, "exporter-only")
        .unwrap();
    let verdict = fixture.import(recipient.path(), false);
    assert_eq!(status(&verdict, "dsse-signature"), CheckStatus::Pass);
    assert_eq!(status(&verdict, "original-evidence"), CheckStatus::Fail);
    assert!(
        !verdict.passed(),
        "bundled trust must not authorize the original signer"
    );
}

#[test]
fn resigning_cannot_launder_a_revoked_original_receipt() {
    let fixture = Fixture::new();
    fixture.export().unwrap();
    assert!(fixture.import(fixture.dir.path(), false).passed());
    KeyStore::new(fixture.dir.path())
        .revoke(&fixture.original_key)
        .unwrap();
    fixture.export().unwrap(); // the different exporter key remains authorized
    let verdict = fixture.import(fixture.dir.path(), false);
    assert_eq!(status(&verdict, "dsse-signature"), CheckStatus::Pass);
    assert_eq!(status(&verdict, "original-evidence"), CheckStatus::Fail);
    assert!(!verdict.passed());
}

#[test]
fn resigning_cannot_discard_an_invalid_original_timestamp() {
    let fixture = Fixture::new();
    let mut receipt: Receipt =
        serde_yaml::from_slice(&std::fs::read(&fixture.receipt).unwrap()).unwrap();
    let token = base64::engine::general_purpose::STANDARD
        .encode(include_bytes!("../fixtures/timestamp/digicert-token.der"));
    receipt.timestamp_token = Some(token.clone()); // genuine token, but for a different imprint
    std::fs::write(&fixture.receipt, serde_yaml::to_string(&receipt).unwrap()).unwrap();
    let statement = payload(&fixture.export().unwrap());
    let original: Receipt = serde_yaml::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(
                statement["predicate"]["attest_evidence"]["receipt"]["content"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(original.timestamp_token, Some(token));
    let verdict = fixture.import(fixture.dir.path(), false);
    assert_eq!(status(&verdict, "dsse-signature"), CheckStatus::Pass);
    assert_eq!(status(&verdict, "timestamp"), CheckStatus::Fail);
    assert!(!verdict.passed());
}

#[test]
fn a_valid_dsse_signature_cannot_substitute_projection_subjects() {
    let fixture = Fixture::new();
    fixture.export().unwrap();
    fixture.rewrite(|statement| {
        statement["subject"][0]["digest"]["blake3"] = serde_json::json!("f".repeat(64))
    });
    let verdict = fixture.import(fixture.dir.path(), false);
    assert_eq!(status(&verdict, "dsse-signature"), CheckStatus::Pass);
    assert_eq!(status(&verdict, "original-evidence"), CheckStatus::Fail);
    assert!(!verdict.passed());
}

#[test]
fn a_projection_cannot_hide_an_unchecked_second_dsse_signature() {
    let fixture = Fixture::new();
    let mut envelope: serde_json::Value = serde_json::from_str(&fixture.export().unwrap()).unwrap();
    envelope["signatures"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"keyid":"unauthorized", "sig":"AAAA"}));
    std::fs::write(&fixture.envelope, serde_json::to_vec(&envelope).unwrap()).unwrap();
    let verdict = fixture.import(fixture.dir.path(), false);
    assert_eq!(status(&verdict, "dsse-signature"), CheckStatus::Fail);
    assert!(!verdict.passed());
}

#[test]
fn exporting_substituted_artifact_bytes_is_refused() {
    let fixture = Fixture::new();
    fixture.export().unwrap();
    std::fs::write(fixture.dir.path().join("artifact.bin"), "substituted").unwrap();
    assert!(fixture.export().is_err());
}

#[test]
fn importing_substituted_artifact_bytes_is_refused() {
    let fixture = Fixture::new();
    fixture.export().unwrap();
    assert!(fixture.import(fixture.dir.path(), true).passed());
    std::fs::write(fixture.dir.path().join("artifact.bin"), "substituted").unwrap();
    let verdict = fixture.import(fixture.dir.path(), true);
    assert_eq!(status(&verdict, "artifacts"), CheckStatus::Fail);
    assert!(!verdict.passed());
}

#[test]
fn a_resigned_projection_cannot_relabel_the_original_signer() {
    let fixture = Fixture::new();
    fixture.export().unwrap();
    fixture.rewrite(|statement| {
        statement["predicate"]["attest_evidence"]["originalSigner"] =
            serde_json::json!("f".repeat(64));
    });
    let verdict = fixture.import(fixture.dir.path(), false);
    assert_eq!(status(&verdict, "dsse-signature"), CheckStatus::Pass);
    assert_eq!(status(&verdict, "original-evidence"), CheckStatus::Fail);
    assert!(!verdict.passed());
}

#[test]
fn a_resigned_projection_cannot_replace_original_receipt_bytes() {
    let fixture = Fixture::new();
    fixture.export().unwrap();
    fixture.rewrite(|statement| {
        let blob = &mut statement["predicate"]["attest_evidence"]["receipt"];
        let raw = base64::engine::general_purpose::STANDARD
            .decode(blob["content"].as_str().unwrap())
            .unwrap();
        let mut receipt: Receipt = serde_yaml::from_slice(&raw).unwrap();
        receipt.signature = Some("00".repeat(64));
        let raw = serde_yaml::to_string(&receipt).unwrap().into_bytes();
        let digest = hex::encode(ring::digest::digest(&ring::digest::SHA256, &raw));
        blob["content"] = serde_json::json!(base64::engine::general_purpose::STANDARD.encode(raw));
        blob["sha256"] = serde_json::json!(digest);
        statement["predicate"]["runDetails"]["metadata"]["invocationId"] =
            serde_json::json!(digest);
    });
    let verdict = fixture.import(fixture.dir.path(), false);
    assert_eq!(status(&verdict, "dsse-signature"), CheckStatus::Pass);
    assert_eq!(status(&verdict, "original-evidence"), CheckStatus::Fail);
    assert!(!verdict.passed());
}

#[test]
fn a_resigned_projection_cannot_smuggle_unknown_build_parameters() {
    let fixture = Fixture::new();
    fixture.export().unwrap();
    fixture.rewrite(|statement| {
        statement["predicate"]["buildDefinition"]["externalParameters"]["approvedWorkflow"] =
            serde_json::json!(true);
    });
    let verdict = fixture.import(fixture.dir.path(), false);
    assert_eq!(status(&verdict, "schema"), CheckStatus::Fail);
    assert!(!verdict.passed());
}
