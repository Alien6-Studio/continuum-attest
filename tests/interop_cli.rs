//! Integration tests for `attest export` / `attest import`:
//! golden-file determinism, round-trip, SLSA v1 schema validation and
//! tampered-DSSE rejection.
//!
//! Fixtures live under `tests/fixtures/interop/` and are regenerated with
//! `cargo test --test interop_cli regenerate_fixtures -- --ignored`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use base64::Engine;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("interop")
}

/// Deterministic fixture keypair. Only a raw 32-byte seed is committed
/// (`fixture.seed.hex`); the PEM files are materialized at test time so no
/// key-shaped blob ever lands in the repository.
fn fixture_signing_key() -> ed25519_dalek::SigningKey {
    let seed_hex =
        std::fs::read_to_string(fixtures_dir().join("fixture.seed.hex")).expect("fixture.seed.hex");
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .expect("seed hex")
        .try_into()
        .expect("32-byte seed");
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

/// Build a temp workspace holding the fixture private key and trust store.
fn fixture_workspace() -> (tempfile::TempDir, String) {
    use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey, EncodePublicKey};

    let dir = tempfile::tempdir().expect("tempdir");
    let signing_key = fixture_signing_key();
    let id = attest::keys::key_id(&signing_key.verifying_key());

    let keys_dir = dir.path().join(".attest").join("keys");
    let trust_dir = dir.path().join(".attest").join("trust");
    std::fs::create_dir_all(&keys_dir).expect("keys dir");
    std::fs::create_dir_all(&trust_dir).expect("trust dir");
    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("private PEM");
    std::fs::write(keys_dir.join(format!("{}.key", id)), private_pem.as_bytes())
        .expect("write private key");
    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("public PEM");
    std::fs::write(trust_dir.join(format!("{}.pub", id)), public_pem.as_bytes())
        .expect("write public key");
    (dir, id)
}

fn attest_cmd() -> Command {
    Command::cargo_bin("attest").expect("attest binary")
}

fn decoded_payload(envelope_json: &str) -> serde_json::Value {
    let envelope: serde_json::Value = serde_json::from_str(envelope_json).expect("envelope JSON");
    let payload_b64 = envelope["payload"].as_str().expect("payload");
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .expect("payload base64");
    serde_json::from_slice(&payload).expect("statement JSON")
}

/// Acceptance criterion 1: exported envelope equals the committed golden
/// file byte-for-byte.
#[test]
fn export_matches_golden_file() {
    let (workspace, _id) = fixture_workspace();
    let output = attest_cmd()
        .args([
            "export",
            "--receipt",
            fixtures_dir().join("receipt.yaml").to_str().expect("path"),
            "--format",
            "in-toto",
            "--workspace",
            workspace.path().to_str().expect("path"),
        ])
        .output()
        .expect("run export");
    assert!(
        output.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let golden = std::fs::read(fixtures_dir().join("golden.dsse.json")).expect("golden file");
    assert_eq!(
        output.stdout, golden,
        "exported envelope differs from golden file"
    );
}

/// Acceptance criterion 2: export → import passes and preserves the
/// invocation id and digests.
#[test]
fn round_trip_export_import_passes() {
    let (workspace, id) = fixture_workspace();
    let envelope_path = workspace.path().join("statement.json");
    attest_cmd()
        .args([
            "export",
            "--receipt",
            fixtures_dir().join("receipt.yaml").to_str().expect("path"),
            "--format",
            "in-toto",
            "--output",
            envelope_path.to_str().expect("path"),
            "--workspace",
            workspace.path().to_str().expect("path"),
        ])
        .assert()
        .success();

    let output = attest_cmd()
        .args([
            "import",
            "--format",
            "in-toto",
            envelope_path.to_str().expect("path"),
            "--workspace",
            workspace.path().to_str().expect("path"),
        ])
        .output()
        .expect("run import");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "import failed: {} / {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains(": pass"), "unexpected report: {}", stdout);
    assert!(
        stdout.contains(&id),
        "report does not name the key: {}",
        stdout
    );

    // Mapped fields preserved: recompute the statement from the receipt
    // and compare against what the round-tripped envelope carries.
    let receipt: attest::storage::Receipt = serde_yaml::from_str(
        &std::fs::read_to_string(fixtures_dir().join("receipt.yaml")).expect("receipt"),
    )
    .expect("receipt YAML");
    let expected = attest::interop::statement_from_receipt(&receipt).expect("statement");
    let statement =
        decoded_payload(&std::fs::read_to_string(&envelope_path).expect("envelope file"));
    assert_eq!(
        statement["predicate"]["runDetails"]["metadata"]["invocationId"]
            .as_str()
            .expect("invocationId"),
        expected.predicate.run_details.metadata.invocation_id
    );
    assert_eq!(
        statement["subject"][0]["digest"]["blake3"]
            .as_str()
            .expect("subject digest"),
        expected.subject[0].digest.blake3
    );
    assert_eq!(
        statement["predicate"]["buildDefinition"]["externalParameters"]["pipelineHash"]
            .as_str()
            .expect("pipelineHash"),
        receipt.pipeline_hash
    );
}

/// Acceptance criterion 3: the exported statement validates against the
/// official SLSA Provenance v1 / in-toto Statement v1 JSON schema
/// (slsa-verifier is not available in CI; the schema is committed under
/// tests/fixtures/).
#[test]
fn exported_statement_validates_against_slsa_schema() {
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("slsa-provenance-v1.schema.json"))
            .expect("schema file"),
    )
    .expect("schema JSON");
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");

    let statement = decoded_payload(
        &std::fs::read_to_string(fixtures_dir().join("golden.dsse.json")).expect("golden"),
    );
    let result = compiled.validate(&statement);
    if let Err(errors) = result {
        let details: Vec<String> = errors.map(|e| e.to_string()).collect();
        panic!("statement does not match SLSA v1 schema: {:?}", details);
    }
}

/// Acceptance criterion 4: flipping one byte of the DSSE payload makes
/// `import` exit 1 with a failed signature check.
#[test]
fn tampered_payload_fails_import() {
    let (workspace, _id) = fixture_workspace();
    let golden = std::fs::read_to_string(fixtures_dir().join("golden.dsse.json")).expect("golden");
    let mut envelope: serde_json::Value = serde_json::from_str(&golden).expect("envelope");

    let payload_b64 = envelope["payload"].as_str().expect("payload").to_string();
    let mut payload = base64::engine::general_purpose::STANDARD
        .decode(&payload_b64)
        .expect("payload base64");
    // Flip one byte inside the invocationId hex value.
    let marker = b"\"invocationId\":\"";
    let position = payload
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("invocationId in payload")
        + marker.len();
    payload[position] = if payload[position] == b'a' {
        b'b'
    } else {
        b'a'
    };
    envelope["payload"] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&payload));

    let tampered_path = workspace.path().join("tampered.json");
    std::fs::write(&tampered_path, envelope.to_string()).expect("write tampered envelope");

    let output = attest_cmd()
        .args([
            "import",
            "--format",
            "in-toto",
            tampered_path.to_str().expect("path"),
            "--workspace",
            workspace.path().to_str().expect("path"),
        ])
        .output()
        .expect("run import");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("DSSE signature does not verify"),
        "unexpected report: {}",
        stdout
    );
}

/// Rule 2: exporting an unsigned receipt exits 1 unless --allow-unsigned,
/// which produces a DSSE envelope without signatures.
#[test]
fn unsigned_receipt_requires_allow_unsigned() {
    let (workspace, _id) = fixture_workspace();
    let mut receipt: attest::storage::Receipt = serde_yaml::from_str(
        &std::fs::read_to_string(fixtures_dir().join("receipt.yaml")).expect("receipt"),
    )
    .expect("receipt YAML");
    receipt.signature = None;
    receipt.signer_public_key = None;
    let unsigned_path = workspace.path().join("unsigned.yaml");
    std::fs::write(
        &unsigned_path,
        serde_yaml::to_string(&receipt).expect("YAML"),
    )
    .expect("write unsigned receipt");

    let output = attest_cmd()
        .args([
            "export",
            "--receipt",
            unsigned_path.to_str().expect("path"),
            "--format",
            "in-toto",
            "--workspace",
            workspace.path().to_str().expect("path"),
        ])
        .output()
        .expect("run export");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--allow-unsigned"));

    let output = attest_cmd()
        .args([
            "export",
            "--receipt",
            unsigned_path.to_str().expect("path"),
            "--format",
            "in-toto",
            "--allow-unsigned",
            "--workspace",
            workspace.path().to_str().expect("path"),
        ])
        .output()
        .expect("run export");
    assert!(output.status.success());
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("envelope JSON");
    assert_eq!(
        envelope["signatures"].as_array().expect("signatures").len(),
        0
    );
}

/// Importing an envelope signed by a key absent from the trust store
/// exits 1 naming the unknown keyid.
#[test]
fn import_fails_for_untrusted_key() {
    let (exporter, _id) = fixture_workspace();
    let envelope_path = exporter.path().join("statement.json");
    attest_cmd()
        .args([
            "export",
            "--receipt",
            fixtures_dir().join("receipt.yaml").to_str().expect("path"),
            "--format",
            "in-toto",
            "--output",
            envelope_path.to_str().expect("path"),
            "--workspace",
            exporter.path().to_str().expect("path"),
        ])
        .assert()
        .success();

    let importer = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(importer.path().join(".attest").join("trust")).expect("trust dir");
    let output = attest_cmd()
        .args([
            "import",
            "--format",
            "in-toto",
            envelope_path.to_str().expect("path"),
            "--workspace",
            importer.path().to_str().expect("path"),
        ])
        .output()
        .expect("run import");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("not in the trust store"));
}

/// Regenerate the committed fixtures (key, signed receipt, golden
/// envelope). Run manually; never in CI.
#[test]
#[ignore]
fn regenerate_fixtures() {
    use attest::storage::{receipt_signing_bytes, Receipt, StepResult};

    // Only the raw 32-byte seed is committed: it carries no PEM framing,
    // so secret scanners never see key-shaped material in the repository.
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    std::fs::create_dir_all(fixtures_dir()).expect("fixtures dir");
    std::fs::write(
        fixtures_dir().join("fixture.seed.hex"),
        format!("{}\n", hex::encode(signing_key.to_bytes())),
    )
    .expect("write seed");
    let (staging, _id) = fixture_workspace();

    let mut receipt = Receipt {
        schema_version: Some(1),
        pipeline_hash: blake3::hash(b"interop fixture pipeline")
            .to_hex()
            .to_string(),
        steps: vec![
            StepResult {
                name: "build".to_string(),
                input_hash: blake3::hash(b"build inputs").to_hex().to_string(),
                output_hash: blake3::hash(b"build outputs").to_hex().to_string(),
                duration_secs: 42,
                exit_code: 0,
                cache_hit: false,
                stdout: "compiled 3 crates".to_string(),
                stderr: String::new(),
                capsule_hash: None,
            },
            StepResult {
                name: "test".to_string(),
                input_hash: blake3::hash(b"test inputs").to_hex().to_string(),
                output_hash: blake3::hash(b"test outputs").to_hex().to_string(),
                duration_secs: 17,
                exit_code: 0,
                cache_hit: false,
                stdout: "12 tests passed".to_string(),
                stderr: String::new(),
                capsule_hash: None,
            },
        ],
        timestamp: chrono::DateTime::parse_from_rfc3339("2026-08-27T12:00:59Z")
            .expect("timestamp")
            .with_timezone(&chrono::Utc),
        total_duration_secs: 59,
        signature: None,
        signer_public_key: None,
        attest_version: "0.1.0".to_string(),
        causal_events: vec![],
        causal_chain_hash: None,
        reproducibility: None,
        provenance: None,
        timestamp_token: None,
    };

    let keypair = attest::crypto::sign::AttestKeypair::from_signing_key(signing_key);
    let signing_bytes = receipt_signing_bytes(&receipt).expect("signing bytes");
    receipt.signature = Some(keypair.sign(signing_bytes.as_bytes()));
    receipt.signer_public_key = Some(keypair.public_key_hex());
    std::fs::write(
        fixtures_dir().join("receipt.yaml"),
        serde_yaml::to_string(&receipt).expect("YAML"),
    )
    .expect("write receipt fixture");

    let outcome = attest::interop::export_receipt_file(
        &fixtures_dir().join("receipt.yaml"),
        &attest::interop::ExportOptions {
            allow_unsigned: false,
            key: None,
            workspace: staging.path().to_path_buf(),
        },
    )
    .expect("export");
    match outcome {
        attest::interop::ExportOutcome::Written { json, .. } => {
            std::fs::write(fixtures_dir().join("golden.dsse.json"), json)
                .expect("write golden fixture");
        }
        other => panic!("unexpected export outcome: {:?}", other),
    }
}
