//! in-toto Statement v1 / SLSA Provenance v1 export and import.
//!
//! `attest export --format in-toto` maps a persisted receipt
//! ([`crate::storage::Receipt`]) to an in-toto Statement v1 carrying the
//! SLSA Provenance v1 predicate, wrapped in a DSSE envelope
//! (`application/vnd.dsse.envelope.v1+json`). `attest import --format
//! in-toto` verifies such an envelope against the local trust store and
//! reports in the same format as `attest verify`.
//!
//! Serialization is deterministic: every struct below declares its fields
//! in byte-lexicographic order of their JSON names and is emitted as
//! compact JSON, so the exported envelope is byte-for-byte reproducible
//! for a given receipt and signing key (Ed25519 signatures are
//! deterministic).
//!
//! The v2 projection keeps the exact original receipt and its trust context
//! in an explicit extension. Import verifies DSSE and native receipt trust
//! separately, using only the recipient's independently configured anchors.
//! The public build-type document defines the mapping and its limitations.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::storage::{receipt_signing_bytes, Receipt};
use crate::verify::{Check, CheckStatus, ReceiptVerdict};

pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
pub const BUILD_TYPE: &str = "https://github.com/Alien6-Studio/continuum-attest/blob/main/docs/specifications/attest-pipeline-v2.md";
pub const LEGACY_BUILD_TYPE: &str = "https://alien6.com/attest/pipeline/v1";
pub const UNKNOWN_BUILDER: &str = "urn:attest:builder:unverified";
const EVIDENCE_FORMAT: &str = "attest-original-evidence/v1";

#[derive(Debug, Serialize)]
pub struct InteropOutcome {
    pub projection: bool,
    pub envelope_signer: Option<String>,
    pub original_signer: Option<String>,
    pub original_receipt_sha256: Option<String>,
    pub original_verdict: Option<Box<ReceiptVerdict>>,
    pub semantics: Vec<String>,
}

// ---------------------------------------------------------------------------
// Wire format. Field declaration order == byte-lexicographic order of the
// serialized JSON names, which makes derived serialization canonical
// without relying on serde_json map-ordering features.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub predicate: Predicate,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub subject: Vec<ResourceDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    pub digest: Digest,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Predicate {
    #[serde(
        default,
        rename = "attest_evidence",
        skip_serializing_if = "Option::is_none"
    )]
    pub attest: Option<OriginalEvidence>,
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

/// An explicit projection with the original evidence kept byte-for-byte.
/// The transported trust files are provenance, never recipient trust anchors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OriginalEvidence {
    pub artifact_binding: String,
    pub format: String,
    pub original_signer: Option<String>,
    pub producer: EvidenceProducer,
    pub receipt: EmbeddedBlob,
    pub semantics: Vec<String>,
    pub trust_material: BTreeMap<String, EmbeddedBlob>,
    pub workflow: Option<crate::identity::IdentityVerification>,
    pub workflow_bundle: Option<EmbeddedBlob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceProducer {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EmbeddedBlob {
    pub content: String,
    pub media_type: String,
    pub sha256: String,
}

impl EmbeddedBlob {
    fn new(bytes: &[u8], media_type: &str) -> Self {
        Self {
            content: base64::engine::general_purpose::STANDARD.encode(bytes),
            media_type: media_type.into(),
            sha256: sha256(bytes),
        }
    }

    fn bytes(&self, limit: u64) -> Result<Vec<u8>> {
        ensure!(
            self.content.len() as u64 <= limit.saturating_mul(4) / 3 + 4,
            "embedded evidence exceeds size limit"
        );
        let bytes = base64::engine::general_purpose::STANDARD.decode(&self.content)?;
        ensure!(
            bytes.len() as u64 <= limit,
            "embedded evidence exceeds size limit"
        );
        ensure!(
            sha256(&bytes) == self.sha256,
            "embedded evidence SHA-256 does not match its bytes"
        );
        Ok(bytes)
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildDefinition {
    #[serde(rename = "buildType")]
    pub build_type: String,
    #[serde(rename = "externalParameters")]
    pub external_parameters: ExternalParameters,
    #[serde(rename = "resolvedDependencies")]
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalParameters {
    #[serde(rename = "pipelineHash")]
    pub pipeline_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDetails {
    pub builder: Builder,
    pub metadata: RunMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Builder {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    #[serde(rename = "finishedOn")]
    pub finished_on: String,
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    #[serde(rename = "startedOn")]
    pub started_on: String,
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Export an unsigned receipt (or a signed one with no local private
    /// key) as a DSSE envelope with an empty `signatures` array.
    pub allow_unsigned: bool,
    /// Signing key id for the DSSE envelope (see `attest keys list`).
    pub key: Option<String>,
    /// Workspace root holding `.attest/keys`.
    pub workspace: PathBuf,
    pub identity_bundle: Option<PathBuf>,
    pub identity_policy: Option<crate::identity::IdentityPolicy>,
    pub trust_store: Option<PathBuf>,
}

/// Outcome of an export attempt. Preconditions that must fail the command
/// with exit code 1 are explicit variants; operational problems are `Err`.
#[derive(Debug)]
pub enum ExportOutcome {
    Written {
        json: String,
        warnings: Vec<String>,
    },
    /// The receipt is unsigned and `--allow-unsigned` was not given.
    UnsignedReceipt,
    /// The receipt carries a signature that does not verify; refusing to
    /// launder a tampered receipt into a standard format.
    InvalidReceiptSignature(String),
    /// No local private key can sign the DSSE envelope and
    /// `--allow-unsigned` was not given.
    NoSigningKey(String),
}

/// Construct a projection from a receipt's signed file inventory. Export also
/// verifies the actual files; this pure mapping alone does not verify artifacts.
pub fn statement_from_receipt(receipt: &Receipt) -> Result<Statement> {
    let bytes = serde_yaml::to_string(receipt)?;
    project_receipt(
        receipt,
        OriginalEvidence {
            artifact_binding: artifact_binding(receipt).into(),
            format: EVIDENCE_FORMAT.into(),
            original_signer: receipt.signer_public_key.clone(),
            producer: EvidenceProducer {
                name: "continuum-attest".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            receipt: EmbeddedBlob::new(bytes.as_bytes(), "application/yaml"),
            semantics: projection_semantics(),
            trust_material: BTreeMap::new(),
            workflow: None,
            workflow_bundle: None,
        },
    )
}

fn projection_semantics() -> Vec<String> {
    [
        "projection: the original receipt is authoritative for Attest verification",
        "receipt-signature and RFC3161 timestamp are carried in the original receipt",
        "trust-material is producer-supplied context, never recipient authorization",
        "step manifests, causal references, isolation, reproducibility and source observations are carried only in the original receipt",
        "external causal objects, capsule manifests, source files and artifact bytes are omitted and require separately delivered evidence",
        "resolvedDependencies is empty: input manifests are not individual resource digests",
        "symlinks are carried in the original inventory but are not file-digest subjects",
        "workflow identifies the authorizing signing workflow, not runner integrity or build correctness",
        "no separate artifact signature is asserted",
        "startedOn is derived from the producer-reported completion and duration, not trusted time",
    ].into_iter().map(String::from).collect()
}

fn artifact_binding(receipt: &Receipt) -> &'static str {
    if receipt
        .provenance
        .as_ref()
        .is_some_and(|p| !p.artifacts.is_empty())
    {
        "signed-file-inventory"
    } else {
        "unavailable"
    }
}

fn project_receipt(receipt: &Receipt, evidence: OriginalEvidence) -> Result<Statement> {
    let mut subjects = BTreeMap::new();
    if artifact_binding(receipt) != "unavailable" {
        crate::evidence::inventory(receipt)?;
        for artifact in &receipt
            .provenance
            .as_ref()
            .context("missing artifact inventory")?
            .artifacts
        {
            if artifact.kind != "file" {
                continue;
            }
            if let Some(previous) = subjects.insert(artifact.path.clone(), artifact.digest.clone())
            {
                ensure!(
                    previous == artifact.digest,
                    "one artifact path has conflicting digests"
                );
            }
        }
    }
    let subject = subjects
        .into_iter()
        .map(|(name, blake3)| ResourceDescriptor {
            name,
            digest: Digest { blake3 },
        })
        .collect();
    let invocation_id = evidence.receipt.sha256.clone();
    let builder = evidence
        .workflow
        .as_ref()
        .map(|identity| identity.workflow.clone())
        .unwrap_or_else(|| UNKNOWN_BUILDER.into());

    // `timestamp` records completion; startedOn is derived.
    let finished = receipt.timestamp;
    let duration =
        i64::try_from(receipt.total_duration_secs).context("total_duration_secs out of range")?;
    let started = finished
        .checked_sub_signed(
            chrono::Duration::try_seconds(duration).context("total_duration_secs out of range")?,
        )
        .context("derived start time is out of range")?;

    Ok(Statement {
        type_: STATEMENT_TYPE.to_string(),
        predicate: Predicate {
            attest: Some(evidence),
            build_definition: BuildDefinition {
                build_type: BUILD_TYPE.to_string(),
                external_parameters: ExternalParameters {
                    pipeline_hash: receipt.pipeline_hash.clone(),
                },
                resolved_dependencies: Vec::new(),
            },
            run_details: RunDetails {
                builder: Builder { id: builder },
                metadata: RunMetadata {
                    finished_on: rfc3339(finished),
                    invocation_id,
                    started_on: rfc3339(started),
                },
            },
        },
        predicate_type: PREDICATE_TYPE.to_string(),
        subject,
    })
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// DSSE Pre-Authentication Encoding (v1).
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Export one receipt file as a signed DSSE envelope.
pub fn export_receipt_file(receipt_path: &Path, options: &ExportOptions) -> Result<ExportOutcome> {
    let content =
        crate::verify::read_bounded(receipt_path, crate::verify::MAX_RECEIPT_BYTES, "receipt")
            .with_context(|| format!("cannot read receipt file: {}", receipt_path.display()))?;
    let receipt: Receipt = serde_yaml::from_slice(&content)
        .with_context(|| format!("invalid receipt: {}", receipt_path.display()))?;

    // Never export a receipt whose own signature is broken.
    let receipt_signed = receipt.signature.is_some() && receipt.signer_public_key.is_some();
    if let (Some(signature), Some(public_key)) = (&receipt.signature, &receipt.signer_public_key) {
        let signing_bytes = receipt_signing_bytes(&receipt)?;
        match crate::crypto::sign::verify_with_public_key(
            public_key,
            signing_bytes.as_bytes(),
            signature,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return Ok(ExportOutcome::InvalidReceiptSignature(
                    "receipt signature does not verify against signer_public_key".to_string(),
                ))
            }
            Err(err) => {
                return Ok(ExportOutcome::InvalidReceiptSignature(format!(
                    "malformed receipt signature material: {}",
                    err
                )))
            }
        }
    } else if !options.allow_unsigned {
        return Ok(ExportOutcome::UnsignedReceipt);
    }

    let mut warnings: Vec<String> = Vec::new();
    if artifact_binding(&receipt) != "unavailable" {
        crate::evidence::inventory(&receipt)?;
        for artifact in &receipt
            .provenance
            .as_ref()
            .context("missing artifact inventory")?
            .artifacts
        {
            let bytes = crate::evidence::artifact_bytes(&options.workspace, artifact)?;
            ensure!(
                blake3::hash(&bytes).to_hex().as_str() == artifact.digest,
                "artifact {} differs from the original receipt",
                artifact.path
            );
        }
    } else {
        warnings.push("original receipt has no signed file inventory; artifact binding is unavailable and subject is empty".into());
    }
    ensure!(
        options.identity_bundle.is_some() == options.identity_policy.is_some(),
        "workflow export requires both --identity-bundle and --identity-policy"
    );
    let (workflow, workflow_bundle) = match (&options.identity_bundle, &options.identity_policy) {
        (Some(path), Some(policy)) => {
            let bytes = crate::verify::read_bounded(
                path,
                crate::identity::MAX_IDENTITY_BYTES,
                "workflow identity",
            )?;
            // Verify the exact snapshots that will be transported, not paths
            // the exporting process or another process could replace later.
            let scratch = tempfile::tempdir()?;
            let original_path = scratch.path().join("receipt.yaml");
            let bundle_path = scratch.path().join("identity.json");
            std::fs::write(&original_path, &content)?;
            std::fs::write(&bundle_path, &bytes)?;
            let verified =
                crate::identity::verify_receipt_identity(&original_path, &bundle_path, policy)?;
            (
                Some(verified),
                Some(EmbeddedBlob::new(
                    &bytes,
                    "application/vnd.dev.sigstore.bundle.v0.3+json",
                )),
            )
        }
        _ => (None, None),
    };
    let trust_dir = options
        .trust_store
        .clone()
        .unwrap_or_else(|| options.workspace.join(".attest/trust"));
    let mut trust_material = public_trust_snapshot(&trust_dir)?;
    if let Some(policy) = &options.identity_policy {
        let root = crate::verify::read_bounded(
            &policy.trusted_root,
            crate::identity::MAX_IDENTITY_BYTES,
            "Sigstore trusted root",
        )?;
        trust_material.insert(
            "sigstore-trusted-root.json".into(),
            EmbeddedBlob::new(&root, "application/json"),
        );
    }
    let statement = project_receipt(
        &receipt,
        OriginalEvidence {
            artifact_binding: artifact_binding(&receipt).into(),
            format: EVIDENCE_FORMAT.into(),
            original_signer: receipt.signer_public_key.clone(),
            producer: EvidenceProducer {
                name: "continuum-attest".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            receipt: EmbeddedBlob::new(&content, "application/yaml"),
            semantics: projection_semantics(),
            trust_material,
            workflow,
            workflow_bundle,
        },
    )?;
    warnings.push("in-toto/SLSA is a projection; original receipt and public trust context are carried in predicate.attest_evidence; recipient trust must be configured independently".into());
    if statement.subject.is_empty() {
        warnings.push("receipt declares no step outputs; exported subject is empty".to_string());
    }

    let payload = serde_json::to_string(&statement).context("cannot serialize statement")?;

    // An unsigned receipt exports as an unsigned envelope: an envelope
    // signature would claim an authenticity the receipt never had.
    let signing_key = if receipt_signed {
        // Pick the envelope signing key: an explicit --key, else the key
        // that signed the receipt (if its private half is local), else the
        // single local signing key.
        let store = crate::keys::KeyStore::new(&options.workspace);
        let requested = match (&options.key, &receipt.signer_public_key) {
            (Some(id), _) => Some(id.clone()),
            (None, Some(public_key)) => {
                let id = crate::keys::key_id_from_hex(public_key)?;
                store
                    .keys_dir()
                    .join(format!("{}.key", id))
                    .is_file()
                    .then_some(id)
            }
            (None, None) => None,
        };
        store.select_signing_key(requested.as_deref())?
    } else {
        warnings.push("receipt is unsigned; DSSE envelope carries no signatures".to_string());
        None
    };

    let signatures = match signing_key {
        Some(signing_key) => {
            let verifying_key = signing_key.verifying_key();
            let keyid = crate::keys::key_id(&verifying_key);
            if let Some(receipt_key) = &receipt.signer_public_key {
                if hex::encode(verifying_key.to_bytes()) != *receipt_key {
                    warnings.push(format!(
                        "DSSE envelope signed by local key {} but the receipt was signed by key {}",
                        keyid,
                        crate::keys::key_id_from_hex(receipt_key)
                            .unwrap_or_else(|_| receipt_key.clone())
                    ));
                }
            }
            use ed25519_dalek::Signer;
            let signature = signing_key.sign(&pae(DSSE_PAYLOAD_TYPE, payload.as_bytes()));
            vec![EnvelopeSignature {
                keyid,
                sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            }]
        }
        None if !receipt_signed || options.allow_unsigned => {
            if receipt_signed {
                warnings
                    .push("no local signing key; DSSE envelope carries no signatures".to_string());
            }
            Vec::new()
        }
        None => {
            return Ok(ExportOutcome::NoSigningKey(
                "no local private key to sign the DSSE envelope (generate one with \
                 'attest keys generate' or pass --allow-unsigned)"
                    .to_string(),
            ))
        }
    };

    let envelope = Envelope {
        payload: base64::engine::general_purpose::STANDARD.encode(payload.as_bytes()),
        payload_type: DSSE_PAYLOAD_TYPE.to_string(),
        signatures,
    };
    let mut json = serde_json::to_string(&envelope).context("cannot serialize envelope")?;
    json.push('\n');
    ensure!(
        json.len() as u64 <= MAX_STATEMENT_BYTES,
        "exported envelope exceeds the supported statement size limit"
    );
    Ok(ExportOutcome::Written { json, warnings })
}

fn public_trust_snapshot(root: &Path) -> Result<BTreeMap<String, EmbeddedBlob>> {
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for directory in ["", "tsa", "bundles"] {
        let path = root.join(directory);
        if !path.exists() {
            continue;
        }
        ensure!(
            !path.symlink_metadata()?.is_symlink(),
            "public trust directory is a symlink"
        );
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let selected = match directory {
                "" => name == "trust.toml" || name.ends_with(".pub"),
                "tsa" => [".crt", ".pem", ".der"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix)),
                "bundles" => name.ends_with(".json"),
                _ => false,
            };
            if !selected {
                continue;
            }
            ensure!(
                entry.file_type()?.is_file(),
                "public trust material is not a regular file"
            );
            let bytes =
                crate::verify::read_bounded(&entry.path(), 1024 * 1024, "public trust material")?;
            total += bytes.len();
            ensure!(
                total <= 4 * 1024 * 1024 && files.len() < 256,
                "public trust snapshot exceeds size limit"
            );
            let relative = if directory.is_empty() {
                name
            } else {
                format!("{directory}/{name}")
            };
            files.insert(
                relative,
                EmbeddedBlob::new(&bytes, "application/octet-stream"),
            );
        }
    }
    Ok(files)
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// Workspace root; the trust store defaults to `<workspace>/.attest/trust`.
    pub workspace: PathBuf,
    pub trust_store: Option<PathBuf>,
    /// Accept a revoked key on the strength of the statement's own
    /// `finishedOn`, with no independent proof of when it was signed.
    ///
    /// Off by default, and for the same reason `attest verify` refuses:
    /// `finishedOn` sits inside the payload the signature covers, so whoever
    /// holds the key chooses it. A DSSE envelope carries no timestamp token,
    /// which means there is no independent time available on this path at
    /// all -- exporting a receipt to in-toto and importing it back would
    /// otherwise launder a revoked signature past the check that `verify`
    /// applies to the receipt itself.
    pub trust_statement_time: bool,
    /// What the caller requires; the same names as `attest verify`.
    pub policy: crate::verify::Policy,
    pub identity_policy: Option<crate::identity::IdentityPolicy>,
    pub artifact_root: Option<PathBuf>,
}

fn check(name: &str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_string(),
        status,
        detail: detail.into(),
    }
}

/// Verify a DSSE-wrapped in-toto statement file and report in the same
/// shape as `attest verify`. `Err` is reserved for operational problems
/// (unreadable file, content that is not JSON at all) and maps to exit
/// code 2; every verification failure is a failed check (exit code 1).
/// Largest DSSE envelope this importer will parse; the same reasoning as
/// [`crate::verify::MAX_RECEIPT_BYTES`].
pub const MAX_STATEMENT_BYTES: u64 = 16 * 1024 * 1024;

pub fn import_statement_file(path: &Path, options: &ImportOptions) -> Result<ReceiptVerdict> {
    let mut effective_policy = options.policy.clone();
    if options.identity_policy.is_some()
        && !effective_policy
            .required
            .contains(&crate::verify::Requirement::Identity)
    {
        effective_policy
            .required
            .push(crate::verify::Requirement::Identity);
    }
    let display_path = path.display().to_string();
    let content = crate::verify::read_bounded(path, MAX_STATEMENT_BYTES, "statement")
        .with_context(|| format!("cannot read statement file: {}", display_path))?;
    let value: serde_json::Value = serde_json::from_slice(&content)
        .with_context(|| format!("unreadable JSON in {}", display_path))?;

    let mut verdict = ReceiptVerdict {
        receipt: display_path,
        verdict: "fail".into(),
        checks: Vec::new(),
        signed_by: None,
        warnings: Vec::new(),
        trust_material: None,
        execution: None,
        policy: None,
        identity: options
            .identity_policy
            .as_ref()
            .map(|policy| crate::identity::IdentityOutcome {
                required: Some(policy.clone()),
                verified: None,
                principals: crate::identity::IdentityPrincipals {
                    evidence_producer: None,
                    workflow: None,
                    artifact_signer: None,
                },
            }),
        interop: None,
    };
    let (envelope, payload, statement) = match parse_envelope(&value) {
        Ok(parsed) => parsed,
        Err(error) => {
            verdict
                .checks
                .push(check("schema", CheckStatus::Fail, error));
            crate::verify::apply_policy(&mut verdict, &effective_policy);
            return Ok(verdict);
        }
    };
    verdict.checks.push(check(
        "schema",
        CheckStatus::Pass,
        "DSSE envelope and in-toto statement match schema",
    ));
    verdict.checks.push(consistency_check(&statement));
    let (mut dsse, signer) = signature_check(
        &envelope,
        &payload,
        &statement,
        options,
        &mut verdict.warnings,
    );
    let envelope_passed = dsse.status == CheckStatus::Pass;
    dsse.name = "dsse-signature".into();
    verdict.checks.push(dsse);
    verdict.signed_by = signer.clone();
    verdict.interop = Some(InteropOutcome {
        projection: true,
        envelope_signer: signer,
        original_signer: None,
        original_receipt_sha256: None,
        original_verdict: None,
        semantics: projection_semantics(),
    });
    let original_passed = if statement.predicate.build_definition.build_type == BUILD_TYPE {
        match verify_original_projection(&statement, options, &mut verdict) {
            Ok(passed) => passed,
            Err(error) => {
                verdict.checks.push(check(
                    "original-evidence",
                    CheckStatus::Fail,
                    format!("{error:#}"),
                ));
                false
            }
        }
    } else {
        verdict.warnings.push("legacy projection: only the DSSE envelope is verified; original receipt signer, trusted time, workflow, artifact bytes and Attest trust semantics are unavailable".into());
        verdict.checks.push(check(
            "original-evidence",
            CheckStatus::Skipped,
            "legacy projection carries no original receipt",
        ));
        verdict.checks.push(check(
            "artifacts",
            CheckStatus::Skipped,
            "legacy step manifest digests do not identify artifact bytes",
        ));
        verdict.checks.push(check(
            "identity",
            if options.identity_policy.is_some() {
                CheckStatus::Fail
            } else {
                CheckStatus::Skipped
            },
            "legacy projection carries no workflow identity evidence",
        ));
        // Retain historical DSSE verification, explicitly bounded above. It
        // never satisfies requirements for properties the legacy format lost.
        true
    };
    verdict.checks.push(check(
        "signature",
        if envelope_passed && original_passed {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        if statement.predicate.build_definition.build_type == BUILD_TYPE {
            "requires both trusted DSSE signature and independently trusted original receipt"
        } else {
            "legacy DSSE envelope signature only; original receipt trust is unavailable"
        },
    ));
    crate::verify::apply_policy(&mut verdict, &effective_policy);
    Ok(verdict)
}

fn verify_original_projection(
    statement: &Statement,
    options: &ImportOptions,
    verdict: &mut ReceiptVerdict,
) -> Result<bool> {
    let evidence = statement
        .predicate
        .attest
        .as_ref()
        .context("v2 projection is missing original evidence")?;
    ensure!(
        evidence.format == EVIDENCE_FORMAT,
        "unsupported original evidence format"
    );
    ensure!(
        evidence.receipt.media_type == "application/yaml",
        "unsupported original receipt media type"
    );
    ensure!(
        evidence.semantics == projection_semantics(),
        "projection must explicitly preserve its trust and omission semantics"
    );
    ensure!(
        !evidence.producer.name.is_empty() && !evidence.producer.version.is_empty(),
        "missing evidence producer tool identity"
    );
    let receipt_bytes = evidence.receipt.bytes(crate::verify::MAX_RECEIPT_BYTES)?;
    let receipt: Receipt = serde_yaml::from_slice(&receipt_bytes)?;
    ensure!(
        evidence.original_signer == receipt.signer_public_key,
        "original signer identity differs from the original receipt"
    );
    ensure!(
        evidence.artifact_binding == artifact_binding(&receipt),
        "artifact binding claim differs from the original receipt"
    );
    ensure!(
        evidence.workflow.is_some() == evidence.workflow_bundle.is_some(),
        "workflow claims require their original cryptographic evidence"
    );
    // Check all transported material's content references, but never install it
    // into the recipient's trust store or use it as verification authority.
    ensure!(
        evidence.trust_material.len() <= 257,
        "too many transported trust files"
    );
    for blob in evidence.trust_material.values() {
        blob.bytes(crate::identity::MAX_IDENTITY_BYTES)?;
    }
    let expected = project_receipt(&receipt, evidence.clone())?;
    ensure!(
        serde_json::to_value(statement)? == serde_json::to_value(expected)?,
        "SLSA projection does not match its original receipt and workflow claims"
    );
    let original = crate::verify::verify_receipt_bytes(
        &receipt_bytes,
        "embedded original receipt",
        &crate::verify::VerifyOptions {
            check_signatures: true,
            recompute: false,
            workspace: options.workspace.clone(),
            trust_store: options.trust_store.clone(),
            trust_receipt_timestamp: false,
            policy: crate::verify::Policy {
                required: vec![crate::verify::Requirement::Signature],
            },
        },
    )?;
    let passed = original.passed();
    let original_signer = original.signed_by.clone();
    verdict.checks.push(check("original-evidence", if passed { CheckStatus::Pass } else { CheckStatus::Fail }, "original receipt verified independently against recipient trust; see interop.original_verdict"));
    if let Some(timestamp) = original.checks.iter().find(|c| c.name == "timestamp") {
        verdict.checks.push(check(
            "timestamp",
            timestamp.status,
            timestamp.detail.clone(),
        ));
    }
    if let Some(execution) = &original.execution {
        verdict.execution = Some(crate::verify::ExecutionOutcome {
            outcome: execution.outcome.clone(),
            failed_steps: execution.failed_steps,
        });
    }
    if let Some(trust) = &original.trust_material {
        verdict.trust_material = Some(crate::verify::TrustMaterial {
            state: trust.state.clone(),
            issuer: trust.issuer.clone(),
            sequence: trust.sequence,
            valid_until: trust.valid_until,
            judged_by: trust.judged_by.clone(),
        });
    }
    let mut verified = None;
    if let Some(policy) = &options.identity_policy {
        let result = (|| -> Result<crate::identity::IdentityVerification> {
            let bundle = evidence
                .workflow_bundle
                .as_ref()
                .context("required workflow identity evidence is missing")?;
            let bytes = bundle.bytes(crate::identity::MAX_IDENTITY_BYTES)?;
            let scratch = tempfile::tempdir()?;
            let receipt_path = scratch.path().join("receipt.yaml");
            let bundle_path = scratch.path().join("bundle.json");
            std::fs::write(&receipt_path, &receipt_bytes)?;
            std::fs::write(&bundle_path, bytes)?;
            let authenticated =
                crate::identity::verify_receipt_identity(&receipt_path, &bundle_path, policy)?;
            ensure!(
                serde_json::to_value(&authenticated)? == serde_json::to_value(&evidence.workflow)?,
                "projected workflow identity differs from the authenticated certificate"
            );
            Ok(authenticated)
        })();
        match result {
            Ok(identity) => {
                verified = Some(identity);
                verdict.checks.push(check(
                    "identity",
                    CheckStatus::Pass,
                    "original receipt workflow matches independent recipient policy",
                ));
            }
            Err(error) => {
                verdict
                    .checks
                    .push(check("identity", CheckStatus::Fail, format!("{error:#}")))
            }
        }
    } else {
        verdict.checks.push(check(
            "identity",
            CheckStatus::Skipped,
            "no recipient identity policy; projected builder workflow is not approved",
        ));
    }
    verdict.identity = Some(crate::identity::IdentityOutcome {
        required: options.identity_policy.clone(),
        principals: crate::identity::IdentityPrincipals {
            evidence_producer: original_signer.clone(),
            workflow: verified.as_ref().map(|i| i.workflow.clone()),
            artifact_signer: None,
        },
        verified,
    });
    if let Some(root) = &options.artifact_root {
        let result = (|| -> Result<()> {
            ensure!(
                artifact_binding(&receipt) != "unavailable",
                "original receipt has no signed file inventory"
            );
            for artifact in &receipt
                .provenance
                .as_ref()
                .context("missing artifact inventory")?
                .artifacts
            {
                let bytes = crate::evidence::artifact_bytes(root, artifact)?;
                ensure!(
                    blake3::hash(&bytes).to_hex().as_str() == artifact.digest,
                    "delivered artifact {} differs from original receipt",
                    artifact.path
                );
            }
            Ok(())
        })();
        verdict.checks.push(match result {
            Ok(()) => check(
                "artifacts",
                CheckStatus::Pass,
                "delivered bytes match the original signed file inventory",
            ),
            Err(error) => check("artifacts", CheckStatus::Fail, format!("{error:#}")),
        });
    } else {
        verdict.checks.push(check(
            "artifacts",
            CheckStatus::Skipped,
            "artifact bytes were not provided; use --artifact-root and --require artifacts",
        ));
    }
    if let Some(outcome) = &mut verdict.interop {
        outcome.original_signer = original_signer;
        outcome.original_receipt_sha256 = Some(evidence.receipt.sha256.clone());
        outcome.original_verdict = Some(Box::new(original));
    }
    verdict.warnings.push("SLSA is a projection; original Attest evidence and its separate verdict are retained; transported trust files never authorize their own signer".into());
    Ok(passed)
}

/// Parse the envelope and its payload; any shape problem is a schema-check
/// failure message, not an operational error.
fn parse_envelope(value: &serde_json::Value) -> Result<(Envelope, Vec<u8>, Statement), String> {
    let envelope: Envelope = serde_json::from_value(value.clone())
        .map_err(|err| format!("not a DSSE envelope: {}", err))?;
    if envelope.payload_type != DSSE_PAYLOAD_TYPE {
        return Err(format!(
            "unsupported payloadType '{}' (expected {})",
            envelope.payload_type, DSSE_PAYLOAD_TYPE
        ));
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .map_err(|err| format!("payload is not valid base64: {}", err))?;
    let statement: Statement = serde_json::from_slice(&payload)
        .map_err(|err| format!("payload is not an in-toto statement: {}", err))?;
    if statement.type_ != STATEMENT_TYPE {
        return Err(format!(
            "unsupported statement _type '{}' (expected {})",
            statement.type_, STATEMENT_TYPE
        ));
    }
    if statement.predicate_type != PREDICATE_TYPE {
        return Err(format!(
            "unsupported predicateType '{}' (expected {})",
            statement.predicate_type, PREDICATE_TYPE
        ));
    }
    Ok((envelope, payload, statement))
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn consistency_check(statement: &Statement) -> Check {
    let mut problems: Vec<String> = Vec::new();
    let predicate = &statement.predicate;

    if predicate.build_definition.build_type != BUILD_TYPE
        && predicate.build_definition.build_type != LEGACY_BUILD_TYPE
    {
        problems.push(format!(
            "buildType '{}' is not the ATTEST pipeline buildType",
            predicate.build_definition.build_type
        ));
    }
    if !is_lower_hex64(&predicate.build_definition.external_parameters.pipeline_hash) {
        problems.push("pipelineHash is not a 64-char lowercase hex digest".to_string());
    }
    for descriptor in statement
        .subject
        .iter()
        .chain(&predicate.build_definition.resolved_dependencies)
    {
        if !is_lower_hex64(&descriptor.digest.blake3) {
            problems.push(format!(
                "'{}': blake3 digest is not a 64-char lowercase hex digest",
                descriptor.name
            ));
        }
    }
    if !is_lower_hex64(&predicate.run_details.metadata.invocation_id) {
        problems.push("invocationId is not a 64-char lowercase hex digest".to_string());
    }
    for (name, stamp) in [
        ("startedOn", &predicate.run_details.metadata.started_on),
        ("finishedOn", &predicate.run_details.metadata.finished_on),
    ] {
        if chrono::DateTime::parse_from_rfc3339(stamp).is_err() {
            problems.push(format!("{} is not an RFC 3339 timestamp", name));
        }
    }
    if predicate.build_definition.build_type == LEGACY_BUILD_TYPE
        && !predicate
            .run_details
            .builder
            .id
            .starts_with("https://alien6.com/attest@v")
    {
        problems.push(format!(
            "builder.id '{}' is not an ATTEST builder",
            predicate.run_details.builder.id
        ));
    }
    if statement.subject.is_empty() && predicate.build_definition.build_type == LEGACY_BUILD_TYPE {
        problems.push("statement has an empty subject".to_string());
    }

    if problems.is_empty() {
        check("consistency", CheckStatus::Pass, "statement is coherent")
    } else {
        check("consistency", CheckStatus::Fail, problems.join("; "))
    }
}

/// Verify the sole supported signature over the DSSE PAE against the trust store
/// (issue-#6 semantics: unknown keys fail; revoked keys fail for
/// statements finished after `revoked_at` and warn otherwise).
fn signature_check(
    envelope: &Envelope,
    payload: &[u8],
    statement: &Statement,
    options: &ImportOptions,
    warnings: &mut Vec<String>,
) -> (Check, Option<String>) {
    if envelope.signatures.len() > 1 {
        return (check("signature", CheckStatus::Fail, "multiple DSSE signatures are unsupported; no subset is represented as fully verified"), None);
    }
    let signature = match envelope.signatures.first() {
        Some(signature) => signature,
        None => {
            return (
                check("signature", CheckStatus::Fail, "envelope is unsigned"),
                None,
            )
        }
    };

    let trust_dir = options
        .trust_store
        .clone()
        .unwrap_or_else(|| options.workspace.join(".attest").join("trust"));
    let trusted = match crate::keys::trust_dir_public_keys(&trust_dir) {
        Ok(map) => map,
        Err(err) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("cannot load trust store: {}", err),
                ),
                None,
            )
        }
    };
    let public_key_hex = match trusted.get(&signature.keyid) {
        Some(key) => key.clone(),
        None => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("keyid {} is not in the trust store", signature.keyid),
                ),
                None,
            )
        }
    };

    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&signature.sig) {
        Ok(bytes) => bytes,
        Err(err) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("signature is not valid base64: {}", err),
                ),
                None,
            )
        }
    };
    let message = pae(&envelope.payload_type, payload);
    match crate::crypto::sign::verify_with_public_key(
        &public_key_hex,
        &message,
        &hex::encode(&signature_bytes),
    ) {
        Ok(true) => {}
        Ok(false) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    "DSSE signature does not verify against the trusted key",
                ),
                None,
            )
        }
        Err(err) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("malformed signature material: {}", err),
                ),
                None,
            )
        }
    }

    // Revocation policy. `attest verify` judges a revoked key against a
    // timestamp token and refuses without one; a DSSE envelope has nowhere
    // to carry such a token, so this path refuses outright unless asked not
    // to. Anything else would make `export | import` a way to launder a
    // signature the receipt path rejects.
    let policy = match crate::keys::TrustPolicy::load(&trust_dir) {
        Ok(policy) => policy,
        Err(err) => {
            return (
                check(
                    "signature",
                    CheckStatus::Fail,
                    format!("cannot load trust policy: {}", err),
                ),
                None,
            )
        }
    };
    // Presence in the trust directory is not trust: only a policy entry
    // makes a key a signer anyone vouched for.
    let Some(entry) = policy.entry(&signature.keyid) else {
        return (
            check(
                "signature",
                CheckStatus::Fail,
                format!(
                    "keyid {} has a public key in the trust store but no trust entry",
                    signature.keyid
                ),
            ),
            None,
        );
    };
    {
        if entry.status == crate::keys::KeyStatus::Revoked {
            let revoked_at = entry
                .revoked_at
                .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
            if !options.trust_statement_time {
                return (
                    check(
                        "signature",
                        CheckStatus::Fail,
                        format!(
                            "signed by revoked key {} and an in-toto statement carries no \
                             independent proof of when it was signed, only a finishedOn the \
                             signer wrote inside the signed payload; verify the receipt \
                             itself with a timestamp token, or pass \
                             --trust-statement-time to accept the signer's own word",
                            signature.keyid
                        ),
                    ),
                    None,
                );
            }
            let finished = chrono::DateTime::parse_from_rfc3339(
                &statement.predicate.run_details.metadata.finished_on,
            )
            .map(|t| t.with_timezone(&chrono::Utc))
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC);
            if finished > revoked_at {
                return (
                    check(
                        "signature",
                        CheckStatus::Fail,
                        format!(
                            "signed by key {} after its revocation at {}",
                            signature.keyid, revoked_at
                        ),
                    ),
                    None,
                );
            }
            warnings.push(format!(
                "signed by key revoked later ({} revoked at {})",
                signature.keyid, revoked_at
            ));
        }
    }

    (
        check(
            "signature",
            CheckStatus::Pass,
            format!("valid DSSE signature by trusted key {}", signature.keyid),
        ),
        Some(public_key_hex),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StepResult;

    fn sample_receipt() -> Receipt {
        let mut receipt = Receipt {
            schema_version: Some(crate::storage::RECEIPT_SCHEMA_VERSION),
            pipeline_hash: "a".repeat(64),
            steps: vec![
                StepResult {
                    name: "build".to_string(),
                    input_hash: "b".repeat(64),
                    output_hash: "c".repeat(64),
                    duration_secs: 5,
                    exit_code: 0,
                    cache_hit: false,
                    stdout: "built".to_string(),
                    stderr: String::new(),
                    capsule_hash: None,
                },
                StepResult {
                    name: "audit".to_string(),
                    input_hash: "d".repeat(64),
                    output_hash: "e".repeat(64),
                    duration_secs: 2,
                    exit_code: 0,
                    cache_hit: false,
                    stdout: String::new(),
                    stderr: String::new(),
                    capsule_hash: None,
                },
            ],
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-08-27T10:00:30Z")
                .expect("valid timestamp")
                .with_timezone(&chrono::Utc),
            total_duration_secs: 30,
            signature: None,
            signer_public_key: None,
            attest_version: env!("CARGO_PKG_VERSION").to_string(),
            causal_events: vec![],
            causal_chain_hash: None,
            reproducibility: None,
            provenance: None,
            timestamp_token: None,
            isolation: None,
        };
        let mut provenance = crate::provenance::collect(Path::new("."), None, true);
        for step in &mut receipt.steps {
            let path = format!("{}.bin", step.name);
            let digest = if step.name == "build" { "c" } else { "e" }.repeat(64);
            step.output_hash = blake3::hash(
                format!("{}\nf:{digest} {path}\n", crate::hashing::MANIFEST_HEADER).as_bytes(),
            )
            .to_hex()
            .to_string();
            provenance.artifacts.push(crate::storage::ArtifactInfo {
                step: step.name.clone(),
                path,
                digest,
                algorithm: "blake3".into(),
                kind: "file".into(),
            });
        }
        receipt.provenance = Some(provenance);
        receipt
    }

    #[test]
    fn statement_mapping_is_deterministic_and_sorted() {
        let receipt = sample_receipt();
        let statement = statement_from_receipt(&receipt).expect("statement");

        // Steps sorted by name: audit before build.
        assert_eq!(statement.subject[0].name, "audit.bin");
        assert_eq!(statement.subject[1].name, "build.bin");
        assert_eq!(statement.subject[1].digest.blake3, "c".repeat(64));
        assert!(statement
            .predicate
            .build_definition
            .resolved_dependencies
            .is_empty());
        assert_eq!(
            statement.predicate.run_details.metadata.started_on,
            "2026-08-27T10:00:00Z"
        );
        assert_eq!(
            statement.predicate.run_details.metadata.finished_on,
            "2026-08-27T10:00:30Z"
        );
        assert_eq!(statement.predicate.run_details.builder.id, UNKNOWN_BUILDER);

        let first = serde_json::to_string(&statement).expect("json");
        let second = serde_json::to_string(&statement_from_receipt(&receipt).expect("statement"))
            .expect("json");
        assert_eq!(first, second);
        // Canonical key order in the serialized payload.
        assert!(first.starts_with("{\"_type\":\"https://in-toto.io/Statement/v1\",\"predicate\":"));
    }

    #[test]
    fn invocation_id_binds_the_original_signature_fields() {
        let unsigned = sample_receipt();
        let mut signed = sample_receipt();
        signed.signature = Some("00".repeat(64));
        signed.signer_public_key = Some("11".repeat(32));
        let a = statement_from_receipt(&unsigned).expect("statement");
        let b = statement_from_receipt(&signed).expect("statement");
        assert_ne!(
            a.predicate.run_details.metadata.invocation_id,
            b.predicate.run_details.metadata.invocation_id
        );
    }

    #[test]
    fn pae_matches_dsse_spec() {
        assert_eq!(
            pae("application/vnd.in-toto+json", b"hi"),
            b"DSSEv1 28 application/vnd.in-toto+json 2 hi".to_vec()
        );
    }
}
