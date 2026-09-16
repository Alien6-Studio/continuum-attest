//! Supply-chain content verification for OCI images (`attest image
//! verify` enrichment).
//!
//! Ports the checks of the mesh `verify-image-supply-chain.sh` verifier
//! to Rust: SBOM structural validity (IMG-7), SLSA provenance
//! completeness (IMG-8), git-revision binding across provenance and
//! signature annotations (IMG-8/IMG-9), and the Azure KMS public-key
//! export workaround (IMG-10). Exit codes follow IMG-12: 0 all enforced
//! checks pass, 1 any enforced check fails, 2 operational error.
//!
//! Attestations are read with `docker buildx imagetools inspect` and
//! parsed with serde — no jq dependency.

use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;

use crate::crypto::image_signing::{validate_digest_ref, validate_revision, SignFailure};
use crate::crypto::image_verification::ImageVerifier;

/// The signature annotation carrying the git revision (IMG-9).
pub const REVISION_ANNOTATION: &str = "continuum.git.revision";

/// What `attest image verify` should enforce.
#[derive(Debug, Clone, Default)]
pub struct SupplyChainRequest {
    /// Digest reference `repo@sha256:<64 hex>` (mandatory once any
    /// supply-chain check is enabled).
    pub image_ref: String,
    /// Enforce IMG-7 (SPDX SBOM attestation).
    pub require_sbom: bool,
    /// Enforce IMG-8 (SLSA provenance attestation).
    pub require_provenance: bool,
    /// Expected git revision `^[a-f0-9]{40,64}$` (IMG-8 v1 vcs.revision
    /// + IMG-9 signature annotation).
    pub expected_revision: Option<String>,
    /// Verification key: `azurekms://…` (exported first, IMG-10) or a
    /// public-key file path. Enables the signature check.
    pub key_uri: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skipped,
}

/// One row of the verification report.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

impl CheckResult {
    fn pass(name: &str, detail: String) -> Self {
        Self {
            name: name.to_string(),
            status: CheckStatus::Pass,
            detail,
        }
    }

    fn fail(name: &str, detail: String) -> Self {
        Self {
            name: name.to_string(),
            status: CheckStatus::Fail,
            detail,
        }
    }

    fn skipped(name: &str, detail: String) -> Self {
        Self {
            name: name.to_string(),
            status: CheckStatus::Skipped,
            detail,
        }
    }
}

/// Full verification report; the JSON `--format json` serialization of
/// this struct is the normative output shape.
#[derive(Debug, Clone, Serialize)]
pub struct SupplyChainReport {
    pub image: String,
    pub verdict: String,
    pub checks: Vec<CheckResult>,
}

impl SupplyChainReport {
    pub fn passed(&self) -> bool {
        self.verdict == "pass"
    }
}

/// Collect attestation documents from `imagetools inspect` JSON
/// (IMG-7/IMG-8 document discovery, port of the jq `spdx_documents` /
/// `slsa_documents` helpers): a non-object yields no documents; an
/// object with `key` is a single-platform attestation; any other object
/// is a per-platform map whose values may each carry `key`.
pub fn collect_documents(value: &serde_json::Value, key: &str) -> Vec<serde_json::Value> {
    let Some(object) = value.as_object() else {
        return vec![];
    };
    if let Some(document) = object.get(key) {
        return vec![document.clone()];
    }
    object
        .values()
        .filter_map(|platform| platform.get(key).cloned())
        .collect()
}

fn is_nonempty_string(value: Option<&serde_json::Value>) -> bool {
    value.and_then(|v| v.as_str()).map(|s| !s.is_empty()) == Some(true)
}

fn is_string(value: Option<&serde_json::Value>) -> bool {
    value.map(|v| v.is_string()) == Some(true)
}

fn is_object(value: Option<&serde_json::Value>) -> bool {
    value.map(|v| v.is_object()) == Some(true)
}

fn is_nonempty_array(value: Option<&serde_json::Value>) -> bool {
    value.and_then(|v| v.as_array()).map(|a| !a.is_empty()) == Some(true)
}

/// Validate one SPDX document per IMG-7. Returns the first violated
/// clause.
pub fn validate_spdx_document(document: &serde_json::Value) -> Result<(), String> {
    if document.get("SPDXID").and_then(|v| v.as_str()) != Some("SPDXRef-DOCUMENT") {
        return Err("SPDXID is not \"SPDXRef-DOCUMENT\"".to_string());
    }
    if !is_string(document.get("spdxVersion")) {
        return Err("spdxVersion is not a string".to_string());
    }
    if !is_string(document.pointer("/creationInfo/created")) {
        return Err("creationInfo.created is not a string".to_string());
    }
    if document.get("packages").map(|v| v.is_array()) != Some(true) {
        return Err("packages is not an array".to_string());
    }
    Ok(())
}

/// SLSA v0.2 field set per IMG-8.
fn valid_slsa_v02(document: &serde_json::Value) -> bool {
    is_nonempty_string(document.get("buildType"))
        && is_object(document.get("builder"))
        && is_object(document.get("invocation"))
        && is_string(document.pointer("/metadata/buildStartedOn"))
        && is_string(document.pointer("/metadata/buildFinishedOn"))
        && is_nonempty_array(document.get("materials"))
}

/// SLSA v1 field set per IMG-8 (structural part; the vcs.revision
/// binding is handled separately so it can be reported as the
/// `revision` check).
fn valid_slsa_v1(document: &serde_json::Value) -> bool {
    is_nonempty_string(document.pointer("/buildDefinition/buildType"))
        && is_object(document.pointer("/buildDefinition/externalParameters"))
        && is_nonempty_array(document.pointer("/buildDefinition/resolvedDependencies"))
        && is_object(document.pointer("/runDetails/builder"))
        && is_string(document.pointer("/runDetails/metadata/startedOn"))
        && is_string(document.pointer("/runDetails/metadata/finishedOn"))
        && is_nonempty_string(document.pointer("/runDetails/metadata/invocationId"))
}

/// The `vcs.revision` recorded by buildkit in a SLSA v1 document.
pub fn slsa_v1_revision(document: &serde_json::Value) -> Option<&str> {
    document
        .pointer("/runDetails/metadata/buildkit_metadata/vcs/revision")
        .and_then(|v| v.as_str())
}

/// Validate one SLSA document per IMG-8: the document must satisfy the
/// v0.2 field set or the v1 field set.
pub fn validate_slsa_document(document: &serde_json::Value) -> Result<(), String> {
    if valid_slsa_v02(document) || valid_slsa_v1(document) {
        Ok(())
    } else {
        Err("document satisfies neither the SLSA v0.2 nor the SLSA v1 field set".to_string())
    }
}

/// IMG-7: validate the `.SBOM` inspection JSON.
pub fn check_sbom(sbom: &serde_json::Value) -> Result<usize, String> {
    let documents = collect_documents(sbom, "SPDX");
    if documents.is_empty() {
        return Err("no SPDX document attached to the image".to_string());
    }
    for (index, document) in documents.iter().enumerate() {
        validate_spdx_document(document)
            .map_err(|clause| format!("SPDX document {index}: {clause}"))?;
    }
    Ok(documents.len())
}

/// IMG-8 structural check: validate the `.Provenance` inspection JSON.
pub fn check_provenance(provenance: &serde_json::Value) -> Result<usize, String> {
    let documents = collect_documents(provenance, "SLSA");
    if documents.is_empty() {
        return Err("no SLSA provenance document attached to the image".to_string());
    }
    for (index, document) in documents.iter().enumerate() {
        validate_slsa_document(document)
            .map_err(|clause| format!("SLSA document {index}: {clause}"))?;
    }
    Ok(documents.len())
}

/// IMG-8 revision binding: every SLSA v1 document must record the
/// expected `vcs.revision`. Returns Ok(None) when no v1 document
/// carries a revision (the check is then reported as skipped).
pub fn check_revision_binding(
    provenance: &serde_json::Value,
    expected: &str,
) -> Result<Option<usize>, String> {
    let documents = collect_documents(provenance, "SLSA");
    let mut compared = 0usize;
    for document in &documents {
        if !valid_slsa_v1(document) {
            continue;
        }
        match slsa_v1_revision(document) {
            Some(actual) if actual == expected => compared += 1,
            Some(actual) => {
                return Err(format!(
                    "provenance revision mismatch: expected {expected}, provenance has {actual}"
                ));
            }
            None => {
                return Err(format!(
                    "SLSA v1 document has no buildkit vcs.revision (expected {expected})"
                ));
            }
        }
    }
    Ok(if compared == 0 { None } else { Some(compared) })
}

/// Shells out to `docker buildx imagetools inspect` and `cosign`.
/// Split from the pure validators so tests can drive them on fixtures.
pub struct SupplyChainVerifier {
    docker: String,
    cosign: Option<String>,
}

impl SupplyChainVerifier {
    /// Locate the required binaries. `docker` is always needed;
    /// `cosign` only when a signature check will run.
    pub fn locate(need_cosign: bool) -> Result<Self, SignFailure> {
        let docker = which::which("docker")
            .map(|p| p.to_string_lossy().to_string())
            .map_err(|_| {
                SignFailure::Operational(
                    "docker binary not found; supply-chain checks read attestations via 'docker buildx imagetools inspect'"
                        .to_string(),
                )
            })?;
        let cosign = if need_cosign {
            Some(
                ImageVerifier::find_cosign_binary()
                    .ok()
                    .flatten()
                    .ok_or_else(|| {
                        SignFailure::Operational(
                            "cosign binary not found; install it: https://docs.sigstore.dev/cosign/system_config/installation/"
                                .to_string(),
                        )
                    })?,
            )
        } else {
            None
        };
        Ok(Self { docker, cosign })
    }

    /// `docker buildx imagetools inspect <ref> --format '{{json .<field>}}'`.
    fn inspect(&self, image_ref: &str, field: &str) -> Result<serde_json::Value, SignFailure> {
        let format = format!("{{{{json .{field}}}}}");
        let output = Command::new(&self.docker)
            .args([
                "buildx",
                "imagetools",
                "inspect",
                image_ref,
                "--format",
                &format,
            ])
            .output()
            .map_err(|e| SignFailure::Operational(format!("failed to execute docker: {e}")))?;
        if !output.status.success() {
            return Err(SignFailure::Operational(format!(
                "docker buildx imagetools inspect failed for {image_ref}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        serde_json::from_slice(&output.stdout).map_err(|e| {
            SignFailure::Operational(format!("cannot parse imagetools {field} JSON: {e}"))
        })
    }

    /// IMG-10: export the public half of an Azure KMS key into a
    /// 0700 tempdir (file 0600), deleted when the returned guard drops.
    /// An empty export is an operational error.
    fn export_kms_public_key(
        &self,
        cosign: &str,
        key_uri: &str,
    ) -> Result<(tempfile::TempDir, PathBuf), SignFailure> {
        let dir = tempfile::Builder::new()
            .prefix("attest-kms-")
            .tempdir()
            .map_err(|e| SignFailure::Operational(format!("cannot create tempdir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .map_err(|e| SignFailure::Operational(format!("cannot chmod tempdir: {e}")))?;
        }
        let public_key = dir.path().join("cosign.pub");
        let output = Command::new(cosign)
            .args(["public-key", "--key", key_uri, "--outfile"])
            .arg(&public_key)
            .output()
            .map_err(|e| SignFailure::Operational(format!("failed to execute cosign: {e}")))?;
        if !output.status.success() {
            return Err(SignFailure::Operational(format!(
                "cosign public-key export failed for {key_uri}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let exported = std::fs::metadata(&public_key)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        if !exported {
            return Err(SignFailure::Operational(format!(
                "cosign did not export a public key from {key_uri}"
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&public_key, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| SignFailure::Operational(format!("cannot chmod public key: {e}")))?;
        }
        Ok((dir, public_key))
    }

    /// IMG-9: `cosign verify --key <key> [-a continuum.git.revision=<rev>] <ref>`.
    fn verify_signature(
        &self,
        cosign: &str,
        key: &str,
        expected_revision: Option<&str>,
        image_ref: &str,
    ) -> Result<(), String> {
        let mut cmd = Command::new(cosign);
        cmd.args(["verify", "--key", key]);
        if let Some(revision) = expected_revision {
            cmd.arg("-a")
                .arg(format!("{REVISION_ANNOTATION}={revision}"));
        }
        cmd.arg(image_ref);
        let output = cmd
            .output()
            .map_err(|e| format!("failed to execute cosign verify: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "cosign verify failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    /// Run all enforced checks and build the report. Operational
    /// problems (exit 2) abort; check failures (exit 1) are recorded.
    pub fn verify(&self, request: &SupplyChainRequest) -> Result<SupplyChainReport, SignFailure> {
        validate_digest_ref(&request.image_ref)?;
        if let Some(revision) = &request.expected_revision {
            validate_revision(revision)?;
        }

        let mut checks = Vec::new();

        // IMG-7: SBOM.
        if request.require_sbom {
            let sbom = self.inspect(&request.image_ref, "SBOM")?;
            checks.push(match check_sbom(&sbom) {
                Ok(count) => CheckResult::pass("sbom", format!("{count} valid SPDX document(s)")),
                Err(detail) => CheckResult::fail("sbom", detail),
            });
        } else {
            checks.push(CheckResult::skipped(
                "sbom",
                "not enforced (pass --require-sbom)".to_string(),
            ));
        }

        // IMG-8: provenance structure, plus revision binding when an
        // expected revision is given.
        let need_provenance = request.require_provenance || request.expected_revision.is_some();
        let provenance = if need_provenance {
            Some(self.inspect(&request.image_ref, "Provenance")?)
        } else {
            None
        };
        if request.require_provenance {
            let provenance = provenance.as_ref().expect("provenance inspected");
            checks.push(match check_provenance(provenance) {
                Ok(count) => {
                    CheckResult::pass("provenance", format!("{count} valid SLSA document(s)"))
                }
                Err(detail) => CheckResult::fail("provenance", detail),
            });
        } else {
            checks.push(CheckResult::skipped(
                "provenance",
                "not enforced (pass --require-provenance)".to_string(),
            ));
        }
        if let Some(expected) = &request.expected_revision {
            let provenance = provenance.as_ref().expect("provenance inspected");
            checks.push(match check_revision_binding(provenance, expected) {
                Ok(Some(count)) => CheckResult::pass(
                    "revision",
                    format!("{count} SLSA v1 document(s) record revision {expected}"),
                ),
                Ok(None) => CheckResult::skipped(
                    "revision",
                    "no SLSA v1 document carries a vcs.revision to compare".to_string(),
                ),
                Err(detail) => CheckResult::fail("revision", detail),
            });
        } else {
            checks.push(CheckResult::skipped(
                "revision",
                "not enforced (pass --expected-revision)".to_string(),
            ));
        }

        // IMG-9/IMG-10: signature with optional revision annotation.
        if let Some(key_uri) = &request.key_uri {
            let cosign = self.cosign.as_deref().expect("cosign located");
            // Keep the exported-key tempdir alive for the verify call.
            let (kms_guard, verification_key) = if key_uri.starts_with("azurekms://") {
                let (guard, path) = self.export_kms_public_key(cosign, key_uri)?;
                (Some(guard), path.to_string_lossy().to_string())
            } else {
                (None, key_uri.clone())
            };
            checks.push(
                match self.verify_signature(
                    cosign,
                    &verification_key,
                    request.expected_revision.as_deref(),
                    &request.image_ref,
                ) {
                    Ok(()) => CheckResult::pass(
                        "signature",
                        match &request.expected_revision {
                            Some(revision) => format!(
                                "cosign signature valid with {REVISION_ANNOTATION}={revision}"
                            ),
                            None => "cosign signature valid".to_string(),
                        },
                    ),
                    Err(detail) => CheckResult::fail("signature", detail),
                },
            );
            drop(kms_guard);
        } else {
            checks.push(CheckResult::skipped(
                "signature",
                "not enforced (pass --key)".to_string(),
            ));
        }

        let verdict = if checks.iter().any(|c| c.status == CheckStatus::Fail) {
            "fail"
        } else {
            "pass"
        };
        Ok(SupplyChainReport {
            image: request.image_ref.clone(),
            verdict: verdict.to_string(),
            checks,
        })
    }
}

/// How the verification receipt is persisted (dogfooding:
/// mesh keeps sign *and* verify receipts under `.attest/receipts/`).
#[derive(Debug, Clone, Default)]
pub struct VerifyReceiptOptions {
    /// Receipt directory (default `<workspace>/.attest/receipts/`).
    pub receipt_dir: Option<PathBuf>,
    /// Sign the receipt with the local ATTEST key.
    pub sign_receipt: bool,
    /// ATTEST receipt signing key id (default: sole trusted key).
    pub receipt_key: Option<String>,
}

/// Canonical input manifest for the verification receipt: blake3 over
/// the image digest and every enforcement the report answers for.
fn verification_input_manifest(request: &SupplyChainRequest) -> String {
    let mut manifest = String::from("attest-image-verify/v1\n");
    manifest.push_str(&format!("image:{}\n", request.image_ref));
    manifest.push_str(&format!("require-sbom:{}\n", request.require_sbom));
    manifest.push_str(&format!(
        "require-provenance:{}\n",
        request.require_provenance
    ));
    if let Some(revision) = &request.expected_revision {
        manifest.push_str(&format!("expected-revision:{revision}\n"));
    }
    if let Some(key) = &request.key_uri {
        manifest.push_str(&format!("key:{key}\n"));
    }
    manifest
}

/// Build, optionally sign, and persist the verification receipt. The
/// receipt is written for failing verdicts too (step `exit_code` 1):
/// a recorded refusal is audit data, not an error.
pub fn write_verification_receipt(
    workspace: &std::path::Path,
    request: &SupplyChainRequest,
    report: &SupplyChainReport,
    options: &VerifyReceiptOptions,
) -> anyhow::Result<PathBuf> {
    use anyhow::Context;

    let manifest = verification_input_manifest(request);
    let input_hash = blake3::hash(manifest.as_bytes()).to_hex().to_string();
    let report_json = serde_json::to_string_pretty(report)?;
    let output_hash = blake3::hash(report_json.as_bytes()).to_hex().to_string();

    let step = crate::storage::StepResult {
        name: "image-verify".to_string(),
        input_hash: input_hash.clone(),
        output_hash,
        duration_secs: 0,
        exit_code: if report.passed() { 0 } else { 1 },
        cache_hit: false,
        stdout: report_json,
        stderr: String::new(),
        capsule_hash: None,
    };

    let mut receipt = crate::storage::Receipt {
        schema_version: Some(crate::storage::RECEIPT_SCHEMA_VERSION),
        pipeline_hash: input_hash,
        steps: vec![step],
        timestamp: chrono::Utc::now(),
        total_duration_secs: 0,
        signature: None,
        signer_public_key: None,
        attest_version: "0.1.0".to_string(),
        causal_events: vec![],
        causal_chain_hash: None,
        reproducibility: None,
        provenance: None,
        timestamp_token: None,
    };

    if options.sign_receipt {
        let mut storage = crate::storage::Storage::new(workspace)?;
        let store = crate::keys::KeyStore::new(workspace);
        match store.select_signing_key(options.receipt_key.as_deref())? {
            Some(signing_key) => storage.set_keypair(
                crate::crypto::sign::AttestKeypair::from_signing_key(signing_key),
            ),
            None => storage.load_keypair(true)?,
        }
        receipt = storage.sign_receipt(&receipt)?;
    }

    let receipts_dir = options
        .receipt_dir
        .clone()
        .unwrap_or_else(|| workspace.join(".attest").join("receipts"));
    std::fs::create_dir_all(&receipts_dir)
        .with_context(|| format!("cannot create {}", receipts_dir.display()))?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    crate::storage::write_receipt_unique(
        &receipts_dir,
        &stamp,
        Some("image-verify"),
        &serde_yaml::to_string(&receipt)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/imagetools")
            .join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("fixture {} unreadable: {e}", path.display()));
        serde_json::from_str(&text).expect("fixture parses")
    }

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    // IMG-7 — document discovery.

    #[test]
    fn sbom_single_platform_passes() {
        assert_eq!(check_sbom(&fixture("sbom_single.json")), Ok(1));
    }

    #[test]
    fn sbom_multi_platform_passes() {
        assert_eq!(check_sbom(&fixture("sbom_multiplatform.json")), Ok(2));
    }

    #[test]
    fn sbom_null_fails_with_zero_documents() {
        let err = check_sbom(&serde_json::Value::Null).unwrap_err();
        assert!(err.contains("no SPDX document"), "{err}");
    }

    // IMG-7 — one test per clause.

    #[test]
    fn sbom_wrong_spdxid_fails() {
        let mut sbom = fixture("sbom_single.json");
        sbom["SPDX"]["SPDXID"] = "SPDXRef-Other".into();
        assert!(check_sbom(&sbom).unwrap_err().contains("SPDXID"));
    }

    #[test]
    fn sbom_missing_spdx_version_fails() {
        let mut sbom = fixture("sbom_single.json");
        sbom["SPDX"]
            .as_object_mut()
            .expect("object")
            .remove("spdxVersion");
        assert!(check_sbom(&sbom).unwrap_err().contains("spdxVersion"));
    }

    #[test]
    fn sbom_missing_creation_info_fails() {
        let mut sbom = fixture("sbom_single.json");
        sbom["SPDX"]["creationInfo"]["created"] = 42.into();
        assert!(check_sbom(&sbom)
            .unwrap_err()
            .contains("creationInfo.created"));
    }

    #[test]
    fn sbom_packages_not_array_fails() {
        let mut sbom = fixture("sbom_single.json");
        sbom["SPDX"]["packages"] = serde_json::json!({});
        assert!(check_sbom(&sbom).unwrap_err().contains("packages"));
    }

    #[test]
    fn sbom_one_bad_platform_fails_the_set() {
        let mut sbom = fixture("sbom_multiplatform.json");
        sbom["linux/arm64"]["SPDX"]["packages"] = serde_json::json!(null);
        assert!(check_sbom(&sbom).is_err());
    }

    // IMG-8 — SLSA v0.2 clauses.

    #[test]
    fn provenance_v02_passes() {
        assert_eq!(
            check_provenance(&fixture("provenance_slsa_v02.json")),
            Ok(1)
        );
    }

    #[test]
    fn provenance_v02_clause_violations_fail() {
        for (pointer, bad) in [
            ("buildType", serde_json::json!("")),
            ("builder", serde_json::json!("not-an-object")),
            ("invocation", serde_json::json!([])),
            ("metadata", serde_json::json!({"buildStartedOn": "t"})), // no buildFinishedOn
            ("materials", serde_json::json!([])),
        ] {
            let mut provenance = fixture("provenance_slsa_v02.json");
            provenance["SLSA"][pointer] = bad;
            assert!(
                check_provenance(&provenance).is_err(),
                "clause {pointer} not enforced"
            );
        }
    }

    // IMG-8 — SLSA v1 clauses.

    #[test]
    fn provenance_v1_passes_single_and_multi() {
        assert_eq!(check_provenance(&fixture("provenance_slsa_v1.json")), Ok(1));
        assert_eq!(
            check_provenance(&fixture("provenance_multiplatform.json")),
            Ok(2)
        );
    }

    #[test]
    fn provenance_v1_clause_violations_fail() {
        for (pointer, field, bad) in [
            ("/SLSA/buildDefinition", "buildType", serde_json::json!("")),
            (
                "/SLSA/buildDefinition",
                "externalParameters",
                serde_json::json!(7),
            ),
            (
                "/SLSA/buildDefinition",
                "resolvedDependencies",
                serde_json::json!([]),
            ),
            ("/SLSA/runDetails", "builder", serde_json::json!(null)),
            (
                "/SLSA/runDetails/metadata",
                "startedOn",
                serde_json::json!(1),
            ),
            (
                "/SLSA/runDetails/metadata",
                "finishedOn",
                serde_json::json!(null),
            ),
            (
                "/SLSA/runDetails/metadata",
                "invocationId",
                serde_json::json!(""),
            ),
        ] {
            let mut provenance = fixture("provenance_slsa_v1.json");
            provenance
                .pointer_mut(pointer)
                .expect("pointer resolves")
                .as_object_mut()
                .expect("object")
                .insert(field.to_string(), bad);
            assert!(
                check_provenance(&provenance).is_err(),
                "clause {pointer}/{field} not enforced"
            );
        }
    }

    #[test]
    fn provenance_missing_fails() {
        let err = check_provenance(&serde_json::Value::Null).unwrap_err();
        assert!(err.contains("no SLSA provenance"), "{err}");
    }

    // IMG-8 — revision binding.

    #[test]
    fn revision_binding_matches() {
        let provenance = fixture("provenance_slsa_v1.json");
        assert_eq!(check_revision_binding(&provenance, REVISION), Ok(Some(1)));
    }

    #[test]
    fn revision_binding_mismatch_names_both_revisions() {
        let provenance = fixture("provenance_slsa_v1.json");
        let other = "f".repeat(40);
        let err = check_revision_binding(&provenance, &other).unwrap_err();
        assert!(err.contains(&other), "{err}");
        assert!(err.contains(REVISION), "{err}");
    }

    #[test]
    fn revision_binding_skipped_for_v02_only() {
        let provenance = fixture("provenance_slsa_v02.json");
        assert_eq!(check_revision_binding(&provenance, REVISION), Ok(None));
    }

    #[test]
    fn revision_binding_missing_in_v1_fails() {
        let mut provenance = fixture("provenance_slsa_v1.json");
        provenance
            .pointer_mut("/SLSA/runDetails/metadata")
            .expect("metadata")
            .as_object_mut()
            .expect("object")
            .remove("buildkit_metadata");
        assert!(check_revision_binding(&provenance, REVISION).is_err());
    }

    #[test]
    fn verification_manifest_is_canonical() {
        let request = SupplyChainRequest {
            image_ref: "registry.example/gateway@sha256:8f3c".to_string(),
            require_sbom: true,
            require_provenance: false,
            expected_revision: Some(REVISION.to_string()),
            key_uri: Some("azurekms://v/keys/k/1".to_string()),
        };
        assert_eq!(
            verification_input_manifest(&request),
            format!(
                "attest-image-verify/v1\n\
                 image:registry.example/gateway@sha256:8f3c\n\
                 require-sbom:true\n\
                 require-provenance:false\n\
                 expected-revision:{REVISION}\n\
                 key:azurekms://v/keys/k/1\n"
            )
        );
    }

    #[test]
    fn verification_receipt_records_report_and_verdict() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let request = SupplyChainRequest {
            image_ref: "registry.example/gateway@sha256:8f3c".to_string(),
            require_sbom: true,
            ..Default::default()
        };
        let report = SupplyChainReport {
            image: request.image_ref.clone(),
            verdict: "fail".to_string(),
            checks: vec![CheckResult::fail(
                "sbom",
                "packages is not an array".to_string(),
            )],
        };

        let path = write_verification_receipt(
            workspace.path(),
            &request,
            &report,
            &VerifyReceiptOptions::default(),
        )
        .expect("receipt written");

        assert!(path.starts_with(workspace.path().join(".attest/receipts")));
        let receipt: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).expect("read receipt"))
                .expect("receipt parses");
        assert_eq!(receipt["steps"][0]["name"].as_str(), Some("image-verify"));
        assert_eq!(receipt["steps"][0]["exit_code"].as_i64(), Some(1));
        let stdout = receipt["steps"][0]["stdout"].as_str().expect("stdout");
        assert!(stdout.contains("packages is not an array"), "{stdout}");
    }
}
