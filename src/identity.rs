//! Workflow identity attached to the exact bytes of a receipt.
//!
//! Cosign 3 verifies the Sigstore certificate, blob signature, transparency
//! proof and signing time against a recipient-supplied local trusted root.
//! Only then do we read Fulcio's authenticated source repository and revision
//! extensions. Runner environment variables are never verification evidence.
//! A workflow identity identifies the signer; it does not prove that its
//! runner was uncompromised or that its build faithfully used the source.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::storage::Receipt;
use crate::verify::{read_bounded, MAX_RECEIPT_BYTES};

pub const MAX_IDENTITY_BYTES: u64 = 4 * 1024 * 1024;
const BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// Recipient policy. This file and its trusted root must arrive independently
/// of the evidence being checked. Values are exact matches, never regexes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPolicy {
    /// Expected OIDC issuer, for example https://token.actions.githubusercontent.com.
    pub issuer: String,
    /// Source repository URI from Fulcio extension 1.3.6.1.4.1.57264.1.12.
    pub repository: String,
    /// Complete certificate SAN: workflow URL, including its @ref suffix.
    pub workflow: String,
    /// Source commit from Fulcio extension 1.3.6.1.4.1.57264.1.13.
    pub revision: String,
    /// Local Sigstore TrustedRoot JSON. Never taken from an evidence archive.
    pub trusted_root: PathBuf,
}

impl IdentityPolicy {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("issuer", &self.issuer),
            ("repository", &self.repository),
            ("workflow", &self.workflow),
        ] {
            let url = reqwest::Url::parse(value)
                .with_context(|| format!("identity policy {name} must be an HTTPS URL"))?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || value.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                bail!("identity policy {name} must be an HTTPS URL without credentials");
            }
        }
        if ![40, 64].contains(&self.revision.len())
            || !self
                .revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("identity policy revision must be a full lowercase SHA-1 or SHA-256 commit id");
        }
        if self.trusted_root.as_os_str().is_empty() {
            bail!("identity policy requires an independently configured local trusted_root");
        }
        Ok(())
    }
}

/// Values authenticated by the certificate and matched against the policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityVerification {
    pub issuer: String,
    pub repository: String,
    pub workflow: String,
    pub revision: String,
}

/// Roles are kept separate: authorizing a receipt's workflow does not prove
/// that the same principal signed the artifact itself.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityPrincipals {
    pub evidence_producer: Option<String>,
    pub workflow: Option<String>,
    pub artifact_signer: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityOutcome {
    pub required: Option<IdentityPolicy>,
    pub verified: Option<IdentityVerification>,
    pub principals: IdentityPrincipals,
}

/// Obtain an online keyless signature over the exact receipt bytes. On GitHub,
/// Cosign obtains its job token automatically; GitLab supplies an ID token with
/// audience `sigstore` through `SIGSTORE_ID_TOKEN`. The token is never put in
/// argv, the receipt or the resulting bundle. This operation publishes signing
/// metadata and the receipt digest to the configured Sigstore transparency log.
pub fn sign_receipt_identity(
    receipt_path: &Path,
    bundle_path: &Path,
    identity_token: Option<&str>,
) -> Result<()> {
    sign_with_cosign(&cosign_binary()?, receipt_path, bundle_path, identity_token)
}

fn sign_with_cosign(
    cosign: &Path,
    receipt_path: &Path,
    bundle_path: &Path,
    identity_token: Option<&str>,
) -> Result<()> {
    if bundle_path.symlink_metadata().is_ok() {
        bail!("workflow bundle already exists: {}", bundle_path.display());
    }
    let parent = bundle_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .context("cannot stage workflow bundle in output directory")?;
    let bytes = read_bounded(receipt_path, MAX_RECEIPT_BYTES, "receipt")?;
    let _: Receipt =
        serde_yaml::from_slice(&bytes).context("invalid receipt for workflow signing")?;
    let scratch = tempfile::tempdir()?;
    let receipt = scratch.path().join("receipt.yaml");
    let bundle = scratch.path().join("workflow.sigstore.json");
    std::fs::write(&receipt, bytes)?;
    check_cosign_version(cosign)?;
    let mut command = Command::new(cosign);
    command
        .args([
            "sign-blob",
            "--yes",
            "--new-bundle-format=true",
            "--tlog-upload=true",
            "--bundle",
        ])
        .arg(&bundle)
        .arg(&receipt)
        .current_dir(scratch.path());
    if let Some(token) = identity_token {
        if token.trim().is_empty() {
            bail!("workflow signing token is empty");
        }
        command.env("SIGSTORE_ID_TOKEN", token);
    }
    let output = command
        .output()
        .context("cannot execute cosign sign-blob")?;
    if !output.status.success() {
        // Do not replay a subprocess diagnostic that could include its token.
        bail!("cosign workflow signing failed ({})", output.status);
    }
    let bytes = read_bounded(&bundle, MAX_IDENTITY_BYTES, "workflow identity")?;
    bundle_certificate(&bytes).context("cosign did not produce a supported workflow bundle")?;
    // Publish atomically and refuse replacing another proof, including a
    // destination created while signing was in progress.
    use std::io::Write;
    staged
        .write_all(&bytes)
        .context("cannot write workflow bundle")?;
    staged
        .persist_noclobber(bundle_path)
        .map_err(|error| error.error)
        .with_context(|| format!("cannot create workflow bundle {}", bundle_path.display()))?;
    Ok(())
}

/// Verify without network access. Explicit local trust material prevents
/// Cosign's TUF bootstrap; `--offline` prevents a transparency-log lookup.
/// The receipt and bundle are snapshotted before invoking the verifier, so the
/// certificate inspected below is the one whose signature Cosign checked.
pub fn verify_receipt_identity(
    receipt_path: &Path,
    bundle_path: &Path,
    policy: &IdentityPolicy,
) -> Result<IdentityVerification> {
    verify_with_cosign(&cosign_binary()?, receipt_path, bundle_path, policy)
}

fn verify_with_cosign(
    cosign: &Path,
    receipt_path: &Path,
    bundle_path: &Path,
    policy: &IdentityPolicy,
) -> Result<IdentityVerification> {
    policy.validate()?;
    let receipt_bytes = read_bounded(receipt_path, MAX_RECEIPT_BYTES, "receipt")?;
    let bundle_bytes = read_bounded(bundle_path, MAX_IDENTITY_BYTES, "workflow identity")?;
    let root_bytes = read_bounded(
        &policy.trusted_root,
        MAX_IDENTITY_BYTES,
        "Sigstore trusted root",
    )?;
    let receipt: Receipt = serde_yaml::from_slice(&receipt_bytes).context("invalid receipt")?;
    let source = receipt
        .provenance
        .as_ref()
        .and_then(|p| p.source.as_ref())
        .context("workflow identity requires source revision in receipt provenance")?;
    if source.commit != policy.revision {
        bail!("receipt source revision does not match identity policy");
    }
    verify_blob_bytes(cosign, &receipt_bytes, &bundle_bytes, &root_bytes, policy)
}

fn verify_blob_bytes(
    cosign: &Path,
    receipt_bytes: &[u8],
    bundle_bytes: &[u8],
    root_bytes: &[u8],
    policy: &IdentityPolicy,
) -> Result<IdentityVerification> {
    let scratch = tempfile::tempdir()?;
    let receipt_path = scratch.path().join("receipt.yaml");
    let bundle_path = scratch.path().join("workflow.sigstore.json");
    let root_path = scratch.path().join("trusted-root.json");
    std::fs::write(&receipt_path, receipt_bytes)?;
    std::fs::write(&bundle_path, bundle_bytes)?;
    std::fs::write(&root_path, root_bytes)?;
    check_cosign_version(cosign)?;
    let output = Command::new(cosign)
        .args([
            "verify-blob",
            "--offline=true",
            "--new-bundle-format=true",
            "--insecure-ignore-tlog=false",
            "--insecure-ignore-sct=false",
            "--trusted-root",
        ])
        .arg(&root_path)
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--certificate-identity")
        .arg(&policy.workflow)
        .arg("--certificate-oidc-issuer")
        .arg(&policy.issuer)
        .arg(&receipt_path)
        .current_dir(scratch.path())
        .output()
        .context("cannot execute cosign verify-blob")?;
    if !output.status.success() {
        bail!(
            "workflow signature, certificate identity or Sigstore proof rejected by cosign ({})",
            output.status
        );
    }
    // Fulcio .12/.13 contain provider-authenticated claims, unlike the
    // runner-supplied provenance. Authentication happened above, not here.
    let certificate = bundle_certificate(bundle_bytes)?;
    let (repository, revision) = certificate_source(&certificate)?;
    if repository != policy.repository {
        bail!("certified source repository does not match identity policy");
    }
    if revision != policy.revision {
        bail!("certified source revision does not match identity policy");
    }
    Ok(IdentityVerification {
        issuer: policy.issuer.clone(),
        repository,
        workflow: policy.workflow.clone(),
        revision,
    })
}

fn cosign_binary() -> Result<PathBuf> {
    which::which("cosign").context("workflow identity requires cosign 3 on PATH")
}

fn check_cosign_version(cosign: &Path) -> Result<()> {
    let output = Command::new(cosign).arg("version").output()?;
    if !output.status.success() {
        bail!("cannot determine cosign version; workflow identity requires cosign 3");
    }
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let major = text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("GitVersion:")?
            .trim()
            .strip_prefix('v')?
            .split('.')
            .next()?
            .parse::<u32>()
            .ok()
    });
    if !major.is_some_and(|major| major >= 3) {
        bail!("workflow identity requires cosign 3 or newer");
    }
    Ok(())
}

fn bundle_certificate(bytes: &[u8]) -> Result<Vec<u8>> {
    let bundle: serde_json::Value =
        serde_json::from_slice(bytes).context("invalid Sigstore bundle JSON")?;
    let media = bundle.get("mediaType").and_then(|v| v.as_str());
    if media != Some(BUNDLE_MEDIA_TYPE)
        && media != Some("application/vnd.dev.sigstore.bundle+json;version=0.3")
    {
        bail!("workflow identity requires a Sigstore v0.3 bundle");
    }
    let material = bundle
        .get("verificationMaterial")
        .context("missing Sigstore verification material")?;
    if material.get("publicKey").is_some() || material.get("x509CertificateChain").is_some() {
        bail!("workflow bundle must carry one leaf certificate");
    }
    if bundle.get("messageSignature").is_none() || bundle.get("dsseEnvelope").is_some() {
        bail!("workflow bundle must hold a blob signature over the receipt");
    }
    let encoded = material
        .pointer("/certificate/rawBytes")
        .and_then(|v| v.as_str())
        .context("workflow bundle has no leaf certificate")?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("invalid workflow certificate encoding")
}

/// Narrow, definite-length DER reader. It extracts two strings after Cosign
/// has authenticated the certificate; it does not implement X.509 validation.
struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    fn take(&mut self, tag: u8) -> Result<&'a [u8]> {
        if self.0.first() != Some(&tag) {
            bail!("unexpected certificate DER tag");
        }
        let first = *self.0.get(1).context("truncated certificate DER length")?;
        let (len, header) = if first < 128 {
            (first as usize, 2)
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                bail!("unsupported certificate DER length");
            }
            let raw = self
                .0
                .get(2..2 + count)
                .context("truncated certificate DER length")?;
            if raw[0] == 0 {
                bail!("noncanonical certificate DER length");
            }
            let len = raw
                .iter()
                .try_fold(0usize, |n, b| n.checked_mul(256)?.checked_add(*b as usize))
                .context("certificate DER length overflow")?;
            if len < 128 {
                bail!("noncanonical certificate DER length");
            }
            (len, 2 + count)
        };
        let end = header
            .checked_add(len)
            .context("certificate DER length overflow")?;
        let contents = self
            .0
            .get(header..end)
            .context("truncated certificate DER value")?;
        self.0 = &self.0[end..];
        Ok(contents)
    }

    fn finish(self) -> Result<()> {
        if !self.0.is_empty() {
            bail!("trailing certificate DER data");
        }
        Ok(())
    }
}

fn certificate_source(bytes: &[u8]) -> Result<(String, String)> {
    let mut outer = Der(bytes);
    let mut certificate = Der(outer.take(0x30)?);
    outer.finish()?;
    let mut tbs = Der(certificate.take(0x30)?);
    certificate.take(0x30)?; // signature algorithm
    certificate.take(0x03)?; // signature value, authenticated by Cosign
    certificate.finish()?;
    if tbs.0.first() == Some(&0xa0) {
        tbs.take(0xa0)?;
    }
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30, 0x30] {
        tbs.take(tag)?;
    }
    for tag in [0x81, 0x82] {
        if tbs.0.first() == Some(&tag) {
            tbs.take(tag)?;
        }
    }
    let mut explicit = Der(tbs
        .take(0xa3)
        .context("workflow certificate has no extensions")?);
    tbs.finish()?;
    let mut extensions = Der(explicit.take(0x30)?);
    explicit.finish()?;
    let mut repository = None;
    let mut revision = None;
    let mut seen = std::collections::HashSet::new();
    while !extensions.0.is_empty() {
        let mut extension = Der(extensions.take(0x30)?);
        let oid = extension.take(0x06)?;
        if !seen.insert(oid) {
            bail!("duplicate workflow certificate extension");
        }
        if extension.0.first() == Some(&0x01) {
            extension.take(0x01)?;
        }
        let value = extension.take(0x04)?;
        extension.finish()?;
        let target = match oid {
            [0x2b, 6, 1, 4, 1, 0x83, 0xbf, 0x30, 1, 12] => &mut repository,
            [0x2b, 6, 1, 4, 1, 0x83, 0xbf, 0x30, 1, 13] => &mut revision,
            _ => continue,
        };
        let mut string = Der(value);
        let value =
            std::str::from_utf8(string.take(0x0c)?).context("workflow extension is not UTF-8")?;
        string.finish()?;
        *target = Some(value.to_owned());
    }
    Ok((
        repository.context("workflow certificate is missing certified source repository")?,
        revision.context("workflow certificate is missing certified source revision")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPOSITORY: &str = "https://gitlab.com/team/project";
    const REVISION: &str = "0123456789012345678901234567890123456789";

    fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut value = vec![tag];
        if bytes.len() < 128 {
            value.push(bytes.len() as u8);
        } else {
            value.extend([0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]);
            // DER lengths must use their shortest representation.
            if value[2] == 0 {
                value[1] = 0x81;
                value.remove(2);
            }
        }
        value.extend(bytes);
        value
    }

    fn extension(id: u8, text: &str) -> Vec<u8> {
        let oid = [0x2b, 6, 1, 4, 1, 0x83, 0xbf, 0x30, 1, id];
        tlv(
            0x30,
            &[tlv(6, &oid), tlv(4, &tlv(12, text.as_bytes()))].concat(),
        )
    }

    // Only structural scaffolding: this certificate is never claimed to be
    // cryptographically valid. Cosign owns signature/path/time verification.
    fn certificate(extensions: Vec<Vec<u8>>) -> Vec<u8> {
        let mut tbs = tlv(0xa0, &tlv(2, &[2]));
        tbs.extend(tlv(2, &[1]));
        for _ in 0..5 {
            tbs.extend(tlv(0x30, &[]));
        }
        tbs.extend(tlv(0xa3, &tlv(0x30, &extensions.concat())));
        tlv(
            0x30,
            &[tlv(0x30, &tbs), tlv(0x30, &[]), tlv(3, &[0])].concat(),
        )
    }

    #[test]
    fn certified_source_uses_generic_fulcio_extensions() {
        let cert = certificate(vec![extension(12, REPOSITORY), extension(13, REVISION)]);
        assert_eq!(
            certificate_source(&cert).unwrap(),
            (REPOSITORY.into(), REVISION.into())
        );
    }

    #[test]
    fn certified_source_refuses_absence_duplicates_and_trailing_bytes() {
        assert!(certificate_source(&certificate(vec![extension(12, REPOSITORY)])).is_err());
        assert!(certificate_source(&certificate(vec![
            extension(12, REPOSITORY),
            extension(12, REPOSITORY),
            extension(13, REVISION)
        ]))
        .is_err());
        let mut cert = certificate(vec![extension(12, REPOSITORY), extension(13, REVISION)]);
        cert.push(0);
        assert!(certificate_source(&cert).is_err());
    }

    #[test]
    fn every_truncation_is_refused() {
        let cert = certificate(vec![extension(12, REPOSITORY), extension(13, REVISION)]);
        for end in 0..cert.len() {
            assert!(
                certificate_source(&cert[..end]).is_err(),
                "accepted truncation {end}"
            );
        }
    }

    #[test]
    fn real_certificate_without_workflow_claims_is_refused() {
        let cert = include_bytes!("../tests/fixtures/timestamp/digicert-tsa-ca.der");
        let error = certificate_source(cert).unwrap_err().to_string();
        assert!(
            error.contains("missing certified source repository"),
            "{error}"
        );
    }

    const REAL_BUNDLE: &[u8] = include_bytes!("../tests/fixtures/identity/github.sigstore.json");
    const REAL_ROOT: &[u8] = include_bytes!("../tests/fixtures/identity/trusted-root.json");
    const REAL_ARTIFACT: &[u8] = include_bytes!("../tests/fixtures/identity/artifact.txt");

    fn real_policy() -> IdentityPolicy {
        IdentityPolicy {
            issuer: "https://token.actions.githubusercontent.com".into(),
            repository: "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon".into(),
            workflow: "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main".into(),
            revision: "c7b3dfb335f051e1c86bda4c716fac97df62ad81".into(),
            trusted_root: "tests/fixtures/identity/trusted-root.json".into(),
        }
    }

    #[test]
    fn extracts_certified_source_from_real_fulcio_certificate() {
        let certificate = bundle_certificate(REAL_BUNDLE).unwrap();
        let (repository, revision) = certificate_source(&certificate).unwrap();
        assert_eq!(repository, real_policy().repository);
        assert_eq!(revision, real_policy().revision);
    }

    /// Run with ATTEST_TEST_COSIGN=/absolute/path/to/cosign cargo test --lib
    /// identity::tests::real_sigstore_verification -- --ignored.
    /// Fixtures are public conformance evidence, not trusted release identities.
    #[test]
    #[ignore = "requires independently installed cosign 3 (ATTEST_TEST_COSIGN)"]
    fn real_sigstore_verification() {
        let cosign = PathBuf::from(
            std::env::var("ATTEST_TEST_COSIGN").expect("ATTEST_TEST_COSIGN is required"),
        );
        let expected = real_policy();
        verify_blob_bytes(&cosign, REAL_ARTIFACT, REAL_BUNDLE, REAL_ROOT, &expected).unwrap();
        let mut replaced = REAL_ARTIFACT.to_vec();
        replaced[0] ^= 1;
        assert!(verify_blob_bytes(&cosign, &replaced, REAL_BUNDLE, REAL_ROOT, &expected).is_err());
        let mut unauthorized = expected.clone();
        unauthorized.workflow =
            "https://github.com/attacker/project/.github/workflows/release.yml@refs/heads/main"
                .into();
        assert!(verify_blob_bytes(
            &cosign,
            REAL_ARTIFACT,
            REAL_BUNDLE,
            REAL_ROOT,
            &unauthorized
        )
        .is_err());
        unauthorized = expected.clone();
        unauthorized.issuer = "https://gitlab.com".into();
        assert!(verify_blob_bytes(
            &cosign,
            REAL_ARTIFACT,
            REAL_BUNDLE,
            REAL_ROOT,
            &unauthorized
        )
        .is_err());
        unauthorized = expected.clone();
        unauthorized.repository = "https://github.com/attacker/project".into();
        assert!(verify_blob_bytes(
            &cosign,
            REAL_ARTIFACT,
            REAL_BUNDLE,
            REAL_ROOT,
            &unauthorized
        )
        .is_err());
        unauthorized = expected.clone();
        unauthorized.revision = REVISION.into();
        assert!(verify_blob_bytes(
            &cosign,
            REAL_ARTIFACT,
            REAL_BUNDLE,
            REAL_ROOT,
            &unauthorized
        )
        .is_err());
        assert!(verify_blob_bytes(&cosign, REAL_ARTIFACT, REAL_BUNDLE, b"{}", &expected).is_err());
        let mut tampered: serde_json::Value = serde_json::from_slice(REAL_BUNDLE).unwrap();
        tampered["messageSignature"]["signature"] = serde_json::json!("AAAA");
        assert!(verify_blob_bytes(
            &cosign,
            REAL_ARTIFACT,
            &serde_json::to_vec(&tampered).unwrap(),
            REAL_ROOT,
            &expected
        )
        .is_err());
        tampered = serde_json::from_slice(REAL_BUNDLE).unwrap();
        tampered["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"] =
            serde_json::json!("AAAA");
        assert!(verify_blob_bytes(
            &cosign,
            REAL_ARTIFACT,
            &serde_json::to_vec(&tampered).unwrap(),
            REAL_ROOT,
            &expected
        )
        .is_err());
        tampered = serde_json::from_slice(REAL_BUNDLE).unwrap();
        tampered["verificationMaterial"]["tlogEntries"] = serde_json::json!([]);
        assert!(verify_blob_bytes(
            &cosign,
            REAL_ARTIFACT,
            &serde_json::to_vec(&tampered).unwrap(),
            REAL_ROOT,
            &expected
        )
        .is_err());
    }

    #[test]
    fn der_refuses_ber_and_noncanonical_lengths() {
        for bytes in [
            &[0x30, 0x80][..],
            &[0x30, 0x81, 0][..],
            &[0x30, 0x82, 0, 128][..],
            &[0x30, 0xff][..],
        ] {
            assert!(Der(bytes).take(0x30).is_err());
        }
    }

    fn policy(root: PathBuf) -> IdentityPolicy {
        IdentityPolicy {
            issuer: "https://gitlab.com".into(),
            repository: REPOSITORY.into(),
            workflow: format!("{REPOSITORY}//.gitlab-ci.yml@refs/heads/main"),
            revision: REVISION.into(),
            trusted_root: root,
        }
    }

    #[test]
    fn recipient_policy_rejects_partial_identity_and_unusable_revision() {
        let mut expected = policy("trusted-root.json".into());
        expected.validate().unwrap();
        expected.revision = "main".into();
        assert!(expected.validate().is_err());
        expected.revision = REVISION.into();
        expected.issuer = "https://user:secret@gitlab.com".into();
        assert!(expected.validate().is_err());
        expected.issuer = "https://gitlab.com".into();
        expected.trusted_root = PathBuf::new();
        assert!(expected.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn verifier_binds_exact_receipt_and_rejects_unauthorized_certified_source() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("cosign");
        std::fs::write(
            &program,
            r#"#!/bin/sh
if [ "$1" = version ]; then echo 'GitVersion: v3.1.4'; exit 0; fi
printf '%s\n' "$@" > "$0.args"
for arg do last="$arg"; done
cmp "$last" "$0.receipt" || exit 1
if [ -f "$0.reject" ]; then exit 1; fi
exit 0
"#,
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut receipt: Receipt =
            serde_yaml::from_str(include_str!("../tests/fixtures/interop/receipt.yaml")).unwrap();
        receipt.provenance = Some(crate::provenance::collect(
            dir.path(),
            Some("build".into()),
            false,
        ));
        receipt.provenance.as_mut().unwrap().source = Some(crate::storage::SourceInfo {
            repository: Some("https://mirror.example/team/project".into()),
            commit: REVISION.into(),
            branch: None,
            tracked_dirty: false,
        });
        let bytes = serde_yaml::to_string(&receipt).unwrap();
        let receipt_path = dir.path().join("receipt.yaml");
        std::fs::write(&receipt_path, &bytes).unwrap();
        std::fs::write(dir.path().join("cosign.receipt"), bytes).unwrap();
        let root = dir.path().join("trusted-root.json");
        std::fs::write(&root, "{}").unwrap();
        let policy = policy(root);
        let bundle_path = dir.path().join("bundle.json");
        let write_bundle = |repository: &str, revision: &str| {
            let cert = certificate(vec![extension(12, repository), extension(13, revision)]);
            let bundle = serde_json::json!({
                "mediaType": BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {"certificate": {"rawBytes": base64::engine::general_purpose::STANDARD.encode(cert)}},
                "messageSignature": {}
            });
            std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        };
        write_bundle(REPOSITORY, REVISION);
        let result = verify_with_cosign(&program, &receipt_path, &bundle_path, &policy).unwrap();
        assert_eq!(result.repository, REPOSITORY);
        let args = std::fs::read_to_string(dir.path().join("cosign.args")).unwrap();
        assert!(args.contains("--offline=true\n"));
        assert!(args.contains("--insecure-ignore-tlog=false\n"));
        assert!(args.contains("--insecure-ignore-sct=false\n"));
        assert!(args.contains(&format!("--certificate-identity\n{}\n", policy.workflow)));
        assert!(args.contains(&format!("--certificate-oidc-issuer\n{}\n", policy.issuer)));
        assert!(args.contains("--trusted-root\n"));
        write_bundle("https://gitlab.com/attacker/project", REVISION);
        assert!(
            verify_with_cosign(&program, &receipt_path, &bundle_path, &policy)
                .unwrap_err()
                .to_string()
                .contains("repository")
        );
        write_bundle(REPOSITORY, "ffffffffffffffffffffffffffffffffffffffff");
        assert!(
            verify_with_cosign(&program, &receipt_path, &bundle_path, &policy)
                .unwrap_err()
                .to_string()
                .contains("revision")
        );
        write_bundle(REPOSITORY, REVISION);
        std::fs::write(dir.path().join("cosign.reject"), "").unwrap();
        assert!(
            verify_with_cosign(&program, &receipt_path, &bundle_path, &policy)
                .unwrap_err()
                .to_string()
                .contains("rejected by cosign")
        );
        std::fs::remove_file(dir.path().join("cosign.reject")).unwrap();
        // Same parsed receipt, different exact bytes: still a substitution.
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&receipt_path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert!(verify_with_cosign(&program, &receipt_path, &bundle_path, &policy).is_err());
    }
}
