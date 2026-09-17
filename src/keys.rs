//! Key management and trust store (`attest keys`).
//!
//! On-disk layout:
//! - `.attest/keys/<key-id>.key` — Ed25519 private key, PKCS#8 v2 PEM, mode 0600 (git-ignored)
//! - `.attest/trust/<key-id>.pub` — public key PEM ("BEGIN PUBLIC KEY"), committed
//! - `.attest/trust/trust.toml` — trust policy (names, trusted/revoked status)
//!
//! `key-id` is derived, never user-chosen: lowercase hex of the first
//! 16 bytes of `blake3(raw 32-byte public key)`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Derive the canonical key id from a raw 32-byte Ed25519 public key.
pub fn key_id(public_key: &VerifyingKey) -> String {
    let digest = blake3::hash(public_key.as_bytes());
    hex::encode(&digest.as_bytes()[..16])
}

/// Derive the key id from a hex-encoded raw 32-byte public key (the form
/// embedded in receipts as `signer_public_key`).
pub fn key_id_from_hex(public_key_hex: &str) -> Result<String> {
    let bytes = hex::decode(public_key_hex).context("invalid public key hex")?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&array)
        .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;
    Ok(key_id(&verifying_key))
}

/// Derive the key id from a public key PEM ("BEGIN PUBLIC KEY").
pub fn key_id_from_pem(pem: &str) -> Result<String> {
    let verifying_key = VerifyingKey::from_public_key_pem(pem)
        .map_err(|e| anyhow::anyhow!("invalid public key PEM: {}", e))?;
    Ok(key_id(&verifying_key))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub id: String,
    pub name: String,
    pub status: String, // "trusted" | "revoked"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicy {
    pub version: u32,
    #[serde(default, rename = "key")]
    pub keys: Vec<TrustEntry>,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            keys: Vec::new(),
        }
    }
}

impl TrustPolicy {
    pub fn load(trust_dir: &Path) -> Result<Self> {
        let path = trust_dir.join("trust.toml");
        if !path.is_file() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        toml::from_str(&content).with_context(|| format!("invalid trust policy {}", path.display()))
    }

    pub fn save(&self, trust_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(trust_dir)?;
        let path = trust_dir.join("trust.toml");
        let content = toml::to_string_pretty(self).context("cannot serialize trust policy")?;
        std::fs::write(&path, content).with_context(|| format!("cannot write {}", path.display()))
    }

    pub fn entry(&self, id: &str) -> Option<&TrustEntry> {
        self.keys.iter().find(|k| k.id == id)
    }
}

/// File-based key store rooted at a workspace directory.
pub struct KeyStore {
    workspace: PathBuf,
}

/// One row of `attest keys list`.
#[derive(Debug, Serialize)]
pub struct KeyListing {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub private_key_present: bool,
}

impl KeyStore {
    pub fn new(workspace: impl Into<PathBuf>) -> Self {
        Self {
            workspace: workspace.into(),
        }
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.workspace.join(".attest").join("keys")
    }

    pub fn trust_dir(&self) -> PathBuf {
        self.workspace.join(".attest").join("trust")
    }

    /// Generate a new keypair, add it to the trust store as trusted, and
    /// return its key id. Refuses to overwrite existing key material.
    pub fn generate(&self, name: &str) -> Result<String> {
        let mut csprng = rand::rngs::OsRng {};
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let id = key_id(&verifying_key);

        let private_path = self.keys_dir().join(format!("{}.key", id));
        let public_path = self.trust_dir().join(format!("{}.pub", id));
        if private_path.exists() || public_path.exists() {
            bail!("key {} already exists, refusing to overwrite", id);
        }

        std::fs::create_dir_all(self.keys_dir())?;
        std::fs::create_dir_all(self.trust_dir())?;

        let private_pem = signing_key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .context("cannot encode private key as PKCS#8 PEM")?;
        std::fs::write(&private_path, private_pem.as_bytes())?;
        set_mode(&private_path, 0o600)?;

        let public_pem = verifying_key
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .context("cannot encode public key as PEM")?;
        std::fs::write(&public_path, public_pem.as_bytes())?;
        set_mode(&public_path, 0o644)?;

        let mut policy = TrustPolicy::load(&self.trust_dir())?;
        policy.keys.push(TrustEntry {
            id: id.clone(),
            name: name.to_string(),
            status: "trusted".to_string(),
            revoked_at: None,
        });
        policy.save(&self.trust_dir())?;

        Ok(id)
    }

    /// List trust policy entries plus whether the private half is local.
    pub fn list(&self) -> Result<Vec<KeyListing>> {
        let policy = TrustPolicy::load(&self.trust_dir())?;
        Ok(policy
            .keys
            .iter()
            .map(|entry| KeyListing {
                id: entry.id.clone(),
                name: entry.name.clone(),
                status: entry.status.clone(),
                revoked_at: entry.revoked_at,
                private_key_present: self.keys_dir().join(format!("{}.key", entry.id)).is_file(),
            })
            .collect())
    }

    /// Return the PUBLIC key PEM for a key id. By construction this reads
    /// only from the trust directory — private material cannot leak here.
    pub fn export(&self, id: &str) -> Result<String> {
        let path = self.trust_dir().join(format!("{}.pub", id));
        if !path.is_file() {
            bail!("unknown key id: {}", id);
        }
        let pem = std::fs::read_to_string(&path)?;
        // Defense in depth: `export` must never emit private material,
        // whatever ends up in the trust directory.
        if !pem.contains("BEGIN PUBLIC KEY") || pem.contains("PRIVATE") {
            bail!("{} does not contain a public key", path.display());
        }
        Ok(pem)
    }

    /// Import a public key PEM into the trust store as trusted.
    /// Idempotent: importing the same key twice adds no duplicate entry.
    pub fn import(&self, pem_path: &Path, name: &str) -> Result<String> {
        let pem = std::fs::read_to_string(pem_path)
            .with_context(|| format!("cannot read {}", pem_path.display()))?;
        if pem.contains("PRIVATE") {
            bail!("refusing to import private key material into the trust store");
        }
        let verifying_key = VerifyingKey::from_public_key_pem(&pem)
            .map_err(|e| anyhow::anyhow!("invalid public key PEM: {}", e))?;
        let id = key_id(&verifying_key);

        std::fs::create_dir_all(self.trust_dir())?;
        let public_path = self.trust_dir().join(format!("{}.pub", id));
        if !public_path.exists() {
            let canonical = verifying_key
                .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                .context("cannot re-encode public key as PEM")?;
            std::fs::write(&public_path, canonical.as_bytes())?;
            set_mode(&public_path, 0o644)?;
        }

        let mut policy = TrustPolicy::load(&self.trust_dir())?;
        if policy.entry(&id).is_none() {
            policy.keys.push(TrustEntry {
                id: id.clone(),
                name: name.to_string(),
                status: "trusted".to_string(),
                revoked_at: None,
            });
            policy.save(&self.trust_dir())?;
        }
        Ok(id)
    }

    /// Mark a key as revoked at `now`. Never deletes files.
    /// Returns false when the id is unknown (verification-meaningful failure).
    pub fn revoke(&self, id: &str) -> Result<bool> {
        let mut policy = TrustPolicy::load(&self.trust_dir())?;
        match policy.keys.iter_mut().find(|k| k.id == id) {
            Some(entry) => {
                entry.status = "revoked".to_string();
                entry.revoked_at = Some(Utc::now());
                policy.save(&self.trust_dir())?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Select the signing key for `attest run --sign`: the `--key` flag
    /// wins, else the only private key present, else an error — never a
    /// silent choice between several keys. Returns `Ok(None)` when no managed private key exists so the
    /// caller can fall back to the legacy auto-generated keypair.
    pub fn select_signing_key(&self, requested: Option<&str>) -> Result<Option<SigningKey>> {
        if let Some(id) = requested {
            let path = self.keys_dir().join(format!("{}.key", id));
            if !path.is_file() {
                bail!(
                    "no private key for id {} in {}",
                    id,
                    self.keys_dir().display()
                );
            }
            return Ok(Some(load_private_pem(&path)?));
        }

        let mut candidates: Vec<PathBuf> = Vec::new();
        if self.keys_dir().is_dir() {
            for entry in std::fs::read_dir(self.keys_dir())? {
                let path = entry?.path();
                let is_managed = path.extension().map(|e| e == "key").unwrap_or(false)
                    && path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n != "private.key" && n != "public.key") // legacy raw keypair, not managed PEM
                        .unwrap_or(false);
                if is_managed {
                    candidates.push(path);
                }
            }
        }

        match candidates.len() {
            0 => Ok(None),
            1 => Ok(Some(load_private_pem(&candidates[0])?)),
            _ => bail!("multiple private keys, use --key"),
        }
    }
}

fn load_private_pem(path: &Path) -> Result<SigningKey> {
    let pem =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| anyhow::anyhow!("invalid private key {}: {}", path.display(), e))
}

/// Load the hex-encoded raw public key for every `.pub` file in a trust
/// directory, keyed by key id. Used by `attest verify`.
pub fn trust_dir_public_keys(
    trust_dir: &Path,
) -> Result<std::collections::HashMap<String, String>> {
    let mut keys = std::collections::HashMap::new();
    if !trust_dir.is_dir() {
        return Ok(keys);
    }
    for entry in std::fs::read_dir(trust_dir)? {
        let path = entry?.path();
        if !path.is_file() || path.extension().map(|e| e != "pub").unwrap_or(true) {
            continue;
        }
        let pem = std::fs::read_to_string(&path)?;
        if let Ok(verifying_key) = VerifyingKey::from_public_key_pem(&pem) {
            keys.insert(
                key_id(&verifying_key),
                hex::encode(verifying_key.to_bytes()),
            );
        }
    }
    Ok(keys)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

impl KeyStore {
    /// Pin a timestamp authority by copying its certificate into the trust
    /// store as `<trust>/tsa/<name>.crt`.
    ///
    /// Pin the authority that *issues* the timestamping certificates, not a
    /// responder: responders rotate, often yearly, and pinning one would
    /// stop verification of every receipt issued after the rotation.
    /// Pinning several is normal, and old ones should stay — they are what
    /// keeps old receipts verifiable.
    pub fn trust_tsa(&self, certificate_path: &Path, name: &str) -> Result<String> {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!("name must be non-empty and use only letters, digits, '-' or '_'");
        }

        let bytes = std::fs::read(certificate_path)
            .with_context(|| format!("cannot read {}", certificate_path.display()))?;
        let certificates = certificates_from_bytes(&bytes);
        let Some(first) = certificates.first() else {
            bail!(
                "{} contains no certificate (expected PEM or DER)",
                certificate_path.display()
            );
        };
        // Parse it now rather than discover at verification time that a
        // pinned file never matches anything.
        let subject = crate::crypto::timestamp::certificate_subject(first).map_err(|e| {
            anyhow::anyhow!(
                "{} is not a usable certificate: {e}",
                certificate_path.display()
            )
        })?;

        let dir = self.trust_dir().join("tsa");
        std::fs::create_dir_all(&dir)?;
        let destination = dir.join(format!("{name}.crt"));
        if destination.exists() {
            bail!(
                "{} already exists; remove it first or choose another name",
                destination.display()
            );
        }
        std::fs::write(&destination, &bytes)?;
        set_mode(&destination, 0o644)?;
        Ok(subject)
    }
}

/// Load the pinned timestamp-authority certificates from a trust directory.
///
/// They live in `<trust_dir>/tsa/`, alongside the signer keys, because they
/// are the same kind of thing: something a repository commits, reviews in a
/// diff, and can point at. Accepts PEM or raw DER; an unreadable or
/// unparseable file is skipped rather than fatal, so one bad file cannot
/// stop every receipt from verifying.
///
/// What is pinned is the *issuing* authority, not the certificate that
/// signs tokens. Timestamp responders rotate, often yearly; pinning one
/// would silently stop verification of receipts issued after the rotation.
/// Several may be pinned at once, and old ones should stay: they are what
/// keeps old receipts checkable.
pub fn tsa_issuers(trust_dir: &Path) -> Vec<Vec<u8>> {
    let dir = trust_dir.join("tsa");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut certificates: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        for der in certificates_from_bytes(&bytes) {
            certificates.push((name.clone(), der));
        }
    }
    // Sorted so the set a receipt is checked against does not depend on
    // directory iteration order.
    certificates.sort();
    certificates.into_iter().map(|(_, der)| der).collect()
}

/// Extract every certificate from a file that may be PEM, may be DER, and
/// may hold more than one.
fn certificates_from_bytes(bytes: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let Ok(text) = std::str::from_utf8(bytes) else {
        // Not text: treat it as DER if it at least starts like a SEQUENCE.
        return if bytes.first() == Some(&0x30) {
            vec![bytes.to_vec()]
        } else {
            Vec::new()
        };
    };

    if !text.contains(BEGIN) {
        return if bytes.first() == Some(&0x30) {
            vec![bytes.to_vec()]
        } else {
            Vec::new()
        };
    }

    let mut out = Vec::new();
    for block in text.split(BEGIN).skip(1) {
        let Some((body, _)) = block.split_once(END) else {
            continue;
        };
        let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, base64)
        {
            out.push(der);
        }
    }
    out
}
