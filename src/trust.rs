//! A trust bundle: the trust store in a form that can be handed to someone
//! else and judged on arrival.
//!
//! The local store is a directory of `.pub` files and a `trust.toml`.
//! Nothing in it says who assembled it, until when it should be believed,
//! or whether it arrived intact; a recipient has to take it on trust, which
//! is the one thing this project exists to avoid. A bundle carries exactly
//! that: the keys an issuer vouches for and the ones it has revoked, each
//! revocation with its moment, an issuer identified by a key, a validity
//! window, and an Ed25519 signature over the whole. A recipient can tell
//! who issued it, over what period, and whether anything in it was altered,
//! before trusting a single key from it.
//!
//! What a bundle does not say is whether the recipient should believe the
//! issuer. That is pinning, a separate act; `examine` judges a bundle on
//! its own terms only.
//!
//! The signed bytes are the bundle serialised as JSON with the signature
//! absent and the keys sorted by id, the same discipline as a receipt.

use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::keys::{
    key_id, key_id_from_hex, trust_dir_public_keys, KeyStatus, KeyStore, TrustPolicy,
};

/// Bumped when the signed shape changes incompatibly. A verifier refuses a
/// version it does not know rather than guessing at its fields.
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

/// The key that signed the bundle. The id is derived from the public key
/// and checked on arrival, so an issuer cannot claim another key's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub key_id: String,
    /// Hex of the raw 32-byte Ed25519 public key.
    pub public_key: String,
}

/// One key the issuer makes a statement about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundledKey {
    pub id: String,
    pub name: String,
    /// Hex of the raw 32-byte Ed25519 public key.
    pub public_key: String,
    pub status: KeyStatus,
    /// Present on every revoked key: a signature made before this moment
    /// can still be judged on its own merits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBundle {
    pub schema_version: u32,
    pub issuer: Issuer,
    pub issued_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// Orders bundles from one issuer: a later bundle carries a larger
    /// value. It is the Unix time of `issued_at`; recipients compare it,
    /// they do not read it as a clock.
    pub sequence: u64,
    pub keys: Vec<BundledKey>,
    /// Hex Ed25519 signature by the issuer over [`TrustBundle::signing_bytes`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl TrustBundle {
    /// The bytes the issuer signs: the bundle without its signature, keys
    /// sorted by id so that order is not content.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        unsigned.keys.sort_by(|a, b| a.id.cmp(&b.id));
        serde_json::to_vec(&unsigned).context("cannot serialise the bundle for signing")
    }
}

/// Assemble a bundle from the workspace's trust store and sign it with
/// the issuer key, which must be trusted by that same store.
pub fn produce(
    workspace: &Path,
    requested_key: Option<&str>,
    valid_for: Duration,
) -> Result<TrustBundle> {
    let store = KeyStore::new(workspace);
    let signing_key = store.select_signing_key(requested_key)?.context(
        "no managed signing key; generate one with `attest keys generate` or name one with --key",
    )?;
    let issuer_key = signing_key.verifying_key();
    let issuer = Issuer {
        key_id: key_id(&issuer_key),
        public_key: hex::encode(issuer_key.to_bytes()),
    };

    let policy = TrustPolicy::load(&store.trust_dir())?;
    let public_keys = trust_dir_public_keys(&store.trust_dir())?;
    let mut keys = Vec::with_capacity(policy.keys.len());
    for entry in &policy.keys {
        let public_key = public_keys.get(&entry.id).with_context(|| {
            format!(
                "entry '{}' names key {} but no public key file in the trust store holds it",
                entry.name, entry.id
            )
        })?;
        if entry.status == KeyStatus::Revoked && entry.revoked_at.is_none() {
            bail!(
                "key {} ('{}') is revoked without a date; a bundle has to say when, so a \
                 recipient can judge signatures made before it. Set revoked_at in trust.toml",
                entry.id,
                entry.name
            );
        }
        keys.push(BundledKey {
            id: entry.id.clone(),
            name: entry.name.clone(),
            public_key: public_key.clone(),
            status: entry.status,
            revoked_at: entry.revoked_at,
        });
    }
    if keys.is_empty() {
        bail!("the trust store lists no keys; there is nothing to bundle");
    }
    // The issuer vouches for itself, in the open: a recipient has to be
    // able to tell the bundle's signer from a stranger, and a key the
    // store revoked cannot vouch for anything.
    match keys.iter().find(|k| k.id == issuer.key_id) {
        Some(k) if k.status == KeyStatus::Trusted => {}
        Some(_) => bail!(
            "issuer key {} is revoked in the very store it would sign",
            issuer.key_id
        ),
        None => bail!(
            "issuer key {} is not listed in the trust store",
            issuer.key_id
        ),
    }

    let issued_at = Utc::now();
    let mut bundle = TrustBundle {
        schema_version: BUNDLE_SCHEMA_VERSION,
        issuer,
        issued_at,
        valid_until: issued_at + valid_for,
        sequence: u64::try_from(issued_at.timestamp()).context("clock reads before 1970")?,
        keys,
        signature: None,
    };
    bundle.keys.sort_by(|a, b| a.id.cmp(&b.id));
    let bytes = bundle.signing_bytes()?;
    bundle.signature = Some(hex::encode(signing_key.sign(&bytes).to_bytes()));
    Ok(bundle)
}

pub fn write(bundle: &TrustBundle, path: &Path) -> Result<()> {
    let mut json = serde_json::to_string_pretty(bundle).context("cannot serialise the bundle")?;
    json.push('\n');
    std::fs::write(path, json).with_context(|| format!("cannot write {}", path.display()))
}

/// Largest bundle this reader will parse. A bundle lists keys, not
/// evidence; anything bigger is not one.
const BUNDLE_LIMIT: u64 = 1024 * 1024;

pub fn read(path: &Path) -> Result<TrustBundle> {
    let size = std::fs::metadata(path)
        .with_context(|| format!("cannot read {}", path.display()))?
        .len();
    if size > BUNDLE_LIMIT {
        bail!(
            "{} is {} bytes; a trust bundle is at most {}",
            path.display(),
            size,
            BUNDLE_LIMIT
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a trust bundle", path.display()))
}

/// One thing `examine` established, or failed to.
#[derive(Debug, Clone, Serialize)]
pub struct BundleCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

fn check(name: &'static str, passed: bool, detail: impl Into<String>) -> BundleCheck {
    BundleCheck {
        name,
        passed,
        detail: detail.into(),
    }
}

/// Judge a bundle on its own terms at `now`: a known shape, an issuer
/// whose id matches its key, a signature that holds over these exact
/// contents, keys that hold together, and a validity window that contains
/// `now`. Every check runs; a reader sees all that is wrong, not the first
/// thing.
pub fn examine(bundle: &TrustBundle, now: DateTime<Utc>) -> Vec<BundleCheck> {
    let mut checks = Vec::with_capacity(5);

    checks.push(if bundle.schema_version == BUNDLE_SCHEMA_VERSION {
        check(
            "schema",
            true,
            format!("bundle schema {}", bundle.schema_version),
        )
    } else {
        check(
            "schema",
            false,
            format!(
                "unsupported bundle schema {}; this verifier reads {}",
                bundle.schema_version, BUNDLE_SCHEMA_VERSION
            ),
        )
    });

    let issuer_key = match key_id_from_hex(&bundle.issuer.public_key) {
        Ok(derived) if derived == bundle.issuer.key_id => {
            checks.push(check(
                "issuer",
                true,
                format!("issued by key {}", bundle.issuer.key_id),
            ));
            hex::decode(&bundle.issuer.public_key)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        }
        Ok(derived) => {
            checks.push(check(
                "issuer",
                false,
                format!(
                    "issuer claims key id {} but its public key derives to {}",
                    bundle.issuer.key_id, derived
                ),
            ));
            None
        }
        Err(err) => {
            checks.push(check("issuer", false, format!("issuer public key: {err}")));
            None
        }
    };

    checks.push(match (&bundle.signature, issuer_key) {
        (None, _) => check("signature", false, "the bundle is unsigned"),
        (Some(_), None) => check(
            "signature",
            false,
            "cannot verify: the issuer public key is unusable",
        ),
        (Some(signature_hex), Some(verifying_key)) => {
            let parsed = hex::decode(signature_hex)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b).ok())
                .map(|b| Signature::from_bytes(&b));
            match (parsed, bundle.signing_bytes()) {
                (Some(signature), Ok(bytes)) => {
                    let intact = verifying_key.verify(&bytes, &signature).is_ok();
                    if intact {
                        check(
                            "signature",
                            true,
                            format!("valid signature by issuer {}", bundle.issuer.key_id),
                        )
                    } else {
                        check(
                            "signature",
                            false,
                            "signature does not verify: the bundle was altered after signing, \
                             or was not signed by the issuer it names",
                        )
                    }
                }
                (None, _) => check("signature", false, "signature is not 64 bytes of hex"),
                (_, Err(err)) => check(
                    "signature",
                    false,
                    format!("cannot derive signed bytes: {err}"),
                ),
            }
        }
    });

    checks.push(keys_check(bundle));

    checks.push(if bundle.valid_until < bundle.issued_at {
        check(
            "validity",
            false,
            format!(
                "validity window ends ({}) before it starts ({})",
                bundle.valid_until, bundle.issued_at
            ),
        )
    } else if now < bundle.issued_at {
        check(
            "validity",
            false,
            format!("not yet valid: issued at {}", bundle.issued_at),
        )
    } else if now > bundle.valid_until {
        check(
            "validity",
            false,
            format!("expired at {}", bundle.valid_until),
        )
    } else {
        check(
            "validity",
            true,
            format!(
                "valid from {} until {}",
                bundle.issued_at, bundle.valid_until
            ),
        )
    });

    checks
}

fn keys_check(bundle: &TrustBundle) -> BundleCheck {
    if bundle.keys.is_empty() {
        return check("keys", false, "the bundle lists no keys");
    }
    let mut seen = std::collections::HashSet::new();
    let mut revoked = 0usize;
    for key in &bundle.keys {
        match key_id_from_hex(&key.public_key) {
            Ok(derived) if derived == key.id => {}
            Ok(derived) => {
                return check(
                    "keys",
                    false,
                    format!(
                        "key '{}' claims id {} but its public key derives to {}",
                        key.name, key.id, derived
                    ),
                )
            }
            Err(err) => {
                return check(
                    "keys",
                    false,
                    format!("key '{}' ({}): {err}", key.name, key.id),
                )
            }
        }
        if !seen.insert(key.id.as_str()) {
            return check("keys", false, format!("key {} is listed twice", key.id));
        }
        if key.status == KeyStatus::Revoked {
            revoked += 1;
            if key.revoked_at.is_none() {
                return check(
                    "keys",
                    false,
                    format!("key {} is revoked without saying when", key.id),
                );
            }
        }
    }
    match bundle.keys.iter().find(|k| k.id == bundle.issuer.key_id) {
        Some(k) if k.status == KeyStatus::Trusted => check(
            "keys",
            true,
            format!(
                "{} trusted, {} revoked, issuer among the trusted",
                bundle.keys.len() - revoked,
                revoked
            ),
        ),
        Some(_) => check(
            "keys",
            false,
            "the issuer key is revoked by the bundle it signed",
        ),
        None => check(
            "keys",
            false,
            "the issuer key is not among the keys the bundle vouches for",
        ),
    }
}

/// What `attest trust show` reports, in a shape a machine can read.
#[derive(Debug, Serialize)]
pub struct BundleReport {
    pub bundle: String,
    pub verdict: &'static str,
    pub issuer: Issuer,
    pub issued_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub sequence: u64,
    pub keys: Vec<BundledKey>,
    pub checks: Vec<BundleCheck>,
}

pub fn report(path: &Path, bundle: &TrustBundle, now: DateTime<Utc>) -> BundleReport {
    let checks = examine(bundle, now);
    let verdict = if checks.iter().all(|c| c.passed) {
        "pass"
    } else {
        "fail"
    };
    BundleReport {
        bundle: path.display().to_string(),
        verdict,
        issuer: bundle.issuer.clone(),
        issued_at: bundle.issued_at,
        valid_until: bundle.valid_until,
        sequence: bundle.sequence,
        keys: bundle.keys.clone(),
        checks,
    }
}
