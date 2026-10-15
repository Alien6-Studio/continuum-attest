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
    /// value. It is the Unix time of `issued_at` in nanoseconds, so two
    /// bundles issued in the same second still order; recipients compare
    /// it, they do not read it as a clock.
    pub sequence: u64,
    pub keys: Vec<BundledKey>,
    /// The authority this issuer hands over to, if it is stepping down.
    /// Signed by the issuer, so a recipient learns the successor's key from
    /// the authority it already trusts rather than from the successor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor: Option<Issuer>,
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
    successor: Option<&str>,
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

    // A successor is named by the authority stepping down, and has to be
    // a key that authority already trusts: the handover is a statement
    // the recipient can check against keys it is being given at the same
    // time, by the same signature.
    let successor = match successor {
        None => None,
        Some(id) if id == issuer.key_id => bail!("a key cannot be its own successor"),
        Some(id) => match keys.iter().find(|k| k.id == id) {
            Some(k) if k.status == KeyStatus::Trusted => Some(Issuer {
                key_id: k.id.clone(),
                public_key: k.public_key.clone(),
            }),
            Some(_) => bail!("successor {} is revoked; it cannot take over", id),
            None => bail!(
                "successor {} is not in the trust store; generate or import it first",
                id
            ),
        },
    };

    let issued_at = Utc::now();
    let mut bundle = TrustBundle {
        schema_version: BUNDLE_SCHEMA_VERSION,
        issuer,
        issued_at,
        valid_until: issued_at + valid_for,
        sequence: u64::try_from(
            issued_at
                .timestamp_nanos_opt()
                .context("clock out of the range a sequence can hold")?,
        )
        .context("clock reads before 1970")?,
        keys,
        successor,
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

    if let Some(successor) = &bundle.successor {
        checks.push(successor_check(bundle, successor));
    }

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

fn successor_check(bundle: &TrustBundle, successor: &Issuer) -> BundleCheck {
    if successor.key_id == bundle.issuer.key_id {
        return check("successor", false, "the issuer names itself as successor");
    }
    match key_id_from_hex(&successor.public_key) {
        Ok(derived) if derived == successor.key_id => {}
        Ok(derived) => {
            return check(
                "successor",
                false,
                format!(
                    "successor claims key id {} but its public key derives to {}",
                    successor.key_id, derived
                ),
            )
        }
        Err(err) => return check("successor", false, format!("successor public key: {err}")),
    }
    match bundle.keys.iter().find(|k| k.id == successor.key_id) {
        Some(k) if k.status == KeyStatus::Trusted && k.public_key == successor.public_key => check(
            "successor",
            true,
            format!(
                "hands over to {}, listed among the trusted",
                successor.key_id
            ),
        ),
        Some(k) if k.status == KeyStatus::Trusted => check(
            "successor",
            false,
            "the successor's key differs from the key listed under its id",
        ),
        Some(_) => check(
            "successor",
            false,
            "the successor is revoked by this very bundle",
        ),
        None => check(
            "successor",
            false,
            "the successor is not among the keys the bundle vouches for",
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successor: Option<Issuer>,
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
        successor: bundle.successor.clone(),
        checks,
    }
}

// ---------------------------------------------------------------------------
// Import: a bundle becomes local trust, and says what it changed.
// ---------------------------------------------------------------------------

/// Where accepted bundles are kept, one per issuer, named by the issuer's
/// key id. The copy is what a later import is compared against, so that
/// "newer than what I already accepted" survives a restart.
fn accepted_dir(trust_dir: &Path) -> std::path::PathBuf {
    trust_dir.join("bundles")
}

fn accepted_bundle(trust_dir: &Path, issuer: &str) -> Result<Option<TrustBundle>> {
    let path = accepted_dir(trust_dir).join(format!("{issuer}.json"));
    if !path.is_file() {
        return Ok(None);
    }
    read(&path).map(Some)
}

/// What an import did to the local store, key by key.
#[derive(Debug, Default, Serialize)]
pub struct ImportReport {
    pub issuer: String,
    pub sequence: u64,
    pub valid_until: Option<DateTime<Utc>>,
    /// Keys the store did not have: id, name, status as imported.
    pub added: Vec<(String, String, KeyStatus)>,
    /// Keys the store trusted and the bundle revokes: id, name, when.
    pub revoked: Vec<(String, String, DateTime<Utc>)>,
    /// Keys the store had already revoked and the bundle lists as trusted.
    /// A bundle does not un-revoke: the local decision stands, and the
    /// recipient is told.
    pub kept_revoked: Vec<(String, String)>,
    /// Keys already revoked whose revocation the bundle dates earlier:
    /// id, name, the new, earlier moment.
    pub revocation_moved_earlier: Vec<(String, String, DateTime<Utc>)>,
    pub unchanged: usize,
    /// True when the bundle was already the accepted one; nothing was
    /// written.
    pub already_current: bool,
    /// Set when a first bundle from this issuer was accepted because an
    /// already pinned authority named it as successor: that authority's
    /// key id, and the sequence of the bundle that said so.
    pub handover_from: Option<(String, u64)>,
}

/// Every bundle accepted so far, whatever the issuer. Read as local
/// state, like `trust.toml`: each was verified when it was accepted.
pub fn accepted_bundles(trust_dir: &Path) -> Result<Vec<TrustBundle>> {
    let dir = accepted_dir(trust_dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut bundles = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") {
            bundles.push(read(&path)?);
        }
    }
    Ok(bundles)
}

/// Import a bundle into the workspace's trust store, or refresh from a
/// newer one. Never reaches the network: the file is what it is given.
///
/// The first bundle from an issuer needs `expected_issuer`: the recipient
/// names the key id they obtained through another channel, and a bundle
/// from anyone else is refused whatever it contains. Later bundles from
/// that issuer must be newer than the one already accepted, by the signed
/// sequence; an older one is a replay and is refused.
pub fn import(
    workspace: &Path,
    bundle_path: &Path,
    expected_issuer: Option<&str>,
    now: DateTime<Utc>,
) -> Result<ImportReport> {
    let bundle = read(bundle_path)?;
    let failed: Vec<String> = examine(&bundle, now)
        .into_iter()
        .filter(|c| !c.passed)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();
    if !failed.is_empty() {
        bail!("refusing {}: {}", bundle_path.display(), failed.join("; "));
    }

    let store = KeyStore::new(workspace);
    let trust_dir = store.trust_dir();
    let issuer = bundle.issuer.key_id.clone();
    // An authority this store has revoked does not get to update it,
    // however well-formed its bundle and whoever once pinned it. Its key
    // may be in someone else's hands; that is what revocation means.
    let local_policy = TrustPolicy::load(&trust_dir)?;
    if local_policy
        .entry(&issuer)
        .is_some_and(|entry| entry.status == KeyStatus::Revoked)
    {
        bail!(
            "bundle is issued by {}, which this store has revoked; a revoked authority cannot update it",
            issuer
        );
    }
    if let Some(expected) = expected_issuer {
        if expected != issuer {
            bail!(
                "bundle is issued by {} but you expected {}; refusing it whatever it contains",
                issuer,
                expected
            );
        }
    }
    let previous = accepted_bundle(&trust_dir, &issuer)?;
    // A first bundle from an unknown issuer is accepted on one of two
    // grounds only: the recipient named that issuer, or an authority the
    // recipient already accepted named it as successor, in a bundle that
    // also vouched for its key. Anything else is a stranger.
    let mut handover_from = None;
    match &previous {
        None if expected_issuer.is_none() => {
            let predecessor = accepted_bundles(&trust_dir)?.into_iter().find(|accepted| {
                accepted
                    .successor
                    .as_ref()
                    .is_some_and(|s| s.key_id == issuer && s.public_key == bundle.issuer.public_key)
            });
            match predecessor {
                Some(predecessor) => {
                    handover_from = Some((predecessor.issuer.key_id.clone(), predecessor.sequence));
                }
                None => bail!(
                    "first bundle from issuer {}: name the issuer you expect with --issuer <KEY_ID>, \
                     obtained from the producer through a channel other than this file",
                    issuer
                ),
            }
        }
        None => {}
        Some(previous) if bundle.sequence < previous.sequence => bail!(
            "bundle sequence {} is older than the one already accepted from {} (sequence {}); \
             a bundle cannot go backwards",
            bundle.sequence,
            issuer,
            previous.sequence
        ),
        Some(previous)
            if bundle.sequence == previous.sequence && bundle.signature != previous.signature =>
        {
            bail!(
                "a different bundle with sequence {} was already accepted from {}; \
                 two bundles cannot share a sequence",
                bundle.sequence,
                issuer
            )
        }
        Some(_) => {}
    }

    let mut report = ImportReport {
        issuer: issuer.clone(),
        sequence: bundle.sequence,
        valid_until: Some(bundle.valid_until),
        handover_from,
        ..ImportReport::default()
    };
    if previous
        .as_ref()
        .is_some_and(|p| p.signature == bundle.signature)
    {
        report.already_current = true;
        report.unchanged = bundle.keys.len();
        return Ok(report);
    }

    // Public key files first: the policy is checked against them on load.
    std::fs::create_dir_all(&trust_dir)?;
    for key in &bundle.keys {
        let public_path = trust_dir.join(format!("{}.pub", key.id));
        if public_path.exists() {
            continue;
        }
        let bytes = hex::decode(&key.public_key).context("public key hex")?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&array).context("public key")?;
        let pem = ed25519_dalek::pkcs8::EncodePublicKey::to_public_key_pem(
            &verifying_key,
            ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF,
        )
        .context("cannot encode public key as PEM")?;
        std::fs::write(&public_path, pem.as_bytes())
            .with_context(|| format!("cannot write {}", public_path.display()))?;
    }

    let mut policy = TrustPolicy::load(&trust_dir)?;
    for key in &bundle.keys {
        match policy.keys.iter_mut().find(|k| k.id == key.id) {
            None => {
                policy.keys.push(crate::keys::TrustEntry {
                    id: key.id.clone(),
                    name: key.name.clone(),
                    status: key.status,
                    revoked_at: key.revoked_at,
                });
                report
                    .added
                    .push((key.id.clone(), key.name.clone(), key.status));
            }
            Some(entry) => match (entry.status, key.status) {
                (KeyStatus::Trusted, KeyStatus::Revoked) => {
                    entry.status = KeyStatus::Revoked;
                    entry.revoked_at = key.revoked_at;
                    report.revoked.push((
                        key.id.clone(),
                        entry.name.clone(),
                        key.revoked_at.unwrap_or(DateTime::<Utc>::MIN_UTC),
                    ));
                }
                (KeyStatus::Revoked, KeyStatus::Trusted) => {
                    report
                        .kept_revoked
                        .push((key.id.clone(), entry.name.clone()));
                }
                // Both revoked: the earlier date wins. An issuer who learns
                // a key was compromised before the date first recorded
                // moves the revocation back, and every signature between
                // the two dates has to fall with it; a later date never
                // reopens a window. No local date means always revoked,
                // which is stricter than every dated bundle revocation.
                (KeyStatus::Revoked, KeyStatus::Revoked)
                    if key
                        .revoked_at
                        .is_some_and(|at| entry.revoked_at.is_some_and(|known| at < known)) =>
                {
                    entry.revoked_at = key.revoked_at;
                    report.revocation_moved_earlier.push((
                        key.id.clone(),
                        entry.name.clone(),
                        key.revoked_at.unwrap_or(DateTime::<Utc>::MIN_UTC),
                    ));
                }
                _ => report.unchanged += 1,
            },
        }
    }
    policy.save(&trust_dir)?;

    // Only once the store holds the keys: an accepted-bundle record for a
    // policy that failed to write would refuse the retry as a replay.
    let dir = accepted_dir(&trust_dir);
    std::fs::create_dir_all(&dir)?;
    write(&bundle, &dir.join(format!("{issuer}.json")))?;
    Ok(report)
}

/// The most recently accepted bundle, by signed sequence, across issuers:
/// the point up to which this store's revocations are known to be current.
pub fn latest_accepted(trust_dir: &Path) -> Result<Option<TrustBundle>> {
    Ok(accepted_bundles(trust_dir)?
        .into_iter()
        .max_by_key(|b| b.sequence))
}
