//! C2SP signed-note / checkpoint profile: an independently configured
//! Ed25519 log key, never a key supplied by the checkpoint being checked.

use std::collections::BTreeSet;

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

use super::merkle::{empty_root, Hash};

pub const MAX_NOTE_BYTES: usize = 128 * 1024;
const MAX_SIGNATURES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    pub format: String,
    pub origin: String,
    pub verifier_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<std::path::PathBuf>,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '+')
}

fn canonical_base64(text: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD.decode(text).context("invalid note base64")?;
    ensure!(STANDARD.encode(&bytes) == text, "non-canonical note base64");
    Ok(bytes)
}

pub struct Verifier {
    name: String,
    id: [u8; 4],
    key: VerifyingKey,
}

impl Verifier {
    pub fn parse(text: &str) -> Result<Self> {
        ensure!(text.len() <= 4096, "note verifier key is too long");
        let mut parts = text.splitn(3, '+');
        let name = parts.next().context("missing verifier name")?;
        ensure!(valid_name(name), "invalid verifier name");
        let id = parts.next().context("missing verifier key identifier")?;
        ensure!(
            id.len() == 8
                && id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid verifier key identifier"
        );
        let material = canonical_base64(parts.next().context("missing verifier public key")?)?;
        ensure!(
            material.len() == 33 && material[0] == 1,
            "this log profile requires an Ed25519 note verifier key"
        );
        let mut preimage = name.as_bytes().to_vec();
        preimage.push(b'\n');
        preimage.extend_from_slice(&material);
        let key_hash = digest(&SHA256, &preimage);
        let expected = &key_hash.as_ref()[..4];
        ensure!(
            hex::encode(expected) == id,
            "verifier key identifier mismatch"
        );
        let mut identifier = [0; 4];
        identifier.copy_from_slice(expected);
        let raw: [u8; 32] = material[1..]
            .try_into()
            .context("invalid Ed25519 public key length")?;
        let key = VerifyingKey::from_bytes(&raw).context("invalid Ed25519 log public key")?;
        ensure!(!key.is_weak(), "weak Ed25519 log public key");
        Ok(Self {
            name: name.into(),
            id: identifier,
            key,
        })
    }

    pub fn verify_note<'a>(&self, note: &'a str) -> Result<&'a str> {
        ensure!(note.len() <= MAX_NOTE_BYTES, "checkpoint note is too large");
        ensure!(
            note.ends_with('\n') && !note.bytes().any(|c| c < 0x20 && c != b'\n'),
            "invalid signed-note text"
        );
        let separator = note
            .rfind("\n\n")
            .context("missing note signature separator")?;
        let body = &note[..separator + 1];
        let signatures = &note[separator + 2..];
        ensure!(
            !body.is_empty() && !signatures.is_empty(),
            "empty signed note"
        );
        let lines: Vec<_> = signatures.lines().collect();
        ensure!(lines.len() <= MAX_SIGNATURES, "too many note signatures");
        let mut seen = BTreeSet::new();
        let mut authenticated = false;
        for line in lines {
            let line = line
                .strip_prefix("— ")
                .context("invalid note signature line")?;
            let (name, signature) = line
                .split_once(' ')
                .context("invalid note signature fields")?;
            ensure!(valid_name(name), "invalid note signer name");
            ensure!(signature.len() <= 16 * 1024, "note signature is too long");
            let signature = canonical_base64(signature)?;
            ensure!(
                (5..=8192).contains(&signature.len()),
                "invalid note signature length"
            );
            let id: [u8; 4] = signature[..4]
                .try_into()
                .context("missing note signature id")?;
            ensure!(
                seen.insert((name.to_string(), id)),
                "duplicate note signer tuple"
            );
            if name == self.name && id == self.id {
                let signature = Signature::from_slice(&signature[4..])
                    .context("invalid Ed25519 note signature length")?;
                self.key
                    .verify_strict(body.as_bytes(), &signature)
                    .context("invalid signature from configured log key")?;
                authenticated = true;
            }
        }
        ensure!(
            authenticated,
            "checkpoint has no signature from configured log key"
        );
        Ok(body)
    }
}

impl LogConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "attest-log/v1",
            "unsupported log configuration format"
        );
        ensure!(
            valid_name(&self.origin) && self.origin.len() <= 4096,
            "invalid checkpoint origin"
        );
        Verifier::parse(&self.verifier_key)?;
        Ok(())
    }

    pub fn log_id(&self) -> Result<String> {
        self.validate()?;
        let bytes = format!("attest-log/v1\n{}\n{}", self.origin, self.verifier_key);
        Ok(hex::encode(digest(&SHA256, bytes.as_bytes()).as_ref()))
    }
}

#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub tree_size: u64,
    pub root: Hash,
    pub signed_note: String,
}

impl Checkpoint {
    pub fn verify(note: &str, trust: &LogConfig) -> Result<Self> {
        trust.validate()?;
        let verifier = Verifier::parse(&trust.verifier_key)?;
        let body = verifier.verify_note(note)?;
        let mut lines = body.lines();
        ensure!(
            lines.next() == Some(trust.origin.as_str()),
            "checkpoint origin differs from configured log"
        );
        let size = lines.next().context("checkpoint lacks tree size")?;
        ensure!(
            !size.is_empty()
                && size.bytes().all(|c| c.is_ascii_digit())
                && (size == "0" || !size.starts_with('0')),
            "non-canonical checkpoint tree size"
        );
        let tree_size = size
            .parse::<u64>()
            .context("checkpoint tree size overflows")?;
        let encoded = lines.next().context("checkpoint lacks root hash")?;
        let root: Hash = canonical_base64(encoded)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid checkpoint root length"))?;
        ensure!(
            lines.all(|line| !line.is_empty()),
            "empty checkpoint extension line"
        );
        if tree_size == 0 {
            ensure!(root == empty_root(), "invalid empty-tree checkpoint root");
        }
        Ok(Self {
            tree_size,
            root,
            signed_note: note.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c2sp_published_note_vector_verifies_and_tampering_fails() {
        // Public conformance example from https://c2sp.org/signed-note@v1.1.0.
        let key = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
        let note = "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";
        let verifier = Verifier::parse(key).unwrap();
        assert_eq!(
            verifier.verify_note(note).unwrap(),
            "This is an example message.\n"
        );
        assert!(verifier
            .verify_note(&note.replace("message", "forgery"))
            .is_err());
        assert!(verifier.verify_note(note.trim_end()).is_err());
        assert!(Verifier::parse(&key.replace("530d903a", "00000000")).is_err());
        let repeated = format!("{note}{}", note.split("\n\n").nth(1).unwrap());
        assert!(verifier.verify_note(&repeated).is_err());
    }
}
