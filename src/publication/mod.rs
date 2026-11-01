//! Explicit external publication. Pure proof verification lives separately
//! from the publisher's network client; reading evidence never contacts a log.

pub mod client;
pub mod merkle;
pub mod note;
pub mod record;
pub mod tiles;

use anyhow::{ensure, Context, Result};
use ring::digest::{digest, SHA256};

pub const ENTRY_PREFIX: &[u8] = b"attest-causal-root/v1\n";
const COMMITMENT_DOMAIN: &[u8] = b"attest-causal-root/v1\0";

/// Decode a canonical, lower-case 32-byte hash or opening nonce.
pub fn hash_bytes(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "expected a canonical 32-byte hexadecimal value"
    );
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid hash length"))
}

/// The only bytes submitted to the log. The opening stays with the private
/// evidence. Neither the receipt root nor a producer identifier is uploaded.
pub fn entry_for_root(root: &str, nonce: &str) -> Result<Vec<u8>> {
    let root = hash_bytes(root).context("invalid causal root")?;
    let nonce = hash_bytes(nonce).context("invalid publication opening")?;
    let mut preimage = Vec::with_capacity(COMMITMENT_DOMAIN.len() + 64);
    preimage.extend_from_slice(COMMITMENT_DOMAIN);
    preimage.extend_from_slice(&nonce);
    preimage.extend_from_slice(&root);
    let mut entry = ENTRY_PREFIX.to_vec();
    entry.extend_from_slice(digest(&SHA256, &preimage).as_ref());
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_commitments_bind_the_root_and_private_opening() {
        let root = "11".repeat(32);
        let nonce = "22".repeat(32);
        let entry = entry_for_root(&root, &nonce).unwrap();
        assert_eq!(entry.len(), ENTRY_PREFIX.len() + 32);
        assert!(entry.starts_with(ENTRY_PREFIX));
        assert!(!entry.windows(32).any(|w| w == [0x11; 32]));
        assert!(!entry.windows(32).any(|w| w == [0x22; 32]));
        assert_ne!(entry, entry_for_root(&"33".repeat(32), &nonce).unwrap());
        assert_ne!(entry, entry_for_root(&root, &"33".repeat(32)).unwrap());
        assert!(entry_for_root(&"AA".repeat(32), &nonce).is_err());
        assert!(entry_for_root(&root, "22").is_err());
    }
}
