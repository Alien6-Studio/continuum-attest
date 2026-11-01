//! RFC 6962 SHA-256 trees. These hashes are distinct from Attest's BLAKE3
//! causal DAG. Verification consumes every proof node and performs no I/O.

use anyhow::{ensure, Context, Result};
use ring::digest::{digest, SHA256};

pub type Hash = [u8; 32];
// A consistency proof can include its initial subtree hash in addition to
// the 64 siblings needed at the full u64 tree-size boundary.
pub const MAX_PROOF_NODES: usize = 65;
pub const MAX_INCLUSION_NODES: usize = 64;

pub fn empty_root() -> Hash {
    let mut hash = [0; 32];
    hash.copy_from_slice(digest(&SHA256, &[]).as_ref());
    hash
}

pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut preimage = Vec::with_capacity(entry.len() + 1);
    preimage.push(0);
    preimage.extend_from_slice(entry);
    let mut hash = [0; 32];
    hash.copy_from_slice(digest(&SHA256, &preimage).as_ref());
    hash
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut preimage = [0; 65];
    preimage[0] = 1;
    preimage[1..33].copy_from_slice(left);
    preimage[33..].copy_from_slice(right);
    let mut hash = [0; 32];
    hash.copy_from_slice(digest(&SHA256, &preimage).as_ref());
    hash
}

fn split(size: u64) -> u64 {
    // Called only for subtrees with at least two leaves.
    1u64 << (63 - (size - 1).leading_zeros())
}

fn inclusion_root(
    index: u64,
    size: u64,
    leaf: Hash,
    path: &mut std::slice::Iter<'_, Hash>,
) -> Result<Hash> {
    if size == 1 {
        return Ok(leaf);
    }
    let left_size = split(size);
    if index < left_size {
        let left = inclusion_root(index, left_size, leaf, path)?;
        let right = path.next().context("inclusion path is too short")?;
        Ok(node_hash(&left, right))
    } else {
        let right = inclusion_root(index - left_size, size - left_size, leaf, path)?;
        let left = path.next().context("inclusion path is too short")?;
        Ok(node_hash(left, &right))
    }
}

pub fn verify_inclusion(
    entry: &[u8],
    index: u64,
    size: u64,
    path: &[Hash],
    root: &Hash,
) -> Result<()> {
    ensure!(
        size > 0 && index < size,
        "inclusion index is outside the tree"
    );
    ensure!(
        path.len() <= MAX_INCLUSION_NODES,
        "inclusion path is too long"
    );
    let mut remaining = path.iter();
    let calculated = inclusion_root(index, size, leaf_hash(entry), &mut remaining)?;
    ensure!(remaining.next().is_none(), "inclusion path has extra nodes");
    ensure!(
        calculated == *root,
        "inclusion proof does not bind this entry to the checkpoint"
    );
    Ok(())
}

fn consistency_roots(
    old_size: u64,
    new_size: u64,
    known_old_root: &Hash,
    complete: bool,
    path: &mut std::slice::Iter<'_, Hash>,
) -> Result<(Hash, Hash)> {
    if old_size == new_size {
        let root = if complete {
            *known_old_root
        } else {
            *path.next().context("consistency path is too short")?
        };
        return Ok((root, root));
    }
    let left_size = split(new_size);
    if old_size <= left_size {
        let (old, left) = consistency_roots(old_size, left_size, known_old_root, complete, path)?;
        let right = path.next().context("consistency path is too short")?;
        Ok((old, node_hash(&left, right)))
    } else {
        let (old_right, new_right) = consistency_roots(
            old_size - left_size,
            new_size - left_size,
            known_old_root,
            false,
            path,
        )?;
        let left = path.next().context("consistency path is too short")?;
        Ok((node_hash(left, &old_right), node_hash(left, &new_right)))
    }
}

pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &Hash,
    new_root: &Hash,
    path: &[Hash],
) -> Result<()> {
    ensure!(old_size <= new_size, "consistency sizes are reversed");
    ensure!(
        path.len() <= MAX_PROOF_NODES,
        "consistency path is too long"
    );
    if old_size == new_size {
        ensure!(
            path.is_empty(),
            "equal-size checkpoints need no proof nodes"
        );
        ensure!(
            old_root == new_root,
            "conflicting roots at the same tree size"
        );
        if old_size == 0 {
            ensure!(*old_root == empty_root(), "invalid empty-tree root");
        }
        return Ok(());
    }
    if old_size == 0 {
        ensure!(*old_root == empty_root(), "invalid empty-tree root");
        ensure!(path.is_empty(), "an empty prefix needs no proof nodes");
        return Ok(());
    }
    let mut remaining = path.iter();
    let (calculated_old, calculated_new) =
        consistency_roots(old_size, new_size, old_root, true, &mut remaining)?;
    ensure!(
        remaining.next().is_none(),
        "consistency path has extra nodes"
    );
    ensure!(
        calculated_old == *old_root && calculated_new == *new_root,
        "checkpoints are not connected by this consistency proof"
    );
    Ok(())
}

/// Ordered subtree ranges whose hashes form a leaf's inclusion path.
pub fn inclusion_ranges(index: u64, size: u64) -> Result<Vec<(u64, u64)>> {
    ensure!(
        size > 0 && index < size,
        "inclusion index is outside the tree"
    );
    fn walk(index: u64, start: u64, size: u64, out: &mut Vec<(u64, u64)>) {
        if size == 1 {
            return;
        }
        let k = split(size);
        if index < k {
            walk(index, start, k, out);
            out.push((start + k, size - k));
        } else {
            walk(index - k, start + k, size - k, out);
            out.push((start, k));
        }
    }
    let mut ranges = Vec::new();
    walk(index, 0, size, &mut ranges);
    Ok(ranges)
}

/// Ordered subtree ranges for the RFC 6962 consistency proof.
pub fn consistency_ranges(old_size: u64, new_size: u64) -> Result<Vec<(u64, u64)>> {
    ensure!(old_size <= new_size, "consistency sizes are reversed");
    fn walk(old: u64, start: u64, size: u64, complete: bool, out: &mut Vec<(u64, u64)>) {
        if old == size {
            if !complete {
                out.push((start, size));
            }
            return;
        }
        let k = split(size);
        if old <= k {
            walk(old, start, k, complete, out);
            out.push((start + k, size - k));
        } else {
            walk(old - k, start + k, size - k, false, out);
            out.push((start, k));
        }
    }
    let mut ranges = Vec::new();
    if old_size != 0 {
        walk(old_size, 0, new_size, true, &mut ranges);
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_and_internal_nodes_have_different_domains() {
        let left = leaf_hash(b"left");
        let right = leaf_hash(b"right");
        let mut bytes = left.to_vec();
        bytes.extend_from_slice(&right);
        assert_ne!(leaf_hash(&bytes), node_hash(&left, &right));
        assert_ne!(leaf_hash(b""), empty_root());
    }

    #[test]
    fn altered_entries_and_unconsumed_nodes_are_refused() {
        let left = leaf_hash(b"left");
        let right = leaf_hash(b"right");
        let root = node_hash(&left, &right);
        verify_inclusion(b"left", 0, 2, &[right], &root).unwrap();
        verify_inclusion(b"right", 1, 2, &[left], &root).unwrap();
        assert!(verify_inclusion(b"changed", 0, 2, &[right], &root).is_err());
        assert!(verify_inclusion(b"left", 1, 2, &[right], &root).is_err());
        assert!(verify_inclusion(b"left", 0, 2, &[right, right], &root).is_err());
        assert!(verify_inclusion(b"left", 0, 2, &[], &root).is_err());
        assert!(verify_inclusion(b"left", 2, 2, &[right], &root).is_err());
        assert!(verify_inclusion(b"left", 0, 0, &[], &empty_root()).is_err());
        verify_consistency(1, 2, &left, &root, &[right]).unwrap();
        assert!(verify_consistency(1, 2, &left, &root, &[]).is_err());
        assert!(verify_consistency(1, 2, &right, &root, &[right]).is_err());
        assert!(verify_consistency(1, 2, &left, &root, &[right, left]).is_err());
        assert!(verify_consistency(2, 2, &left, &right, &[]).is_err());
        assert!(verify_consistency(2, 1, &root, &left, &[]).is_err());
        assert!(verify_consistency(0, 2, &left, &root, &[]).is_err());
        verify_consistency(0, 2, &empty_root(), &root, &[]).unwrap();
    }
}
