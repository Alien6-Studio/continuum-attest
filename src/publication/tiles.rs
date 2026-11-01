//! C2SP tlog-tiles hash reads. A source supplies bounded responses, while
//! inclusion and consistency remain independently checked by the caller.

use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;

use super::merkle::{self, Hash};

pub const TILE_BYTES: usize = 256 * 32;

/// None means the resource does not exist. A missing historical partial
/// tile may be retried as a full tile; other failures are not hidden.
#[async_trait]
pub trait TileSource: Sync {
    async fn tile(&self, path: &str) -> Result<Option<Vec<u8>>>;
}

pub fn tile_path(level: u32, index: u64, width: usize) -> Result<String> {
    ensure!(
        level <= 63 && (1..=256).contains(&width),
        "invalid tile coordinates"
    );
    let mut groups = vec![format!("{:03}", index % 1000)];
    let mut index = index / 1000;
    while index != 0 {
        groups.push(format!("x{:03}", index % 1000));
        index /= 1000;
    }
    groups.reverse();
    let suffix = if width == 256 {
        String::new()
    } else {
        format!(".p/{width}")
    };
    Ok(format!("tile/{level}/{}{suffix}", groups.join("/")))
}

pub struct TileReader<'a, S> {
    source: &'a S,
    /// Must come from an authenticated checkpoint before any partial read.
    tree_size: u64,
    cache: BTreeMap<(u32, u64), Vec<Hash>>,
}

impl<'a, S: TileSource> TileReader<'a, S> {
    pub fn new(source: &'a S, authenticated_tree_size: u64) -> Self {
        Self {
            source,
            tree_size: authenticated_tree_size,
            cache: BTreeMap::new(),
        }
    }

    async fn perfect_root(&mut self, start: u64, size: u64) -> Result<Hash> {
        ensure!(
            size.is_power_of_two()
                && start.is_multiple_of(size)
                && start
                    .checked_add(size)
                    .is_some_and(|end| end <= self.tree_size),
            "subtree is outside the authenticated tree"
        );
        let height = size.trailing_zeros();
        let level = height / 8;
        let node_index = start >> (8 * level);
        let tile_index = node_index / 256;
        let offset = (node_index % 256) as usize;
        let count = 1usize << (height % 8);
        let width = ((self.tree_size >> (8 * level)) - tile_index * 256).min(256) as usize;
        ensure!(
            offset + count <= width,
            "subtree exceeds the authenticated tile width"
        );
        if !self.cache.contains_key(&(level, tile_index)) {
            ensure!(
                self.cache.len() < 512,
                "publication needs too many hash tiles"
            );
            let path = tile_path(level, tile_index, width)?;
            let (bytes, received_width) = match self.source.tile(&path).await? {
                Some(bytes) => (bytes, width),
                None if width < 256 => (
                    self.source
                        .tile(&tile_path(level, tile_index, 256)?)
                        .await?
                        .context("log has neither the partial nor the full hash tile")?,
                    256,
                ),
                None => anyhow::bail!("log hash tile is unavailable"),
            };
            ensure!(
                bytes.len() == received_width * 32 && bytes.len() <= TILE_BYTES,
                "invalid hash tile length"
            );
            let hashes = bytes.as_chunks::<32>().0.to_vec();
            self.cache.insert((level, tile_index), hashes);
        }
        let tile = self
            .cache
            .get(&(level, tile_index))
            .context("hash tile was not cached")?;
        let mut level = tile[offset..offset + count].to_vec();
        while level.len() > 1 {
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| merkle::node_hash(&pair[0], &pair[1]))
                .collect();
        }
        level.first().copied().context("empty subtree")
    }

    /// Compute a requested subtree without recursive async calls. Non-perfect
    /// subtrees are folded in RFC 6962 order, not padded or duplicated.
    pub async fn range_root(&mut self, start: u64, size: u64) -> Result<Hash> {
        ensure!(
            size > 0
                && start
                    .checked_add(size)
                    .is_some_and(|end| end <= self.tree_size),
            "range is outside the authenticated tree"
        );
        let mut pending = vec![(start, size, false)];
        let mut roots = Vec::new();
        while let Some((start, size, join)) = pending.pop() {
            if join {
                let right = roots.pop().context("missing right subtree")?;
                let left = roots.pop().context("missing left subtree")?;
                roots.push(merkle::node_hash(&left, &right));
            } else if size.is_power_of_two() {
                roots.push(self.perfect_root(start, size).await?);
            } else {
                let left_size = 1u64 << (63 - (size - 1).leading_zeros());
                pending.push((start, size, true));
                pending.push((start + left_size, size - left_size, false));
                pending.push((start, left_size, false));
            }
        }
        ensure!(roots.len() == 1, "invalid subtree assembly");
        roots.pop().context("missing assembled root")
    }

    pub async fn inclusion(&mut self, index: u64) -> Result<Vec<Hash>> {
        let mut hashes = Vec::new();
        for (start, size) in merkle::inclusion_ranges(index, self.tree_size)? {
            hashes.push(self.range_root(start, size).await?);
        }
        Ok(hashes)
    }

    pub async fn consistency(&mut self, old_size: u64, new_size: u64) -> Result<Vec<Hash>> {
        ensure!(
            new_size <= self.tree_size,
            "comparison exceeds the authenticated tree"
        );
        let mut hashes = Vec::new();
        for (start, size) in merkle::consistency_ranges(old_size, new_size)? {
            hashes.push(self.range_root(start, size).await?);
        }
        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_follow_c2sp_coordinates() {
        assert_eq!(
            tile_path(0, 1_234_067, 256).unwrap(),
            "tile/0/x001/x234/067"
        );
        assert_eq!(tile_path(2, 0, 1).unwrap(), "tile/2/000.p/1");
        assert!(tile_path(64, 0, 256).is_err());
        assert!(tile_path(0, 0, 0).is_err());
        assert!(tile_path(0, 0, 257).is_err());
    }

    struct Source(BTreeMap<String, Vec<u8>>);

    #[async_trait]
    impl TileSource for Source {
        async fn tile(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.get(path).cloned())
        }
    }

    #[tokio::test]
    async fn deleted_partial_tiles_fall_back_without_consuming_future_hashes() {
        let hashes: Vec<_> = (0..256u16).map(|i| merkle::leaf_hash(&[i as u8])).collect();
        let bytes = hashes.iter().flatten().copied().collect();
        let source = Source(BTreeMap::from([("tile/0/000".into(), bytes)]));
        let mut reader = TileReader::new(&source, 3);
        let root = merkle::node_hash(&merkle::node_hash(&hashes[0], &hashes[1]), &hashes[2]);
        assert_eq!(reader.range_root(0, 3).await.unwrap(), root);
        let proof = reader.inclusion(2).await.unwrap();
        merkle::verify_inclusion(&[2], 2, 3, &proof, &root).unwrap();
        assert!(reader.range_root(3, 1).await.is_err());
        assert!(reader.inclusion(3).await.is_err());
        assert!(reader.consistency(3, 4).await.is_err());
    }

    #[tokio::test]
    async fn malformed_partial_tiles_are_not_silently_replaced() {
        let source = Source(BTreeMap::from([
            ("tile/0/000.p/3".into(), vec![0; 95]),
            ("tile/0/000".into(), vec![0; TILE_BYTES]),
        ]));
        let mut reader = TileReader::new(&source, 3);
        assert!(reader.range_root(0, 2).await.is_err());
    }
}
