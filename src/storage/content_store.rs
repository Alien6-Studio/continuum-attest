//! Content-addressable storage for artifacts

use anyhow::Result;
use blake3;
use std::path::PathBuf;

pub struct ContentStore {
    store_dir: PathBuf,
}

impl ContentStore {
    pub fn new(store_dir: PathBuf) -> Self {
        Self { store_dir }
    }

    pub fn store_content(&self, content: &[u8]) -> Result<String> {
        let hash = blake3::hash(content);
        let hash_str = hash.to_hex().to_string();

        let content_path = self.store_dir.join(&hash_str);
        std::fs::create_dir_all(&self.store_dir)?;
        std::fs::write(content_path, content)?;

        Ok(hash_str)
    }

    pub fn get_content(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        let content_path = self.store_dir.join(hash);
        if content_path.exists() {
            Ok(Some(std::fs::read(content_path)?))
        } else {
            Ok(None)
        }
    }
}
