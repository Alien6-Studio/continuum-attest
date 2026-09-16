pub mod causal_ledger;
pub mod content_store;
pub mod receipt;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::sign::AttestKeypair;
use crate::ignore::AttestIgnore;
pub use causal_ledger::{CausalEvent, CausalLedger};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub total_size_bytes: u64,
    pub total_cache_hits: u64,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheCleanupResult {
    pub removed_entries: usize,
    pub removed_size_bytes: u64,
    pub remaining_entries: usize,
    pub remaining_size_bytes: u64,
}

mod receipt_format;
pub use receipt_format::{
    receipt_signing_bytes, ArtifactInfo, CiInfo, ExecutionProvenance, Receipt, ReproducibilityInfo,
    SignerInfo, SourceInfo, StepProvenance, StepResult, RECEIPT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub content_hash: String,
    pub step_name: String,
    pub input_paths: Vec<String>,
    pub output_paths: Vec<String>,
    pub command: String,
    pub environment_hash: String,
    pub result: StepResult,
    pub cached_at: DateTime<Utc>,
    pub dependencies: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheIndex {
    pub entries: HashMap<String, CacheIndexEntry>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheIndexEntry {
    pub content_hash: String,
    pub step_name: String,
    pub cached_at: DateTime<Utc>,
    pub file_size: u64,
    pub access_count: u64,
    pub last_accessed: DateTime<Utc>,
}

#[derive(Debug)]
pub struct Storage {
    attest_dir: PathBuf,
    objects_dir: PathBuf,
    cache_dir: PathBuf,
    receipts_dir: PathBuf,
    ignore: AttestIgnore,
    keypair: Option<AttestKeypair>,
    causal_ledger: Option<CausalLedger>,
}

impl Storage {
    pub fn new(root: &Path) -> Result<Self> {
        let attest_dir = root.join(".attest");
        let objects_dir = attest_dir.join("objects");
        let cache_dir = attest_dir.join("cache");
        let receipts_dir = attest_dir.join("receipts");

        let ignore_file = root.join(".attestignore");
        let ignore = AttestIgnore::new(&ignore_file)?;

        Ok(Self {
            attest_dir,
            objects_dir,
            cache_dir,
            receipts_dir,
            ignore,
            keypair: None,
            causal_ledger: None,
        })
    }

    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.attest_dir)?;
        fs::create_dir_all(&self.objects_dir)?;
        fs::create_dir_all(&self.cache_dir)?;
        fs::create_dir_all(&self.receipts_dir)?;

        let config = format!(
            r#"# ATTEST Configuration
version: "0.1"
deterministic: true
cache_enabled: true
created: "{}"
"#,
            Utc::now().to_rfc3339()
        );

        fs::write(self.attest_dir.join("config.yaml"), config)?;

        // Initialize cache index
        self.init_cache_index()?;

        let attestignore_path = self
            .attest_dir
            .parent()
            .expect("attest_dir is always root.join(\".attest\"), which always has a parent")
            .join(".attestignore");
        if !attestignore_path.exists() {
            AttestIgnore::create_default(&attestignore_path)?;
            tracing::info!("Created .attestignore file");
        }

        Ok(())
    }

    pub async fn hash_path(&self, path: &Path) -> Result<String> {
        if path.is_file() {
            self.hash_file(path).await
        } else if path.is_dir() {
            self.hash_directory(path).await
        } else {
            anyhow::bail!("Path does not exist: {}", path.display());
        }
    }

    async fn hash_file(&self, path: &Path) -> Result<String> {
        let content =
            fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;

        Ok(blake3::hash(&content).to_hex().to_string())
    }

    async fn hash_directory(&self, path: &Path) -> Result<String> {
        let mut hasher = blake3::Hasher::new();

        // Simple directory hashing - can be improved
        let entries = walkdir::WalkDir::new(path)
            .sort_by_file_name()
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| !self.ignore.is_ignored(e.path()));

        for entry in entries {
            let content = fs::read(entry.path())?;
            hasher.update(&content);
        }

        Ok(hasher.finalize().to_hex().to_string())
    }

    pub fn hash_content(&self, content: &str) -> Result<String> {
        Ok(blake3::hash(content.as_bytes()).to_hex().to_string())
    }

    pub fn attest_dir(&self) -> &Path {
        &self.attest_dir
    }

    /// Compute the cache key for a step.
    ///
    /// The declared-input portion is the canonical `attest-manifest/v1`
    /// input hash (src/hashing.rs) — the same hash recorded in receipts —
    /// so the cache key can never disagree with verification: binary
    /// inputs are hashed byte-for-byte and a missing declared input is an
    /// error, never a silent skip. The `run` command participates through
    /// the manifest's `run:` line.
    pub fn compute_content_hash(
        &self,
        workspace: &Path,
        step_name: &str,
        command: &str,
        inputs: &[PathBuf],
        env: &HashMap<String, String>,
    ) -> Result<String> {
        let input_hash = crate::hashing::hash_inputs(workspace, step_name, command, inputs)
            .with_context(|| format!("cannot compute cache key for step '{step_name}'"))?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"attest-cache-key/v1\n");
        hasher.update(step_name.as_bytes());
        hasher.update(b"\n");
        hasher.update(input_hash.as_bytes());
        hasher.update(b"\n");

        // Hash environment variables (sorted for determinism)
        let mut env_entries: Vec<_> = env.iter().collect();
        env_entries.sort_by_key(|(k, _)| *k);
        for (key, value) in env_entries {
            hasher.update(format!("{}={}\n", key, value).as_bytes());
        }

        Ok(hasher.finalize().to_hex().to_string())
    }

    // Each parameter is an independently-sourced piece of the cache key/entry;
    // grouping them into a struct would be a breaking API change out of scope here.
    #[allow(clippy::too_many_arguments)]
    pub fn create_cache_entry(
        &self,
        workspace: &Path,
        step_name: &str,
        command: &str,
        input_paths: Vec<PathBuf>,
        output_paths: Vec<PathBuf>,
        env: &HashMap<String, String>,
        result: StepResult,
        dependencies: Vec<String>,
    ) -> Result<CacheEntry> {
        let content_hash =
            self.compute_content_hash(workspace, step_name, command, &input_paths, env)?;

        // Hash environment for tracking changes
        let mut env_hasher = blake3::Hasher::new();
        let mut env_sorted: Vec<_> = env.iter().collect();
        env_sorted.sort_by_key(|(k, _)| *k);
        for (key, value) in env_sorted {
            env_hasher.update(format!("{}={}", key, value).as_bytes());
        }
        let environment_hash = env_hasher.finalize().to_hex().to_string();

        Ok(CacheEntry {
            content_hash,
            step_name: step_name.to_string(),
            input_paths: input_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            output_paths: output_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            command: command.to_string(),
            environment_hash,
            result,
            cached_at: Utc::now(),
            dependencies,
            metadata: HashMap::new(),
        })
    }

    fn init_cache_index(&self) -> Result<()> {
        let index_file = self.cache_dir.join("index.yaml");

        if !index_file.exists() {
            let index = CacheIndex {
                entries: HashMap::new(),
                last_updated: Utc::now(),
            };

            let content = serde_yaml::to_string(&index)?;
            fs::write(index_file, content)?;
        }

        Ok(())
    }

    fn update_cache_index(&self, content_hash: &str, step_name: &str) -> Result<()> {
        let index_file = self.cache_dir.join("index.yaml");
        let cache_file = self.cache_dir.join(format!("{}.yaml", content_hash));

        let mut index = if index_file.exists() {
            let content = fs::read_to_string(&index_file)?;
            serde_yaml::from_str::<CacheIndex>(&content)?
        } else {
            CacheIndex {
                entries: HashMap::new(),
                last_updated: Utc::now(),
            }
        };

        let file_size = cache_file.metadata().map(|m| m.len()).unwrap_or(0);

        let entry = CacheIndexEntry {
            content_hash: content_hash.to_string(),
            step_name: step_name.to_string(),
            cached_at: Utc::now(),
            file_size,
            access_count: 1,
            last_accessed: Utc::now(),
        };

        index.entries.insert(content_hash.to_string(), entry);
        index.last_updated = Utc::now();

        let content = serde_yaml::to_string(&index)?;
        fs::write(index_file, content)?;

        Ok(())
    }

    pub fn get_cache_stats(&self) -> Result<CacheStats> {
        let index_file = self.cache_dir.join("index.yaml");

        if !index_file.exists() {
            return Ok(CacheStats::default());
        }

        let content = fs::read_to_string(index_file)?;
        let index: CacheIndex = serde_yaml::from_str(&content)?;

        let total_entries = index.entries.len();
        let total_size = index.entries.values().map(|e| e.file_size).sum();
        let total_hits = index.entries.values().map(|e| e.access_count).sum();

        Ok(CacheStats {
            total_entries,
            total_size_bytes: total_size,
            total_cache_hits: total_hits,
            oldest_entry: index.entries.values().map(|e| e.cached_at).min(),
            newest_entry: index.entries.values().map(|e| e.cached_at).max(),
        })
    }

    pub fn cleanup_cache(
        &self,
        max_size_bytes: u64,
        max_age_days: u64,
    ) -> Result<CacheCleanupResult> {
        let index_file = self.cache_dir.join("index.yaml");

        if !index_file.exists() {
            return Ok(CacheCleanupResult::default());
        }

        let content = fs::read_to_string(&index_file)?;
        let mut index: CacheIndex = serde_yaml::from_str(&content)?;

        let max_age = chrono::Duration::days(max_age_days as i64);
        let cutoff_time = Utc::now() - max_age;

        let mut removed_entries = 0;
        let mut removed_size = 0;
        let mut entries_to_remove = Vec::new();

        // Find entries to remove (old or to reduce size)
        let mut entries_by_access: Vec<_> = index.entries.iter().collect();
        entries_by_access.sort_by_key(|(_, entry)| entry.last_accessed);

        let current_size: u64 = index.entries.values().map(|e| e.file_size).sum();
        let mut remaining_size = current_size;

        for (hash, entry) in entries_by_access {
            let should_remove = entry.cached_at < cutoff_time || remaining_size > max_size_bytes;

            if should_remove {
                entries_to_remove.push(hash.clone());
                removed_size += entry.file_size;
                remaining_size -= entry.file_size;
                removed_entries += 1;
            }
        }

        // Remove cache files and index entries
        for hash in &entries_to_remove {
            let cache_file = self.cache_dir.join(format!("{}.yaml", hash));
            if cache_file.exists() {
                fs::remove_file(cache_file)?;
            }
            index.entries.remove(hash);
        }

        // Update index
        index.last_updated = Utc::now();
        let updated_content = serde_yaml::to_string(&index)?;
        fs::write(index_file, updated_content)?;

        Ok(CacheCleanupResult {
            removed_entries,
            removed_size_bytes: removed_size,
            remaining_entries: index.entries.len(),
            remaining_size_bytes: remaining_size,
        })
    }

    /// Install an explicitly selected keypair (see `attest keys`).
    pub fn set_keypair(&mut self, keypair: AttestKeypair) {
        self.keypair = Some(keypair);
    }

    pub fn load_keypair(&mut self, signing_enabled: bool) -> Result<()> {
        if signing_enabled {
            let keys_dir = self.attest_dir.join("keys");
            self.keypair = Some(AttestKeypair::load_or_generate(&keys_dir)?);
            tracing::info!("Loaded signing keypair from {}", keys_dir.display());
        }
        Ok(())
    }

    /// Initialize and get access to causal ledger
    pub async fn get_causal_ledger(&mut self) -> Result<&mut CausalLedger> {
        if self.causal_ledger.is_none() {
            let mut ledger = CausalLedger::new(&self.attest_dir)?;
            ledger.init().await?;

            // Load keypair if available
            if let Some(keypair) = &self.keypair {
                ledger.load_keypair(keypair.clone())?;
            }

            // Load existing events
            ledger.load_events().await?;

            self.causal_ledger = Some(ledger);
            tracing::info!("Initialized causal ledger");
        }

        Ok(self
            .causal_ledger
            .as_mut()
            .expect("just initialized to Some above if it was None"))
    }

    /// Record causal event during step execution
    pub async fn record_causal_event(
        &mut self,
        step_name: &str,
        causal_parents: Vec<String>,
        step_result: &StepResult,
        pipeline_hash: &str,
        environment_hash: &str,
    ) -> Result<CausalEvent> {
        let ledger = self.get_causal_ledger().await?;

        let mut metadata = HashMap::new();
        metadata.insert(
            "duration_secs".to_string(),
            step_result.duration_secs.to_string(),
        );
        metadata.insert("cache_hit".to_string(), step_result.cache_hit.to_string());

        if !step_result.stdout.is_empty() {
            metadata.insert(
                "stdout_hash".to_string(),
                blake3::hash(step_result.stdout.as_bytes())
                    .to_hex()
                    .to_string(),
            );
        }

        ledger
            .record_event(
                step_name,
                causal_parents,
                &step_result.input_hash,
                &step_result.output_hash,
                step_result.exit_code,
                pipeline_hash,
                environment_hash,
                metadata,
            )
            .await
    }

    /// Attach an RFC 3161 timestamp token to an already-signed receipt.
    ///
    /// Must run *after* signing: the token is requested over the signature,
    /// which is the whole point — it places that signature in time, by a
    /// party the signer does not control.
    ///
    /// The default authority is DigiCert's public service. It is free and
    /// its issuing certificates are widely distributed, but it publishes no
    /// terms for this endpoint, so anything depending on it should pin its
    /// own choice with `--tsa` and keep more than one option open.
    pub fn timestamp_receipt(&self, receipt: &Receipt, tsa_url: &str) -> Result<Receipt> {
        use base64::Engine as _;

        let signature = receipt
            .signature
            .as_ref()
            .context("cannot timestamp an unsigned receipt")?;
        let imprint = crate::crypto::timestamp::signature_imprint(signature)?;
        let token = crate::crypto::timestamp::request_token(
            tsa_url,
            &imprint,
            std::time::Duration::from_secs(30),
        )?;

        let mut timestamped = receipt.clone();
        timestamped.timestamp_token =
            Some(base64::engine::general_purpose::STANDARD.encode(&token));
        Ok(timestamped)
    }

    pub fn sign_receipt(&self, receipt: &Receipt) -> Result<Receipt> {
        if let Some(keypair) = &self.keypair {
            // Create canonical representation for signing
            let signing_data = self.create_signing_data(receipt)?;
            let signature = keypair.sign(signing_data.as_bytes());

            let mut signed_receipt = receipt.clone();
            signed_receipt.signature = Some(signature);
            signed_receipt.signer_public_key = Some(keypair.public_key_hex());

            tracing::info!(
                "Signed receipt with public key: {}",
                keypair.public_key_hex()
            );
            Ok(signed_receipt)
        } else {
            // Return unsigned receipt if no keypair loaded
            Ok(receipt.clone())
        }
    }

    pub fn verify_receipt(&self, receipt: &Receipt) -> Result<bool> {
        if let (Some(signature), Some(public_key_hex)) =
            (&receipt.signature, &receipt.signer_public_key)
        {
            // Create a temporary keypair from the public key for verification
            let _public_key_bytes =
                hex::decode(public_key_hex).context("Invalid public key hex in receipt")?;

            // For Ed25519, we need the original keypair to verify
            // In practice, we'd store public keys separately or use a different verification method
            if let Some(keypair) = &self.keypair {
                if keypair.public_key_hex() == *public_key_hex {
                    let signing_data = self.create_signing_data_for_verification(receipt)?;
                    return keypair.verify(signing_data.as_bytes(), signature);
                }
            }

            // If we don't have the matching keypair, we cannot verify
            // In a full implementation, we'd have a key store or trust chain
            tracing::warn!(
                "Cannot verify receipt: no matching keypair for public key {}",
                public_key_hex
            );
            Ok(false)
        } else {
            // Unsigned receipt
            Ok(false)
        }
    }

    fn create_signing_data(&self, receipt: &Receipt) -> Result<String> {
        receipt_signing_bytes(receipt)
    }

    fn create_signing_data_for_verification(&self, receipt: &Receipt) -> Result<String> {
        // Same as create_signing_data but ensure we don't modify the original
        self.create_signing_data(receipt)
    }

    pub fn get_signer_info(&self) -> Option<SignerInfo> {
        self.keypair.as_ref().map(|kp| SignerInfo {
            public_key: kp.public_key_hex(),
            algorithm: "Ed25519".to_string(),
        })
    }

    pub fn get_cached_entry(&self, content_hash: &str) -> Result<Option<CacheEntry>> {
        let cache_file = self.cache_dir.join(format!("{}.yaml", content_hash));

        if cache_file.exists() {
            let content = fs::read_to_string(&cache_file)?;
            let entry: CacheEntry = serde_yaml::from_str(&content)?;

            // Verify content integrity
            if entry.content_hash == content_hash {
                return Ok(Some(entry));
            } else {
                // Cache corruption detected, remove invalid entry
                let _ = fs::remove_file(cache_file);
                tracing::warn!("Removed corrupted cache entry: {}", content_hash);
            }
        }

        Ok(None)
    }

    /// Get cached result by step name and input hash
    pub fn get_cached_result(
        &self,
        step_name: &str,
        input_hash: &str,
    ) -> Result<Option<StepResult>> {
        // A step-name cache, keyed without declared inputs. It is the
        // counterpart of `cache_result` and consistent with it, but it is
        // NOT the cache the executor uses: that one keys on the full
        // manifest hash, which is the only key that can tell two runs of the
        // same step apart. Kept as a separate, simpler lookup for callers
        // that only have a step name.
        let content_hash = self.compute_content_hash(
            Path::new(""),
            step_name,
            "",
            &[],
            &std::collections::HashMap::new(),
        )?;

        if let Some(cache_entry) = self.get_cached_entry(&content_hash)? {
            // Verify the input hash matches
            if cache_entry.result.input_hash == input_hash {
                Ok(Some(cache_entry.result))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn cache_entry(&self, entry: &CacheEntry) -> Result<()> {
        // Ensure cache directory exists
        fs::create_dir_all(&self.cache_dir)?;

        let cache_file = self.cache_dir.join(format!("{}.yaml", entry.content_hash));
        let content = serde_yaml::to_string(entry)?;
        fs::write(cache_file, content)?;

        // Update cache index for faster lookups
        self.update_cache_index(&entry.content_hash, &entry.step_name)?;

        Ok(())
    }

    /// Cache a step result with individual parameters
    pub fn cache_result(
        &self,
        step_name: &str,
        _input_hash: &str,
        result: &StepResult,
    ) -> Result<()> {
        let cache_entry = self.create_cache_entry(
            Path::new(""), // no declared inputs at this level, workspace unused
            step_name,
            "", // command is not available at this level
            vec![],
            vec![],
            &std::collections::HashMap::new(),
            result.clone(),
            vec![],
        )?;

        self.cache_entry(&cache_entry)
    }

    pub async fn save_receipt(&self, receipt: &Receipt) -> Result<PathBuf> {
        // Ensure receipts directory exists
        fs::create_dir_all(&self.receipts_dir)?;

        let timestamp = receipt.timestamp.format("%Y%m%d_%H%M%S_%3f").to_string();
        let content = serde_yaml::to_string(receipt)?;
        write_receipt_unique(&self.receipts_dir, &timestamp, None, &content)
    }

    pub async fn load_receipt(&self, receipt_path: &Path) -> Result<Receipt> {
        let content = fs::read_to_string(receipt_path)?;
        let receipt: Receipt = serde_yaml::from_str(&content).context("Invalid receipt format")?;
        Ok(receipt)
    }

    pub async fn list_receipts(&self, limit: usize) -> Result<Vec<Receipt>> {
        let mut receipts = Vec::new();

        if !self.receipts_dir.exists() {
            return Ok(receipts);
        }

        let mut entries: Vec<_> = fs::read_dir(&self.receipts_dir)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|ext| ext == "yaml")
                    .unwrap_or(false)
            })
            .collect();

        entries.sort_by_key(|entry| {
            entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });
        entries.reverse();

        for entry in entries.into_iter().take(limit) {
            if let Ok(receipt) = self.load_receipt(&entry.path()).await {
                receipts.push(receipt);
            }
        }

        Ok(receipts)
    }
}

/// Write a receipt to `dir` under a unique, collision-free filename.
///
/// The name embeds a short content hash so receipts written within the same
/// timestamp granularity never overwrite each other, and the file is opened
/// with `create_new` so concurrent writers race safely: on a name clash a
/// numeric discriminator is appended and the write is retried.
pub fn write_receipt_unique(
    dir: &Path,
    stamp: &str,
    label: Option<&str>,
    content: &str,
) -> Result<PathBuf> {
    use std::io::Write;

    let short_hash: String = blake3::hash(content.as_bytes())
        .to_hex()
        .chars()
        .take(12)
        .collect();
    let base = match label {
        Some(label) => format!("receipt_{stamp}_{label}_{short_hash}"),
        None => format!("receipt_{stamp}_{short_hash}"),
    };

    for attempt in 0u32.. {
        let name = if attempt == 0 {
            format!("{base}.yaml")
        } else {
            format!("{base}-{attempt}.yaml")
        };
        let path = dir.join(name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(content.as_bytes())?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).context(format!("cannot write receipt {}", path.display()));
            }
        }
    }
    unreachable!("receipt filename discriminator space exhausted")
}
