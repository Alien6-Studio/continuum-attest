//! Causal ledger: a Merkle DAG of what caused what during a run.
//!
//! Each step's execution becomes an event committing to its inputs, outputs,
//! exit code, environment and the events it depended on. The chain root is a
//! pure function of the ordered events, so a verifier holding the events and
//! the order the receipt publishes them in can recompute it offline.
//!
//! Not immutable, and the distinction matters. These are files in a
//! directory; anyone who can write there can replace them. What the
//! structure gives is tamper-evidence *relative to a signed root*: the root
//! is a receipt field, the signature covers it, and `--timestamp` puts a
//! third party over the signature, so a history that has been anchored
//! cannot be rewritten afterwards.
//!
//! Nor is it a transparency log. The root is signed by whoever produced it,
//! not by an independent operator, and nobody witnesses it. Append-only
//! against the producer is what a log like Rekor provides, through
//! consistency proofs between signed tree heads that third parties observe;
//! that is a different property from the one here, and this module should
//! not be read as offering it.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::sign::AttestKeypair;

/// A causal event in the pipeline execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalEvent {
    /// Unique event ID (Blake3 hash of content)
    pub event_id: String,
    /// Step name this event represents
    pub step_name: String,
    /// Previous events this event causally depends on
    pub causal_parents: Vec<String>,
    /// Input hash for reproducibility
    pub input_hash: String,
    /// Output hash after execution
    pub output_hash: String,
    /// Execution timestamp
    pub timestamp: DateTime<Utc>,
    /// Step execution result
    pub exit_code: i32,
    /// Pipeline context hash
    pub pipeline_hash: String,
    /// Environment hash for determinism
    pub environment_hash: String,
    /// Public key of whoever signed this event, hex-encoded.
    ///
    /// Without it the signature below is unverifiable by anyone but the
    /// machine that produced it: there was nothing to check it against, so
    /// an archive carried signatures no reader could use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_public_key: Option<String>,
    /// Digital signature of this event
    pub signature: Option<String>,
    /// Metadata for extended causality tracking
    pub metadata: HashMap<String, String>,
}

/// Merkle proof for event integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Path from leaf to root in Merkle tree
    pub path: Vec<String>,
    /// Direction indicators (left/right)
    pub directions: Vec<bool>,
    /// Root hash of Merkle tree
    pub root_hash: String,
}

/// Causal chain representing execution flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalChain {
    /// Chain identifier
    pub chain_id: String,
    /// Ordered sequence of causal events
    pub events: Vec<CausalEvent>,
    /// Chain creation timestamp
    pub created_at: DateTime<Utc>,
    /// Total chain hash (Merkle root)
    pub chain_hash: String,
    /// Digital signature of entire chain
    pub chain_signature: Option<String>,
}

/// Causal path between two events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalPath {
    /// Starting event ID
    pub from_event: String,
    /// Target event ID
    pub to_event: String,
    /// Sequence of event IDs forming the path
    pub path: Vec<String>,
}

/// Causal query result for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalQuery {
    /// Starting event ID
    pub from_event: String,
    /// Target event ID
    pub to_event: String,
    /// Causal path between events
    pub causal_path: Vec<String>,
    /// Path verification status
    pub is_valid: bool,
    /// Additional path metadata
    pub path_metadata: HashMap<String, String>,
}

/// Main causal ledger structure
#[derive(Debug)]
pub struct CausalLedger {
    /// Storage directory for ledger data
    ledger_dir: PathBuf,
    /// Current causal events index
    events_index: HashMap<String, CausalEvent>,
    /// Event dependencies graph
    dependency_graph: HashMap<String, Vec<String>>,
    /// Signing keypair for events
    keypair: Option<AttestKeypair>,
}

impl CausalLedger {
    /// Create new causal ledger
    pub fn new(attest_dir: &Path) -> Result<Self> {
        let ledger_dir = attest_dir.join("causal_ledger");

        Ok(Self {
            ledger_dir,
            events_index: HashMap::new(),
            dependency_graph: HashMap::new(),
            keypair: None,
        })
    }

    /// Initialize the causal ledger storage
    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.ledger_dir)?;
        fs::create_dir_all(self.ledger_dir.join("events"))?;
        fs::create_dir_all(self.ledger_dir.join("chains"))?;
        fs::create_dir_all(self.ledger_dir.join("proofs"))?;

        // Create ledger metadata
        let metadata = serde_json::json!({
            "version": "0.1.0",
            "created_at": Utc::now().to_rfc3339(),
            "description": "ATTEST Causal Ledger - Merkle-DAG based execution journal",
            "algorithm": "Blake3 + Ed25519"
        });

        fs::write(
            self.ledger_dir.join("metadata.json"),
            serde_json::to_string_pretty(&metadata)?,
        )?;

        Ok(())
    }

    /// Load signing keypair
    pub fn load_keypair(&mut self, keypair: AttestKeypair) -> Result<()> {
        self.keypair = Some(keypair);
        Ok(())
    }

    /// Record a new causal event
    // Each parameter is an independently-sourced piece of the causal event record;
    // grouping them into a struct would be a breaking API change out of scope here.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_event(
        &mut self,
        step_name: &str,
        causal_parents: Vec<String>,
        input_hash: &str,
        output_hash: &str,
        exit_code: i32,
        pipeline_hash: &str,
        environment_hash: &str,
        metadata: HashMap<String, String>,
    ) -> Result<CausalEvent> {
        let mut event = CausalEvent {
            // Filled in below, once the fields it commits to exist.
            event_id: String::new(),
            step_name: step_name.to_string(),
            causal_parents: causal_parents.clone(),
            input_hash: input_hash.to_string(),
            output_hash: output_hash.to_string(),
            timestamp: Utc::now(),
            exit_code,
            pipeline_hash: pipeline_hash.to_string(),
            environment_hash: environment_hash.to_string(),
            signer_public_key: None,
            signature: None,
            metadata,
        };
        event.event_id = Self::event_id_of(&event);
        let event_id = event.event_id.clone();

        // Sign the event if keypair is available
        if let Some(keypair) = &self.keypair {
            let signing_data = self.create_event_signing_data(&event)?;
            event.signature = Some(keypair.sign(signing_data.as_bytes()));
            event.signer_public_key = Some(keypair.public_key_hex());
        }

        // Generate Merkle proof

        // Store event
        self.store_event(&event).await?;

        // Update indices
        self.events_index.insert(event_id.clone(), event.clone());
        self.dependency_graph
            .insert(event_id.clone(), causal_parents);

        tracing::info!(
            "Recorded causal event: {} for step: {}",
            event_id,
            step_name
        );

        Ok(event)
    }

    /// Record a causal event from a pre-built CausalEvent struct (helper for tests)
    pub async fn record_event_struct(&mut self, event: CausalEvent) -> Result<()> {
        // Store event
        self.store_event(&event).await?;

        // Update indices
        self.events_index
            .insert(event.event_id.clone(), event.clone());
        self.dependency_graph
            .insert(event.event_id.clone(), event.causal_parents.clone());

        tracing::info!(
            "Recorded causal event: {} for step: {}",
            event.event_id,
            event.step_name
        );

        Ok(())
    }

    /// Store event to disk
    async fn store_event(&self, event: &CausalEvent) -> Result<()> {
        let event_file = self
            .ledger_dir
            .join("events")
            .join(format!("{}.json", event.event_id));

        let event_json = serde_json::to_string_pretty(event)?;
        fs::write(event_file, event_json)?;

        Ok(())
    }

    /// Create canonical signing data for an event
    fn create_event_signing_data(&self, event: &CausalEvent) -> Result<String> {
        // Create deterministic representation for signing
        let signing_data = serde_json::json!({
            "event_id": event.event_id,
            "step_name": event.step_name,
            "causal_parents": event.causal_parents,
            "input_hash": event.input_hash,
            "output_hash": event.output_hash,
            "timestamp": event.timestamp.to_rfc3339(),
            "exit_code": event.exit_code,
            "pipeline_hash": event.pipeline_hash,
            "environment_hash": event.environment_hash
        });

        Ok(serde_json::to_string(&signing_data)?)
    }

    /// Build causal chain from events
    pub async fn build_causal_chain(&self, event_ids: Vec<String>) -> Result<CausalChain> {
        let mut events = Vec::new();

        // Collect events in dependency order
        let sorted_ids = self.topological_sort_events(&event_ids)?;

        for event_id in sorted_ids {
            if let Some(event) = self.events_index.get(&event_id) {
                events.push(event.clone());
            }
        }

        // Calculate chain hash (Merkle root of all events)
        let chain_hash = self.calculate_chain_hash(&events)?;

        let chain_id = blake3::hash(
            format!(
                "chain:{}:{}",
                events
                    .first()
                    .map(|e| &e.event_id)
                    .unwrap_or(&String::new()),
                events.last().map(|e| &e.event_id).unwrap_or(&String::new())
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string();

        let mut chain = CausalChain {
            chain_id: chain_id.clone(),
            events,
            created_at: Utc::now(),
            chain_hash,
            chain_signature: None,
        };

        // Sign the entire chain
        if let Some(keypair) = &self.keypair {
            let chain_data = serde_json::to_string(&chain)?;
            chain.chain_signature = Some(keypair.sign(chain_data.as_bytes()));
        }

        // Store chain
        self.store_causal_chain(&chain).await?;

        Ok(chain)
    }

    /// Calculate Merkle root hash for causal chain
    fn calculate_chain_hash(&self, events: &[CausalEvent]) -> Result<String> {
        Ok(Self::chain_hash(events))
    }

    /// The bytes an event's identity commits to.
    ///
    /// Every field a reader would rely on, `causal_parents` included. The
    /// parents were previously outside the identity, so the causal graph --
    /// the thing this ledger exists to record -- could be rewritten without
    /// changing any event id or the chain root. The timestamp used is the
    /// one stored on the event, so the id can actually be recomputed; the
    /// previous derivation mixed in a separate `Utc::now()` that was never
    /// written down, which made it unverifiable by construction.
    ///
    /// Lengths are prefixed so that no concatenation of fields can be read
    /// as a different one: without them, a step named `a` with parent `bc`
    /// and a step named `ab` with parent `c` would commit to the same bytes.
    pub fn event_content(event: &CausalEvent) -> Vec<u8> {
        // Through the shared primitive rather than a local encoder. This
        // function used to build its own length-prefixed string and carried
        // the same defect for the same reason -- the label was written
        // before its length, so `("a", "0:")` and `("a:2", "")` encoded
        // alike. Two encoders meant two chances to get it wrong; there is
        // one now, and it is the one the injectivity tests exercise.
        let mut hasher = blake3::Hasher::new();
        crate::hashing::hash_field(&mut hasher, "domain", b"attest-causal-event/v2");
        crate::hashing::hash_field(&mut hasher, "step", event.step_name.as_bytes());
        crate::hashing::hash_field(&mut hasher, "input", event.input_hash.as_bytes());
        crate::hashing::hash_field(&mut hasher, "output", event.output_hash.as_bytes());
        crate::hashing::hash_field(&mut hasher, "pipeline", event.pipeline_hash.as_bytes());
        crate::hashing::hash_field(
            &mut hasher,
            "environment",
            event.environment_hash.as_bytes(),
        );
        crate::hashing::hash_field(&mut hasher, "exit", event.exit_code.to_string().as_bytes());
        crate::hashing::hash_field(
            &mut hasher,
            "timestamp",
            event.timestamp.to_rfc3339().as_bytes(),
        );
        crate::hashing::hash_field(
            &mut hasher,
            "parents",
            event.causal_parents.len().to_string().as_bytes(),
        );
        for parent in &event.causal_parents {
            crate::hashing::hash_field(&mut hasher, "parent", parent.as_bytes());
        }
        hasher.finalize().as_bytes().to_vec()
    }

    /// The id an event's content implies, whatever id it carries.
    pub fn event_id_of(event: &CausalEvent) -> String {
        blake3::hash(&Self::event_content(event))
            .to_hex()
            .to_string()
    }

    /// Whether an event's recorded id matches the content it carries.
    ///
    /// A verifier reading events from an archive has no other way to tell
    /// that the fields were not edited after the fact.
    pub fn event_id_is_authentic(event: &CausalEvent) -> bool {
        event.event_id == Self::event_id_of(event)
    }

    /// The bytes an event's signature covers.
    ///
    /// Separate from `event_content`: the identity commits to what happened,
    /// this is what a signer attests to. They cover the same facts; keeping
    /// them distinct means changing one encoding cannot silently invalidate
    /// every stored signature.
    pub fn event_signing_data(event: &CausalEvent) -> String {
        serde_json::json!({
            "event_id": event.event_id,
            "step_name": event.step_name,
            "causal_parents": event.causal_parents,
            "input_hash": event.input_hash,
            "output_hash": event.output_hash,
            "timestamp": event.timestamp.to_rfc3339(),
            "exit_code": event.exit_code,
            "pipeline_hash": event.pipeline_hash,
            "environment_hash": event.environment_hash
        })
        .to_string()
    }

    /// Verify an event's signature against the key it names.
    ///
    /// Returns `None` when the event is unsigned, which is not an error: a
    /// run without a signing key produces unsigned events. Callers decide
    /// whether unsigned is acceptable; this only answers whether a signature
    /// that is present holds.
    pub fn event_signature_holds(event: &CausalEvent) -> Option<bool> {
        let signature = event.signature.as_ref()?;
        // A signature with no key to check it against is not "unsigned": it
        // is a claim that cannot be examined, and returning None here let an
        // archive pass by deleting the key beside a forged signature. An
        // event carries both or neither.
        let Some(public_key) = event.signer_public_key.as_ref() else {
            return Some(false);
        };
        let data = Self::event_signing_data(event);
        Some(
            crate::crypto::sign::verify_with_public_key(public_key, data.as_bytes(), signature)
                .unwrap_or(false),
        )
    }

    /// Merkle root over an ordered sequence of events.
    ///
    /// A pure function of the sequence, deliberately: an offline verifier
    /// holding the events and the order the receipt publishes them in must
    /// be able to recompute this without a ledger. The order is the
    /// receipt's `causal_events` order — not a re-derived topological sort,
    /// which could differ and would turn an honest archive into a failure.
    pub fn chain_hash(events: &[CausalEvent]) -> String {
        let mut hasher = blake3::Hasher::new();
        for event in events {
            // The full content, not the id: hashing the id alone would let a
            // rewritten event pass as long as its stale id was left in place.
            hasher.update(&Self::event_content(event));
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Store causal chain to disk
    async fn store_causal_chain(&self, chain: &CausalChain) -> Result<()> {
        let chain_file = self
            .ledger_dir
            .join("chains")
            .join(format!("{}.json", chain.chain_id));

        let chain_json = serde_json::to_string_pretty(chain)?;
        fs::write(chain_file, chain_json)?;

        Ok(())
    }

    /// Topologically sort events by causal dependencies
    fn topological_sort_events(&self, event_ids: &[String]) -> Result<Vec<String>> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();

        // Build graph and calculate in-degrees
        for event_id in event_ids {
            in_degree.insert(event_id.clone(), 0);
            graph.insert(event_id.clone(), Vec::new());
        }

        for event_id in event_ids {
            if let Some(parents) = self.dependency_graph.get(event_id) {
                for parent in parents {
                    if event_ids.contains(parent) {
                        graph
                            .get_mut(parent)
                            .expect(
                                "`parent` was inserted into `graph` above since it is in event_ids",
                            )
                            .push(event_id.clone());
                        *in_degree
                            .get_mut(event_id)
                            .expect("`event_id` was inserted into `in_degree` above") += 1;
                    }
                }
            }
        }

        // Kahn's algorithm for topological sorting
        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|(_, &degree)| degree == 0)
            .map(|(id, _)| id.clone())
            .collect();

        let mut result = Vec::new();

        while let Some(current) = queue.pop() {
            result.push(current.clone());

            if let Some(neighbors) = graph.get(&current) {
                for neighbor in neighbors {
                    let degree = in_degree
                        .get_mut(neighbor)
                        .expect("`neighbor` is always present in `in_degree`, built from the same event_ids");
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push(neighbor.clone());
                    }
                }
            }
        }

        if result.len() != event_ids.len() {
            anyhow::bail!("Circular dependency detected in causal events");
        }

        Ok(result)
    }

    /// Query causal path between two events
    pub async fn query_causal_path(&self, from_event: &str, to_event: &str) -> Result<CausalQuery> {
        let path_result = self.find_causal_path(from_event, to_event).await?;
        let (path, is_valid) = if let Some(causal_path) = path_result {
            let is_valid = self.verify_causal_path(&causal_path.path).await?;
            (causal_path.path, is_valid)
        } else {
            (Vec::new(), false)
        };

        Ok(CausalQuery {
            from_event: from_event.to_string(),
            to_event: to_event.to_string(),
            causal_path: path,
            is_valid,
            path_metadata: HashMap::new(),
        })
    }

    /// Verify causal path integrity
    async fn verify_causal_path(&self, path: &[String]) -> Result<bool> {
        if path.is_empty() {
            return Ok(false);
        }

        // Verify each event in path exists and has valid signature
        for event_id in path {
            if let Some(event) = self.events_index.get(event_id) {
                if !self.verify_event_signature(event).await? {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        // Verify causal ordering
        for i in 1..path.len() {
            let current_event = self
                .events_index
                .get(&path[i])
                .expect("existence of every path element was verified in the loop above");
            if !current_event.causal_parents.contains(&path[i - 1]) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify event signature
    async fn verify_event_signature(&self, event: &CausalEvent) -> Result<bool> {
        if let (Some(signature), Some(keypair)) = (&event.signature, &self.keypair) {
            let signing_data = self.create_event_signing_data(event)?;
            keypair.verify(signing_data.as_bytes(), signature)
        } else {
            Ok(false) // No signature or no keypair to verify
        }
    }

    /// Load existing events from storage
    pub async fn load_events(&mut self) -> Result<()> {
        let events_dir = self.ledger_dir.join("events");

        if !events_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(events_dir)? {
            let entry = entry?;
            if entry.path().extension() == Some(std::ffi::OsStr::new("json")) {
                let content = fs::read_to_string(entry.path())?;
                let event: CausalEvent = serde_json::from_str(&content)?;

                self.events_index
                    .insert(event.event_id.clone(), event.clone());
                self.dependency_graph
                    .insert(event.event_id.clone(), event.causal_parents);
            }
        }

        tracing::info!("Loaded {} causal events", self.events_index.len());
        Ok(())
    }

    /// Get causal ledger statistics
    pub fn get_statistics(&self) -> CausalLedgerStats {
        let total_events = self.events_index.len();
        let total_chains = self.count_chains();
        let root_events = self.count_root_events();
        let leaf_events = self.count_leaf_events();

        CausalLedgerStats {
            total_events,
            total_chains,
            root_events,
            leaf_events,
            avg_chain_length: total_events.checked_div(total_chains).unwrap_or(0),
        }
    }

    /// Alias for get_statistics (for backward compatibility with tests)
    pub async fn get_stats(&self) -> Result<CausalLedgerStats> {
        Ok(self.get_statistics())
    }

    fn count_chains(&self) -> usize {
        // Count unique causal chains by finding connected components
        let mut visited = HashSet::new();
        let mut chains = 0;

        for event_id in self.events_index.keys() {
            if !visited.contains(event_id) {
                self.dfs_mark_visited(event_id, &mut visited);
                chains += 1;
            }
        }

        chains
    }

    fn dfs_mark_visited(&self, event_id: &str, visited: &mut HashSet<String>) {
        if visited.contains(event_id) {
            return;
        }

        visited.insert(event_id.to_string());

        if let Some(parents) = self.dependency_graph.get(event_id) {
            for parent in parents {
                self.dfs_mark_visited(parent, visited);
            }
        }
    }

    fn count_root_events(&self) -> usize {
        self.events_index
            .values()
            .filter(|event| event.causal_parents.is_empty())
            .count()
    }

    fn count_leaf_events(&self) -> usize {
        let mut has_children = HashSet::new();

        for parents in self.dependency_graph.values() {
            for parent in parents {
                has_children.insert(parent.clone());
            }
        }

        self.events_index.len() - has_children.len()
    }

    /// Get events by step name
    pub async fn get_events_by_step(&self, step_name: &str) -> Result<Vec<CausalEvent>> {
        let events = self
            .events_index
            .values()
            .filter(|event| event.step_name == step_name)
            .cloned()
            .collect();
        Ok(events)
    }

    /// Get all events
    pub async fn get_all_events(&self) -> Result<Vec<CausalEvent>> {
        Ok(self.events_index.values().cloned().collect())
    }

    /// Find causal path between two events
    pub async fn find_causal_path(
        &self,
        from_event: &str,
        to_event: &str,
    ) -> Result<Option<CausalPath>> {
        // Basic implementation - traverse from one event to another
        if !self.events_index.contains_key(from_event) || !self.events_index.contains_key(to_event)
        {
            return Ok(None);
        }

        if from_event == to_event {
            return Ok(Some(CausalPath {
                from_event: from_event.to_string(),
                to_event: to_event.to_string(),
                path: vec![from_event.to_string()],
            }));
        }

        // Simple breadth-first search through causal_parents
        let mut visited = std::collections::HashSet::<String>::new();
        let mut queue = std::collections::VecDeque::new();
        let mut paths = std::collections::HashMap::new();

        queue.push_back(from_event.to_string());
        visited.insert(from_event.to_string());
        paths.insert(from_event.to_string(), vec![from_event.to_string()]);

        while let Some(current_event_id) = queue.pop_front() {
            if current_event_id == to_event {
                if let Some(path) = paths.get(to_event).cloned() {
                    return Ok(Some(CausalPath {
                        from_event: from_event.to_string(),
                        to_event: to_event.to_string(),
                        path,
                    }));
                }
            }

            if let Some(current_event) = self.events_index.get(&current_event_id) {
                for dep in &current_event.causal_parents {
                    if !visited.contains(dep) {
                        visited.insert(dep.clone());
                        queue.push_back(dep.clone());

                        let mut new_path = paths[&current_event_id].clone();
                        new_path.push(dep.clone());
                        paths.insert(dep.clone(), new_path);
                    }
                }
            }
        }

        Ok(None)
    }
}

/// Statistics about the causal ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalLedgerStats {
    pub total_events: usize,
    pub total_chains: usize,
    pub root_events: usize,
    pub leaf_events: usize,
    pub avg_chain_length: usize,
}
