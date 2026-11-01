//! Public vectors generated with golang.org/x/mod's independent tlog/note
//! implementation. No network or fixture private keys are needed to verify.

use std::collections::BTreeMap;

use anyhow::Result;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;

use attest::publication::merkle::{self, Hash};
use attest::publication::note::{Checkpoint, LogConfig};
use attest::publication::record::{
    self, CheckpointComparison, PublicationRecord, PublicationState, UnconfirmedReason,
    VerificationMaterial, COMPARISON_FORMAT, RECORD_FORMAT,
};
use attest::publication::tiles::{TileReader, TileSource};
use attest::publication::{entry_for_root, hash_bytes};
use attest::verify::CheckStatus;

#[derive(Deserialize)]
struct Vectors {
    format: String,
    generator: String,
    config: LogConfig,
    roots: BTreeMap<u64, String>,
    checkpoints: Vec<CheckpointVector>,
    inclusion: Vec<InclusionVector>,
    consistency: Vec<ConsistencyVector>,
    tiles: BTreeMap<String, String>,
    opening: Opening,
    conflicting: BTreeMap<u64, String>,
    untrusted: BTreeMap<u64, String>,
}

#[derive(Deserialize)]
struct Opening {
    causal_root: String,
    nonce: String,
    entry: String,
}

#[derive(Deserialize)]
struct CheckpointVector {
    size: u64,
    root: String,
    note: String,
}

#[derive(Deserialize)]
struct InclusionVector {
    size: u64,
    index: u64,
    entry: String,
    path: Vec<String>,
}

#[derive(Deserialize)]
struct ConsistencyVector {
    old: u64,
    new: u64,
    path: Vec<String>,
}

fn vectors() -> Vectors {
    let vectors: Vectors =
        serde_json::from_str(include_str!("fixtures/publication/go-tlog-v1.json")).unwrap();
    assert_eq!(vectors.format, "attest-publication-test/v1");
    assert_eq!(
        vectors.generator,
        "golang.org/x/mod/sumdb/{note,tlog}@v0.42.0"
    );
    vectors
}

fn path(values: &[String]) -> Vec<Hash> {
    values
        .iter()
        .map(|value| hash_bytes(value).unwrap())
        .collect()
}

struct Source<'a>(&'a BTreeMap<String, String>);

#[async_trait]
impl TileSource for Source<'_> {
    async fn tile(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.0
            .get(name)
            .map(|value| hex::decode(value).map_err(Into::into))
            .transpose()
    }
}

#[tokio::test]
async fn rust_proofs_and_tile_reads_agree_with_go_across_tree_boundaries() {
    let vectors = vectors();
    let source = Source(&vectors.tiles);
    assert!(vectors.inclusion.len() > 60);
    assert!(vectors.consistency.len() > 80);
    for vector in &vectors.checkpoints {
        let checkpoint = Checkpoint::verify(&vector.note, &vectors.config).unwrap();
        assert_eq!(checkpoint.tree_size, vector.size);
        assert_eq!(checkpoint.root, hash_bytes(&vector.root).unwrap());
    }
    for vector in &vectors.inclusion {
        let root = hash_bytes(&vectors.roots[&vector.size]).unwrap();
        let entry = STANDARD.decode(&vector.entry).unwrap();
        let expected = path(&vector.path);
        merkle::verify_inclusion(&entry, vector.index, vector.size, &expected, &root).unwrap();
        let mut reader = TileReader::new(&source, vector.size);
        assert_eq!(reader.inclusion(vector.index).await.unwrap(), expected);
        let mut altered = entry.clone();
        altered[0] ^= 1;
        assert!(
            merkle::verify_inclusion(&altered, vector.index, vector.size, &expected, &root)
                .is_err()
        );
        let mut extra = expected.clone();
        extra.push([0; 32]);
        assert!(
            merkle::verify_inclusion(&entry, vector.index, vector.size, &extra, &root).is_err()
        );
    }
    for vector in &vectors.consistency {
        let old = hash_bytes(&vectors.roots[&vector.old]).unwrap();
        let new = hash_bytes(&vectors.roots[&vector.new]).unwrap();
        let expected = path(&vector.path);
        merkle::verify_consistency(vector.old, vector.new, &old, &new, &expected).unwrap();
        let mut reader = TileReader::new(&source, vector.new);
        assert_eq!(
            reader.consistency(vector.old, vector.new).await.unwrap(),
            expected
        );
        let mut altered = new;
        altered[0] ^= 1;
        if vector.old > 0 {
            assert!(
                merkle::verify_consistency(vector.old, vector.new, &old, &altered, &expected)
                    .is_err()
            );
        } else {
            // Every tree extends the empty tree. Authenticating the new root
            // is the checkpoint verifier's separate responsibility.
            merkle::verify_consistency(0, vector.new, &old, &altered, &expected).unwrap();
        }
    }
}

fn checkpoint(vectors: &Vectors, size: u64) -> String {
    vectors
        .checkpoints
        .iter()
        .find(|c| c.size == size)
        .unwrap()
        .note
        .clone()
}

fn publication(vectors: &Vectors, size: u64) -> PublicationRecord {
    let proof = vectors
        .inclusion
        .iter()
        .find(|p| p.size == size && p.index == 0)
        .unwrap();
    PublicationRecord {
        format: RECORD_FORMAT.into(),
        causal_root: vectors.opening.causal_root.clone(),
        opening_nonce: vectors.opening.nonce.clone(),
        entry: vectors.opening.entry.clone(),
        log_id: vectors.config.log_id().unwrap(),
        submit_url: "https://log.test/add".into(),
        created_at: "2026-11-01T00:00:00Z".parse().unwrap(),
        submissions: vec![],
        outcome: PublicationState::Confirmed {
            leaf_index: 0,
            checkpoint: checkpoint(vectors, size),
            inclusion_path: proof.path.clone(),
        },
    }
}

#[test]
fn opening_and_receipt_binding_are_independent_of_a_valid_log_proof() {
    let vectors = vectors();
    assert_eq!(
        hex::encode(entry_for_root(&vectors.opening.causal_root, &vectors.opening.nonce).unwrap()),
        vectors.opening.entry
    );
    let original = publication(&vectors, 513);
    original
        .verify(&vectors.opening.causal_root, &vectors.config)
        .unwrap();
    let mut changed = original.clone();
    changed.causal_root = "33".repeat(32);
    changed.entry =
        hex::encode(entry_for_root(&changed.causal_root, &changed.opening_nonce).unwrap());
    assert!(changed
        .verify(&changed.causal_root, &vectors.config)
        .is_err());
    assert!(original
        .verify(&changed.causal_root, &vectors.config)
        .is_err());
    let mut changed = original.clone();
    changed.opening_nonce = "44".repeat(32);
    assert!(changed
        .verify(&vectors.opening.causal_root, &vectors.config)
        .is_err());
}

#[test]
fn no_log_key_is_learned_from_evidence_and_unknown_signatures_cannot_authorize() {
    let vectors = vectors();
    let mut record = publication(&vectors, 2);
    if let PublicationState::Confirmed { checkpoint, .. } = &mut record.outcome {
        *checkpoint = vectors.untrusted[&2].clone();
    }
    assert!(record
        .verify(&vectors.opening.causal_root, &vectors.config)
        .is_err());
    let bytes = serde_json::to_vec(&record).unwrap();
    let checks = record::assess(
        Some(&vectors.opening.causal_root),
        Some(&bytes),
        &VerificationMaterial::default(),
    );
    assert_eq!(checks[0].status, CheckStatus::Skipped);
    let checks = record::assess(
        Some(&vectors.opening.causal_root),
        Some(&bytes),
        &VerificationMaterial {
            trust: Some(&vectors.config),
            ..Default::default()
        },
    );
    assert_eq!(checks[0].status, CheckStatus::Fail);
}

#[test]
fn unconfirmed_submissions_never_become_verified_inclusion() {
    let vectors = vectors();
    let mut record = publication(&vectors, 2);
    record.outcome = PublicationState::Unconfirmed {
        reason: UnconfirmedReason::AwaitingInclusion,
    };
    let bytes = serde_json::to_vec(&record).unwrap();
    let checks = record::assess(
        Some(&vectors.opening.causal_root),
        Some(&bytes),
        &VerificationMaterial {
            trust: Some(&vectors.config),
            ..Default::default()
        },
    );
    assert_eq!(checks[0].status, CheckStatus::Skipped);
    assert_eq!(checks[1].status, CheckStatus::Skipped);
    assert!(record
        .verify(&vectors.opening.causal_root, &vectors.config)
        .is_err());
}

#[test]
fn consistency_needs_the_recipients_reference_and_distinguishes_missing_from_conflict() {
    let vectors = vectors();
    let record = publication(&vectors, 2);
    let bytes = serde_json::to_vec(&record).unwrap();
    let proof = vectors
        .consistency
        .iter()
        .find(|v| v.old == 1 && v.new == 2)
        .unwrap();
    let comparison = CheckpointComparison {
        format: COMPARISON_FORMAT.into(),
        log_id: vectors.config.log_id().unwrap(),
        first_checkpoint: checkpoint(&vectors, 1),
        second_checkpoint: checkpoint(&vectors, 2),
        consistency_path: proof.path.clone(),
    };
    let exchange = serde_json::to_vec(&comparison).unwrap();
    let reference = checkpoint(&vectors, 1);
    let material = VerificationMaterial {
        trust: Some(&vectors.config),
        reference_checkpoint: Some(&reference),
        comparison: Some(&exchange),
    };
    let checks = record::assess(Some(&vectors.opening.causal_root), Some(&bytes), &material);
    assert_eq!(checks[0].status, CheckStatus::Pass);
    assert_eq!(checks[1].status, CheckStatus::Pass);
    let checks = record::assess(
        Some(&vectors.opening.causal_root),
        Some(&bytes),
        &VerificationMaterial {
            reference_checkpoint: None,
            ..material
        },
    );
    assert_eq!(checks[1].status, CheckStatus::Skipped);
    let checks = record::assess(
        Some(&vectors.opening.causal_root),
        Some(&bytes),
        &VerificationMaterial {
            comparison: None,
            ..material
        },
    );
    assert_eq!(checks[1].status, CheckStatus::Skipped);
    let conflict = &vectors.conflicting[&2];
    let checks = record::assess(
        Some(&vectors.opening.causal_root),
        Some(&bytes),
        &VerificationMaterial {
            reference_checkpoint: Some(conflict),
            comparison: None,
            ..material
        },
    );
    assert_eq!(checks[1].status, CheckStatus::Fail);
    assert!(checks[1].detail.contains("conflicting roots"));
    let untrusted = &vectors.untrusted[&2];
    let checks = record::assess(
        Some(&vectors.opening.causal_root),
        Some(&bytes),
        &VerificationMaterial {
            reference_checkpoint: Some(untrusted),
            comparison: None,
            ..material
        },
    );
    assert_eq!(checks[1].status, CheckStatus::Fail);
    assert!(!checks[1].detail.contains("conflicting roots"));
    let mut unrelated = comparison.clone();
    unrelated.first_checkpoint = checkpoint(&vectors, 2);
    unrelated.second_checkpoint = checkpoint(&vectors, 3);
    unrelated.consistency_path = vectors
        .consistency
        .iter()
        .find(|v| v.old == 2 && v.new == 3)
        .unwrap()
        .path
        .clone();
    unrelated.verify(&vectors.config).unwrap();
    let exchange = serde_json::to_vec(&unrelated).unwrap();
    let checks = record::assess(
        Some(&vectors.opening.causal_root),
        Some(&bytes),
        &VerificationMaterial {
            comparison: Some(&exchange),
            ..material
        },
    );
    assert_eq!(checks[1].status, CheckStatus::Fail);
    assert!(checks[1].detail.contains("does not cover"));
    let mut malformed = comparison.clone();
    malformed.consistency_path.clear();
    assert!(malformed.verify(&vectors.config).is_err());
    malformed = comparison;
    malformed.consistency_path.push("00".repeat(32));
    assert!(malformed.verify(&vectors.config).is_err());
}

#[test]
fn proof_bounds_cover_the_largest_supported_integer_without_panicking() {
    let size = u64::MAX;
    for index in [0, size / 2, size - 1] {
        let ranges = merkle::inclusion_ranges(index, size).unwrap();
        assert!(ranges.len() <= merkle::MAX_PROOF_NODES);
        assert!(ranges
            .iter()
            .all(|(start, length)| start.checked_add(*length).unwrap() <= size));
    }
    for old in [1, size / 2, size - 1, size] {
        assert!(merkle::consistency_ranges(old, size).unwrap().len() <= merkle::MAX_PROOF_NODES);
    }
    assert!(merkle::verify_inclusion(b"entry", 0, size, &[[0; 32]; 65], &[0; 32]).is_err());
    // A repeated leaf gives an enormous valid tree without allocating leaves.
    // Some non-power-of-two prefixes need 65 consistency nodes, not 64.
    fn repeated_root(size: u64, perfect: &[Hash]) -> Hash {
        let height = 63 - size.leading_zeros() as usize;
        let power = 1u64 << height;
        if power == size {
            perfect[height]
        } else {
            merkle::node_hash(&perfect[height], &repeated_root(size - power, perfect))
        }
    }
    let mut perfect = vec![merkle::leaf_hash(b"leaf")];
    for height in 1..64 {
        perfect.push(merkle::node_hash(
            &perfect[height - 1],
            &perfect[height - 1],
        ));
    }
    let old = (1u64 << 63) - 1;
    let ranges = merkle::consistency_ranges(old, size).unwrap();
    assert_eq!(ranges.len(), 65);
    let proof: Vec<_> = ranges
        .iter()
        .map(|(_, length)| repeated_root(*length, &perfect))
        .collect();
    merkle::verify_consistency(
        old,
        size,
        &repeated_root(old, &perfect),
        &repeated_root(size, &perfect),
        &proof,
    )
    .unwrap();
}
