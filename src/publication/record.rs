//! Retained publication material. Producer status cannot authorize a proof:
//! the recipient checks the opening, its own log identity and every path.

use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::verify::{Check, CheckStatus};

use super::merkle::{self, Hash};
use super::note::{Checkpoint, LogConfig};
use super::{entry_for_root, hash_bytes, ENTRY_PREFIX};

pub const RECORD_FORMAT: &str = "attest-publication/v1";
pub const COMPARISON_FORMAT: &str = "attest-log-comparison/v1";
pub const MAX_RECORD_BYTES: u64 = 512 * 1024;
pub const MAX_COMPARISON_BYTES: u64 = 1024 * 1024;
pub const MAX_SUBMISSIONS: usize = 3;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UnconfirmedReason {
    Prepared,
    RequestFailed,
    ServiceRefused,
    AwaitingInclusion,
    InvalidProof,
    Deadline,
    AttemptLimit,
}

impl UnconfirmedReason {
    pub fn description(self) -> &'static str {
        match self {
            Self::Prepared => "publication was prepared but has not been confirmed",
            Self::RequestFailed => "a publication request failed; submission may have occurred",
            Self::ServiceRefused => "the publication service did not accept the request",
            Self::AwaitingInclusion => "a returned index has not established verified inclusion",
            Self::InvalidProof => "the log did not provide valid publication evidence",
            Self::Deadline => "the publication deadline expired without verified inclusion",
            Self::AttemptLimit => "the bounded submission attempt count was exhausted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub started_at: DateTime<Utc>,
    pub returned_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PublicationState {
    Unconfirmed {
        reason: UnconfirmedReason,
    },
    Confirmed {
        leaf_index: u64,
        checkpoint: String,
        inclusion_path: Vec<String>,
    },
}

// Opening material belongs in the retained file, never in Debug diagnostics.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRecord {
    pub format: String,
    pub causal_root: String,
    pub opening_nonce: String,
    /// Lower-case hex of the exact binary entry submitted, not the root.
    pub entry: String,
    pub log_id: String,
    pub submit_url: String,
    /// Producer clock only; this is not a trusted log timestamp.
    pub created_at: DateTime<Utc>,
    pub submissions: Vec<Submission>,
    pub outcome: PublicationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointComparison {
    pub format: String,
    pub log_id: String,
    pub first_checkpoint: String,
    pub second_checkpoint: String,
    pub consistency_path: Vec<String>,
}

fn hashes(values: &[String]) -> Result<Vec<Hash>> {
    ensure!(
        values.len() <= merkle::MAX_PROOF_NODES,
        "too many log proof nodes"
    );
    values.iter().map(|value| hash_bytes(value)).collect()
}

pub fn decode_record(bytes: &[u8]) -> Result<PublicationRecord> {
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "publication record is too large"
    );
    // Decode failures must not echo private opening material into diagnostics.
    serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid publication record JSON"))
}

pub fn decode_comparison(bytes: &[u8]) -> Result<CheckpointComparison> {
    ensure!(
        bytes.len() as u64 <= MAX_COMPARISON_BYTES,
        "checkpoint comparison is too large"
    );
    serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid checkpoint comparison JSON"))
}

impl PublicationRecord {
    pub fn entry_bytes(&self, receipt_root: &str) -> Result<Vec<u8>> {
        ensure!(
            self.format == RECORD_FORMAT,
            "unsupported publication record format"
        );
        ensure!(
            self.submissions.len() <= MAX_SUBMISSIONS,
            "too many recorded submission attempts"
        );
        ensure!(
            self.submit_url.len() <= 4096 && !self.submit_url.chars().any(char::is_control),
            "invalid publication destination"
        );
        hash_bytes(&self.log_id).context("invalid log identifier")?;
        hash_bytes(receipt_root).context("receipt has an invalid causal root")?;
        ensure!(
            self.causal_root == receipt_root,
            "publication belongs to a different causal root"
        );
        let entry = entry_for_root(receipt_root, &self.opening_nonce)?;
        ensure!(
            self.entry.len() == (ENTRY_PREFIX.len() + 32) * 2 && hex::encode(&entry) == self.entry,
            "published entry does not match the receipt root and opening"
        );
        Ok(entry)
    }

    pub fn verify(&self, receipt_root: &str, trust: &LogConfig) -> Result<Checkpoint> {
        let entry = self.entry_bytes(receipt_root)?;
        ensure!(
            self.log_id == trust.log_id()?,
            "publication names a different configured log"
        );
        let PublicationState::Confirmed {
            leaf_index,
            checkpoint,
            inclusion_path,
        } = &self.outcome
        else {
            anyhow::bail!("publication has no confirmed inclusion evidence")
        };
        let checkpoint = Checkpoint::verify(checkpoint, trust)?;
        merkle::verify_inclusion(
            &entry,
            *leaf_index,
            checkpoint.tree_size,
            &hashes(inclusion_path)?,
            &checkpoint.root,
        )?;
        Ok(checkpoint)
    }
}

fn same_checkpoint(a: &Checkpoint, b: &Checkpoint) -> bool {
    a.tree_size == b.tree_size && a.root == b.root
}

impl CheckpointComparison {
    /// Authenticate before comparing. Equal-sized different roots prove a
    /// conflict; failure of a supplied path does not by itself prove a fork.
    pub fn verify(&self, trust: &LogConfig) -> Result<(Checkpoint, Checkpoint)> {
        ensure!(
            self.format == COMPARISON_FORMAT,
            "unsupported checkpoint comparison format"
        );
        ensure!(
            self.log_id == trust.log_id()?,
            "comparison names a different configured log"
        );
        let first = Checkpoint::verify(&self.first_checkpoint, trust)?;
        let second = Checkpoint::verify(&self.second_checkpoint, trust)?;
        ensure!(
            first.tree_size != second.tree_size || first.root == second.root,
            "authenticated conflicting roots at the same tree size"
        );
        merkle::verify_consistency(
            first.tree_size,
            second.tree_size,
            &first.root,
            &second.root,
            &hashes(&self.consistency_path)?,
        )?;
        Ok((first, second))
    }
}

fn check(name: &str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

/// Both inputs and log trust are supplied by the caller. In particular, a
/// comparison file cannot select the recipient's reference checkpoint.
#[derive(Default)]
pub struct VerificationMaterial<'a> {
    pub trust: Option<&'a LogConfig>,
    pub reference_checkpoint: Option<&'a str>,
    pub comparison: Option<&'a [u8]>,
}

pub fn assess(
    receipt_root: Option<&str>,
    record: Option<&[u8]>,
    material: &VerificationMaterial<'_>,
) -> Vec<Check> {
    let skipped = |detail: &str| check("log-consistency", CheckStatus::Skipped, detail);
    let Some(bytes) = record else {
        return vec![
            check(
                "log-inclusion",
                CheckStatus::Skipped,
                "no retained publication evidence",
            ),
            skipped("no authenticated publication checkpoint to compare"),
        ];
    };
    let prepared = (|| -> Result<_> {
        let root = receipt_root.context("receipt has no causal root")?;
        let record = decode_record(bytes)?;
        record.entry_bytes(root)?;
        Ok((root, record))
    })();
    let (root, record) = match prepared {
        Ok(value) => value,
        Err(error) => {
            return vec![
                check("log-inclusion", CheckStatus::Fail, error.to_string()),
                skipped("publication evidence did not bind the receipt"),
            ]
        }
    };
    let Some(trust) = material.trust else {
        return vec![
            check(
                "log-inclusion",
                CheckStatus::Skipped,
                "no independently configured log trust",
            ),
            skipped("no independently configured log trust"),
        ];
    };
    if let PublicationState::Unconfirmed { reason } = &record.outcome {
        return vec![
            check("log-inclusion", CheckStatus::Skipped, reason.description()),
            skipped("publication has no authenticated inclusion checkpoint"),
        ];
    }
    let publication = match record.verify(root, trust) {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            return vec![
                check("log-inclusion", CheckStatus::Fail, error.to_string()),
                skipped("publication checkpoint was not established"),
            ]
        }
    };
    let inclusion = check(
        "log-inclusion",
        CheckStatus::Pass,
        format!(
            "entry is included in configured log {} at tree size {}",
            record.log_id, publication.tree_size
        ),
    );
    let Some(reference) = material.reference_checkpoint else {
        return vec![
            inclusion,
            skipped("no independently supplied reference checkpoint"),
        ];
    };
    let compared = (|| -> Result<Option<String>> {
        let reference = Checkpoint::verify(reference, trust)?;
        ensure!(
            reference.tree_size != publication.tree_size || reference.root == publication.root,
            "authenticated conflicting roots at the same tree size"
        );
        if let Some(bytes) = material.comparison {
            let comparison = decode_comparison(bytes)?;
            let (first, second) = comparison.verify(trust)?;
            ensure!(
                (same_checkpoint(&first, &reference) && same_checkpoint(&second, &publication))
                    || (same_checkpoint(&second, &reference)
                        && same_checkpoint(&first, &publication)),
                "comparison does not cover the recipient reference and publication checkpoint"
            );
        } else if same_checkpoint(&reference, &publication) {
            // Authentication and root equality are sufficient for this pair.
        } else if reference.tree_size == 0 || publication.tree_size == 0 {
            let (first, second) = if reference.tree_size < publication.tree_size {
                (&reference, &publication)
            } else {
                (&publication, &reference)
            };
            merkle::verify_consistency(
                first.tree_size,
                second.tree_size,
                &first.root,
                &second.root,
                &[],
            )?;
        } else {
            return Ok(None);
        }
        Ok(Some(format!(
            "consistency established only between configured-log checkpoints of sizes {} and {}",
            reference.tree_size, publication.tree_size,
        )))
    })();
    let consistency = match compared {
        Ok(Some(detail)) => check("log-consistency", CheckStatus::Pass, detail),
        Ok(None) => skipped("no consistency proof for the supplied reference checkpoint"),
        Err(error) => check("log-consistency", CheckStatus::Fail, error.to_string()),
    };
    vec![inclusion, consistency]
}
