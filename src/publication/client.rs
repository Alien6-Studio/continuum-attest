//! Online acquisition, invoked only by explicit publication/comparison
//! commands. A submission is recorded before the first request. Confirmation
//! requires the same local proof checks the recipient performs offline.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use rand_core::RngCore;
use reqwest::{Client, Response, Url};

use super::entry_for_root;
use super::merkle;
use super::note::{Checkpoint, LogConfig, MAX_NOTE_BYTES};
use super::record::{
    decode_record, CheckpointComparison, PublicationRecord, PublicationState, Submission,
    UnconfirmedReason, COMPARISON_FORMAT, MAX_RECORD_BYTES, MAX_SUBMISSIONS, RECORD_FORMAT,
};
use super::tiles::{TileReader, TileSource, TILE_BYTES};

const MAX_REQUESTS: usize = 2048;
const MAX_CHECKPOINT_POLLS: usize = 30;

#[derive(Debug, thiserror::Error)]
enum TransportFault {
    #[error("log request failed")]
    Unavailable,
    #[error("log returned HTTP {0}")]
    Rejected(u16),
    #[error("log response exceeds its size limit")]
    Oversize,
    #[error("log request budget exhausted")]
    Budget,
}

fn reason(error: &anyhow::Error) -> UnconfirmedReason {
    match error.downcast_ref::<TransportFault>() {
        Some(TransportFault::Unavailable) => UnconfirmedReason::RequestFailed,
        Some(TransportFault::Rejected(_)) => UnconfirmedReason::ServiceRefused,
        Some(TransportFault::Oversize | TransportFault::Budget) | None => {
            UnconfirmedReason::InvalidProof
        }
    }
}

pub fn validate_timeout(timeout: Duration) -> Result<()> {
    ensure!(
        !timeout.is_zero() && timeout <= Duration::from_secs(120),
        "publication deadline must be positive and at most 120 seconds"
    );
    Ok(())
}

fn endpoint(text: &str) -> Result<Url> {
    ensure!(text.len() <= 4096, "log URL is too long");
    let url = Url::parse(text).context("invalid log URL")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "log URLs require HTTPS and cannot contain credentials, queries or fragments"
    );
    Ok(url)
}

pub struct HttpLog {
    client: Client,
    read: Url,
    submit: Option<Url>,
    requests: AtomicUsize,
}

impl HttpLog {
    pub fn new(config: &LogConfig, publishing: bool) -> Result<Self> {
        config.validate()?;
        let read = config
            .read_url
            .as_deref()
            .context("log read URL is required")?;
        let read = endpoint(&format!("{}/", read.trim_end_matches('/')))?;
        let submit = config.submit_url.as_deref().map(endpoint).transpose()?;
        ensure!(
            !publishing || submit.is_some(),
            "log submission URL is required"
        );
        let mut client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("continuum-attest/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = &config.tls_ca {
            let pem = crate::verify::read_bounded(path, 1024 * 1024, "log TLS CA")?;
            client = client.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).context("invalid log TLS CA certificate")?,
            );
        }
        Ok(Self {
            client: client.build()?,
            read,
            submit,
            requests: AtomicUsize::new(0),
        })
    }

    fn budget(&self) -> Result<()> {
        if self.requests.fetch_add(1, Ordering::Relaxed) >= MAX_REQUESTS {
            return Err(TransportFault::Budget.into());
        }
        Ok(())
    }

    async fn body(mut response: Response, maximum: usize) -> Result<Vec<u8>> {
        if response
            .content_length()
            .is_some_and(|length| length > maximum as u64)
        {
            return Err(TransportFault::Oversize.into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| TransportFault::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > maximum {
                return Err(TransportFault::Oversize.into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn read(&self, path: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
        let url = self.read.join(path)?;
        for attempt in 0..3 {
            self.budget()?;
            let response = self.client.get(url.clone()).send().await;
            match response {
                Ok(response) if response.status().as_u16() == 404 => return Ok(None),
                Ok(response) if response.status().is_success() => {
                    return Ok(Some(Self::body(response, maximum).await?))
                }
                Ok(response) => {
                    let status = response.status();
                    if attempt == 2 || !(status.is_server_error() || status.as_u16() == 429) {
                        return Err(TransportFault::Rejected(status.as_u16()).into());
                    }
                }
                Err(_) if attempt == 2 => return Err(TransportFault::Unavailable.into()),
                Err(_) => {}
            }
            tokio::time::sleep(Duration::from_millis(100 * (attempt + 1))).await;
        }
        Err(TransportFault::Unavailable.into())
    }

    async fn submit(&self, entry: &[u8]) -> Result<u64> {
        self.budget()?;
        let response = self
            .client
            .post(
                self.submit
                    .as_ref()
                    .context("missing submission endpoint")?
                    .clone(),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(entry.to_vec())
            .send()
            .await
            .map_err(|_| TransportFault::Unavailable)?;
        if !response.status().is_success() {
            return Err(TransportFault::Rejected(response.status().as_u16()).into());
        }
        let bytes = Self::body(response, 32).await?;
        let text = std::str::from_utf8(&bytes).context("invalid publication index encoding")?;
        let text = text.strip_suffix('\n').unwrap_or(text);
        ensure!(
            !text.is_empty()
                && text.bytes().all(|b| b.is_ascii_digit())
                && (text == "0" || !text.starts_with('0')),
            "invalid publication index"
        );
        let index = text.parse::<u64>().context("publication index overflows")?;
        ensure!(
            index < u64::MAX,
            "publication index cannot fit a checkpoint"
        );
        Ok(index)
    }

    async fn checkpoint(&self, trust: &LogConfig) -> Result<Option<Checkpoint>> {
        self.read("checkpoint", MAX_NOTE_BYTES)
            .await?
            .map(|bytes| {
                let text =
                    std::str::from_utf8(&bytes).context("invalid checkpoint text encoding")?;
                Checkpoint::verify(text, trust)
            })
            .transpose()
    }
}

#[async_trait]
impl TileSource for HttpLog {
    async fn tile(&self, path: &str) -> Result<Option<Vec<u8>>> {
        ensure!(
            path.starts_with("tile/") && !path.contains(".."),
            "invalid hash tile resource"
        );
        self.read(path, TILE_BYTES).await
    }
}

/// A sidecar lock prevents two publishers from rewriting one audit record.
/// A stale lock after a crash requires operator inspection, not silent expiry.
struct RecordStore {
    output: PathBuf,
    parent: PathBuf,
    lock: PathBuf,
    _lock_file: File,
}

impl RecordStore {
    fn acquire(output: &Path) -> Result<Self> {
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        ensure!(
            parent.is_dir(),
            "publication output directory does not exist"
        );
        let name = output
            .file_name()
            .context("publication output must name a file")?;
        let mut lock_name = name.to_os_string();
        lock_name.push(".lock");
        let lock = parent.join(lock_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&lock).context(
            "cannot acquire publication record lock; inspect any stale lock before retrying",
        )?;
        Ok(Self {
            output: output.into(),
            parent: parent.into(),
            lock,
            _lock_file: file,
        })
    }

    fn load(&self) -> Result<Option<PublicationRecord>> {
        let metadata = match std::fs::symlink_metadata(&self.output) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            metadata.is_file() && !metadata.is_symlink(),
            "publication record is not a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "publication record must be private to its owner"
            );
        }
        let bytes =
            crate::verify::read_bounded(&self.output, MAX_RECORD_BYTES, "publication record")?;
        Ok(Some(decode_record(&bytes)?))
    }

    fn save(&self, record: &PublicationRecord, initial: bool) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(record)?;
        ensure!(
            (bytes.len() as u64) < MAX_RECORD_BYTES,
            "publication record exceeds its size limit"
        );
        let mut staged = tempfile::NamedTempFile::new_in(&self.parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            staged
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        staged.write_all(&bytes)?;
        staged.write_all(b"\n")?;
        staged.as_file().sync_all()?;
        if initial {
            staged
                .persist_noclobber(&self.output)
                .map_err(|error| error.error)?;
        } else {
            staged.persist(&self.output).map_err(|error| error.error)?;
        }
        File::open(&self.parent)?.sync_all()?;
        Ok(())
    }
}

impl Drop for RecordStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock);
    }
}

async fn obtain_inclusion(
    log: &HttpLog,
    trust: &LogConfig,
    record: &mut PublicationRecord,
    store: &RecordStore,
) -> Result<()> {
    let entry = record.entry_bytes(&record.causal_root)?;
    let mut index = record
        .submissions
        .iter()
        .rev()
        .find_map(|attempt| attempt.returned_index);
    while index.is_none() && record.submissions.len() < MAX_SUBMISSIONS {
        record.submissions.push(Submission {
            started_at: Utc::now(),
            returned_index: None,
        });
        // This is the disclosure boundary: record exact intent before POST.
        store.save(record, false)?;
        match log.submit(&entry).await {
            Ok(returned) => {
                record
                    .submissions
                    .last_mut()
                    .context("submission was not recorded")?
                    .returned_index = Some(returned);
                index = Some(returned);
                record.outcome = PublicationState::Unconfirmed {
                    reason: UnconfirmedReason::AwaitingInclusion,
                };
                store.save(record, false)?;
            }
            Err(error) => {
                record.outcome = PublicationState::Unconfirmed {
                    reason: reason(&error),
                };
                store.save(record, false)?;
                if matches!(error.downcast_ref::<TransportFault>(), Some(TransportFault::Rejected(code)) if !(500..600).contains(code) && *code != 429)
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    let Some(index) = index else {
        return Ok(());
    };
    for _ in 0..MAX_CHECKPOINT_POLLS {
        if let Some(checkpoint) = log.checkpoint(trust).await? {
            if checkpoint.tree_size > index {
                let mut reader = TileReader::new(log, checkpoint.tree_size);
                let path = reader.inclusion(index).await?;
                merkle::verify_inclusion(
                    &entry,
                    index,
                    checkpoint.tree_size,
                    &path,
                    &checkpoint.root,
                )?;
                let mut confirmed = record.clone();
                confirmed.outcome = PublicationState::Confirmed {
                    leaf_index: index,
                    checkpoint: checkpoint.signed_note,
                    inclusion_path: path.iter().map(hex::encode).collect(),
                };
                confirmed.verify(&record.causal_root, trust)?;
                store.save(&confirmed, false)?;
                *record = confirmed;
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

/// Validate the receipt and destination before generating any disclosure.
/// Existing matching records resume with the same entry and bounded attempts.
pub async fn publish(
    receipt_path: &Path,
    receipt_trust: &Path,
    config: &LogConfig,
    output: &Path,
    timeout: Duration,
) -> Result<PublicationRecord> {
    validate_timeout(timeout)?;
    config.validate()?;
    let log = HttpLog::new(config, true)?;
    let receipt_bytes =
        crate::verify::read_bounded(receipt_path, crate::verify::MAX_RECEIPT_BYTES, "receipt")?;
    let options = crate::verify::VerifyOptions {
        check_signatures: true,
        recompute: false,
        workspace: std::env::current_dir()?,
        trust_store: Some(receipt_trust.into()),
        trust_receipt_timestamp: false,
        policy: crate::verify::Policy {
            required: vec![crate::verify::Requirement::Signature],
        },
    };
    let verdict = crate::verify::verify_receipt_bytes(
        &receipt_bytes,
        &receipt_path.display().to_string(),
        &options,
    )?;
    ensure!(verdict.passed(), "receipt verification refused publication");
    let receipt: crate::storage::Receipt = serde_yaml::from_slice(&receipt_bytes)?;
    let root = receipt
        .causal_chain_hash
        .as_deref()
        .context("receipt has no causal root to publish")?;
    super::hash_bytes(root)?;
    let store = RecordStore::acquire(output)?;
    let mut record = if let Some(record) = store.load()? {
        record.entry_bytes(root)?;
        ensure!(
            record.log_id == config.log_id()?
                && record.submit_url == config.submit_url.as_deref().unwrap_or(""),
            "existing record targets a different configured log"
        );
        if matches!(record.outcome, PublicationState::Confirmed { .. }) {
            record.verify(root, config)?;
            return Ok(record);
        }
        record
    } else {
        let mut nonce = [0; 32];
        rand_core::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| anyhow::anyhow!("operating-system randomness unavailable"))?;
        let opening_nonce = hex::encode(nonce);
        let entry = entry_for_root(root, &opening_nonce)?;
        let record = PublicationRecord {
            format: RECORD_FORMAT.into(),
            causal_root: root.into(),
            opening_nonce,
            entry: hex::encode(entry),
            log_id: config.log_id()?,
            submit_url: config
                .submit_url
                .clone()
                .context("missing submission URL")?,
            created_at: Utc::now(),
            submissions: vec![],
            outcome: PublicationState::Unconfirmed {
                reason: UnconfirmedReason::Prepared,
            },
        };
        store.save(&record, true)?;
        record
    };
    let result =
        tokio::time::timeout(timeout, obtain_inclusion(&log, config, &mut record, &store)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            record.outcome = PublicationState::Unconfirmed {
                reason: reason(&error),
            }
        }
        Err(_) => {
            record.outcome = PublicationState::Unconfirmed {
                reason: UnconfirmedReason::Deadline,
            }
        }
    }
    if !matches!(record.outcome, PublicationState::Confirmed { .. })
        && record.submissions.len() >= MAX_SUBMISSIONS
        && record
            .submissions
            .iter()
            .all(|attempt| attempt.returned_index.is_none())
    {
        // Preserve a more informative transport failure when one is available.
        if matches!(
            record.outcome,
            PublicationState::Unconfirmed {
                reason: UnconfirmedReason::Prepared
            }
        ) {
            record.outcome = PublicationState::Unconfirmed {
                reason: UnconfirmedReason::AttemptLimit,
            };
        }
    }
    store.save(&record, false)?;
    Ok(record)
}

/// An explicit read operation for checkpoint exchange. No leaf is submitted.
pub async fn fetch_comparison(
    first_note: &str,
    second_note: &str,
    config: &LogConfig,
    timeout: Duration,
) -> Result<CheckpointComparison> {
    validate_timeout(timeout)?;
    let first = Checkpoint::verify(first_note, config)?;
    let second = Checkpoint::verify(second_note, config)?;
    ensure!(
        first.tree_size != second.tree_size || first.root == second.root,
        "authenticated conflicting roots at the same tree size"
    );
    let (first, second) = if first.tree_size <= second.tree_size {
        (first, second)
    } else {
        (second, first)
    };
    let log = HttpLog::new(config, false)?;
    let acquire = async {
        let mut reader = TileReader::new(&log, second.tree_size);
        let path = reader
            .consistency(first.tree_size, second.tree_size)
            .await?;
        let comparison = CheckpointComparison {
            format: COMPARISON_FORMAT.into(),
            log_id: config.log_id()?,
            first_checkpoint: first.signed_note,
            second_checkpoint: second.signed_note,
            consistency_path: path.iter().map(hex::encode).collect(),
        };
        comparison.verify(config)?;
        Ok::<_, anyhow::Error>(comparison)
    };
    tokio::time::timeout(timeout, acquire)
        .await
        .context("checkpoint comparison deadline expired")?
}
