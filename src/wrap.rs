//! Wrap mode: attest a single command inside an existing CI job
//! (`attest run --wrap`).
//!
//! Wrap mode executes an arbitrary command verbatim — no sandbox, no
//! pipeline file — hashes the declared inputs before and the declared
//! outputs after execution using the canonical `attest-manifest/v1`
//! algorithm (src/hashing.rs), and appends a single-step receipt under
//! `<workspace>/.attest/receipts/`. This is the first rung of the
//! progressive-adoption ladder: "add one job", not "replace your CI".
//!
//! Exit-code contract:
//! - The wrapped command's exit code is always propagated; a wrapped
//!   failure is never masked by attestation bookkeeping.
//! - If the command succeeds but attestation fails (e.g. a declared
//!   output is missing), the process exits 1 with a distinct
//!   `attestation failed` message on stderr.
//! - Operational errors (unwritable receipt directory, key-store
//!   failures) surface as `Err` and map to exit code 2 in the CLI.
//!
//! The receipt's `pipeline_hash` is `blake3("attest-wrap/v1\n" + command)`
//! since no pipeline file exists in wrap mode; the `run:` line of the
//! input manifest carries the same command string, so the recorded hashes
//! bind both the file contents and the exact command.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::Utc;

use crate::storage::{write_receipt_unique, Receipt, StepResult, Storage};

/// Domain-separation prefix for the wrap-mode pipeline hash.
const WRAP_PIPELINE_DOMAIN: &str = "attest-wrap/v1";

/// Captured stream size limit; CI logs can be arbitrarily large and are
/// already persisted by the CI system itself, so the receipt records at
/// most this many bytes per stream with an explicit truncation marker.
const CAPTURE_LIMIT: usize = 64 * 1024;

/// Marker appended to a captured stream that hit [`CAPTURE_LIMIT`].
const TRUNCATION_MARKER: &str = "\n[truncated by attest run --wrap]";

#[derive(Debug, Clone)]
pub struct WrapOptions {
    /// Step name recorded in the receipt (required).
    pub name: String,
    /// Declared input paths, relative to the workspace root.
    pub inputs: Vec<PathBuf>,
    /// Declared output paths, relative to the workspace root.
    pub outputs: Vec<PathBuf>,
    /// Sign the receipt with a managed key.
    pub sign: bool,
    /// Explicit signing key id (`attest keys list`).
    pub key: Option<String>,
    /// Timestamp authority URL. `None` disables timestamping; requires
    /// `sign`, since the token is requested over the signature.
    pub tsa: Option<String>,
    /// Workspace root; declared paths are hashed relative to it and the
    /// receipt is written under `<workspace>/.attest/receipts/`.
    pub workspace: PathBuf,
}

/// Execute `command` verbatim and append a single-step receipt.
///
/// Returns the process exit code per the module-level contract; `Err`
/// means an operational failure (exit 2 in the CLI).
pub fn run_wrap(command: &[String], options: &WrapOptions) -> Result<i32> {
    let (first, rest) = match command.split_first() {
        Some(split) => split,
        None => anyhow::bail!("--wrap requires a command after `--`"),
    };
    let run_string = command.join(" ");
    let mut provenance =
        crate::provenance::collect(&options.workspace, Some(options.name.clone()), false);
    provenance.steps.push(crate::provenance::step(
        &options.name,
        &run_string,
        &[],
        &options.inputs,
        &options.outputs,
    ));

    if options.inputs.is_empty() {
        eprintln!("warning: no inputs declared; attestation covers command string only");
    }

    let input_hash = match crate::hashing::hash_inputs(
        &options.workspace,
        &options.name,
        &run_string,
        &options.inputs,
    ) {
        Ok(hash) => hash,
        Err(err) => {
            eprintln!("error: attestation failed: {err}");
            return Ok(1);
        }
    };

    let started = Instant::now();
    let mut child = match Command::new(first)
        .args(rest)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            // Shell convention: 127 = command not found / not executable.
            eprintln!("attest: failed to execute '{first}': {err}");
            return Ok(127);
        }
    };

    let stdout_pipe = child.stdout.take().context("child stdout not captured")?;
    let stderr_pipe = child.stderr.take().context("child stderr not captured")?;
    let stdout_thread = std::thread::spawn(move || tee(stdout_pipe, std::io::stdout()));
    let stderr_thread = std::thread::spawn(move || tee(stderr_pipe, std::io::stderr()));

    let status = child.wait().context("failed to wait for wrapped command")?;
    let stdout = stdout_thread
        .join()
        .unwrap_or_else(|_| String::from("[capture failed]"));
    let stderr = stderr_thread
        .join()
        .unwrap_or_else(|_| String::from("[capture failed]"));
    let duration_secs = started.elapsed().as_secs();
    let exit_code = exit_code_of(&status);

    let (output_hash, artifacts) = match crate::hashing::outputs_with_artifacts(
        &options.workspace,
        &options.name,
        &options.outputs,
    ) {
        Ok(hash) => hash,
        Err(err) if exit_code == 0 => {
            eprintln!("error: attestation failed: {err}");
            return Ok(1);
        }
        Err(err) => {
            // The command already failed; report its exit code and do not
            // fabricate output hashes for artifacts that were never built.
            eprintln!("warning: attestation incomplete: {err}; no receipt written");
            return Ok(exit_code);
        }
    };

    provenance.artifacts = artifacts;
    let mut receipt = Receipt {
        schema_version: Some(crate::storage::RECEIPT_SCHEMA_VERSION),
        pipeline_hash: blake3::hash(format!("{WRAP_PIPELINE_DOMAIN}\n{run_string}").as_bytes())
            .to_hex()
            .to_string(),
        steps: vec![StepResult {
            name: options.name.clone(),
            input_hash,
            output_hash,
            duration_secs,
            exit_code,
            cache_hit: false,
            stdout,
            stderr,
            capsule_hash: None,
        }],
        timestamp: Utc::now(),
        total_duration_secs: duration_secs,
        signature: None,
        signer_public_key: None,
        attest_version: env!("CARGO_PKG_VERSION").to_string(),
        causal_events: vec![],
        causal_chain_hash: None,
        reproducibility: None,
        provenance: Some(provenance),
        timestamp_token: None,
    };

    if options.sign {
        let mut storage = Storage::new(&options.workspace)?;
        let store = crate::keys::KeyStore::new(&options.workspace);
        match store.select_signing_key(options.key.as_deref())? {
            Some(signing_key) => storage.set_keypair(
                crate::crypto::sign::AttestKeypair::from_signing_key(signing_key),
            ),
            // No managed key: fall back to the legacy auto-generated raw
            // keypair under .attest/keys/ (same behavior as `attest run`).
            None => storage.load_keypair(true)?,
        }
        receipt = storage.sign_receipt(&receipt)?;
        if let Some(url) = &options.tsa {
            receipt = storage.timestamp_receipt(&receipt, url)?;
            tracing::info!("Signature timestamped by {}", url);
        }
    } else if options.tsa.is_some() {
        anyhow::bail!("--timestamp requires --sign; there is no signature to timestamp");
    }

    let receipts_dir = options.workspace.join(".attest").join("receipts");
    std::fs::create_dir_all(&receipts_dir)
        .with_context(|| format!("cannot create {}", receipts_dir.display()))?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let label = sanitize_label(&options.name);
    let receipt_path = write_receipt_unique(
        &receipts_dir,
        &stamp,
        Some(&label),
        &serde_yaml::to_string(&receipt)?,
    )?;
    // stderr, not stdout: the wrapped command owns stdout in wrap mode.
    eprintln!("attest: receipt written to {}", receipt_path.display());
    crate::sync::after_receipt(&options.workspace, &receipt_path);

    Ok(exit_code)
}

/// Forward a child stream to the parent stream while capturing up to
/// [`CAPTURE_LIMIT`] bytes for the receipt.
fn tee(mut source: impl Read, mut sink: impl Write) -> String {
    let mut captured: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 8192];
    loop {
        match source.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = sink.write_all(&buf[..n]);
                let _ = sink.flush();
                if captured.len() < CAPTURE_LIMIT {
                    let take = n.min(CAPTURE_LIMIT - captured.len());
                    captured.extend_from_slice(&buf[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    let mut text = String::from_utf8_lossy(&captured).into_owned();
    if truncated {
        text.push_str(TRUNCATION_MARKER);
    }
    text
}

/// Exit code of a finished process; signal deaths map to 128+signal on
/// Unix (shell convention).
fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

/// Filesystem-safe receipt label (same character set as `attest run`).
fn sanitize_label(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_label_replaces_specials() {
        assert_eq!(sanitize_label("build & test/1"), "build---test-1");
    }

    #[test]
    fn tee_truncates_and_marks() {
        let data = vec![b'x'; CAPTURE_LIMIT + 10];
        let text = tee(&data[..], std::io::sink());
        assert!(text.ends_with(TRUNCATION_MARKER));
        assert_eq!(text.len(), CAPTURE_LIMIT + TRUNCATION_MARKER.len());
    }

    #[test]
    fn tee_passes_small_output_through() {
        let mut sink = Vec::new();
        let text = tee(&b"hello"[..], &mut sink);
        assert_eq!(text, "hello");
        assert_eq!(sink, b"hello");
    }
}
