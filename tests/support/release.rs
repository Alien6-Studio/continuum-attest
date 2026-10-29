//! Shared producer/recipient setup for release tests and security invariants.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use attest::archive::{read_archive, write_archive, ArchiveEntry};
use attest::keys::KeyStore;
use serde_json::Value;

pub(super) fn attest() -> Command {
    let mut command = Command::cargo_bin("attest").expect("attest binary");
    command.env_remove("ATTEST_KEYS_DIR");
    command
}

pub(super) struct Release {
    pub(super) producer: tempfile::TempDir,
    pub(super) recipient: tempfile::TempDir,
    pub(super) receipt: PathBuf,
    pub(super) archive: PathBuf,
    pub(super) key: String,
}

impl Release {
    pub(super) fn new(exit_code: i32) -> Self {
        let producer = tempfile::tempdir().unwrap();
        let recipient = tempfile::tempdir().unwrap();
        let store = KeyStore::new(producer.path());
        let key = store.generate("release").unwrap();
        // In an actual handoff this key is authenticated out of band. The
        // archive is deliberately not consulted when establishing trust.
        KeyStore::new(recipient.path())
            .import(&store.trust_dir().join(format!("{key}.pub")), "producer")
            .unwrap();
        std::fs::write(producer.path().join("source.txt"), "release payload\n").unwrap();
        let build = format!(
            "mkdir -p dist; cp source.txt dist/program; printf manifest > dist/metadata; exit {exit_code}"
        );
        attest()
            .current_dir(producer.path())
            .args([
                "run",
                "--wrap",
                "--name",
                "build",
                "--input",
                "source.txt",
                "--output",
                "dist",
                "--sign",
                "--",
                "sh",
                "-c",
                &build,
            ])
            .assert()
            .code(exit_code);
        let receipt = std::fs::read_dir(producer.path().join(".attest/receipts"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "yaml")
            })
            .unwrap();
        let archive = recipient.path().join("release.attest.tar.zst");
        let release = Self {
            producer,
            recipient,
            receipt,
            archive,
            key,
        };
        release.pack().assert().success();
        release
    }

    pub(super) fn pack(&self) -> Command {
        let mut command = attest();
        command
            .current_dir(self.producer.path())
            .args(["evidence", "pack"])
            .arg(&self.receipt)
            .arg("--workspace")
            .arg(self.producer.path())
            .arg("--output")
            .arg(&self.archive);
        command
    }

    pub(super) fn verify(&self, extra: &[&str], code: i32) -> Value {
        verify(
            self.recipient.path(),
            &self.archive,
            &self.recipient.path().join(".attest/trust"),
            extra,
            code,
        )
    }

    pub(super) fn mutate_archive(&self, mutation: impl FnOnce(&mut Vec<ArchiveEntry>)) {
        let mut entries = read_archive(&self.archive).unwrap();
        mutation(&mut entries);
        write_archive(entries, &self.archive).unwrap();
    }
}

pub(super) fn verify(
    workspace: &Path,
    archive: &Path,
    trust: &Path,
    extra: &[&str],
    code: i32,
) -> Value {
    let output = attest()
        .current_dir(workspace)
        .args(["evidence", "verify"])
        .arg(archive)
        .arg("--trust-store")
        .arg(trust)
        .args(["--format", "json"])
        .args(extra)
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

pub(super) fn check(result: &Value, name: &str) -> Value {
    result["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == name)
        .unwrap()
        .clone()
}
