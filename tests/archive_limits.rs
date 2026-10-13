//! Issue #44: evidence supplied by someone else is bounded before it is
//! looked at. Each case builds a hostile input, requires the refusal to be
//! an operational error (exit 2) distinct from a verdict, requires the
//! refusal to name a resource limit, and, where the command would have
//! written state, requires nothing to have been written.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

fn attest() -> Command {
    Command::cargo_bin("attest").expect("attest binary builds")
}

/// A tar.zst with the given entries, each `(path, bytes, entry type)`.
fn pack(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes, kind) in entries {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(*kind);
        header.set_size(if *kind == tar::EntryType::Regular {
            bytes.len() as u64
        } else {
            0
        });
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        if *kind == tar::EntryType::Symlink {
            builder
                .append_link(&mut header, path, "/etc/passwd")
                .unwrap();
        } else {
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
    }
    let tar_bytes = builder.into_inner().unwrap();
    zstd::encode_all(&tar_bytes[..], 3).unwrap()
}

fn manifest() -> Vec<u8> {
    br#"{"format":"attest-archive/v1","created":"2026-01-01T00:00:00Z","attest_version":"0.1.0","partial":false}"#.to_vec()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// Run `verify --archive` with extra flags, in text and in JSON; both
/// must agree on the exit code, and JSON must name the error kind.
fn refused(dir: &Path, archive: &Path, extra: &[&str], kind: &str, mentions: &str) {
    let mut args = vec!["verify", "--archive", archive.to_str().unwrap()];
    args.extend_from_slice(extra);
    attest()
        .args(&args)
        .current_dir(dir)
        .assert()
        .code(2)
        .stderr(predicates::str::contains(mentions));
    args.extend_from_slice(&["--format", "json"]);
    let out = attest().args(&args).current_dir(dir).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let record: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(record["verdict"], "error");
    assert_eq!(record["error"], kind, "{record}");
}

/// A few kilobytes that expand to far more: refused as soon as the
/// decompressor crosses the limit, before any entry is parsed, and well
/// within the time a verifier has.
#[test]
fn a_decompression_bomb_is_refused_before_it_expands() {
    let tmp = tempfile::tempdir().unwrap();
    let zeros = vec![0u8; 32 * 1024 * 1024];
    let bomb = pack(&[
        ("manifest.json", &manifest(), tar::EntryType::Regular),
        ("receipt.yaml", &zeros, tar::EntryType::Regular),
    ]);
    assert!(bomb.len() < 64 * 1024, "the bomb should be small on disk");
    let archive = write(tmp.path(), "bomb.attest.tar.zst", &bomb);

    let started = std::time::Instant::now();
    refused(
        tmp.path(),
        &archive,
        &["--max-unpacked-bytes", "1048576"],
        "resource-limit",
        "expands past 1048576 bytes",
    );
    assert!(
        started.elapsed().as_secs() < 20,
        "the refusal must not wait for the expansion"
    );
}

/// Count and per-entry size are bounded separately, before the entry's
/// bytes are read in.
#[test]
fn too_many_entries_and_oversized_entries_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let small = b"{}".to_vec();
    let mut many: Vec<(String, Vec<u8>)> = vec![("manifest.json".into(), manifest())];
    for i in 0..50 {
        many.push((format!("events/{i:04}.json"), small.clone()));
    }
    let refs: Vec<(&str, &[u8], tar::EntryType)> = many
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice(), tar::EntryType::Regular))
        .collect();
    let crowded = write(tmp.path(), "crowded.attest.tar.zst", &pack(&refs));
    refused(
        tmp.path(),
        &crowded,
        &["--max-entries", "10"],
        "resource-limit",
        "more than 10 entries",
    );

    let big = vec![b'x'; 200_000];
    let fat = write(
        tmp.path(),
        "fat.attest.tar.zst",
        &pack(&[
            ("manifest.json", &manifest(), tar::EntryType::Regular),
            ("receipt.yaml", &big, tar::EntryType::Regular),
        ]),
    );
    refused(
        tmp.path(),
        &fat,
        &["--max-entry-bytes", "100000"],
        "resource-limit",
        "declares 200000 bytes",
    );
}

/// The file on disk is the first thing checked, before it is opened.
#[test]
fn an_archive_over_the_disk_limit_is_refused_unopened() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = write(
        tmp.path(),
        "plain.attest.tar.zst",
        &pack(&[("manifest.json", &manifest(), tar::EntryType::Regular)]),
    );
    refused(
        tmp.path(),
        &archive,
        &["--max-archive-bytes", "10"],
        "resource-limit",
        "bytes on disk",
    );
    // Not a zstd stream at all, but over the limit: the limit speaks
    // first, so nothing is ever decoded.
    let junk = write(tmp.path(), "junk.attest.tar.zst", &vec![7u8; 1000]);
    refused(
        tmp.path(),
        &junk,
        &["--max-archive-bytes", "10"],
        "resource-limit",
        "bytes on disk",
    );
}

/// An archive that contradicts itself, or that is shaped in a way the
/// writer never produces, is refused deterministically: the same input
/// gets the same answer, and it is never "whichever entry came last".
#[test]
fn duplicate_and_unexpected_entries_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let twice = write(
        tmp.path(),
        "twice.attest.tar.zst",
        &pack(&[
            ("manifest.json", &manifest(), tar::EntryType::Regular),
            ("receipt.yaml", b"a: 1\n", tar::EntryType::Regular),
            ("receipt.yaml", b"a: 2\n", tar::EntryType::Regular),
        ]),
    );
    for _ in 0..2 {
        refused(
            tmp.path(),
            &twice,
            &[],
            "operational",
            "lists receipt.yaml twice",
        );
    }

    let linked = write(
        tmp.path(),
        "linked.attest.tar.zst",
        &pack(&[
            ("manifest.json", &manifest(), tar::EntryType::Regular),
            ("receipt.yaml", b"", tar::EntryType::Symlink),
        ]),
    );
    refused(
        tmp.path(),
        &linked,
        &[],
        "operational",
        "is not a regular file",
    );

    // The tar crate refuses to write a `..` path itself, so the header is
    // filled in by hand, as an attacker would.
    let escaping = {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(manifest().len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "manifest.json", &manifest()[..])
            .unwrap();
        let mut header = tar::Header::new_ustar();
        let name = b"../outside.yaml";
        header.as_ustar_mut().unwrap().name[..name.len()].copy_from_slice(name);
        header.set_size(1);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &b"x"[..]).unwrap();
        let tar_bytes = builder.into_inner().unwrap();
        write(
            tmp.path(),
            "escaping.attest.tar.zst",
            &zstd::encode_all(&tar_bytes[..], 3).unwrap(),
        )
    };
    refused(
        tmp.path(),
        &escaping,
        &[],
        "operational",
        "escapes the archive",
    );
}

/// The same principle on the other externally supplied inputs: a receipt
/// file and a trust bundle past their caps are refused before being
/// parsed, and a refused bundle leaves the store exactly as it was.
#[test]
fn oversized_receipts_and_bundles_are_refused_without_side_effects() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();

    let huge_receipt = write(tmp.path(), "huge.yaml", &vec![b'#'; 17 * 1024 * 1024]);
    attest()
        .args(["verify", huge_receipt.to_str().unwrap()])
        .current_dir(tmp.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("the limit for a receipt is"));

    let trust = tmp.path().join(".attest/trust");
    let listing = |dir: &Path| -> Vec<String> {
        std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    let before = listing(&trust);
    let huge_bundle = write(tmp.path(), "huge.json", &vec![b' '; 2 * 1024 * 1024]);
    attest()
        .args([
            "trust",
            "import",
            huge_bundle.to_str().unwrap(),
            "--issuer",
            "00000000000000000000000000000000",
        ])
        .current_dir(tmp.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("a trust bundle is at most"));
    let after = listing(&trust);
    assert_eq!(
        before, after,
        "a refused bundle must leave the store untouched"
    );
    assert!(!trust.join("bundles").exists());
}

/// Within the limits, an archive the writer produced verifies as before:
/// the bounds refuse hostile input, they do not change the answer for
/// honest input.
#[test]
fn an_ordinary_archive_still_verifies_within_the_limits() {
    let tmp = tempfile::tempdir().unwrap();
    attest()
        .arg("init")
        .current_dir(tmp.path())
        .assert()
        .success();
    std::fs::write(
        tmp.path().join("attest.yaml"),
        "version: \"1.0\"\nname: toy\nsteps:\n  copy:\n    run: \"cat in.txt > out.txt\"\n    inputs: [\"in.txt\"]\n    outputs: [\"out.txt\"]\n    cache: false\n",
    )
    .unwrap();
    std::fs::write(tmp.path().join("in.txt"), "payload").unwrap();
    attest()
        .arg("run")
        .current_dir(tmp.path())
        .assert()
        .success();
    let receipt = std::fs::read_dir(tmp.path().join(".attest/receipts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "yaml"))
        .unwrap();
    let archive = tmp.path().join("ok.attest.tar.zst");
    attest()
        .args([
            "causal",
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
        ])
        .current_dir(tmp.path())
        .assert()
        .success();
    attest()
        .args([
            "verify",
            "--archive",
            archive.to_str().unwrap(),
            "--check-signatures",
            "false",
        ])
        .current_dir(tmp.path())
        .assert()
        .code(0);
}

/// PAX extension headers and GNU long names are physical entries the tar
/// reader folds into the next one, past the entry count and the per-entry
/// size. The writer produces neither, and the reader refuses both.
#[test]
fn pax_extensions_and_long_names_are_refused() {
    let tmp = tempfile::tempdir().unwrap();

    let with_pax = {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(manifest().len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "manifest.json", &manifest()[..])
            .unwrap();
        let padding = "x".repeat(32 * 1024);
        let mut header = tar::Header::new_ustar();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_pax_extensions([("comment", padding.as_bytes())])
            .unwrap();
        builder
            .append_data(&mut header, "receipt.yaml", &b"x"[..])
            .unwrap();
        let bytes = builder.into_inner().unwrap();
        write(
            tmp.path(),
            "pax.attest.tar.zst",
            &zstd::encode_all(&bytes[..], 3).unwrap(),
        )
    };
    refused(
        tmp.path(),
        &with_pax,
        &["--max-entry-bytes", "8192", "--max-entries", "3"],
        "operational",
        "PAX extensions",
    );

    let long = format!("events/{}.json", "a".repeat(120));
    let with_long_name = write(
        tmp.path(),
        "long.attest.tar.zst",
        &pack(&[
            ("manifest.json", &manifest(), tar::EntryType::Regular),
            (long.as_str(), b"{}", tar::EntryType::Regular),
        ]),
    );
    refused(
        tmp.path(),
        &with_long_name,
        &[],
        "operational",
        "long-name extension",
    );
}
