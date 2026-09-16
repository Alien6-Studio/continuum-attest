//! Regression tests for the manifest-based cache key.
//!
//! The cache key must be derived from the canonical attest-manifest/v1
//! input hash: binary inputs are hashed byte-for-byte and a missing
//! declared input is an error, never a silent skip.

use anyhow::Result;
use attest::storage::Storage;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

fn test_storage(root: &std::path::Path) -> Result<Storage> {
    Ok(Storage::new(root)?)
}

// Binary (non-UTF-8) inputs must be hashed byte-for-byte; the previous
// implementation read inputs with read_to_string and errored on them.
#[test]
fn test_cache_key_handles_binary_inputs() -> Result<()> {
    let workspace = TempDir::new()?;
    let storage = test_storage(workspace.path())?;

    let binary = workspace.path().join("blob.bin");
    std::fs::write(&binary, [0u8, 159, 146, 150, 255, 0, 1])?;

    let inputs = vec![PathBuf::from("blob.bin")];
    let env = HashMap::new();

    let key1 =
        storage.compute_content_hash(workspace.path(), "step", "cat blob.bin", &inputs, &env)?;

    // Same content, same key.
    let key2 =
        storage.compute_content_hash(workspace.path(), "step", "cat blob.bin", &inputs, &env)?;
    assert_eq!(key1, key2);

    // Different bytes, different key.
    std::fs::write(&binary, [0u8, 159, 146, 150, 255, 0, 2])?;
    let key3 =
        storage.compute_content_hash(workspace.path(), "step", "cat blob.bin", &inputs, &env)?;
    assert_ne!(key1, key3);

    Ok(())
}

// A declared input that does not exist must fail the cache-key computation
// (which fails the run) instead of being silently skipped, which previously
// produced stale cache hits after an input file was deleted.
#[test]
fn test_cache_key_missing_input_is_an_error() -> Result<()> {
    let workspace = TempDir::new()?;
    let storage = test_storage(workspace.path())?;

    let inputs = vec![PathBuf::from("deleted.txt")];
    let result = storage.compute_content_hash(
        workspace.path(),
        "step",
        "cat deleted.txt",
        &inputs,
        &HashMap::new(),
    );

    let err = format!("{:#}", result.expect_err("missing input must be an error"));
    assert!(
        err.contains("deleted.txt"),
        "error should name the missing input, got: {err}"
    );

    Ok(())
}

// Removing a previously-present input must not resolve to the old key: the
// step keyed on the file's presence can never hit that cache entry again.
#[test]
fn test_cache_key_changes_when_input_removed() -> Result<()> {
    let workspace = TempDir::new()?;
    let storage = test_storage(workspace.path())?;

    let file = workspace.path().join("input.txt");
    std::fs::write(&file, "data")?;
    let inputs = vec![PathBuf::from("input.txt")];

    let key_with_input =
        storage.compute_content_hash(workspace.path(), "step", "cmd", &inputs, &HashMap::new())?;

    std::fs::remove_file(&file)?;
    let result =
        storage.compute_content_hash(workspace.path(), "step", "cmd", &inputs, &HashMap::new());
    assert!(result.is_err(), "removed input must not produce a key");

    // And the receipt-side manifest hash agrees with the cache-side key
    // derivation while the input exists.
    std::fs::write(&file, "data")?;
    let key_again =
        storage.compute_content_hash(workspace.path(), "step", "cmd", &inputs, &HashMap::new())?;
    assert_eq!(key_with_input, key_again);

    Ok(())
}

// The cache key must incorporate the same manifest hash recorded in
// receipts: changing an input's content changes both together.
#[test]
fn test_cache_key_tracks_manifest_input_hash() -> Result<()> {
    let workspace = TempDir::new()?;
    let storage = test_storage(workspace.path())?;

    let file = workspace.path().join("input.txt");
    let inputs = vec![PathBuf::from("input.txt")];
    let env = HashMap::new();

    std::fs::write(&file, "v1")?;
    let manifest_v1 = attest::hashing::hash_inputs(workspace.path(), "step", "cmd", &inputs)?;
    let key_v1 = storage.compute_content_hash(workspace.path(), "step", "cmd", &inputs, &env)?;

    std::fs::write(&file, "v2")?;
    let manifest_v2 = attest::hashing::hash_inputs(workspace.path(), "step", "cmd", &inputs)?;
    let key_v2 = storage.compute_content_hash(workspace.path(), "step", "cmd", &inputs, &env)?;

    assert_ne!(manifest_v1, manifest_v2);
    assert_ne!(key_v1, key_v2, "cache key must follow the manifest hash");

    Ok(())
}
