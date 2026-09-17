//! Regression tests for collision-free receipt filenames.

use anyhow::Result;
use attest::storage::{Receipt, Storage};
use std::collections::HashSet;
use tempfile::TempDir;

fn make_receipt(discriminator: u64) -> Receipt {
    Receipt {
        schema_version: Some(1),
        pipeline_hash: format!("hash-{discriminator}"),
        steps: vec![],
        timestamp: chrono::Utc::now(),
        total_duration_secs: discriminator,
        signature: None,
        signer_public_key: None,
        attest_version: "0.1.0".to_string(),
        causal_events: vec![],
        causal_chain_hash: None,
        reproducibility: None,
        provenance: None,
        timestamp_token: None,
    }
}

// Many receipts saved in a tight loop (well inside one timestamp tick) must
// all land in distinct files, with no silent overwrite.
#[tokio::test]
async fn test_save_receipt_never_collides() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let storage = Storage::new(temp_dir.path())?;
    storage.init().await?;

    let mut paths = HashSet::new();
    for i in 0..100 {
        let path = storage.save_receipt(&make_receipt(i)).await?;
        assert!(
            paths.insert(path.clone()),
            "duplicate receipt path: {}",
            path.display()
        );
        assert!(path.is_file());
    }

    let on_disk = std::fs::read_dir(temp_dir.path().join(".attest").join("receipts"))?
        .filter_map(|e| e.ok())
        .count();
    assert_eq!(on_disk, 100, "every save must produce its own file");
    Ok(())
}

// Byte-identical receipts (same content hash, same timestamp) must still get
// distinct files via the numeric discriminator instead of overwriting.
#[tokio::test]
async fn test_identical_receipts_get_distinct_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let storage = Storage::new(temp_dir.path())?;
    storage.init().await?;

    let receipt = make_receipt(0);
    let first = storage.save_receipt(&receipt).await?;
    let second = storage.save_receipt(&receipt).await?;

    assert_ne!(first, second);
    assert!(first.is_file() && second.is_file());
    assert_eq!(
        std::fs::read_to_string(&first)?,
        std::fs::read_to_string(&second)?
    );
    Ok(())
}
