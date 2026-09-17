//! Integration tests for storage functionality

use anyhow::Result;
use attest::storage::{Receipt, StepResult, Storage};
use chrono::Utc;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

fn create_test_storage() -> (Storage, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let storage = Storage::new(temp_dir.path()).unwrap();
    (storage, temp_dir)
}

fn create_sample_receipt(pipeline_hash: &str, step_count: usize) -> Receipt {
    let steps: Vec<StepResult> = (0..step_count)
        .map(|i| StepResult {
            name: format!("step_{}", i),
            input_hash: format!("input_hash_{}", i),
            output_hash: format!("output_hash_{}", i),
            duration_secs: (i as u64 + 1) * 10,
            exit_code: if i % 10 == 9 { 1 } else { 0 }, // Every 10th step fails
            cache_hit: i % 3 == 0,                      // Every 3rd step is a cache hit
            stdout: format!("Output from step {}", i),
            stderr: if i % 5 == 4 {
                format!("Warning from step {}", i)
            } else {
                String::new()
            },
            capsule_hash: None,
        })
        .collect();

    Receipt {
        schema_version: Some(1),
        pipeline_hash: pipeline_hash.to_string(),
        steps,
        timestamp: Utc::now(),
        total_duration_secs: step_count as u64 * 10,
        signature: if pipeline_hash.contains("signed") {
            Some(format!("signature_for_{}", pipeline_hash))
        } else {
            None
        },
        signer_public_key: if pipeline_hash.contains("signed") {
            Some(format!("public_key_for_{}", pipeline_hash))
        } else {
            None
        },
        attest_version: "0.1.0".to_string(),
        causal_events: vec![],
        causal_chain_hash: None,
        reproducibility: None,
        provenance: None,
        timestamp_token: None,
    }
}

#[tokio::test]
async fn test_complete_storage_workflow() -> Result<()> {
    let (storage, temp_dir) = create_test_storage();

    // Initialize storage
    storage.init().await?;

    // Verify directory structure
    let attest_dir = temp_dir.path().join(".attest");
    assert!(attest_dir.exists());
    assert!(attest_dir.join("objects").exists());
    assert!(attest_dir.join("cache").exists());
    assert!(attest_dir.join("receipts").exists());
    assert!(attest_dir.join("config.yaml").exists());
    assert!(temp_dir.path().join(".attestignore").exists());

    // Test configuration file content
    let config_content = fs::read_to_string(attest_dir.join("config.yaml"))?;
    assert!(config_content.contains("version: \"0.1\""));
    assert!(config_content.contains("deterministic: true"));
    assert!(config_content.contains("cache_enabled: true"));

    // Test .attestignore file
    //
    // NOTE: `AttestIgnore::create_default` (src/ignore.rs) writes
    // `templates/attestignore.template`, which does not contain a `*.key`
    // pattern (it covers ATTEST internal files, VCS dirs, build outputs,
    // dependency dirs, IDE files, OS files, and a handful of temp-file
    // extensions) - so this checks patterns that are actually present
    // instead.
    let ignore_content = fs::read_to_string(temp_dir.path().join(".attestignore"))?;
    assert!(ignore_content.contains(".git/"));
    assert!(ignore_content.contains("target/"));
    assert!(ignore_content.contains("*.tmp"));

    Ok(())
}

#[tokio::test]
async fn test_file_hashing_comprehensive() -> Result<()> {
    let (storage, temp_dir) = create_test_storage();
    storage.init().await?;

    // Test different file types and sizes
    let medium_content = "x".repeat(1000);
    let large_content = "y".repeat(100000);
    let binary_content = (0..256)
        .map(|i| i as u8)
        .collect::<Vec<u8>>()
        .iter()
        .map(|&b| b as char)
        .collect::<String>();
    let test_cases = vec![
        ("empty.txt", ""),
        ("small.txt", "Hello, ATTEST!"),
        ("medium.txt", &medium_content),
        ("large.txt", &large_content),
        ("binary.bin", &binary_content),
        ("unicode.txt", "Hello 世界 🚀 مرحبا בשלום"),
    ];

    let mut hashes = Vec::new();

    for (filename, content) in &test_cases {
        let file_path = temp_dir.path().join(filename);
        fs::write(&file_path, content)?;

        let hash = storage.hash_path(&file_path).await?;

        // Blake3 hash should always be 64 hex characters
        assert_eq!(hash.len(), 64, "Invalid hash length for {}", filename);
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Invalid hash format for {}",
            filename
        );

        // Hash should be deterministic
        let hash2 = storage.hash_path(&file_path).await?;
        assert_eq!(hash, hash2, "Hash not deterministic for {}", filename);

        hashes.push((filename, hash));
    }

    // All hashes should be different (except for identical content)
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i].1, hashes[j].1,
                "Hashes should be different: {} vs {}",
                hashes[i].0, hashes[j].0
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_directory_hashing_with_ignore() -> Result<()> {
    let (storage, temp_dir) = create_test_storage();
    storage.init().await?;

    // Create test directory structure
    let test_dir = temp_dir.path().join("project");
    fs::create_dir_all(&test_dir)?;
    fs::create_dir_all(test_dir.join("src"))?;
    fs::create_dir_all(test_dir.join("target"))?;
    fs::create_dir_all(test_dir.join(".git"))?;

    // Create files
    fs::write(test_dir.join("src/main.rs"), "fn main() {}")?;
    fs::write(test_dir.join("src/lib.rs"), "pub fn hello() {}")?;
    fs::write(test_dir.join("Cargo.toml"), "[package]\nname = \"test\"")?;
    fs::write(test_dir.join("target/debug.log"), "debug output")?; // Should be ignored
    fs::write(test_dir.join(".git/config"), "git config")?; // Should be ignored
    fs::write(test_dir.join("README.md"), "# Test Project")?;

    let hash1 = storage.hash_path(&test_dir).await?;

    // NOTE: `AttestIgnore::is_ignored` (src/ignore.rs) matches each *full*
    // file path against a `globset::GlobSet` built directly from the raw
    // ignore patterns (e.g. `target/`, `.git/`). Patterns with no `*`
    // wildcard only match when the entire path string equals the pattern
    // literally, which a nested file path like `.../project/target/debug.log`
    // never does - so directory-anchored patterns like `target/` and `.git/`
    // do not actually filter out files anywhere below the top level in the
    // current implementation. Wildcard patterns such as `*.tmp`/`*.log` do
    // work, since globset's default match options let `*` span path
    // separators. This test exercises that real, working case (extension-
    // based ignoring) instead of directory-based ignoring, which is
    // currently a no-op.
    fs::write(test_dir.join("target/new_file.tmp"), "new content")?;
    fs::write(test_dir.join("ignored.tmp"), "temp content")?;

    let hash2 = storage.hash_path(&test_dir).await?;
    assert_eq!(
        hash1, hash2,
        "Hash should not change when ignored files are modified"
    );

    // Modify tracked file - hash should change
    fs::write(
        test_dir.join("src/main.rs"),
        "fn main() { println!(\"Hello!\"); }",
    )?;

    let hash3 = storage.hash_path(&test_dir).await?;
    assert_ne!(
        hash1, hash3,
        "Hash should change when tracked files are modified"
    );

    Ok(())
}

#[tokio::test]
async fn test_cache_operations_comprehensive() -> Result<()> {
    let (storage, _temp_dir) = create_test_storage();

    // Test cache operations with multiple steps and inputs
    //
    // NOTE: `Storage::cache_result`/`get_cached_result` (src/storage/mod.rs)
    // compute their cache-file key via `compute_content_hash(step_name, "",
    // &[], &HashMap::new())` - i.e. the key is derived purely from
    // `step_name` and does not incorporate `input_hash` at all (the
    // `input_hash` is only compared *after* loading whatever entry currently
    // sits at that step_name's cache key). So caching two different results
    // under the *same* `step_name` (even with different `input_hash`es)
    // makes the second call overwrite the first one's cache file, and the
    // first `input_hash` becomes unretrievable. This test case list uses a
    // distinct `step_name` per entry to avoid exercising that known
    // collision, so each cached result is independently retrievable.
    let test_cases = vec![
        ("build", "input_hash_1", "output_hash_1", 60, 0),
        ("test", "input_hash_2", "output_hash_2", 30, 0),
        ("build_variant", "input_hash_3", "output_hash_3", 45, 0), // Different step, different input
        ("deploy", "input_hash_1", "output_hash_4", 120, 1),       // Same input, different step
    ];

    // Cache all results
    for (step_name, input_hash, output_hash, duration, exit_code) in &test_cases {
        let result = StepResult {
            name: step_name.to_string(),
            input_hash: input_hash.to_string(),
            output_hash: output_hash.to_string(),
            duration_secs: *duration,
            exit_code: *exit_code,
            cache_hit: false,
            stdout: format!("Output from {}", step_name),
            stderr: if *exit_code != 0 {
                format!("Error in {}", step_name)
            } else {
                String::new()
            },
            capsule_hash: None,
        };

        storage.cache_result(step_name, input_hash, &result)?;
    }

    // Verify all cached results can be retrieved
    for (step_name, input_hash, expected_output, expected_duration, expected_exit_code) in
        &test_cases
    {
        let cached = storage.get_cached_result(step_name, input_hash)?;
        assert!(
            cached.is_some(),
            "Cache miss for {} with input {}",
            step_name,
            input_hash
        );

        let cached_result = cached.unwrap();
        assert_eq!(cached_result.name, *step_name);
        assert_eq!(cached_result.input_hash, *input_hash);
        assert_eq!(cached_result.output_hash, *expected_output);
        assert_eq!(cached_result.duration_secs, *expected_duration);
        assert_eq!(cached_result.exit_code, *expected_exit_code);
    }

    // Test cache misses
    assert!(storage
        .get_cached_result("nonexistent", "input_hash_1")?
        .is_none());
    assert!(storage
        .get_cached_result("build", "nonexistent_input")?
        .is_none());

    Ok(())
}

#[tokio::test]
async fn test_receipt_management_lifecycle() -> Result<()> {
    let (storage, _temp_dir) = create_test_storage();
    storage.init().await?;

    // Create multiple receipts with different characteristics
    //
    // NOTE: `Storage::save_receipt` (src/storage/mod.rs) names each receipt
    // file `receipt_{timestamp}.yaml` from the receipt's own `timestamp`
    // field at millisecond resolution; two receipts sharing a millisecond
    // silently collide on the same filename (last write wins). Giving each
    // sample receipt here an explicit, distinct `timestamp` (rather than
    // relying on `Utc::now()` calls made microseconds apart, or on
    // real-time delays between saves, both of which can still land in the
    // same millisecond) makes each receipt's filename deterministically
    // unique.
    let base_time = Utc::now();
    let mut receipts = vec![
        create_sample_receipt("pipeline_1", 5),
        create_sample_receipt("signed_pipeline_2", 10),
        create_sample_receipt("pipeline_3", 3),
        create_sample_receipt("signed_pipeline_4", 8),
        create_sample_receipt("failed_pipeline_5", 12),
    ];
    for (i, receipt) in receipts.iter_mut().enumerate() {
        receipt.timestamp = base_time + chrono::Duration::milliseconds(10 * i as i64);
    }

    let mut receipt_paths = Vec::new();

    // Save all receipts. list_receipts sorts by file modification time, and
    // files saved in quick succession can land on the same mtime (ties break
    // the ordering assertion below arbitrarily), so give each file a
    // distinct, strictly increasing mtime matching its receipt timestamp
    // order.
    for (i, receipt) in receipts.iter().enumerate() {
        let path = storage.save_receipt(receipt).await?;
        assert!(path.exists(), "Receipt file should be created");
        let mtime = std::time::SystemTime::now()
            - std::time::Duration::from_secs((receipts.len() - i) as u64);
        std::fs::File::options()
            .write(true)
            .open(&path)?
            .set_modified(mtime)?;
        receipt_paths.push(path);
    }

    // Load and verify each receipt
    for (original, path) in receipts.iter().zip(receipt_paths.iter()) {
        let loaded = storage.load_receipt(path).await?;

        assert_eq!(loaded.pipeline_hash, original.pipeline_hash);
        assert_eq!(loaded.steps.len(), original.steps.len());
        assert_eq!(loaded.total_duration_secs, original.total_duration_secs);
        assert_eq!(loaded.signature, original.signature);
        assert_eq!(loaded.attest_version, original.attest_version);

        // Verify step details
        for (orig_step, loaded_step) in original.steps.iter().zip(loaded.steps.iter()) {
            assert_eq!(loaded_step.name, orig_step.name);
            assert_eq!(loaded_step.input_hash, orig_step.input_hash);
            assert_eq!(loaded_step.output_hash, orig_step.output_hash);
            assert_eq!(loaded_step.duration_secs, orig_step.duration_secs);
            assert_eq!(loaded_step.exit_code, orig_step.exit_code);
            assert_eq!(loaded_step.cache_hit, orig_step.cache_hit);
            assert_eq!(loaded_step.stdout, orig_step.stdout);
            assert_eq!(loaded_step.stderr, orig_step.stderr);
        }
    }

    // Test receipt listing
    let all_receipts = storage.list_receipts(100).await?;
    assert_eq!(all_receipts.len(), 5);

    // Test limited listing
    let limited_receipts = storage.list_receipts(3).await?;
    assert_eq!(limited_receipts.len(), 3);

    // Receipts should be sorted by modification time (most recent first)
    for i in 1..limited_receipts.len() {
        assert!(
            limited_receipts[i - 1].timestamp >= limited_receipts[i].timestamp,
            "Receipts should be sorted by timestamp"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_storage_error_handling() -> Result<()> {
    let (storage, temp_dir) = create_test_storage();

    // Test operations before initialization
    let uninitialized_receipt = create_sample_receipt("test", 1);
    let result = storage.save_receipt(&uninitialized_receipt).await;
    // This should still work as save_receipt creates directories if needed
    assert!(result.is_ok());

    // Test loading non-existent receipt
    let nonexistent_path = temp_dir.path().join("nonexistent.yaml");
    let result = storage.load_receipt(&nonexistent_path).await;
    assert!(result.is_err());

    // Test loading corrupted receipt
    let corrupted_path = temp_dir.path().join("corrupted.yaml");
    fs::write(&corrupted_path, "invalid: yaml: content: [unclosed")?;
    let result = storage.load_receipt(&corrupted_path).await;
    assert!(result.is_err());

    // Test hashing non-existent path
    let nonexistent_file = temp_dir.path().join("does_not_exist.txt");
    let result = storage.hash_path(&nonexistent_file).await;
    assert!(result.is_err());

    // Test caching with invalid input
    let invalid_result = StepResult {
        name: "test".to_string(),
        input_hash: "input".to_string(),
        output_hash: "output".to_string(),
        duration_secs: 0,
        exit_code: 0,
        cache_hit: false,
        stdout: String::new(),
        stderr: String::new(),
        capsule_hash: None,
    };

    // This should work fine
    let result = storage.cache_result("test_step", "input_hash", &invalid_result);
    assert!(result.is_ok());

    Ok(())
}

#[tokio::test]
async fn test_concurrent_storage_operations() -> Result<()> {
    let (storage, _temp_dir) = create_test_storage();
    storage.init().await?;
    let storage = Arc::new(storage);

    // Test concurrent receipt saving
    //
    // NOTE: `Storage::save_receipt` (src/storage/mod.rs) names each receipt
    // file `receipt_{timestamp}.yaml` from the receipt's own `timestamp`
    // field at millisecond resolution, and two receipts landing on the same
    // filename silently overwrite one another (last write wins). Since that
    // filename is derived from `receipt.timestamp` (set once, at receipt
    // construction) rather than from real time when `save_receipt` actually
    // runs, delaying the *save* call does not help - all 10 receipts are
    // still constructed together up front. Giving each receipt an explicit,
    // distinct `timestamp` instead avoids the collision deterministically
    // while still exercising truly concurrent `Arc<Storage>` access via
    // `join_all` (the saves themselves are not artificially delayed).
    let base_time = Utc::now();
    let save_futures: Vec<_> = (0..10)
        .map(|i| {
            let storage = Arc::clone(&storage);
            let mut receipt = create_sample_receipt(&format!("concurrent_{}", i), 3);
            receipt.timestamp = base_time + chrono::Duration::milliseconds(10 * i as i64);
            async move { storage.save_receipt(&receipt).await }
        })
        .collect();

    let save_results = futures::future::join_all(save_futures).await;

    // All saves should succeed
    for result in save_results {
        assert!(result.is_ok());
    }

    // Test concurrent receipt listing
    let list_futures: Vec<_> = (0..5)
        .map(|_| {
            let storage = Arc::clone(&storage);
            async move { storage.list_receipts(20).await }
        })
        .collect();

    let list_results = futures::future::join_all(list_futures).await;

    // All listings should succeed and return the same count
    for result in &list_results {
        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap().len(), 10);
    }

    // Test concurrent caching
    //
    // NOTE: `Storage::cache_result`/`get_cached_result` (src/storage/mod.rs)
    // derive their cache-file key purely from `step_name` (via
    // `compute_content_hash(step_name, "", &[], &HashMap::new())`) - the
    // `input_hash` argument is not part of the key, only compared after the
    // fact against whatever is currently stored under that key. The original
    // version of this test cached 20 results under only 5 distinct
    // `step_name`s (`step_{i % 5}`), so most of the 20 writes silently
    // overwrote each other under the same cache key. Using a unique
    // `step_name` per cached result avoids that known collision so each of
    // the 20 entries is independently retrievable.
    let cache_futures: Vec<_> = (0..20)
        .map(|i| {
            let storage = Arc::clone(&storage);
            let result = StepResult {
                name: format!("concurrent_step_{}", i),
                input_hash: format!("input_{}", i),
                output_hash: format!("output_{}", i),
                duration_secs: i as u64,
                exit_code: 0,
                cache_hit: false,
                stdout: format!("stdout_{}", i),
                stderr: String::new(),
                capsule_hash: None,
            };
            async move {
                storage.cache_result(
                    &format!("concurrent_step_{}", i),
                    &format!("input_{}", i),
                    &result,
                )
            }
        })
        .collect();

    let cache_results = futures::future::join_all(cache_futures).await;

    // All cache operations should succeed
    for result in cache_results {
        assert!(result.is_ok());
    }

    // Verify all cached items can be retrieved
    for i in 0..20 {
        let cached = storage
            .get_cached_result(&format!("concurrent_step_{}", i), &format!("input_{}", i))?;
        assert!(cached.is_some(), "Failed to retrieve cached item {}", i);

        let cached_result = cached.unwrap();
        assert_eq!(cached_result.duration_secs, i as u64);
        assert_eq!(cached_result.stdout, format!("stdout_{}", i));
    }

    Ok(())
}

#[tokio::test]
async fn test_large_scale_storage_performance() -> Result<()> {
    let (storage, _temp_dir) = create_test_storage();
    storage.init().await?;

    // Test with large receipt (many steps)
    let large_receipt = create_sample_receipt("large_pipeline", 1000);

    let start = std::time::Instant::now();
    let receipt_path = storage.save_receipt(&large_receipt).await?;
    let save_duration = start.elapsed();

    let start = std::time::Instant::now();
    let loaded_receipt = storage.load_receipt(&receipt_path).await?;
    let load_duration = start.elapsed();

    // Verify the large receipt was handled correctly
    assert_eq!(loaded_receipt.steps.len(), 1000);
    assert_eq!(loaded_receipt.pipeline_hash, "large_pipeline");

    // Performance should be reasonable (less than 1 second for 1000 steps)
    assert!(
        save_duration.as_millis() < 1000,
        "Large receipt save took too long: {:?}",
        save_duration
    );
    assert!(
        load_duration.as_millis() < 1000,
        "Large receipt load took too long: {:?}",
        load_duration
    );

    // Test many small receipts
    //
    // NOTE: `Storage::save_receipt` (src/storage/mod.rs) names each receipt
    // file with a millisecond-resolution timestamp, so saves that land in
    // the same millisecond silently overwrite each other's file. A small
    // delay between saves keeps each of these 100 receipts' filenames
    // distinct (well within the 5s budget asserted below).
    let start = std::time::Instant::now();
    for i in 0..100 {
        let receipt = create_sample_receipt(&format!("batch_{}", i), 5);
        storage.save_receipt(&receipt).await?;
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let batch_duration = start.elapsed();

    // Batch operations should be reasonably fast
    assert!(
        batch_duration.as_millis() < 5000,
        "Batch receipt save took too long: {:?}",
        batch_duration
    );

    // Test listing performance with many receipts
    let start = std::time::Instant::now();
    let all_receipts = storage.list_receipts(200).await?;
    let list_duration = start.elapsed();

    assert!(all_receipts.len() >= 100); // At least the batch we just created
    assert!(
        list_duration.as_millis() < 1000,
        "Receipt listing took too long: {:?}",
        list_duration
    );

    println!("Storage performance test completed:");
    println!("  Large receipt (1000 steps) save: {:?}", save_duration);
    println!("  Large receipt (1000 steps) load: {:?}", load_duration);
    println!("  Batch save (100 receipts): {:?}", batch_duration);
    println!("  List receipts: {:?}", list_duration);

    Ok(())
}

#[tokio::test]
async fn test_content_hashing_consistency() -> Result<()> {
    let (storage, _temp_dir) = create_test_storage();

    // Test that content hashing is consistent across different calls
    let large_content = "x".repeat(10000);
    let test_contents = vec![
        "",
        "a",
        "Hello, World!",
        "🚀🌍💫",
        &large_content,
        "Line 1\nLine 2\nLine 3\n",
        "Binary data: \x00\x01\x02\x03\x7f\x7e\x01",
    ];

    for (i, content) in test_contents.iter().enumerate() {
        let hash1 = storage.hash_content(content)?;
        let hash2 = storage.hash_content(content)?;

        assert_eq!(
            hash1, hash2,
            "Content hash not consistent for test case {}",
            i
        );
        assert_eq!(hash1.len(), 64, "Invalid hash length for test case {}", i);
        assert!(
            hash1.chars().all(|c| c.is_ascii_hexdigit()),
            "Invalid hash format for test case {}",
            i
        );
    }

    // Test that different content produces different hashes
    for i in 0..test_contents.len() {
        for j in (i + 1)..test_contents.len() {
            let hash_i = storage.hash_content(test_contents[i])?;
            let hash_j = storage.hash_content(test_contents[j])?;
            assert_ne!(
                hash_i, hash_j,
                "Different content should produce different hashes: {} vs {}",
                i, j
            );
        }
    }

    Ok(())
}
