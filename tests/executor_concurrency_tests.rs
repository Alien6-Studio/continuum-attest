//! Advanced concurrency and performance tests for the executor module
//!
//! This module focuses on stress testing, race conditions, deadlock prevention,
//! and performance characteristics under high load.

use anyhow::Result;
use attest::executor::{Executor, ExecutorConfig};
use attest::pipeline::{Pipeline, Step};
use attest::storage::Storage;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinSet;

#[derive(Debug)]
struct ConcurrencyTestContext {
    #[allow(dead_code)]
    temp_dir: TempDir,
    storage_root: std::path::PathBuf,
    counter: Arc<AtomicUsize>,
    // Directory that step commands actually execute in (via `Step::working_dir`).
    //
    // The executor (`src/executor/mod.rs`) runs every step's shell command with
    // no working directory override when `Step::working_dir` is `None` (it
    // simply inherits the test *process's* current directory), and that
    // process-wide current directory is shared by every concurrently-running
    // `#[tokio::test]` in this binary. Several pipelines built below use
    // filenames that are only unique *within* a single test (e.g.
    // `result_{id}.txt` for `id` in `0..20`), so when two tests that reuse
    // overlapping id ranges (e.g. `test_high_concurrency_execution` and
    // `test_mixed_workload_concurrency`) run concurrently under cargo's
    // default parallel test scheduling, their shell commands collide on the
    // same filenames in the same shared directory - e.g. one test's `rm
    // temp_5.dat` can unlink the file out from under another test's `dd ...
    // of=temp_5.dat && rm temp_5.dat`, making the second `rm` fail with exit
    // code 1. Giving every pipeline created from a given
    // `ConcurrencyTestContext` its own private `work_dir` (one per test,
    // since each test creates its own context) eliminates the collision
    // entirely.
    //
    // ADDITIONALLY: the manifest hashing layer (`src/hashing.rs`) refuses any
    // declared input/output path outside the workspace root, which the
    // executor resolves as the *process's* current directory. A `work_dir`
    // under the system temp directory therefore can no longer be hashed at
    // all ("path is outside the workspace root"). `work_dir` is instead a
    // unique directory under `target/` inside the crate root (= the test
    // process's current directory), which keeps declared paths inside the
    // workspace while preserving per-test isolation. It is cleaned up when
    // `_work_dir_guard` drops.
    work_dir: std::path::PathBuf,
    #[allow(dead_code)]
    work_dir_guard: TempDir,
}

impl ConcurrencyTestContext {
    async fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let storage = Storage::new(temp_dir.path())?;
        storage.init().await?;

        let work_root = std::env::current_dir()?
            .join("target")
            .join("concurrency-tests");
        std::fs::create_dir_all(&work_root)?;
        let work_dir_guard = TempDir::new_in(&work_root)?;
        let work_dir = work_dir_guard.path().to_path_buf();

        let storage_root = temp_dir.path().to_path_buf();
        Ok(Self {
            temp_dir,
            storage_root,
            counter: Arc::new(AtomicUsize::new(0)),
            work_dir,
            work_dir_guard,
        })
    }

    fn create_cpu_intensive_pipeline(id: usize, work_dir: &std::path::Path) -> Pipeline {
        let mut steps = HashMap::new();

        // NOTE: `Step::working_dir` is set below for documentation purposes,
        // but the current non-sandboxed execution path in
        // `Executor::execute_step` (src/executor/mod.rs) never actually
        // applies it to the spawned `sh -c` process (no `.current_dir()`
        // call), so every step still runs in the test process's shared
        // current directory regardless. To keep each concurrently-running
        // pipeline instance's file I/O genuinely isolated (and avoid
        // filename collisions with other tests/pipelines that reuse the same
        // small `id` range and run concurrently in this shared directory),
        // the actual output/temp file paths baked into the shell commands
        // below are absolute paths under `work_dir` rather than relying on
        // `working_dir`.
        let result_file = work_dir.join(format!("result_{}.txt", id));
        let temp_file = work_dir.join(format!("temp_{}.dat", id));

        // CPU intensive computation step
        steps.insert(
            "compute".to_string(),
            Step {
                run: format!(
                    "echo 'Starting computation {}' && \
                 for i in $(seq 1 1000); do echo $i > /dev/null; done && \
                 echo 'Computation {} complete' > {}",
                    id,
                    id,
                    result_file.display()
                ),
                inputs: vec![],
                outputs: vec![result_file.clone()],
                needs: None,
                env: Some({
                    let mut env = HashMap::new();
                    env.insert("PIPELINE_ID".to_string(), id.to_string());
                    env.insert("COMPUTATION_SIZE".to_string(), "1000".to_string());
                    env
                }),
                working_dir: Some(work_dir.to_path_buf()),
                image: None,
                capsule: None,
                cache: true,
                timeout_secs: Some(30),
                attestation: None,
            },
        );

        // Memory intensive step
        steps.insert(
            "memory_test".to_string(),
            Step {
                run: format!(
                    "echo 'Memory test {}' && \
                 dd if=/dev/zero of={} bs=1M count=10 2>/dev/null && \
                 rm {} && \
                 echo 'Memory test {} complete'",
                    id,
                    temp_file.display(),
                    temp_file.display(),
                    id
                ),
                inputs: vec![result_file],
                outputs: vec![],
                needs: Some(vec!["compute".to_string()]),
                env: None,
                working_dir: Some(work_dir.to_path_buf()),
                image: None,
                capsule: None,
                cache: false, // Don't cache memory tests
                timeout_secs: Some(15),
                attestation: None,
            },
        );

        Pipeline {
            schema_version: None,
            version: "0.1".to_string(),
            name: Some(format!("concurrency-test-{}", id)),
            env: HashMap::new(),
            attestation: attest::pipeline::parser::AttestationConfig {
                sign_all_steps: false,
                verify_dependencies: false,
                require_reproducible: false,
            },
            steps,
        }
    }

    fn create_io_intensive_pipeline(id: usize, work_dir: &std::path::Path) -> Pipeline {
        let mut steps = HashMap::new();

        // See the comment in `create_cpu_intensive_pipeline` above: absolute
        // paths under `work_dir` are used to keep concurrently-running
        // pipelines' file I/O isolated, since `Step::working_dir` itself is
        // not applied by the non-sandboxed execution path.
        let io_file = work_dir.join(format!("io_test_{}.txt", id));
        let lines_file = work_dir.join(format!("lines_{}.txt", id));

        // I/O intensive step
        steps.insert(
            "io_test".to_string(),
            Step {
                run: format!(
                    "echo 'I/O test {}' && \
                 for i in $(seq 1 100); do \
                   echo 'Line $i from pipeline {}' >> {}; \
                 done && \
                 cat {} | wc -l > {}",
                    id,
                    id,
                    io_file.display(),
                    io_file.display(),
                    lines_file.display()
                ),
                inputs: vec![],
                outputs: vec![io_file, lines_file],
                needs: None,
                env: Some({
                    let mut env = HashMap::new();
                    env.insert("IO_PIPELINE_ID".to_string(), id.to_string());
                    env
                }),
                working_dir: Some(work_dir.to_path_buf()),
                image: None,
                capsule: None,
                cache: true,
                timeout_secs: Some(20),
                attestation: None,
            },
        );

        Pipeline {
            schema_version: None,
            version: "0.1".to_string(),
            name: Some(format!("io-test-{}", id)),
            env: HashMap::new(),
            attestation: attest::pipeline::parser::AttestationConfig {
                sign_all_steps: false,
                verify_dependencies: false,
                require_reproducible: false,
            },
            steps,
        }
    }
}

// Test high concurrency execution
#[tokio::test]
async fn test_high_concurrency_execution() -> Result<()> {
    let ctx = ConcurrencyTestContext::new().await?;
    let num_concurrent = 20;
    let semaphore = Arc::new(Semaphore::new(10)); // Limit to 10 concurrent operations

    let mut join_set = JoinSet::new();
    let results = Arc::new(RwLock::new(Vec::new()));

    for i in 0..num_concurrent {
        let storage_root = ctx.storage_root.clone();
        let counter = Arc::clone(&ctx.counter);
        let semaphore = Arc::clone(&semaphore);
        let results = Arc::clone(&results);
        let work_dir = ctx.work_dir.clone();

        join_set.spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            let pipeline = ConcurrencyTestContext::create_cpu_intensive_pipeline(i, &work_dir);
            let config = ExecutorConfig {
                max_parallel: 2,
                deterministic: false, // Allow different timestamps
                ..ExecutorConfig::default()
            };

            // A Storage per task, over the same directory. Concurrent
            // executors cannot share one: each writes the causal ledger.
            let mut storage = Storage::new(&storage_root)?;
            let mut executor = Executor::new(&mut storage, config)?;

            let start_time = Instant::now();
            let receipt = executor.run(&pipeline).await?;
            let execution_time = start_time.elapsed();

            counter.fetch_add(1, Ordering::SeqCst);

            results.write().await.push((i, receipt, execution_time));

            Ok::<(), anyhow::Error>(())
        });
    }

    // Wait for all tasks to complete
    while let Some(result) = join_set.join_next().await {
        result??;
    }

    // Verify results
    let results = results.read().await;
    assert_eq!(results.len(), num_concurrent);
    assert_eq!(ctx.counter.load(Ordering::SeqCst), num_concurrent);

    // Check that all executions succeeded
    for (id, receipt, execution_time) in results.iter() {
        assert_eq!(
            receipt.steps.len(),
            2,
            "Pipeline {} should have 2 steps",
            id
        );

        for step in &receipt.steps {
            assert_eq!(
                step.exit_code, 0,
                "Step '{}' in pipeline {} failed: stdout={:?} stderr={:?}",
                step.name, id, step.stdout, step.stderr
            );
        }

        // Execution should be reasonably fast even under high concurrency
        assert!(
            execution_time < &Duration::from_secs(60),
            "Pipeline {} took too long: {:?}",
            id,
            execution_time
        );
    }

    // Calculate performance metrics
    let total_time: Duration = results.iter().map(|(_, _, time)| *time).sum();
    let avg_time = total_time / num_concurrent as u32;

    println!("High concurrency test completed:");
    println!("  Concurrent pipelines: {}", num_concurrent);
    println!("  Average execution time: {:?}", avg_time);
    println!("  Total execution time: {:?}", total_time);

    Ok(())
}

// Test mixed workload concurrency (CPU + I/O intensive)
#[tokio::test]
async fn test_mixed_workload_concurrency() -> Result<()> {
    let ctx = ConcurrencyTestContext::new().await?;
    let num_cpu_intensive = 10;
    let num_io_intensive = 10;

    let mut join_set = JoinSet::new();
    let cpu_results = Arc::new(RwLock::new(Vec::new()));
    let io_results = Arc::new(RwLock::new(Vec::new()));

    // Launch CPU intensive tasks
    for i in 0..num_cpu_intensive {
        let storage_root = ctx.storage_root.clone();
        let results = Arc::clone(&cpu_results);
        let work_dir = ctx.work_dir.clone();

        join_set.spawn(async move {
            let pipeline = ConcurrencyTestContext::create_cpu_intensive_pipeline(i, &work_dir);
            let config = ExecutorConfig {
                max_parallel: 1, // Sequential for CPU intensive
                ..ExecutorConfig::default()
            };

            // A Storage per task, over the same directory. Concurrent
            // executors cannot share one: each writes the causal ledger.
            let mut storage = Storage::new(&storage_root)?;
            let mut executor = Executor::new(&mut storage, config)?;

            let start_time = Instant::now();
            let receipt = executor.run(&pipeline).await?;
            let execution_time = start_time.elapsed();

            results.write().await.push((i, receipt, execution_time));

            Ok::<(), anyhow::Error>(())
        });
    }

    // Launch I/O intensive tasks
    for i in 0..num_io_intensive {
        let storage_root = ctx.storage_root.clone();
        let results = Arc::clone(&io_results);
        let work_dir = ctx.work_dir.clone();

        join_set.spawn(async move {
            let pipeline = ConcurrencyTestContext::create_io_intensive_pipeline(i, &work_dir);
            let config = ExecutorConfig {
                max_parallel: 3, // More parallel for I/O
                ..ExecutorConfig::default()
            };

            // A Storage per task, over the same directory. Concurrent
            // executors cannot share one: each writes the causal ledger.
            let mut storage = Storage::new(&storage_root)?;
            let mut executor = Executor::new(&mut storage, config)?;

            let start_time = Instant::now();
            let receipt = executor.run(&pipeline).await?;
            let execution_time = start_time.elapsed();

            results.write().await.push((i, receipt, execution_time));

            Ok::<(), anyhow::Error>(())
        });
    }

    // Wait for all tasks to complete
    while let Some(result) = join_set.join_next().await {
        result??;
    }

    // Verify results
    let cpu_results = cpu_results.read().await;
    let io_results = io_results.read().await;

    assert_eq!(cpu_results.len(), num_cpu_intensive);
    assert_eq!(io_results.len(), num_io_intensive);

    // All executions should succeed
    for (id, receipt, _) in cpu_results.iter() {
        assert_eq!(receipt.steps.len(), 2, "CPU pipeline {} failed", id);
        for step in &receipt.steps {
            assert_eq!(
                step.exit_code, 0,
                "CPU step '{}' in pipeline {} failed",
                step.name, id
            );
        }
    }

    for (id, receipt, _) in io_results.iter() {
        assert_eq!(receipt.steps.len(), 1, "I/O pipeline {} failed", id);
        for step in &receipt.steps {
            assert_eq!(
                step.exit_code, 0,
                "I/O step '{}' in pipeline {} failed",
                step.name, id
            );
        }
    }

    Ok(())
}

// Test cache contention under high concurrency
#[tokio::test]
async fn test_cache_contention() -> Result<()> {
    let ctx = ConcurrencyTestContext::new().await?;
    let num_concurrent = 15;

    // Create identical pipelines that should hit cache
    let identical_pipeline =
        ConcurrencyTestContext::create_cpu_intensive_pipeline(999, &ctx.work_dir);

    let mut join_set = JoinSet::new();
    let results = Arc::new(RwLock::new(Vec::new()));

    for i in 0..num_concurrent {
        let storage_root = ctx.storage_root.clone();
        let pipeline = identical_pipeline.clone();
        let results = Arc::clone(&results);

        join_set.spawn(async move {
            let config = ExecutorConfig {
                deterministic: true, // Same inputs should produce same hashes
                ..ExecutorConfig::default()
            };

            // A Storage per task, over the same directory. Concurrent
            // executors cannot share one: each writes the causal ledger.
            let mut storage = Storage::new(&storage_root)?;
            let mut executor = Executor::new(&mut storage, config)?;

            let start_time = Instant::now();
            let receipt = executor.run(&pipeline).await?;
            let execution_time = start_time.elapsed();

            results.write().await.push((i, receipt, execution_time));

            Ok::<(), anyhow::Error>(())
        });
    }

    // Wait for all tasks to complete
    while let Some(result) = join_set.join_next().await {
        result??;
    }

    let results = results.read().await;
    assert_eq!(results.len(), num_concurrent);

    // Count cache hits - most should be cache hits after the first execution
    let mut cache_hits = 0;
    let mut cache_misses = 0;

    for (id, receipt, execution_time) in results.iter() {
        assert_eq!(
            receipt.steps.len(),
            2,
            "Pipeline {} should have 2 steps",
            id
        );

        for step in &receipt.steps {
            assert_eq!(
                step.exit_code, 0,
                "Step '{}' in pipeline {} failed",
                step.name, id
            );

            if step.cache_hit {
                cache_hits += 1;
            } else {
                cache_misses += 1;
            }
        }

        // Cache hits should be much faster
        if receipt.steps.iter().all(|s| s.cache_hit) {
            assert!(
                execution_time < &Duration::from_millis(500),
                "Cached execution {} should be fast: {:?}",
                id,
                execution_time
            );
        }
    }

    println!("Cache contention test completed:");
    println!("  Total cache hits: {}", cache_hits);
    println!("  Total cache misses: {}", cache_misses);
    println!(
        "  Cache hit ratio: {:.2}%",
        (cache_hits as f64 / (cache_hits + cache_misses) as f64) * 100.0
    );

    // We should have some cache hits (though exact number depends on timing)
    assert!(
        cache_hits > 0,
        "Should have some cache hits with identical pipelines"
    );

    Ok(())
}

// Test resource exhaustion and recovery
#[tokio::test]
async fn test_resource_exhaustion_recovery() -> Result<()> {
    let ctx = ConcurrencyTestContext::new().await?;

    // Create a pipeline that uses significant resources. The command must
    // actually create its declared output: the executor now verifies declared
    // outputs exist after the step runs (MissingOutput otherwise).
    let heavy_output = ctx.work_dir.join("heavy_output.txt");
    let resource_heavy_pipeline = Pipeline {
        schema_version: None,
        version: "0.1".to_string(),
        name: Some("resource-heavy".to_string()),
        env: HashMap::new(),
        attestation: attest::pipeline::parser::AttestationConfig::default(),
        steps: {
            let mut steps = HashMap::new();
            steps.insert(
                "heavy_step".to_string(),
                Step {
                    run: format!(
                        "echo 'Heavy computation' && sleep 0.5 && echo 'Complete' > {}",
                        heavy_output.display()
                    ),
                    inputs: vec![],
                    outputs: vec![heavy_output.clone()],
                    needs: None,
                    env: None,
                    working_dir: None,
                    image: None,
                    capsule: None,
                    cache: false,
                    timeout_secs: Some(10),
                    attestation: None,
                },
            );
            steps
        },
    };

    // Launch many concurrent executions to stress the system
    let num_concurrent = 30;
    let mut join_set = JoinSet::new();
    let results = Arc::new(RwLock::new(Vec::new()));

    for i in 0..num_concurrent {
        let storage_root = ctx.storage_root.clone();
        let pipeline = resource_heavy_pipeline.clone();
        let results = Arc::clone(&results);

        join_set.spawn(async move {
            let config = ExecutorConfig {
                max_parallel: 1,
                ..ExecutorConfig::default()
            };

            let execution_result = async {
                // A Storage per task, over the same directory. Concurrent
                // executors cannot share one: each writes the causal ledger.
                let mut storage = Storage::new(&storage_root)?;
                let mut executor = Executor::new(&mut storage, config)?;
                let receipt = executor.run(&pipeline).await?;
                Ok::<_, anyhow::Error>(receipt)
            }
            .await;

            results.write().await.push((i, execution_result));

            Ok::<(), anyhow::Error>(())
        });
    }

    // Wait for all tasks to complete
    while let Some(result) = join_set.join_next().await {
        result??;
    }

    let results = results.read().await;
    assert_eq!(results.len(), num_concurrent);

    // Count successes and failures
    let mut successes = 0;
    let mut failures = 0;

    for (id, execution_result) in results.iter() {
        match execution_result {
            Ok(receipt) => {
                successes += 1;
                assert_eq!(receipt.steps.len(), 1, "Pipeline {} should have 1 step", id);

                for step in &receipt.steps {
                    assert_eq!(
                        step.exit_code, 0,
                        "Step '{}' in pipeline {} failed",
                        step.name, id
                    );
                }
            }
            Err(e) => {
                failures += 1;
                println!("Pipeline {} failed (expected under stress): {}", id, e);
            }
        }
    }

    println!("Resource exhaustion test completed:");
    println!("  Successful executions: {}", successes);
    println!("  Failed executions: {}", failures);
    println!(
        "  Success rate: {:.2}%",
        (successes as f64 / num_concurrent as f64) * 100.0
    );

    // We expect most executions to succeed even under stress
    assert!(
        successes > num_concurrent / 2,
        "Too many failures under resource stress"
    );

    Ok(())
}

// Test deadlock prevention in complex dependency graphs
#[tokio::test]
async fn test_deadlock_prevention() -> Result<()> {
    let ctx = ConcurrencyTestContext::new().await?;

    // Create a complex dependency graph that could potentially deadlock.
    // Absolute paths under `work_dir` are used both in the commands and in
    // the declared inputs/outputs because `Step::working_dir` is not applied
    // by the non-sandboxed execution path — relative paths would read/write
    // the crate root itself.
    let root_file = ctx.work_dir.join("root.txt");
    let left_file = ctx.work_dir.join("left.txt");
    let right_file = ctx.work_dir.join("right.txt");
    let merged_file = ctx.work_dir.join("merged.txt");
    let complex_pipeline = Pipeline {
        schema_version: None,
        version: "0.1".to_string(),
        name: Some("complex-dependencies".to_string()),
        env: HashMap::new(),
        attestation: attest::pipeline::parser::AttestationConfig::default(),
        steps: {
            let mut steps = HashMap::new();

            // Create a diamond dependency pattern
            steps.insert(
                "root".to_string(),
                Step {
                    run: format!("echo 'Root' > {}", root_file.display()),
                    inputs: vec![],
                    outputs: vec![root_file.clone()],
                    needs: None,
                    env: None,
                    working_dir: Some(ctx.work_dir.clone()),
                    image: None,
                    capsule: None,
                    cache: true,
                    timeout_secs: Some(5),
                    attestation: None,
                },
            );

            steps.insert(
                "left".to_string(),
                Step {
                    run: format!("echo 'Left branch' > {}", left_file.display()),
                    inputs: vec![root_file.clone()],
                    outputs: vec![left_file.clone()],
                    needs: Some(vec!["root".to_string()]),
                    env: None,
                    working_dir: Some(ctx.work_dir.clone()),
                    image: None,
                    capsule: None,
                    cache: true,
                    timeout_secs: Some(5),
                    attestation: None,
                },
            );

            steps.insert(
                "right".to_string(),
                Step {
                    run: format!("echo 'Right branch' > {}", right_file.display()),
                    inputs: vec![root_file.clone()],
                    outputs: vec![right_file.clone()],
                    needs: Some(vec!["root".to_string()]),
                    env: None,
                    working_dir: Some(ctx.work_dir.clone()),
                    image: None,
                    capsule: None,
                    cache: true,
                    timeout_secs: Some(5),
                    attestation: None,
                },
            );

            steps.insert(
                "merge".to_string(),
                Step {
                    run: format!(
                        "cat {} {} > {}",
                        left_file.display(),
                        right_file.display(),
                        merged_file.display()
                    ),
                    inputs: vec![left_file.clone(), right_file.clone()],
                    outputs: vec![merged_file.clone()],
                    needs: Some(vec!["left".to_string(), "right".to_string()]),
                    env: None,
                    working_dir: Some(ctx.work_dir.clone()),
                    image: None,
                    capsule: None,
                    cache: true,
                    timeout_secs: Some(5),
                    attestation: None,
                },
            );

            steps
        },
    };

    // Execute multiple instances concurrently to test for deadlocks
    let num_concurrent = 10;
    let mut join_set = JoinSet::new();
    let results = Arc::new(RwLock::new(Vec::new()));

    for i in 0..num_concurrent {
        let storage_root = ctx.storage_root.clone();
        let pipeline = complex_pipeline.clone();
        let results = Arc::clone(&results);

        join_set.spawn(async move {
            let config = ExecutorConfig {
                max_parallel: 4, // Allow parallel execution
                deterministic: false, // Different timestamps to avoid cache conflicts
                ..ExecutorConfig::default()
            };

            // A Storage per task, over the same directory. Concurrent
            // executors cannot share one: each writes the causal ledger.
            let mut storage = Storage::new(&storage_root)?;
            let mut executor = Executor::new(&mut storage, config)?;

            // Set a timeout for the entire execution to detect deadlocks
            let execution_future = executor.run(&pipeline);
            let timeout_future = tokio::time::sleep(Duration::from_secs(30));

            let result = tokio::select! {
                result = execution_future => Ok(result?),
                _ = timeout_future => Err(anyhow::anyhow!("Execution timed out - possible deadlock")),
            };

            results.write().await.push((i, result));

            Ok::<(), anyhow::Error>(())
        });
    }

    // Wait for all tasks to complete
    while let Some(result) = join_set.join_next().await {
        result??;
    }

    let results = results.read().await;
    assert_eq!(results.len(), num_concurrent);

    // All executions should complete without deadlock
    for (id, result) in results.iter() {
        match result {
            Ok(receipt) => {
                assert_eq!(
                    receipt.steps.len(),
                    4,
                    "Pipeline {} should have 4 steps",
                    id
                );

                // Verify correct execution order was maintained
                let step_names: Vec<&str> = receipt.steps.iter().map(|s| s.name.as_str()).collect();
                let root_idx = step_names.iter().position(|&s| s == "root").unwrap();
                let left_idx = step_names.iter().position(|&s| s == "left").unwrap();
                let right_idx = step_names.iter().position(|&s| s == "right").unwrap();
                let merge_idx = step_names.iter().position(|&s| s == "merge").unwrap();

                // Root should come before left and right
                assert!(
                    root_idx < left_idx && root_idx < right_idx,
                    "Pipeline {}: Root step should execute before branches",
                    id
                );

                // Merge should come after both left and right
                assert!(
                    left_idx < merge_idx && right_idx < merge_idx,
                    "Pipeline {}: Merge step should execute after both branches",
                    id
                );

                for step in &receipt.steps {
                    assert_eq!(
                        step.exit_code, 0,
                        "Step '{}' in pipeline {} failed",
                        step.name, id
                    );
                }
            }
            Err(e) => {
                panic!("Pipeline {} failed - possible deadlock: {}", id, e);
            }
        }
    }

    println!("Deadlock prevention test completed successfully");
    println!(
        "  All {} concurrent complex pipelines executed without deadlock",
        num_concurrent
    );

    Ok(())
}

// Test performance under memory pressure
#[tokio::test]
async fn test_performance_under_memory_pressure() -> Result<()> {
    let ctx = ConcurrencyTestContext::new().await?;

    // Create pipelines that use varying amounts of memory
    let memory_sizes = vec![10, 50, 100]; // MB
    let num_pipelines_per_size = 5;

    let mut join_set = JoinSet::new();
    let results = Arc::new(RwLock::new(Vec::new()));

    for &memory_mb in &memory_sizes {
        for i in 0..num_pipelines_per_size {
            let storage_root = ctx.storage_root.clone();
            let results = Arc::clone(&results);
            let pipeline_id = format!("mem_{}_{}", memory_mb, i);
            let work_dir = ctx.work_dir.clone();

            join_set.spawn(async move {
                let temp_mem_file = work_dir.join(format!("temp_mem_{}.dat", pipeline_id));
                let pipeline = Pipeline {
                    schema_version: None,
                    version: "0.1".to_string(),
                    name: Some(pipeline_id.clone()),
                    env: HashMap::new(),
                    attestation: attest::pipeline::parser::AttestationConfig::default(),
                    steps: {
                        let mut steps = HashMap::new();
                        steps.insert(
                            "memory_step".to_string(),
                            Step {
                                run: format!(
                                    "echo 'Allocating {}MB' && \
                                 dd if=/dev/zero of={} bs=1M count={} 2>/dev/null && \
                                 ls -lh {} && \
                                 rm {} && \
                                 echo 'Memory test complete'",
                                    memory_mb,
                                    temp_mem_file.display(),
                                    memory_mb,
                                    temp_mem_file.display(),
                                    temp_mem_file.display()
                                ),
                                inputs: vec![],
                                outputs: vec![],
                                needs: None,
                                env: Some({
                                    let mut env = HashMap::new();
                                    env.insert("MEMORY_SIZE_MB".to_string(), memory_mb.to_string());
                                    env
                                }),
                                working_dir: Some(work_dir.clone()),
                                image: None,
                                capsule: None,
                                cache: false,
                                timeout_secs: Some(30),
                                attestation: None,
                            },
                        );
                        steps
                    },
                };

                let config = ExecutorConfig::default();
                // A Storage per task, over the same directory. Concurrent
                // executors cannot share one: each writes the causal ledger.
                let mut storage = Storage::new(&storage_root)?;
                let mut executor = Executor::new(&mut storage, config)?;

                let start_time = Instant::now();
                let receipt = executor.run(&pipeline).await?;
                let execution_time = start_time.elapsed();

                results
                    .write()
                    .await
                    .push((memory_mb, pipeline_id, receipt, execution_time));

                Ok::<(), anyhow::Error>(())
            });
        }
    }

    // Wait for all tasks to complete
    while let Some(result) = join_set.join_next().await {
        result??;
    }

    let results = results.read().await;
    assert_eq!(results.len(), memory_sizes.len() * num_pipelines_per_size);

    // Analyze performance by memory size
    let mut performance_by_size: HashMap<i32, Vec<Duration>> = HashMap::new();

    for (memory_mb, pipeline_id, receipt, execution_time) in results.iter() {
        assert_eq!(
            receipt.steps.len(),
            1,
            "Pipeline {} should have 1 step",
            pipeline_id
        );

        for step in &receipt.steps {
            assert_eq!(
                step.exit_code, 0,
                "Memory step in pipeline {} failed",
                pipeline_id
            );
        }

        performance_by_size
            .entry(*memory_mb)
            .or_insert_with(Vec::new)
            .push(*execution_time);
    }

    // Print performance analysis
    println!("Performance under memory pressure:");
    for &memory_mb in &memory_sizes {
        let times = performance_by_size.get(&memory_mb).unwrap();
        let avg_time = times.iter().sum::<Duration>() / times.len() as u32;
        let max_time = *times.iter().max().unwrap();
        let min_time = *times.iter().min().unwrap();

        println!("  {}MB allocation:", memory_mb);
        println!("    Average time: {:?}", avg_time);
        println!("    Min time: {:?}", min_time);
        println!("    Max time: {:?}", max_time);

        // Performance should degrade gracefully with memory usage
        assert!(
            max_time < Duration::from_secs(45),
            "{}MB allocation took too long: {:?}",
            memory_mb,
            max_time
        );
    }

    Ok(())
}
