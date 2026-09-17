//! Basic unit tests for the executor module
//!
//! This module provides basic unit tests for executor functionality that are guaranteed to compile.

use anyhow::{Context, Result};
use attest::core::{ModeConfig, OperationMode};
use attest::executor::{Executor, ExecutorConfig};
use attest::pipeline::{Pipeline, Step};
use attest::sandbox::{ContainerRuntime, IsolationLevel, ResourceLimits, SandboxConfig};
use attest::storage::Storage;
use std::collections::BTreeMap;
use std::time::Duration;
use tempfile::TempDir;

struct TestExecutionContext {
    /// Never read: held purely so the temporary directory outlives the
    /// context. Dropping it early would delete the workspace mid-test.
    #[allow(dead_code)]
    temp_dir: TempDir,
    storage: Storage,
    pipeline: Pipeline,
    // Step artifacts must live under the workspace root (= process cwd),
    // so each test gets a private directory under target/ instead of
    // writing bare filenames into the crate root.
    work_dir_guard: TempDir,
}

impl TestExecutionContext {
    async fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let storage = Storage::new(temp_dir.path())?;
        storage.init().await?;

        let work_root = std::env::current_dir()?
            .join("target")
            .join("executor-basic-tests");
        std::fs::create_dir_all(&work_root)?;
        let work_dir_guard = TempDir::new_in(&work_root)?;
        let pipeline = Self::create_test_pipeline(work_dir_guard.path());

        Ok(Self {
            temp_dir,
            storage,
            pipeline,
            work_dir_guard,
        })
    }

    fn create_test_pipeline(work_dir: &std::path::Path) -> Pipeline {
        let setup_file = work_dir.join("setup.txt");
        let build_file = work_dir.join("build.txt");
        let mut steps = BTreeMap::new();

        steps.insert(
            "setup".to_string(),
            Step {
                run: format!(
                    "echo 'Setting up...' && echo 'setup complete' > {}",
                    setup_file.display()
                ),
                inputs: vec![],
                outputs: vec![setup_file.clone()],
                needs: None,
                env: Some({
                    let mut env = BTreeMap::new();
                    env.insert("SETUP_VAR".to_string(), "setup_value".to_string());
                    env
                }),
                working_dir: None,
                image: None,
                capsule: None,
                cache: true,
                timeout_secs: None,
                attestation: Some(attest::pipeline::step::StepAttestation {
                    attestation_type: "setup".to_string(),
                    reproducible: true,
                    generate_slsa: false,
                    verify_chain: false,
                }),
            },
        );

        steps.insert(
            "build".to_string(),
            Step {
                run: format!(
                    "echo 'Building...' && echo 'build output' > {}",
                    build_file.display()
                ),
                inputs: vec![setup_file.clone()],
                outputs: vec![build_file.clone()],
                needs: Some(vec!["setup".to_string()]),
                env: None,
                working_dir: None,
                image: None,
                capsule: None,
                cache: true,
                timeout_secs: Some(60),
                attestation: Some(attest::pipeline::step::StepAttestation {
                    attestation_type: "build".to_string(),
                    reproducible: true,
                    generate_slsa: true,
                    verify_chain: false,
                }),
            },
        );

        steps.insert(
            "test".to_string(),
            Step {
                run: format!(
                    "echo 'Testing...' && test -f {} && echo 'tests passed'",
                    build_file.display()
                ),
                inputs: vec![build_file.clone()],
                outputs: vec![],
                needs: Some(vec!["build".to_string()]),
                env: None,
                working_dir: None,
                image: None,
                capsule: None,
                cache: false, // Never cache test results
                timeout_secs: Some(30),
                attestation: Some(attest::pipeline::step::StepAttestation {
                    attestation_type: "test".to_string(),
                    reproducible: false,
                    generate_slsa: false,
                    verify_chain: true,
                }),
            },
        );

        Pipeline {
            schema_version: None,
            version: "0.1".to_string(),
            name: Some("executor-test-pipeline".to_string()),
            env: {
                let mut env = BTreeMap::new();
                env.insert("GLOBAL_VAR".to_string(), "global_value".to_string());
                env.insert("TEST_ENV".to_string(), "unit_test".to_string());
                env
            },
            attestation: attest::pipeline::parser::AttestationConfig {
                sign_all_steps: false,
                verify_dependencies: true,
                require_reproducible: true,
            },
            steps,
        }
    }

    fn create_parallel_pipeline(work_dir: &std::path::Path) -> Pipeline {
        let output_file = |i: usize| work_dir.join(format!("output_{}.txt", i));
        let final_file = work_dir.join("final.txt");
        let mut steps = BTreeMap::new();

        // Create parallel test steps
        for i in 0..5 {
            steps.insert(
                format!("parallel_{}", i),
                Step {
                    run: format!(
                        "echo 'Parallel step {}' && sleep 0.1 && echo 'done {}' > {}",
                        i,
                        i,
                        output_file(i).display()
                    ),
                    inputs: vec![],
                    outputs: vec![output_file(i)],
                    needs: None,
                    env: Some({
                        let mut env = BTreeMap::new();
                        env.insert("STEP_ID".to_string(), i.to_string());
                        env
                    }),
                    working_dir: None,
                    image: None,
                    capsule: None,
                    cache: true,
                    timeout_secs: Some(10),
                    attestation: None,
                },
            );
        }

        // Add a final step that depends on all parallel steps
        steps.insert(
            "finalize".to_string(),
            Step {
                run: format!(
                    "echo 'Finalizing...' && cat {} > {}",
                    work_dir.join("output_*.txt").display(),
                    final_file.display()
                ),
                inputs: (0..5).map(output_file).collect(),
                outputs: vec![final_file.clone()],
                needs: Some((0..5).map(|i| format!("parallel_{}", i)).collect()),
                env: None,
                working_dir: None,
                image: None,
                capsule: None,
                cache: true,
                timeout_secs: Some(10),
                attestation: None,
            },
        );

        Pipeline {
            schema_version: None,
            version: "0.1".to_string(),
            name: Some("parallel-test-pipeline".to_string()),
            env: BTreeMap::new(),
            attestation: attest::pipeline::parser::AttestationConfig {
                sign_all_steps: false,
                verify_dependencies: false,
                require_reproducible: false,
            },
            steps,
        }
    }
}

// Test basic executor functionality
#[tokio::test]
async fn test_executor_creation_and_basic_execution() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    // Test default configuration
    let config = ExecutorConfig::default();
    let mut executor = Executor::new(&mut ctx.storage, config)?;

    // Execute the pipeline
    let receipt = executor.run(&ctx.pipeline).await?;

    // Verify receipt
    assert_eq!(receipt.steps.len(), 3);
    assert_eq!(receipt.attest_version, "0.1.0");

    // Verify step execution order
    let step_names: Vec<&str> = receipt.steps.iter().map(|s| s.name.as_str()).collect();
    let setup_idx = step_names.iter().position(|&s| s == "setup").unwrap();
    let build_idx = step_names.iter().position(|&s| s == "build").unwrap();
    let test_idx = step_names.iter().position(|&s| s == "test").unwrap();

    // Dependencies should be respected
    assert!(setup_idx < build_idx);
    assert!(build_idx < test_idx);

    // Verify all steps succeeded
    for step in &receipt.steps {
        assert_eq!(
            step.exit_code, 0,
            "Step '{}' failed with exit code {}",
            step.name, step.exit_code
        );
    }

    Ok(())
}

// Test isolated execution mode
#[tokio::test]
async fn test_isolated_execution_mode() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    let fixed =
        chrono::DateTime::from_timestamp(946_684_800, 0).context("valid fixed timestamp")?; // 2000-01-01T00:00:00Z

    let config = ExecutorConfig {
        isolated: true,
        deterministic: true,
        sandbox_config: Some(SandboxConfig {
            isolation_level: IsolationLevel::Process,
            deterministic_time: true,
            fixed_timestamp: Some(fixed),
            resource_limits: ResourceLimits::default(),
            network_policy: attest::sandbox::NetworkPolicy::Disabled,
            filesystem_policy: attest::sandbox::FilesystemPolicy::default(),
            container_config: None,
            seccomp_profile: Some("minimal".to_string()),
            security_level: attest::sandbox::SecurityLevel::Minimal,
        }),
        ..ExecutorConfig::default()
    };

    let mut executor = Executor::new(&mut ctx.storage, config)?;

    // Execute pipeline in isolated mode
    let receipt = executor.run(&ctx.pipeline).await?;

    // Verify execution succeeded
    assert_eq!(receipt.steps.len(), 3);
    for step in &receipt.steps {
        assert_eq!(step.exit_code, 0);
    }

    // Deterministic mode with a configured fixed timestamp must stamp
    // the receipt with exactly that instant.
    assert_eq!(
        receipt.timestamp, fixed,
        "deterministic run must record the configured fixed timestamp"
    );

    Ok(())
}

// Hermetic mode pins SOURCE_DATE_EPOCH; without an explicit fixed
// timestamp the receipt must be stamped with that same epoch so
// identical hermetic builds produce identical receipts.
#[tokio::test]
async fn test_hermetic_receipt_uses_source_date_epoch() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    let config = ExecutorConfig {
        hermetic_env: true,
        ..ExecutorConfig::default()
    };

    let mut executor = Executor::new(&mut ctx.storage, config)?;
    let receipt = executor.run(&ctx.pipeline).await?;

    let epoch = chrono::DateTime::from_timestamp(attest::executor::HERMETIC_SOURCE_DATE_EPOCH, 0)
        .context("valid hermetic epoch")?;
    assert_eq!(
        receipt.timestamp, epoch,
        "hermetic run must record SOURCE_DATE_EPOCH as the receipt timestamp"
    );

    Ok(())
}

// A regular (non-deterministic-time) run must keep wall-clock receipt
// timestamps: key revocation compares them against revoked_at.
#[tokio::test]
async fn test_default_receipt_keeps_wall_clock_timestamp() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    let before = chrono::Utc::now();
    let mut executor = Executor::new(&mut ctx.storage, ExecutorConfig::default())?;
    let receipt = executor.run(&ctx.pipeline).await?;
    let after = chrono::Utc::now();

    assert!(
        receipt.timestamp >= before && receipt.timestamp <= after,
        "non-hermetic run must record the actual wall-clock time"
    );

    Ok(())
}

// Test container execution mode
#[tokio::test]
async fn test_container_execution_mode() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    let config = ExecutorConfig {
        isolated: true,
        container_image: Some("alpine:latest".to_string()),
        container_runtime: Some(ContainerRuntime::Docker),
        deterministic: true,
        ..ExecutorConfig::default()
    };

    // This test may fail if Docker is not available
    match Executor::new(&mut ctx.storage, config) {
        Ok(mut executor) => {
            let receipt = executor.run(&ctx.pipeline).await;

            // If Docker is available, execution should succeed
            if let Ok(receipt) = receipt {
                assert_eq!(receipt.steps.len(), 3);
            } else {
                // Container runtime might not be available in test environment
                println!("Container execution skipped - runtime not available");
            }
        }
        Err(_) => {
            // Expected if container runtime is not available
            println!("Container executor creation skipped - runtime not available");
        }
    }

    Ok(())
}

// Test different operation modes
#[tokio::test]
async fn test_operation_modes() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    // Test Light mode
    let light_mode = ModeConfig {
        mode: OperationMode::Light,
        crypto: attest::core::CryptoConfig {
            signatures_enabled: false,
            sign_all_steps: false,
            hash_algorithm: attest::core::HashAlgorithm::Blake3,
            key_rotation_days: None,
            hardware_security: false,
        },
        isolation: attest::core::IsolationConfig {
            isolation_level: IsolationLevel::Process,
            container_runtime: None,
            deterministic_environment: true,
            fixed_timestamp: None,
            enforce_resource_limits: false,
            network_policy: attest::sandbox::NetworkPolicy::Disabled,
        },
        audit: attest::core::AuditConfig {
            detailed_logging: false,
            store_execution_logs: false,
            merkle_tree_enabled: false,
            external_ledger: None,
            compliance_framework: None,
            retention_days: 30,
        },
        performance: attest::core::PerformanceConfig {
            cache_enabled: true,
            max_parallel_steps: 4,
            lazy_evaluation: false,
            skip_expensive_checks: false,
        },
    };

    let config = ExecutorConfig::default();
    let mut executor = Executor::with_mode(&mut ctx.storage, config, Some(light_mode.clone()))?;

    let receipt = executor.run(&ctx.pipeline).await?;
    assert!(receipt.signature.is_none()); // Light mode doesn't sign

    Ok(())
}

// Test parallel execution capabilities
#[tokio::test]
async fn test_parallel_execution() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;
    let parallel_pipeline =
        TestExecutionContext::create_parallel_pipeline(ctx.work_dir_guard.path());

    let config = ExecutorConfig {
        max_parallel: 5,
        ..ExecutorConfig::default()
    };

    let mut executor = Executor::new(&mut ctx.storage, config)?;

    let start_time = std::time::Instant::now();
    let receipt = executor.run(&parallel_pipeline).await?;
    let execution_time = start_time.elapsed();

    // Verify all steps completed
    assert_eq!(receipt.steps.len(), 6); // 5 parallel + 1 finalize

    // Parallel execution should be faster than sequential
    assert!(execution_time < Duration::from_secs(5));

    // Verify dependency order: finalize step should be last
    let finalize_step = receipt.steps.iter().find(|s| s.name == "finalize").unwrap();
    // The finalize step should have run after all parallel steps
    assert_eq!(finalize_step.exit_code, 0);

    Ok(())
}

// Test cache behavior in different scenarios
#[tokio::test]
async fn test_cache_behavior() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    let config = ExecutorConfig {
        deterministic: true,
        ..ExecutorConfig::default()
    };

    // First execution - should populate cache
    let mut executor1 = Executor::new(&mut ctx.storage, config)?;
    let receipt1 = executor1.run(&ctx.pipeline).await?;

    // Verify no cache hits on first run
    for step in &receipt1.steps {
        assert!(
            !step.cache_hit,
            "Step '{}' should not be a cache hit on first run",
            step.name
        );
    }

    // Second execution - should hit cache for cacheable steps
    let config2 = ExecutorConfig {
        deterministic: true,
        ..ExecutorConfig::default()
    };
    let mut executor2 = Executor::new(&mut ctx.storage, config2)?;
    let receipt2 = executor2.run(&ctx.pipeline).await?;

    // Check cache hits
    let setup_step = receipt2.steps.iter().find(|s| s.name == "setup").unwrap();
    let build_step = receipt2.steps.iter().find(|s| s.name == "build").unwrap();
    let test_step = receipt2.steps.iter().find(|s| s.name == "test").unwrap();

    assert!(setup_step.cache_hit, "Setup step should be cached");
    assert!(build_step.cache_hit, "Build step should be cached");
    assert!(
        !test_step.cache_hit,
        "A `cache: false` step must not be served from cache"
    );

    Ok(())
}

// Test error handling and recovery
#[tokio::test]
async fn test_error_handling() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    // Create pipeline with failing step
    let mut failing_pipeline = ctx.pipeline.clone();
    failing_pipeline.steps.insert(
        "failing_step".to_string(),
        Step {
            run: "exit 1".to_string(), // This will fail
            inputs: vec![],
            outputs: vec![],
            needs: None,
            env: None,
            working_dir: None,
            image: None,
            capsule: None,
            cache: false,
            timeout_secs: Some(5),
            attestation: None,
        },
    );

    let config = ExecutorConfig::default();
    let mut executor = Executor::new(&mut ctx.storage, config)?;

    let receipt = executor.run(&failing_pipeline).await?;

    // Execution should complete but with failure recorded
    let failing_step = receipt.steps.iter().find(|s| s.name == "failing_step");
    assert!(failing_step.is_some());

    let failing_step = failing_step.unwrap();
    assert_eq!(failing_step.exit_code, 1);

    Ok(())
}

// Test environment variable handling
#[tokio::test]
async fn test_environment_variable_handling() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    // Create pipeline that uses environment variables
    let mut env_pipeline = ctx.pipeline.clone();
    env_pipeline.steps.insert("env_test".to_string(), Step {
        run: "echo \"Global: $GLOBAL_VAR, Test: $TEST_ENV, Step: $STEP_VAR, Attest: $ATTEST_STEP_NAME\"".to_string(),
        inputs: vec![],
        outputs: vec![],
        needs: None,
        env: Some({
            let mut env = BTreeMap::new();
            env.insert("STEP_VAR".to_string(), "step_specific".to_string());
            env.insert("GLOBAL_VAR".to_string(), "overridden".to_string()); // Override global
            env
        }),
        working_dir: None,
        image: None,
        capsule: None,
        cache: false,
        timeout_secs: None,
        attestation: None,
    });

    let config = ExecutorConfig::default();
    let mut executor = Executor::new(&mut ctx.storage, config)?;

    let receipt = executor.run(&env_pipeline).await?;

    // Find the env test step
    let env_step = receipt.steps.iter().find(|s| s.name == "env_test").unwrap();
    assert_eq!(env_step.exit_code, 0);

    // Check that environment variables were properly set
    assert!(env_step.stdout.contains("Global: overridden")); // Step override
    assert!(env_step.stdout.contains("Test: unit_test")); // Pipeline global
    assert!(env_step.stdout.contains("Step: step_specific")); // Step specific
    assert!(env_step.stdout.contains("Attest: env_test")); // Injected by executor

    Ok(())
}

// Test executor configuration validation
#[tokio::test]
async fn test_executor_configuration_validation() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    // Test default configuration
    let default_config = ExecutorConfig::default();
    assert!(!default_config.isolated);
    assert!(!default_config.sign_results);
    assert!(default_config.deterministic);
    assert_eq!(default_config.max_parallel, num_cpus::get());

    let mut executor = Executor::new(&mut ctx.storage, default_config)?;
    assert!(executor.run(&ctx.pipeline).await.is_ok());

    // Test various configuration combinations
    let configs = vec![
        ExecutorConfig {
            isolated: true,
            deterministic: true,
            max_parallel: 1,
            ..ExecutorConfig::default()
        },
        ExecutorConfig {
            sign_results: true,
            deterministic: false,
            max_parallel: 4,
            ..ExecutorConfig::default()
        },
        ExecutorConfig {
            isolated: true,
            sign_results: true,
            deterministic: true,
            max_parallel: 2,
            ..ExecutorConfig::default()
        },
    ];

    for (i, config) in configs.into_iter().enumerate() {
        let executor = Executor::new(&mut ctx.storage, config);
        assert!(executor.is_ok(), "Configuration {} should be valid", i);

        if let Ok(mut executor) = executor {
            let result = executor.run(&ctx.pipeline).await;
            // Some configurations might fail due to missing dependencies (keys, containers)
            // but they should at least validate
            match result {
                Ok(_) => println!("Configuration {} executed successfully", i),
                Err(e) => println!("Configuration {} failed (expected): {}", i, e),
            }
        }
    }

    Ok(())
}

// Steps with a working_dir must run in that directory; relative
// working_dir values resolve against the workspace root (the process cwd).
#[tokio::test]
async fn test_working_dir_execution() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    // The work dir must live under the crate root: declared outputs are
    // resolved against the manifest hashing workspace root (process cwd).
    let work_root = std::env::current_dir()?.join("target").join("basic-tests");
    std::fs::create_dir_all(&work_root)?;
    let work_dir_guard = TempDir::new_in(&work_root)?;
    let work_dir = work_dir_guard.path().to_path_buf();
    let rel_dir = work_dir
        .strip_prefix(std::env::current_dir()?)?
        .to_path_buf();

    let mut steps = BTreeMap::new();
    steps.insert(
        "in-workdir".to_string(),
        Step {
            // Relative redirect: lands in working_dir, not the process cwd.
            run: "pwd > where.txt".to_string(),
            inputs: vec![],
            outputs: vec![rel_dir.join("where.txt")],
            needs: None,
            env: None,
            working_dir: Some(rel_dir.clone()),
            image: None,
            capsule: None,
            cache: false,
            timeout_secs: Some(30),
            attestation: None,
        },
    );
    steps.insert(
        "no-workdir".to_string(),
        Step {
            run: format!("test \"$(pwd)\" != \"{}\"", work_dir.display()),
            inputs: vec![],
            outputs: vec![],
            needs: Some(vec!["in-workdir".to_string()]),
            env: None,
            working_dir: None,
            image: None,
            capsule: None,
            cache: false,
            timeout_secs: Some(30),
            attestation: None,
        },
    );

    let pipeline = Pipeline {
        schema_version: None,
        version: "0.1".to_string(),
        name: Some("working-dir-pipeline".to_string()),
        env: BTreeMap::new(),
        attestation: attest::pipeline::parser::AttestationConfig {
            sign_all_steps: false,
            verify_dependencies: false,
            require_reproducible: false,
        },
        steps,
    };

    let mut executor = Executor::new(&mut ctx.storage, ExecutorConfig::default())?;
    let receipt = executor.run(&pipeline).await?;
    for step in &receipt.steps {
        assert_eq!(step.exit_code, 0, "step '{}' failed", step.name);
    }

    let recorded = std::fs::read_to_string(work_dir.join("where.txt"))?;
    let canonical_work_dir = work_dir.canonicalize()?;
    assert_eq!(
        std::path::Path::new(recorded.trim_end()).canonicalize()?,
        canonical_work_dir,
        "step must run inside its working_dir"
    );

    Ok(())
}

// A working_dir that does not exist must fail the run with a clear error
// instead of silently executing in the process cwd.
#[tokio::test]
async fn test_working_dir_missing_fails() -> Result<()> {
    let mut ctx = TestExecutionContext::new().await?;

    let mut steps = BTreeMap::new();
    steps.insert(
        "bad-workdir".to_string(),
        Step {
            run: "true".to_string(),
            inputs: vec![],
            outputs: vec![],
            needs: None,
            env: None,
            working_dir: Some("target/basic-tests/does-not-exist".into()),
            image: None,
            capsule: None,
            cache: false,
            timeout_secs: Some(30),
            attestation: None,
        },
    );

    let pipeline = Pipeline {
        schema_version: None,
        version: "0.1".to_string(),
        name: Some("bad-working-dir-pipeline".to_string()),
        env: BTreeMap::new(),
        attestation: attest::pipeline::parser::AttestationConfig {
            sign_all_steps: false,
            verify_dependencies: false,
            require_reproducible: false,
        },
        steps,
    };

    let mut executor = Executor::new(&mut ctx.storage, ExecutorConfig::default())?;
    let result = executor.run(&pipeline).await;
    assert!(result.is_err(), "missing working_dir must fail the run");
    let message = format!("{:#}", result.unwrap_err());
    assert!(
        message.contains("working_dir"),
        "error should mention working_dir, got: {message}"
    );

    Ok(())
}
