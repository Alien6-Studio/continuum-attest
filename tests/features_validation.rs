//! Smoke tests for the core public surface: lifecycle, storage, pipeline.
//!
//! NOTE: This file originally asserted the existence of a large CLI-facing
//! `AttestCore` surface (validate_pipeline/init_gitops/deploy_with_verification/
//! show_deployment_status/list_policies/install_policy/check_policies/
//! create_custom_policy/validate_policy_syntax) that does not exist on the
//! current `attest::core::AttestCore` (see src/core.rs, which only exposes
//! mode management + init()/run_pipeline()). It was rewritten as a minimal
//! smoke test over what does exist.
//!
//! It also carried two tests asserting that the `gitops` and `policy`
//! feature flags compiled. Those modules moved to separate plugin programs
//! (see the plugin protocol on the documentation site) and the crate now
//! has no cargo features, so those tests were removed rather than left to
//! silently pass on a `cfg` that can never be true.

use anyhow::Result;
use attest::core::AttestCore;
use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

/// `AttestCore::new` resolves its storage root via `std::env::current_dir()`,
/// so changing the current directory is process-wide state. `cargo test`
/// runs tests within a binary concurrently by default, so unsynchronized
/// `env::set_current_dir` calls across the (many) tests that use
/// `setup_test_environment` below can race and point a test's `AttestCore`
/// at another test's temp directory. This mutex serializes them; the guard
/// must be held for the lifetime of each test, not just the directory
/// change, so it is returned alongside the `AttestCore`/`TempDir`.
fn cwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn setup_test_environment() -> (AttestCore, TempDir, MutexGuard<'static, ()>) {
    let guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = TempDir::new().unwrap();
    env::set_current_dir(temp_dir.path()).unwrap();

    // Create a basic attest.yaml for testing
    let pipeline_content = r#"
name: "test-features-pipeline"
version: "0.1.0"

env:
  CI: "true"
  ATTEST_ENV: "test"

steps:
  test:
    run: "echo 'Testing features'"
    inputs: []
    outputs: []
"#;

    std::fs::write("attest.yaml", pipeline_content).unwrap();

    let core = AttestCore::new().await.unwrap();
    (core, temp_dir, guard)
}

#[tokio::test]
async fn test_core_methods_exist() -> Result<()> {
    let (core, _temp_dir, _guard) = setup_test_environment().await;

    // Test that basic core lifecycle methods work.
    let result = core.init().await;
    assert!(result.is_ok(), "init should succeed: {:?}", result.err());

    core.show_mode_info().await?;

    println!("Core methods are working");

    Ok(())
}

#[tokio::test]
async fn test_storage_functionality() -> Result<()> {
    let (_core, _temp_dir, _guard) = setup_test_environment().await;

    // Test storage functionality that should always work
    use attest::storage::{Receipt, StepResult, Storage};
    use chrono::Utc;

    let storage = Storage::new(_temp_dir.path())?;
    storage.init().await?;

    // Test basic receipt creation and storage
    let receipt = Receipt {
        schema_version: Some(1),
        pipeline_hash: "test123".to_string(),
        steps: vec![StepResult {
            name: "test".to_string(),
            input_hash: "input123".to_string(),
            output_hash: "output456".to_string(),
            duration_secs: 1,
            exit_code: 0,
            cache_hit: false,
            stdout: "success".to_string(),
            stderr: "".to_string(),
            capsule_hash: None,
        }],
        timestamp: Utc::now(),
        total_duration_secs: 1,
        signature: None,
        signer_public_key: None,
        attest_version: "0.1.0".to_string(),
        causal_events: vec![],
        causal_chain_hash: None,
        reproducibility: None,
        provenance: None,
        timestamp_token: None,
    };

    let receipt_path = storage.save_receipt(&receipt).await?;
    assert!(receipt_path.exists());

    println!("Storage functionality works correctly");

    Ok(())
}

#[tokio::test]
async fn test_pipeline_functionality() -> Result<()> {
    let (_core, _temp_dir, _guard) = setup_test_environment().await;

    // Test pipeline parsing and validation
    use attest::pipeline::Pipeline;

    let pipeline_content = std::fs::read_to_string("attest.yaml")?;
    let pipeline: Pipeline = serde_yaml::from_str(&pipeline_content)?;
    assert_eq!(pipeline.name, Some("test-features-pipeline".to_string()));
    assert!(pipeline.steps.contains_key("test"));

    println!("Pipeline functionality works correctly");

    Ok(())
}

#[tokio::test]
async fn test_features_integration_summary() -> Result<()> {
    let (_core, _temp_dir, _guard) = setup_test_environment().await;

    println!("\nCore surface summary:");
    println!("   Core methods are implemented");
    println!("   Storage functionality works");
    println!("   Pipeline parsing works");

    Ok(())
}
