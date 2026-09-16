//! Extended tests for the core module.
//!
//! Covers the error paths and the advanced behaviour that the basic core
//! tests do not reach.

use anyhow::Result;
use attest::core::{AttestCore, ComplianceFramework, HashAlgorithm, ModeConfig, OperationMode};
use attest::executor::ExecutorConfig;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use tempfile::TempDir;

/// `AttestCore::new`/`with_mode` resolve their storage root via
/// `std::env::current_dir()`, so any test that calls
/// `std::env::set_current_dir` mutates process-wide state. Since `cargo
/// test` runs tests within a binary concurrently on multiple threads by
/// default, unsynchronized calls to `set_current_dir` race with each other
/// and can point a test's `AttestCore` at another test's (possibly
/// already-deleted) temp directory, causing intermittent failures. This
/// mutex serializes all tests below that change the current directory.
fn cwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn test_mode_config_with_overrides_crypto_settings() -> Result<()> {
    let mut overrides = HashMap::new();
    overrides.insert("crypto.signatures_enabled".to_string(), json!(true));
    overrides.insert("crypto.sign_all_steps".to_string(), json!(false));

    let config = ModeConfig::light().with_overrides(overrides)?;

    assert!(config.crypto.signatures_enabled);
    assert!(!config.crypto.sign_all_steps);
    assert_eq!(config.mode, OperationMode::Light);

    Ok(())
}

#[tokio::test]
async fn test_mode_config_with_overrides_isolation_settings() -> Result<()> {
    let mut overrides = HashMap::new();
    overrides.insert(
        "isolation.deterministic_environment".to_string(),
        json!(false),
    );

    let config = ModeConfig::verifiable().with_overrides(overrides)?;

    assert!(!config.isolation.deterministic_environment);
    assert_eq!(config.mode, OperationMode::Verifiable);

    Ok(())
}

#[tokio::test]
async fn test_mode_config_with_overrides_audit_settings() -> Result<()> {
    let mut overrides = HashMap::new();
    overrides.insert("audit.detailed_logging".to_string(), json!(true));

    let config = ModeConfig::light().with_overrides(overrides)?;

    assert!(config.audit.detailed_logging);
    assert_eq!(config.mode, OperationMode::Light);

    Ok(())
}

#[tokio::test]
async fn test_mode_config_with_overrides_performance_settings() -> Result<()> {
    let mut overrides = HashMap::new();
    overrides.insert("performance.cache_enabled".to_string(), json!(false));
    overrides.insert("performance.max_parallel_steps".to_string(), json!(8));

    let config = ModeConfig::verifiable().with_overrides(overrides)?;

    assert!(!config.performance.cache_enabled);
    assert_eq!(config.performance.max_parallel_steps, 8);

    Ok(())
}

#[tokio::test]
async fn test_mode_config_with_overrides_unknown_key() -> Result<()> {
    let mut overrides = HashMap::new();
    overrides.insert("unknown.setting".to_string(), json!(true));

    // Should not fail, just log a warning
    let config = ModeConfig::light().with_overrides(overrides)?;
    assert_eq!(config.mode, OperationMode::Light);

    Ok(())
}

#[tokio::test]
async fn test_mode_config_with_overrides_invalid_values() -> Result<()> {
    let mut overrides = HashMap::new();
    // Invalid boolean value should use default
    overrides.insert("crypto.signatures_enabled".to_string(), json!("invalid"));

    let original_config = ModeConfig::light();
    let config = original_config.clone().with_overrides(overrides)?;

    // Should keep original value when invalid
    assert_eq!(
        config.crypto.signatures_enabled,
        original_config.crypto.signatures_enabled
    );

    Ok(())
}

#[test]
fn test_mode_config_validation_light_mode_violations() {
    let mut config = ModeConfig::light();

    // Light mode with both signatures enabled and sign_all_steps should fail
    config.crypto.signatures_enabled = true;
    config.crypto.sign_all_steps = true;

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Light mode should not sign all steps"));
}

#[test]
fn test_mode_config_validation_verifiable_mode_violations() {
    let mut config = ModeConfig::verifiable();

    // Verifiable mode without signatures should fail
    config.crypto.signatures_enabled = false;

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Verifiable mode requires cryptographic signatures"));

    // Reset and test Merkle tree requirement
    config = ModeConfig::verifiable();
    config.audit.merkle_tree_enabled = false;

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Verifiable mode requires Merkle tree"));
}

#[test]
fn test_mode_config_validation_formal_proof_violations() {
    let mut config = ModeConfig::formal_proof();

    // Formal proof without signatures should fail
    config.crypto.signatures_enabled = false;

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Formal proof mode requires signatures"));

    // Reset and test sign_all_steps requirement
    config = ModeConfig::formal_proof();
    config.crypto.sign_all_steps = false;

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Formal proof mode requires signatures on all steps"));

    // Test network policy requirement
    config = ModeConfig::formal_proof();
    config.isolation.network_policy = attest::sandbox::NetworkPolicy::Restricted;

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Formal proof mode requires network isolation"));

    // Test detailed logging requirement
    config = ModeConfig::formal_proof();
    config.audit.detailed_logging = false;

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Formal proof mode requires detailed audit logging"));
}

#[test]
fn test_mode_config_validation_hardware_security_without_signatures() {
    let mut config = ModeConfig::light();
    config.crypto.hardware_security = true;
    config.crypto.signatures_enabled = false;

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Hardware security requires signatures"));
}

#[test]
fn test_mode_config_validation_zero_parallel_steps() {
    let mut config = ModeConfig::light();
    config.performance.max_parallel_steps = 0;

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("max_parallel_steps must be greater than 0"));
}

#[tokio::test]
async fn test_attest_core_with_invalid_mode_config() {
    let mut config = ModeConfig::verifiable();
    config.crypto.signatures_enabled = false; // Invalid for verifiable mode

    let result = AttestCore::with_mode_config(config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_attest_core_set_invalid_mode_config() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_current_dir(temp_dir.path()).expect("Failed to change directory");

    let mut core = AttestCore::new().await.unwrap();

    let mut invalid_config = ModeConfig::formal_proof();
    invalid_config.crypto.signatures_enabled = false; // Invalid

    let result = core.set_mode_config(invalid_config).await;
    assert!(result.is_err());

    // Original mode should be unchanged
    assert_eq!(core.get_mode(), OperationMode::Light);
}

#[tokio::test]
async fn test_attest_core_init() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_current_dir(temp_dir.path()).expect("Failed to change directory");

    let core = AttestCore::with_mode(OperationMode::Verifiable)
        .await
        .unwrap();

    let result = core.init().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_attest_core_run_pipeline_default_path() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_current_dir(temp_dir.path()).expect("Failed to change directory");

    let core = AttestCore::new().await.unwrap();

    // A bare temp dir is not an ATTEST repository: operational error.
    let result = core
        .run_pipeline(None, ExecutorConfig::default(), None, None)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_attest_core_run_pipeline_custom_path() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_current_dir(temp_dir.path()).expect("Failed to change directory");

    let core = AttestCore::new().await.unwrap();

    // Custom pipeline path in a bare temp dir: operational error.
    let result = core
        .run_pipeline(Some("custom.yaml"), ExecutorConfig::default(), None, None)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_attest_core_run_pipeline_all_modes() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_current_dir(temp_dir.path()).expect("Failed to change directory");

    let modes = [
        OperationMode::Light,
        OperationMode::Verifiable,
        OperationMode::FormalProof,
    ];

    for mode in modes {
        let core = AttestCore::with_mode(mode).await.unwrap();
        let result = core
            .run_pipeline(Some("test.yaml"), ExecutorConfig::default(), None, None)
            .await;
        assert!(
            result.is_err(),
            "bare dir must be rejected in mode: {}",
            mode
        );
    }
}

#[test]
fn test_all_hash_algorithms() {
    let algorithms = [
        HashAlgorithm::Blake3,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha3_256,
    ];

    for algorithm in algorithms {
        let mut config = ModeConfig::light();
        config.crypto.hash_algorithm = algorithm;

        // Should serialize and deserialize correctly
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ModeConfig = serde_json::from_str(&json).unwrap();

        assert!(matches!(
            (
                &config.crypto.hash_algorithm,
                &deserialized.crypto.hash_algorithm
            ),
            (HashAlgorithm::Blake3, HashAlgorithm::Blake3)
                | (HashAlgorithm::Sha256, HashAlgorithm::Sha256)
                | (HashAlgorithm::Sha3_256, HashAlgorithm::Sha3_256)
        ));
    }
}

#[test]
fn test_all_compliance_frameworks() {
    let frameworks = [
        ComplianceFramework::Basic,
        ComplianceFramework::SOX,
        ComplianceFramework::PCI,
        ComplianceFramework::HIPAA,
        ComplianceFramework::FedRAMP,
        ComplianceFramework::SLSA,
    ];

    for framework in frameworks {
        let mut config = ModeConfig::light();
        config.audit.compliance_framework = Some(framework);

        // Should serialize and deserialize correctly
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ModeConfig = serde_json::from_str(&json).unwrap();

        assert!(deserialized.audit.compliance_framework.is_some());
    }
}

#[test]
fn test_mode_config_edge_cases() {
    // Test with minimal performance settings
    let mut config = ModeConfig::light();
    config.performance.max_parallel_steps = 1;
    assert!(config.validate().is_ok());

    // Test with maximum retention
    config.audit.retention_days = u32::MAX;
    assert!(config.validate().is_ok());

    // Test with zero key rotation (None is different from Some(0))
    config.crypto.key_rotation_days = Some(0);
    assert!(config.validate().is_ok());
}

#[test]
fn test_operation_mode_coverage() {
    // Test all operation mode variants are covered
    let modes = [
        OperationMode::Light,
        OperationMode::Verifiable,
        OperationMode::FormalProof,
    ];

    for mode in modes {
        let config = ModeConfig::from_mode(mode);
        assert_eq!(config.mode, mode);
        assert!(config.validate().is_ok());

        // Test description and performance impact
        assert!(!config.description().is_empty());
        assert!(!config.performance_impact().is_empty());

        // Test suitability checks
        let use_cases = [
            "development",
            "testing",
            "personal-projects",
            "enterprise-ci",
            "open-source",
            "production-builds",
            "regulated-industry",
            "critical-infrastructure",
            "financial-services",
            "medical-devices",
            "aerospace",
            "unknown-use-case",
        ];

        for use_case in use_cases {
            // Just ensure it doesn't panic
            let _suitable = config.is_suitable_for(use_case);
        }
    }
}

#[tokio::test]
async fn test_attest_core_mode_transitions() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_current_dir(temp_dir.path()).expect("Failed to change directory");

    let mut core = AttestCore::new().await.unwrap();

    // Test all possible mode transitions
    let modes = [
        OperationMode::Light,
        OperationMode::Verifiable,
        OperationMode::FormalProof,
    ];

    for from_mode in modes {
        for to_mode in modes {
            core.set_mode(from_mode).await.unwrap();
            assert_eq!(core.get_mode(), from_mode);

            let result = core.set_mode(to_mode).await;
            assert!(
                result.is_ok(),
                "Failed to transition from {} to {}",
                from_mode,
                to_mode
            );
            assert_eq!(core.get_mode(), to_mode);
        }
    }
}

#[test]
fn test_crypto_config_edge_cases() {
    let mut config = ModeConfig::light();

    // Test extreme key rotation values
    config.crypto.key_rotation_days = Some(1); // Very short
    assert!(config.validate().is_ok());

    config.crypto.key_rotation_days = Some(u32::MAX); // Very long
    assert!(config.validate().is_ok());

    // Test all hash algorithms in different modes
    let algorithms = [
        HashAlgorithm::Blake3,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha3_256,
    ];
    let modes = [
        OperationMode::Light,
        OperationMode::Verifiable,
        OperationMode::FormalProof,
    ];

    for algorithm in &algorithms {
        for mode in modes {
            let mut config = ModeConfig::from_mode(mode);
            config.crypto.hash_algorithm = algorithm.clone();
            assert!(config.validate().is_ok());
        }
    }
}
