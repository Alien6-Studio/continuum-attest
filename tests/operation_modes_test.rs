use attest::core::{ComplianceFramework, HashAlgorithm, ModeConfig, OperationMode};
use std::collections::HashMap;

#[test]
fn test_operation_mode_parsing() {
    assert_eq!(
        "light".parse::<OperationMode>().unwrap(),
        OperationMode::Light
    );
    assert_eq!(
        "verifiable".parse::<OperationMode>().unwrap(),
        OperationMode::Verifiable
    );
    assert_eq!(
        "formal-proof".parse::<OperationMode>().unwrap(),
        OperationMode::FormalProof
    );
    assert_eq!(
        "formal_proof".parse::<OperationMode>().unwrap(),
        OperationMode::FormalProof
    );
    assert!("invalid".parse::<OperationMode>().is_err());
}

#[test]
fn test_operation_mode_display() {
    assert_eq!(OperationMode::Light.to_string(), "light");
    assert_eq!(OperationMode::Verifiable.to_string(), "verifiable");
    assert_eq!(OperationMode::FormalProof.to_string(), "formal-proof");
}

#[test]
fn test_light_mode_config() {
    let config = ModeConfig::light();
    assert_eq!(config.mode, OperationMode::Light);
    assert!(!config.crypto.signatures_enabled);
    assert!(!config.crypto.sign_all_steps);
    assert_eq!(
        config.isolation.isolation_level,
        attest::sandbox::IsolationLevel::Process
    );
    assert!(!config.audit.detailed_logging);
    assert!(config.performance.cache_enabled);
    assert!(config.performance.skip_expensive_checks);
}

#[test]
fn test_verifiable_mode_config() {
    let config = ModeConfig::verifiable();
    assert_eq!(config.mode, OperationMode::Verifiable);
    assert!(config.crypto.signatures_enabled);
    assert!(!config.crypto.sign_all_steps); // Only critical steps
    assert_eq!(
        config.isolation.isolation_level,
        attest::sandbox::IsolationLevel::Container
    );
    assert!(config.audit.detailed_logging);
    assert!(config.audit.merkle_tree_enabled);
    assert!(!config.performance.skip_expensive_checks);
}

#[test]
fn test_formal_proof_mode_config() {
    let config = ModeConfig::formal_proof();
    assert_eq!(config.mode, OperationMode::FormalProof);
    assert!(config.crypto.signatures_enabled);
    assert!(config.crypto.sign_all_steps); // Sign every step
    assert_eq!(
        config.isolation.isolation_level,
        attest::sandbox::IsolationLevel::StrictContainer
    );
    assert_eq!(
        config.isolation.network_policy,
        attest::sandbox::NetworkPolicy::Disabled
    );
    assert!(config.audit.detailed_logging);
    assert!(config.audit.merkle_tree_enabled);
    assert_eq!(config.audit.retention_days, 2555); // 7 years
}

#[test]
fn test_mode_config_validation() {
    // Valid configurations
    assert!(ModeConfig::light().validate().is_ok());
    assert!(ModeConfig::verifiable().validate().is_ok());
    assert!(ModeConfig::formal_proof().validate().is_ok());

    // Invalid Light mode - shouldn't sign all steps
    let mut invalid_light = ModeConfig::light();
    invalid_light.crypto.signatures_enabled = true;
    invalid_light.crypto.sign_all_steps = true;
    assert!(invalid_light.validate().is_err());

    // Invalid Verifiable mode - must have signatures
    let mut invalid_verifiable = ModeConfig::verifiable();
    invalid_verifiable.crypto.signatures_enabled = false;
    assert!(invalid_verifiable.validate().is_err());

    // Invalid Formal Proof mode - must sign all steps
    let mut invalid_formal = ModeConfig::formal_proof();
    invalid_formal.crypto.sign_all_steps = false;
    assert!(invalid_formal.validate().is_err());
}

#[test]
fn test_mode_config_overrides() {
    let mut overrides = HashMap::new();
    overrides.insert(
        "crypto.signatures_enabled".to_string(),
        serde_json::Value::Bool(true),
    );
    overrides.insert(
        "performance.max_parallel_steps".to_string(),
        serde_json::Value::Number(serde_json::Number::from(8)),
    );

    let config = ModeConfig::light().with_overrides(overrides).unwrap();
    assert!(config.crypto.signatures_enabled); // Overridden
    assert_eq!(config.performance.max_parallel_steps, 8); // Overridden
    assert!(!config.crypto.sign_all_steps); // Not overridden, keeps original value
}

#[test]
fn test_from_mode() {
    let light = ModeConfig::from_mode(OperationMode::Light);
    assert_eq!(light.mode, OperationMode::Light);

    let verifiable = ModeConfig::from_mode(OperationMode::Verifiable);
    assert_eq!(verifiable.mode, OperationMode::Verifiable);

    let formal = ModeConfig::from_mode(OperationMode::FormalProof);
    assert_eq!(formal.mode, OperationMode::FormalProof);
}

#[test]
fn test_use_case_suitability() {
    let light = ModeConfig::light();
    let verifiable = ModeConfig::verifiable();
    let formal = ModeConfig::formal_proof();

    // Light mode suitability
    assert!(light.is_suitable_for("development"));
    assert!(light.is_suitable_for("testing"));
    assert!(light.is_suitable_for("personal-projects"));
    assert!(!light.is_suitable_for("regulated-industry"));
    assert!(!light.is_suitable_for("medical-devices"));

    // Verifiable mode suitability
    assert!(verifiable.is_suitable_for("enterprise-ci"));
    assert!(verifiable.is_suitable_for("open-source"));
    assert!(verifiable.is_suitable_for("production-builds"));
    assert!(!verifiable.is_suitable_for("medical-devices"));
    assert!(!verifiable.is_suitable_for("aerospace"));

    // Formal proof mode suitability
    assert!(formal.is_suitable_for("regulated-industry"));
    assert!(formal.is_suitable_for("medical-devices"));
    assert!(formal.is_suitable_for("financial-services"));
    assert!(formal.is_suitable_for("critical-infrastructure"));
    assert!(formal.is_suitable_for("aerospace"));
    assert!(!formal.is_suitable_for("development"));
    assert!(!formal.is_suitable_for("personal-projects"));
}

#[test]
fn test_performance_impact() {
    let light = ModeConfig::light();
    let verifiable = ModeConfig::verifiable();
    let formal = ModeConfig::formal_proof();

    assert_eq!(light.performance_impact(), "~5-15% overhead");
    assert_eq!(verifiable.performance_impact(), "~15-30% overhead");
    assert_eq!(formal.performance_impact(), "~30-50% overhead");
}

#[test]
fn test_compliance_framework_assignment() {
    let light = ModeConfig::light();
    assert!(matches!(
        light.audit.compliance_framework,
        Some(ComplianceFramework::Basic)
    ));

    let verifiable = ModeConfig::verifiable();
    assert!(matches!(
        verifiable.audit.compliance_framework,
        Some(ComplianceFramework::SLSA)
    ));

    let formal = ModeConfig::formal_proof();
    assert!(matches!(
        formal.audit.compliance_framework,
        Some(ComplianceFramework::FedRAMP)
    ));
}

#[test]
fn test_hash_algorithm_consistency() {
    let light = ModeConfig::light();
    let verifiable = ModeConfig::verifiable();
    let formal = ModeConfig::formal_proof();

    // All modes should use Blake3 by default for consistency
    assert!(matches!(light.crypto.hash_algorithm, HashAlgorithm::Blake3));
    assert!(matches!(
        verifiable.crypto.hash_algorithm,
        HashAlgorithm::Blake3
    ));
    assert!(matches!(
        formal.crypto.hash_algorithm,
        HashAlgorithm::Blake3
    ));
}

#[test]
fn test_serialization_deserialization() {
    let original = ModeConfig::verifiable();

    // Test JSON serialization
    let json = serde_json::to_string(&original).unwrap();
    let deserialized: ModeConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(original.mode, deserialized.mode);
    assert_eq!(
        original.crypto.signatures_enabled,
        deserialized.crypto.signatures_enabled
    );
    assert_eq!(
        original.isolation.isolation_level,
        deserialized.isolation.isolation_level
    );
}
