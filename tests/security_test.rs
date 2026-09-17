use attest::sandbox::filesystem_security::*;
use attest::sandbox::seccomp::SeccompViolation;
use attest::sandbox::*;
use std::path::PathBuf;
use tokio;

#[tokio::test]
async fn test_enhanced_container_sandbox_creation() {
    let config = container::ContainerUtils::secure_attest_config("alpine:latest");
    let result =
        EnhancedContainerSandbox::new(config, SecurityLevel::Standard, NetworkPolicy::Disabled);

    if container::ContainerUtils::is_container_runtime_available() {
        assert!(result.is_ok());
        let sandbox = result.unwrap();
        let (violations, _) = sandbox.get_violation_stats();
        assert_eq!(violations, 0);
    } else {
        println!("Skipping test: no container runtime available");
    }
}

#[tokio::test]
async fn test_security_levels() {
    if !container::ContainerUtils::is_container_runtime_available() {
        println!("Skipping test: no container runtime available");
        return;
    }

    let config = container::ContainerUtils::secure_attest_config("alpine:latest");

    // Test minimal security
    let minimal = EnhancedContainerSandbox::new(
        config.clone(),
        SecurityLevel::Minimal,
        NetworkPolicy::Disabled,
    )
    .unwrap();
    let (violations, _) = minimal.get_violation_stats();
    assert_eq!(violations, 0);

    // Test maximum security
    let maximum =
        EnhancedContainerSandbox::new(config, SecurityLevel::Maximum, NetworkPolicy::Disabled)
            .unwrap();
    let (violations, _) = maximum.get_violation_stats();
    assert_eq!(violations, 0);
}

#[test]
fn test_filesystem_security_policy() {
    let policy = FilesystemSecurityPolicy::default();
    assert_eq!(policy.default_access, AccessMode::Forbidden);
    assert!(!policy.rules.is_empty());
    assert!(policy.prevent_path_traversal);
    assert!(policy.restrict_symlinks);
}

#[test]
fn test_filesystem_security_manager() {
    let mut manager = FilesystemSecurityManager::with_default_policy();

    // Test allowed path
    let allowed = manager
        .check_path_access(&PathBuf::from("/workspace/test.txt"), AccessMode::ReadWrite)
        .unwrap();
    assert!(allowed);

    // Test forbidden path
    let forbidden = manager
        .check_path_access(&PathBuf::from("/etc/passwd"), AccessMode::ReadOnly)
        .unwrap();
    assert!(!forbidden);

    // Should have recorded violation
    assert!(!manager.get_violations().is_empty());
}

#[test]
fn test_strict_filesystem_policy() {
    let mut manager = FilesystemSecurityManager::with_strict_policy();

    // Even workspace files should be more restricted
    let result = manager
        .check_file_size(
            &PathBuf::from("/workspace/large.bin"),
            50 * 1024 * 1024, // 50MB
        )
        .unwrap();
    assert!(!result); // Should exceed strict limit

    assert!(!manager.get_violations().is_empty());
}

#[test]
fn test_path_traversal_detection() {
    let mut manager = FilesystemSecurityManager::with_default_policy();

    // Test path traversal attempts
    let paths = [
        "/workspace/../etc/passwd",
        "/tmp/../../root/.ssh/id_rsa",
        "/workspace/subdir/../../../etc/shadow",
    ];

    for path in &paths {
        let allowed = manager
            .check_path_access(&PathBuf::from(path), AccessMode::ReadOnly)
            .unwrap();
        assert!(!allowed, "Path traversal should be blocked: {}", path);
    }

    // Should have violations for each attempt
    assert!(manager.get_violations().len() >= paths.len());
}

#[test]
fn test_forbidden_extensions() {
    let mut manager = FilesystemSecurityManager::with_default_policy();

    let dangerous_files = [
        "/tmp/malware.exe",
        "/workspace/script.bat",
        "/tmp/virus.com",
        "/workspace/trojan.scr",
    ];

    for file in &dangerous_files {
        let allowed = manager
            .check_path_access(&PathBuf::from(file), AccessMode::ReadWrite)
            .unwrap();
        assert!(!allowed, "Dangerous file should be blocked: {}", file);
    }
}

#[test]
fn test_disk_usage_tracking() {
    let mut manager = FilesystemSecurityManager::with_default_policy();

    // Track small file - should be allowed
    let allowed = manager
        .track_disk_usage(
            &PathBuf::from("/workspace/small.txt"),
            1024, // 1KB
        )
        .unwrap();
    assert!(allowed);

    // Track large file - should exceed limit
    let allowed = manager
        .track_disk_usage(
            &PathBuf::from("/workspace/huge.bin"),
            2 * 1024 * 1024 * 1024, // 2GB
        )
        .unwrap();
    assert!(!allowed);
}

#[test]
fn test_seccomp_profiles() {
    let manager = SeccompManager::new();

    // Test built-in profiles exist
    assert!(manager.list_profiles().contains(&"minimal"));
    assert!(manager.list_profiles().contains(&"standard"));
    assert!(manager.list_profiles().contains(&"maximum"));

    // Test profile for each security level
    let minimal = manager
        .get_profile_for_level(SecurityLevel::Minimal)
        .unwrap();
    assert_eq!(minimal.default_action, seccomp::SeccompAction::Allow);

    let standard = manager
        .get_profile_for_level(SecurityLevel::Standard)
        .unwrap();
    assert_eq!(standard.default_action, seccomp::SeccompAction::Errno(1));

    let maximum = manager
        .get_profile_for_level(SecurityLevel::Maximum)
        .unwrap();
    assert_eq!(maximum.default_action, seccomp::SeccompAction::Kill);
}

#[test]
fn test_seccomp_container_profile_generation() {
    let manager = SeccompManager::new();

    for profile_name in &["minimal", "standard", "maximum"] {
        let json = manager.generate_container_profile(profile_name).unwrap();

        // Should be valid JSON
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Should contain required fields
        assert!(json.contains("defaultAction"));
        assert!(json.contains("architectures"));
        assert!(json.contains("syscalls"));
    }
}

#[test]
fn test_violation_detector() {
    let mut detector = ViolationDetector::new(5);

    // Add multiple violations
    for i in 0..3 {
        let violation = SeccompViolation {
            timestamp: chrono::Utc::now(),
            pid: 1000 + i,
            syscall: format!("syscall_{}", i),
            action: seccomp::SeccompAction::Kill,
            context: format!("Test violation {}", i),
        };
        detector.record_violation(violation);
    }

    assert_eq!(detector.violations_count(), 3);
    assert_eq!(detector.get_violations().len(), 3);

    // Test export
    let exported = detector.export_violations().unwrap();
    assert!(!exported.is_empty());
    let _: Vec<SeccompViolation> = serde_json::from_str(&exported).unwrap();
}

#[tokio::test]
async fn test_sandbox_security_integration() {
    // Test sandbox with strict container isolation
    let mut config = SandboxConfig::default();
    config.isolation_level = IsolationLevel::StrictContainer;
    config.security_level = SecurityLevel::Maximum;
    config.network_policy = NetworkPolicy::Disabled;
    config.container_config = Some(container::ContainerUtils::secure_attest_config(
        "alpine:latest",
    ));

    if container::ContainerUtils::is_container_runtime_available() {
        let result = Sandbox::new(config);
        assert!(result.is_ok());

        let sandbox = result.unwrap();
        assert!(sandbox.has_enhanced_security());
        assert!(sandbox.get_seccomp_profile_info().is_some());
    } else {
        println!("Skipping test: no container runtime available");
    }
}

#[test]
fn test_mount_restrictions() {
    let manager = FilesystemSecurityManager::with_strict_policy();
    let restrictions = manager.generate_mount_restrictions();

    assert!(!restrictions.is_empty());

    // Should have read-only system mounts
    assert!(restrictions
        .iter()
        .any(|r| r.contains("/bin") && r.contains(":ro")));
    assert!(restrictions
        .iter()
        .any(|r| r.contains("/etc") && r.contains(":ro")));

    // Should have tmpfs mounts
    assert!(restrictions.iter().any(|r| r.contains("tmpfs:/tmp")));
}

#[test]
fn test_security_policy_serialization() {
    let policy = FilesystemSecurityPolicy::default();

    // Test JSON serialization
    let json = serde_json::to_string(&policy).unwrap();
    let deserialized: FilesystemSecurityPolicy = serde_json::from_str(&json).unwrap();

    assert_eq!(policy.default_access, deserialized.default_access);
    assert_eq!(policy.rules.len(), deserialized.rules.len());
    assert_eq!(
        policy.prevent_path_traversal,
        deserialized.prevent_path_traversal
    );
}

#[test]
fn test_rule_priority_system() {
    let mut policy = FilesystemSecurityPolicy::default();

    // Add high priority rule that should override workspace access
    policy.rules.push(FilesystemRule {
        path_pattern: "/workspace/sensitive/*".to_string(),
        access_mode: AccessMode::Forbidden,
        recursive: true,
        priority: 999,
        description: "Block sensitive directory".to_string(),
    });

    let mut manager = FilesystemSecurityManager::new(policy);

    // Normal workspace file should be allowed
    let allowed = manager
        .check_path_access(
            &PathBuf::from("/workspace/normal.txt"),
            AccessMode::ReadWrite,
        )
        .unwrap();
    assert!(allowed);

    // Sensitive workspace file should be blocked by high priority rule
    let blocked = manager
        .check_path_access(
            &PathBuf::from("/workspace/sensitive/secret.txt"),
            AccessMode::ReadOnly,
        )
        .unwrap();
    assert!(!blocked);
}

#[tokio::test]
async fn test_security_report_generation() {
    if !container::ContainerUtils::is_container_runtime_available() {
        println!("Skipping test: no container runtime available");
        return;
    }

    let config = container::ContainerUtils::secure_attest_config("alpine:latest");
    let sandbox =
        EnhancedContainerSandbox::new(config, SecurityLevel::Standard, NetworkPolicy::Disabled)
            .unwrap();

    let report = sandbox.export_security_report().unwrap();
    assert!(!report.is_empty());

    // Should be valid JSON
    let json: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert!(json.get("security_level").is_some());
    assert!(json.get("seccomp").is_some());
    assert!(json.get("filesystem").is_some());
    assert!(json.get("generated_at").is_some());
}
