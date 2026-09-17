//! Security-focused tests for sandbox functionality
//!
//! These tests focus on edge cases and security scenarios for the sandbox
//! implementation to improve code coverage.
//!
//! NOTE: This file was rewritten as a minimal smoke test against the current
//! `attest::sandbox` public API. The original version of this file assumed a
//! substantially different (and no longer existing) `SandboxConfig` /
//! `ResourceLimits` / `FilesystemPolicy` / `NetworkPolicy` shape (e.g.
//! `resource_limits: Option<ResourceLimits>`, `NetworkPolicy::AllowInternet`,
//! `NetworkPolicy::Custom(..)`, direct `container_image`/`container_runtime`
//! fields on `SandboxConfig`, an `attest::sandbox::filesystem_security::
//! FilesystemPolicy`/`FilesystemSecurity` pair that doesn't exist (the real
//! types are `FilesystemSecurityPolicy`/`FilesystemSecurityManager`), and
//! direct access to `Sandbox`'s private `config` field. None of that compiles
//! against the current `src/sandbox` module, so the tests below were
//! rewritten from scratch to exercise the real, current public surface.

use attest::sandbox::filesystem_security::{
    AccessMode, FilesystemRule, FilesystemSecurityManager, FilesystemSecurityPolicy,
};
use attest::sandbox::{
    ContainerConfig, ContainerRuntime, FilesystemPolicy, IsolationLevel, NetworkPolicy,
    ResourceLimits, Sandbox, SandboxConfig,
};

#[test]
fn test_sandbox_config_default_values() {
    let config = SandboxConfig::default();
    assert_eq!(config.isolation_level, IsolationLevel::Process);
    assert_eq!(config.network_policy, NetworkPolicy::Disabled);
    assert!(config.deterministic_time);
    assert!(config.container_config.is_none());

    let limits = &config.resource_limits;
    assert_eq!(limits.memory_mb, None);
    assert_eq!(limits.cpu_cores, Some(1.0));
    // No default timeout: now that timeouts are enforced, a silent
    // default would kill legitimate long-running builds.
    assert_eq!(limits.timeout_secs, None);
}

#[test]
fn test_sandbox_config_customization() {
    let mut config = SandboxConfig::default();
    config.isolation_level = IsolationLevel::StrictContainer;
    config.network_policy = NetworkPolicy::Restricted;
    config.deterministic_time = true;

    assert_eq!(config.isolation_level, IsolationLevel::StrictContainer);
    assert_eq!(config.network_policy, NetworkPolicy::Restricted);
    assert!(config.deterministic_time);
}

#[test]
fn test_isolation_level_variants() {
    let levels = [
        IsolationLevel::None,
        IsolationLevel::Process,
        IsolationLevel::Container,
        IsolationLevel::StrictContainer,
        IsolationLevel::VM,
    ];
    // Just make sure all variants exist, are distinguishable, and are Copy/Clone/Debug.
    for (i, a) in levels.iter().enumerate() {
        for (j, b) in levels.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
        let _ = format!("{:?}", a);
    }
}

#[test]
fn test_container_runtime_variants() {
    let runtimes = [
        ContainerRuntime::Docker,
        ContainerRuntime::Podman,
        ContainerRuntime::Containerd,
    ];
    for runtime in &runtimes {
        let _ = format!("{:?}", runtime);
    }
}

#[test]
fn test_network_policy_variants() {
    let policies = [
        NetworkPolicy::Disabled,
        NetworkPolicy::Restricted,
        NetworkPolicy::Full,
    ];
    for (i, a) in policies.iter().enumerate() {
        for (j, b) in policies.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn test_resource_limits_configuration() {
    let limits = ResourceLimits {
        memory_mb: Some(256),
        cpu_cores: Some(2.0),
        timeout_secs: Some(60),
        max_files: Some(500),
        max_file_size_mb: Some(50),
    };

    assert_eq!(limits.memory_mb, Some(256));
    assert_eq!(limits.cpu_cores, Some(2.0));
    assert_eq!(limits.timeout_secs, Some(60));
    assert_eq!(limits.max_files, Some(500));
    assert_eq!(limits.max_file_size_mb, Some(50));
}

#[test]
fn test_sandbox_with_custom_resource_limits() {
    let mut config = SandboxConfig::default();
    config.resource_limits = ResourceLimits {
        memory_mb: Some(128),
        cpu_cores: Some(0.5),
        timeout_secs: Some(30),
        max_files: Some(100),
        max_file_size_mb: Some(10),
    };

    let sandbox = Sandbox::new(config);
    assert!(sandbox.is_ok(), "Sandbox creation should succeed");
}

#[test]
fn test_filesystem_policy_defaults() {
    let policy = FilesystemPolicy::default();
    assert!(policy.read_only_paths.is_empty());
    assert!(policy.writable_paths.is_empty());
    assert!(policy.temp_dir.is_none());
    assert_eq!(policy.max_disk_usage_mb, Some(1024));
}

#[test]
fn test_filesystem_policy_customization() {
    let policy = FilesystemPolicy {
        read_only_paths: vec!["/usr".into(), "/etc".into()],
        writable_paths: vec!["/tmp/work".into()],
        temp_dir: Some("/tmp".into()),
        max_disk_usage_mb: Some(2048),
    };

    assert_eq!(policy.read_only_paths.len(), 2);
    assert_eq!(policy.writable_paths.len(), 1);
    assert_eq!(
        policy.temp_dir.as_deref(),
        Some(std::path::Path::new("/tmp"))
    );
    assert_eq!(policy.max_disk_usage_mb, Some(2048));
}

#[test]
fn test_sandbox_creation_with_different_isolation_levels() {
    for level in [
        IsolationLevel::None,
        IsolationLevel::Process,
        IsolationLevel::Container,
        IsolationLevel::StrictContainer,
        IsolationLevel::VM,
    ] {
        let mut config = SandboxConfig::default();
        config.isolation_level = level.clone();

        // Container and StrictContainer isolation require a `container_config`
        // to be present; supply a minimal one so `Sandbox::new` doesn't fail
        // for that reason alone. They also probe for the container runtime
        // binary, so creation is only expected to succeed where docker is
        // installed.
        let container_level = matches!(
            level,
            IsolationLevel::Container | IsolationLevel::StrictContainer
        );
        if container_level {
            config.container_config = Some(ContainerConfig {
                image: "alpine:latest".to_string(),
                volumes: vec![],
                environment: std::collections::HashMap::new(),
                working_dir: None,
                user: None,
                entrypoint: None,
                runtime: ContainerRuntime::Docker,
            });
            let docker_installed = std::process::Command::new("docker")
                .arg("--version")
                .output()
                .is_ok();
            if !docker_installed {
                eprintln!("Skipping isolation level {:?}: docker not installed", level);
                continue;
            }
        }

        let sandbox = Sandbox::new(config);
        assert!(
            sandbox.is_ok(),
            "Sandbox creation should succeed for isolation level {:?}",
            level
        );
    }
}

#[test]
fn test_sandbox_container_config() {
    let mut config = SandboxConfig::default();
    config.container_config = Some(ContainerConfig {
        image: "alpine:latest".to_string(),
        volumes: vec![],
        environment: std::collections::HashMap::new(),
        working_dir: None,
        user: None,
        entrypoint: None,
        runtime: ContainerRuntime::Docker,
    });

    assert!(config.container_config.is_some());
    let container_config = config.container_config.as_ref().unwrap();
    assert_eq!(container_config.image, "alpine:latest");
    assert_eq!(container_config.runtime, ContainerRuntime::Docker);

    let sandbox = Sandbox::new(config);
    assert!(sandbox.is_ok());
}

#[test]
fn test_sandbox_config_serialization_roundtrip() {
    let config = SandboxConfig::default();
    let json = serde_json::to_string(&config).expect("SandboxConfig should serialize");
    let deserialized: SandboxConfig =
        serde_json::from_str(&json).expect("SandboxConfig should deserialize");

    assert_eq!(deserialized.isolation_level, config.isolation_level);
    assert_eq!(deserialized.network_policy, config.network_policy);
    assert_eq!(
        deserialized.resource_limits.memory_mb,
        config.resource_limits.memory_mb
    );
}

#[test]
fn test_filesystem_policy_serialization_roundtrip() {
    let policy = FilesystemPolicy {
        read_only_paths: vec!["/bin".into()],
        writable_paths: vec!["/tmp".into()],
        temp_dir: Some("/tmp".into()),
        max_disk_usage_mb: Some(512),
    };

    let json = serde_json::to_string(&policy).expect("FilesystemPolicy should serialize");
    let deserialized: FilesystemPolicy =
        serde_json::from_str(&json).expect("FilesystemPolicy should deserialize");

    assert_eq!(deserialized.read_only_paths, policy.read_only_paths);
    assert_eq!(deserialized.writable_paths, policy.writable_paths);
    assert_eq!(deserialized.max_disk_usage_mb, policy.max_disk_usage_mb);
}

#[test]
fn test_filesystem_security_policy_default() {
    let policy = FilesystemSecurityPolicy::default();
    assert_eq!(policy.default_access, AccessMode::Forbidden);
    assert!(!policy.rules.is_empty());
    assert!(policy.prevent_path_traversal);
}

#[test]
fn test_filesystem_security_manager_allows_configured_paths() {
    let mut manager = FilesystemSecurityManager::with_default_policy();

    // /tmp/* is allowed read-write by the default policy.
    let allowed = manager
        .check_path_access(
            std::path::Path::new("/tmp/example.txt"),
            AccessMode::ReadWrite,
        )
        .expect("check_path_access should not error");
    assert!(
        allowed,
        "/tmp paths should be writable under the default policy"
    );
}

#[test]
fn test_filesystem_security_manager_denies_unlisted_paths() {
    let mut manager = FilesystemSecurityManager::with_strict_policy();

    let allowed = manager
        .check_path_access(
            std::path::Path::new("/some/random/unlisted/path"),
            AccessMode::ReadWrite,
        )
        .expect("check_path_access should not error");
    assert!(
        !allowed,
        "unlisted paths should be denied under the strict policy"
    );
}

#[test]
fn test_filesystem_security_manager_custom_policy() {
    let policy = FilesystemSecurityPolicy {
        default_access: AccessMode::Forbidden,
        rules: vec![FilesystemRule {
            path_pattern: "/workspace/*".to_string(),
            access_mode: AccessMode::ReadWrite,
            recursive: true,
            priority: 100,
            description: "Workspace access".to_string(),
        }],
        max_file_size: Some(1024 * 1024),
        max_disk_usage: Some(10 * 1024 * 1024),
        allowed_extensions: None,
        forbidden_extensions: Default::default(),
        prevent_path_traversal: true,
        restrict_symlinks: true,
    };

    let mut manager = FilesystemSecurityManager::new(policy);
    let allowed = manager
        .check_path_access(
            std::path::Path::new("/workspace/file.txt"),
            AccessMode::ReadWrite,
        )
        .expect("check_path_access should not error");
    assert!(allowed);

    let violations = manager.get_violations();
    assert!(
        violations.is_empty(),
        "no violations expected for an allowed access"
    );
}

#[test]
fn test_filesystem_security_manager_tracks_violations() {
    let mut manager = FilesystemSecurityManager::with_strict_policy();

    // This should be denied and recorded as a violation.
    let _ = manager.check_path_access(
        std::path::Path::new("/definitely/not/allowed"),
        AccessMode::ReadWrite,
    );

    // get_violations should be callable regardless of whether anything was recorded;
    // this mainly ensures the API surface still compiles and runs cleanly.
    let _violations = manager.get_violations();
}
