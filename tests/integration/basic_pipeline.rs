//! Basic pipeline integration tests

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_attest_init() {
    let temp_dir = TempDir::new().unwrap();
    
    let mut cmd = Command::cargo_bin("attest").unwrap();
    cmd.current_dir(&temp_dir)
       .arg("init")
       .assert()
       .success()
       .stdout(predicate::str::contains("Initialized ATTEST repository"));
    
    // Check that .attest directory was created
    assert!(temp_dir.path().join(".attest").exists());
    assert!(temp_dir.path().join("attest.yaml").exists());
}

#[test]
fn test_attest_run_basic() {
    let temp_dir = TempDir::new().unwrap();
    
    // Initialize
    Command::cargo_bin("attest").unwrap()
        .current_dir(&temp_dir)
        .arg("init")
        .assert()
        .success();
    
    // Create simple pipeline
    let pipeline = r#"
version: "0.1"
name: "test"

steps:
  hello:
    run: "echo 'Hello World'"
    inputs: []
    outputs: []
"#;
    
    fs::write(temp_dir.path().join("attest.yaml"), pipeline).unwrap();
    
    // Run pipeline
    Command::cargo_bin("attest").unwrap()
        .current_dir(&temp_dir)
        .arg("run")
        .assert()
        .success()
        .stdout(predicate::str::contains("Pipeline completed successfully"));
}

#[test]
fn test_attest_pipeline_validation() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create invalid pipeline (cycle)
    let pipeline = r#"
version: "0.1"
name: "test"

steps:
  step1:
    run: "echo 'step1'"
    needs: ["step2"]
  step2:
    run: "echo 'step2'"  
    needs: ["step1"]
"#;
    
    fs::write(temp_dir.path().join("attest.yaml"), pipeline).unwrap();
    
    // Should fail validation
    Command::cargo_bin("attest").unwrap()
        .current_dir(&temp_dir)
        .arg("pipeline")
        .arg("validate")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Cycle detected"));
}
