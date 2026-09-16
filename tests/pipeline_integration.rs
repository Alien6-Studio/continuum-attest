//! Integration tests for pipeline functionality

use anyhow::Result;
use attest::pipeline::Pipeline;
use std::io::Write;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_complete_pipeline_workflow() -> Result<()> {
    let complex_pipeline = r#"
version: "0.1"
name: "complex-integration-pipeline"

env:
  GLOBAL_VAR: "global_value"
  BUILD_ENV: "integration"
  RUST_LOG: "debug"

attestation:
  sign_all_steps: true
  verify_dependencies: true
  require_reproducible: true

steps:
  prepare:
    run: |
      echo "Preparing environment..."
      mkdir -p artifacts
      echo "preparation complete" > artifacts/prep.txt
    inputs: []
    outputs: ["artifacts/prep.txt"]
    env:
      PREP_VAR: "prepare_value"
    attestation:
      type: "setup"
      reproducible: true

  compile:
    run: |
      echo "Compiling project..."
      echo "using global: $GLOBAL_VAR"
      echo "compile result" > artifacts/compile.out
    needs: ["prepare"]
    inputs: ["artifacts/prep.txt", "src/"]
    outputs: ["artifacts/compile.out"]
    timeout_secs: 300
    attestation:
      type: "build"
      reproducible: true
      generate_slsa: true

  unit-test:
    run: |
      echo "Running unit tests..."
      echo "test results" > artifacts/test.xml
    needs: ["compile"]
    inputs: ["artifacts/compile.out"]
    outputs: ["artifacts/test.xml"]
    env:
      TEST_THREADS: "4"
    attestation:
      type: "test"

  integration-test:
    run: |
      echo "Running integration tests..."
      echo "integration test results" > artifacts/integration.xml
    needs: ["compile"]
    inputs: ["artifacts/compile.out"]
    outputs: ["artifacts/integration.xml"]
    timeout_secs: 600
    attestation:
      type: "integration-test"

  security-scan:
    run: |
      echo "Running security scan..."
      echo "security scan results" > artifacts/security.json
    needs: ["compile"]
    inputs: ["artifacts/compile.out"]
    outputs: ["artifacts/security.json"]
    attestation:
      type: "security-scan"
      verify_chain: true

  package:
    run: |
      echo "Packaging application..."
      echo "packaged app" > artifacts/app.tar.gz
    needs: ["unit-test", "integration-test", "security-scan"]
    inputs: ["artifacts/compile.out", "artifacts/test.xml", "artifacts/integration.xml", "artifacts/security.json"]
    outputs: ["artifacts/app.tar.gz"]
    attestation:
      type: "package"
      generate_slsa: true

  deploy-staging:
    run: |
      echo "Deploying to staging..."
      echo "deployment complete" > artifacts/staging-deploy.log
    needs: ["package"]
    inputs: ["artifacts/app.tar.gz"]
    outputs: ["artifacts/staging-deploy.log"]
    env:
      DEPLOY_ENV: "staging"
      DEPLOY_TIMEOUT: "300"
    attestation:
      type: "deploy"
      verify_chain: true
"#;

    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", complex_pipeline)?;

    // Load and validate the complex pipeline
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;

    // Verify pipeline structure
    assert_eq!(pipeline.version, "0.1");
    assert_eq!(
        pipeline.name.as_ref().unwrap(),
        "complex-integration-pipeline"
    );
    assert_eq!(pipeline.steps.len(), 7);

    // Verify global environment variables
    assert_eq!(
        pipeline.env.get("GLOBAL_VAR"),
        Some(&"global_value".to_string())
    );
    assert_eq!(
        pipeline.env.get("BUILD_ENV"),
        Some(&"integration".to_string())
    );

    // Verify attestation configuration
    assert!(pipeline.attestation.sign_all_steps);
    assert!(pipeline.attestation.verify_dependencies);
    assert!(pipeline.attestation.require_reproducible);

    // Verify specific steps
    let prepare_step = pipeline.steps.get("prepare").unwrap();
    assert!(prepare_step.needs.is_none());
    assert_eq!(prepare_step.outputs.len(), 1);
    assert!(prepare_step.env.is_some());

    let compile_step = pipeline.steps.get("compile").unwrap();
    assert_eq!(
        compile_step.needs.as_ref().unwrap(),
        &vec!["prepare".to_string()]
    );
    assert_eq!(compile_step.timeout_secs, Some(300));

    let package_step = pipeline.steps.get("package").unwrap();
    let package_deps = package_step.needs.as_ref().unwrap();
    assert!(package_deps.contains(&"unit-test".to_string()));
    assert!(package_deps.contains(&"integration-test".to_string()));
    assert!(package_deps.contains(&"security-scan".to_string()));
    assert_eq!(package_deps.len(), 3);

    // Test environment variable merging
    let effective_env = prepare_step.effective_env(&pipeline.env);
    assert_eq!(
        effective_env.get("GLOBAL_VAR"),
        Some(&"global_value".to_string())
    );
    assert_eq!(
        effective_env.get("PREP_VAR"),
        Some(&"prepare_value".to_string())
    );

    // Test pipeline visualization
    pipeline.print_graph();
    pipeline.print_dot();
    assert!(pipeline.print_json().is_ok());

    Ok(())
}

#[tokio::test]
async fn test_pipeline_validation_comprehensive() -> Result<()> {
    // Test 1: Valid pipeline with complex dependencies
    let valid_complex = r#"
version: "0.1"
name: "validation-test"

steps:
  a:
    run: "echo a"
  b:
    run: "echo b"
    needs: ["a"]
  c:
    run: "echo c"
    needs: ["a"]
  d:
    run: "echo d"
    needs: ["b", "c"]
  e:
    run: "echo e"
    needs: ["d"]
"#;

    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", valid_complex)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;
    assert!(
        result.is_ok(),
        "Valid complex pipeline should pass validation"
    );

    // Test 2: Circular dependency detection
    let circular_deps = vec![
        // Simple cycle
        r#"
version: "0.1"
name: "circular-simple"
steps:
  a:
    run: "echo a"
    needs: ["b"]
  b:
    run: "echo b"
    needs: ["a"]
"#,
        // Complex cycle
        r#"
version: "0.1"
name: "circular-complex"
steps:
  a:
    run: "echo a"
    needs: ["c"]
  b:
    run: "echo b"
    needs: ["a"]
  c:
    run: "echo c"
    needs: ["b"]
"#,
        // Self-reference
        r#"
version: "0.1"
name: "self-reference"
steps:
  a:
    run: "echo a"
    needs: ["a"]
"#,
    ];

    for (i, circular_pipeline) in circular_deps.iter().enumerate() {
        let mut temp_file = NamedTempFile::new()?;
        write!(temp_file, "{}", circular_pipeline)?;
        let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;
        assert!(
            result.is_err(),
            "Circular dependency {} should be detected",
            i + 1
        );
    }

    // Test 3: Missing version
    let no_version = r#"
name: "no-version"
steps:
  a:
    run: "echo a"
"#;

    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", no_version)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;
    assert!(result.is_err(), "Missing version should fail validation");

    // Test 4: Empty version
    let empty_version = r#"
version: ""
name: "empty-version"
steps:
  a:
    run: "echo a"
"#;

    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", empty_version)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;
    assert!(result.is_err(), "Empty version should fail validation");

    // Test 5: No steps
    let no_steps = r#"
version: "0.1"
name: "no-steps"
steps: {}
"#;

    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", no_steps)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;
    assert!(
        result.is_err(),
        "Pipeline with no steps should fail validation"
    );

    Ok(())
}

#[tokio::test]
async fn test_step_validation_edge_cases() -> Result<()> {
    // Test valid step configurations
    let valid_steps = vec![
        // Minimal step
        r#"
version: "0.1"
name: "minimal-step"
steps:
  minimal:
    run: "echo hello"
"#,
        // Step with all optional fields
        r#"
version: "0.1"
name: "full-step"
steps:
  full:
    run: "echo full"
    inputs: ["input1.txt", "input2.txt"]
    outputs: ["output1.txt", "output2.txt"]
    needs: []
    env:
      STEP_VAR: "value"
    working_dir: "subdir"
    image: "alpine:latest"
    cache: false
    timeout_secs: 120
    attestation:
      type: "custom"
      reproducible: false
      generate_slsa: false
      verify_chain: true
"#,
    ];

    for (i, valid_step) in valid_steps.iter().enumerate() {
        let mut temp_file = NamedTempFile::new()?;
        write!(temp_file, "{}", valid_step)?;
        let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;
        assert!(
            result.is_ok(),
            "Valid step configuration {} should pass",
            i + 1
        );
    }

    // Test invalid step configurations
    let invalid_steps = vec![
        // Empty run command
        r#"
version: "0.1"
name: "empty-run"
steps:
  empty:
    run: ""
"#,
        // Whitespace-only run command
        r#"
version: "0.1"
name: "whitespace-run"
steps:
  whitespace:
    run: "   \n\t   "
"#,
        // Absolute input path
        r#"
version: "0.1"
name: "absolute-input"
steps:
  absolute:
    run: "echo test"
    inputs: ["/absolute/path/input.txt"]
"#,
        // Absolute output path
        r#"
version: "0.1"
name: "absolute-output"
steps:
  absolute:
    run: "echo test"
    outputs: ["/absolute/path/output.txt"]
"#,
        // Unknown dependency
        r#"
version: "0.1"
name: "unknown-dep"
steps:
  dependent:
    run: "echo dependent"
    needs: ["unknown_step"]
"#,
    ];

    for (i, invalid_step) in invalid_steps.iter().enumerate() {
        let mut temp_file = NamedTempFile::new()?;
        write!(temp_file, "{}", invalid_step)?;
        let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;
        assert!(
            result.is_err(),
            "Invalid step configuration {} should fail",
            i + 1
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_environment_variable_handling() -> Result<()> {
    let env_pipeline = r#"
version: "0.1"
name: "env-test"

env:
  GLOBAL_VAR: "global"
  OVERRIDE_TEST: "global_value"
  EMPTY_VAR: ""

steps:
  step1:
    run: "echo step1"
    env:
      STEP_VAR: "step1_value"
      OVERRIDE_TEST: "step1_overridden"
  
  step2:
    run: "echo step2"
    env:
      STEP_VAR: "step2_value"
  
  step3:
    run: "echo step3"
    # No step-specific environment
"#;

    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", env_pipeline)?;

    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;

    // Test step1 environment
    let step1 = pipeline.steps.get("step1").unwrap();
    let step1_env = step1.effective_env(&pipeline.env);

    assert_eq!(step1_env.get("GLOBAL_VAR"), Some(&"global".to_string()));
    assert_eq!(step1_env.get("STEP_VAR"), Some(&"step1_value".to_string()));
    assert_eq!(
        step1_env.get("OVERRIDE_TEST"),
        Some(&"step1_overridden".to_string())
    );
    assert_eq!(step1_env.get("EMPTY_VAR"), Some(&"".to_string()));

    // Test step2 environment
    let step2 = pipeline.steps.get("step2").unwrap();
    let step2_env = step2.effective_env(&pipeline.env);

    assert_eq!(step2_env.get("GLOBAL_VAR"), Some(&"global".to_string()));
    assert_eq!(step2_env.get("STEP_VAR"), Some(&"step2_value".to_string()));
    assert_eq!(
        step2_env.get("OVERRIDE_TEST"),
        Some(&"global_value".to_string())
    );

    // Test step3 environment (no step-specific vars)
    let step3 = pipeline.steps.get("step3").unwrap();
    let step3_env = step3.effective_env(&pipeline.env);

    assert_eq!(step3_env.get("GLOBAL_VAR"), Some(&"global".to_string()));
    assert_eq!(
        step3_env.get("OVERRIDE_TEST"),
        Some(&"global_value".to_string())
    );
    assert!(step3_env.get("STEP_VAR").is_none());

    Ok(())
}

#[tokio::test]
async fn test_attestation_configuration() -> Result<()> {
    let attestation_pipeline = r#"
version: "0.1"
name: "attestation-test"

attestation:
  sign_all_steps: true
  verify_dependencies: true
  require_reproducible: false

steps:
  build:
    run: "cargo build"
    attestation:
      type: "build"
      reproducible: true
      generate_slsa: true
      verify_chain: false
  
  test:
    run: "cargo test"
    attestation:
      type: "test"
      reproducible: false
      generate_slsa: false
      verify_chain: true
  
  package:
    run: "tar -czf app.tar.gz target/"
    # Uses pipeline-level attestation defaults
"#;

    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", attestation_pipeline)?;

    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;

    // Check pipeline-level attestation
    assert!(pipeline.attestation.sign_all_steps);
    assert!(pipeline.attestation.verify_dependencies);
    assert!(!pipeline.attestation.require_reproducible);

    // Check step-level attestation
    let build_step = pipeline.steps.get("build").unwrap();
    let build_attestation = build_step.attestation.as_ref().unwrap();
    assert_eq!(build_attestation.attestation_type, "build");
    assert!(build_attestation.reproducible);
    assert!(build_attestation.generate_slsa);
    assert!(!build_attestation.verify_chain);

    let test_step = pipeline.steps.get("test").unwrap();
    let test_attestation = test_step.attestation.as_ref().unwrap();
    assert_eq!(test_attestation.attestation_type, "test");
    assert!(!test_attestation.reproducible);
    assert!(!test_attestation.generate_slsa);
    assert!(test_attestation.verify_chain);

    let package_step = pipeline.steps.get("package").unwrap();
    assert!(package_step.attestation.is_none());

    Ok(())
}

#[tokio::test]
async fn test_malformed_yaml_handling() -> Result<()> {
    let malformed_yamls = vec![
        // Invalid YAML syntax
        r#"
version: "0.1"
name: test
steps:
  step1:
    run: echo hello
    invalid_field: [unclosed array
"#,
        // Missing required fields
        r#"
name: "missing-version"
steps:
  step1:
    # Missing 'run' field
    inputs: []
"#,
        // Invalid structure
        r#"
version: "0.1"
name: "invalid-structure"
steps: "this should be an object"
"#,
        // Invalid data types
        r#"
version: 0.1
name: "invalid-types"
steps:
  step1:
    run: 123
    inputs: "should be array"
    timeout_secs: "should be number"
"#,
    ];

    for (i, malformed_yaml) in malformed_yamls.iter().enumerate() {
        let mut temp_file = NamedTempFile::new()?;
        write!(temp_file, "{}", malformed_yaml)?;

        let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;
        assert!(
            result.is_err(),
            "Malformed YAML {} should fail to parse",
            i + 1
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_large_pipeline_performance() -> Result<()> {
    // Generate a large pipeline with many steps
    let mut pipeline_yaml = String::from(
        r#"
version: "0.1"
name: "large-pipeline"

env:
  GLOBAL_VAR: "value"

attestation:
  sign_all_steps: true

steps:
"#,
    );

    // Create 100 steps with dependencies
    for i in 0..100 {
        let step_yaml = if i == 0 {
            format!(
                r#"  step_{i}:
    run: "echo 'Step {i}'"
    inputs: []
    outputs: ["output_{i}.txt"]
    env:
      STEP_ID: "{i}"
"#
            )
        } else {
            format!(
                r#"  step_{i}:
    run: "echo 'Step {i}'"
    needs: ["step_{prev}"]
    inputs: ["output_{prev}.txt"]
    outputs: ["output_{i}.txt"]
    env:
      STEP_ID: "{i}"
"#,
                prev = i - 1
            )
        };
        pipeline_yaml.push_str(&step_yaml);
    }

    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", pipeline_yaml)?;

    // Measure parsing time
    let start = std::time::Instant::now();
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let parse_duration = start.elapsed();

    // Verify the pipeline was parsed correctly
    assert_eq!(pipeline.steps.len(), 100);
    assert_eq!(pipeline.name.unwrap(), "large-pipeline");

    // Verify dependency chain
    for i in 1..100 {
        let step = pipeline.steps.get(&format!("step_{}", i)).unwrap();
        let deps = step.needs.as_ref().unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0], format!("step_{}", i - 1));
    }

    // Parsing should be reasonably fast (less than 1 second for 100 steps)
    assert!(
        parse_duration.as_millis() < 1000,
        "Large pipeline parsing took too long: {:?}",
        parse_duration
    );

    println!("Large pipeline (100 steps) parsed in {:?}", parse_duration);

    Ok(())
}
