//! Comprehensive tests for pipeline validation and cycle detection

use anyhow::Result;
use attest::pipeline::{ExecutionDAG, Pipeline};
use std::io::Write;
use tempfile::NamedTempFile;

fn create_temp_pipeline(yaml_content: &str) -> Result<NamedTempFile> {
    let mut temp_file = NamedTempFile::new()?;
    write!(temp_file, "{}", yaml_content)?;
    Ok(temp_file)
}

#[tokio::test]
async fn test_cycle_detection_simple() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "cycle-test"

steps:
  a:
    run: "echo a"
    needs: ["b"]
  
  b:
    run: "echo b" 
    needs: ["a"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Cycle detected"));
    assert!(error_msg.contains("a -> b -> a") || error_msg.contains("b -> a -> b"));

    Ok(())
}

#[tokio::test]
async fn test_cycle_detection_complex() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "complex-cycle"

steps:
  build:
    run: "make build"
    needs: ["test"]
  
  test:
    run: "make test"
    needs: ["deploy"]
  
  deploy:
    run: "make deploy"
    needs: ["package"]
    
  package:
    run: "make package"
    needs: ["build"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Cycle detected"));

    Ok(())
}

#[tokio::test]
async fn test_self_dependency() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "self-dep"

steps:
  selfish:
    run: "echo hello"
    needs: ["selfish"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;

    // NOTE: `Pipeline::validate` (src/pipeline/parser.rs), called from within
    // `Pipeline::load`, builds an `ExecutionDAG` (src/pipeline/dag.rs) before
    // any step-level checks run, and DAG construction itself detects cycles -
    // including a single step depending on itself. So a self-dependency now
    // fails at `Pipeline::load` time with a "Cycle detected" error, rather
    // than loading successfully and being caught later by
    // `validate_comprehensive`'s "cannot depend on itself" check.
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Cycle detected") || err_msg.contains("selfish"),
        "unexpected error message: {}",
        err_msg
    );

    Ok(())
}

#[tokio::test]
async fn test_unknown_dependency() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "unknown-dep"

steps:
  dependent:
    run: "echo hello"
    needs: ["nonexistent"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unknown step"));

    Ok(())
}

#[tokio::test]
async fn test_comprehensive_validation_success() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "good-pipeline"

env:
  BUILD_MODE: "release"

attestation:
  sign_all_steps: true
  verify_dependencies: true

steps:
  lint:
    run: "cargo clippy"
    inputs: ["src/"]
    outputs: []
    attestation:
      type: "code-quality"
      reproducible: true

  build:
    run: "cargo build --release"
    needs: ["lint"]
    inputs: ["src/", "Cargo.toml"]
    outputs: ["target/release/"]
    env:
      RUSTFLAGS: "-C target-cpu=native"
    cache: true
    timeout_secs: 300
    attestation:
      type: "build"
      reproducible: true
      generate_slsa: true

  test:
    run: "cargo test"
    needs: ["build"]
    inputs: ["src/", "tests/"]
    outputs: ["target/debug/deps/"]
    image: "rust:1.75"
    attestation:
      type: "test"
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let result = pipeline.validate_comprehensive();

    assert!(result.is_valid);
    // Should have some informational messages
    assert!(!result.info.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_validation_warnings() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "warning-pipeline"

env:
  API_TOKEN: "hardcoded-secret-123456789"

steps:
  dangerous:
    run: "rm -rf /tmp/* && chmod 777 file.txt"
    inputs: ["/absolute/path"]
    outputs: ["target/"]
    image: "latest"
    env:
      PASSWORD: "secret123"
    timeout_secs: 100000
    attestation:
      type: ""

  reproducible-but-date:
    run: "echo $(date) > timestamp.txt"
    attestation:
      type: "build"
      reproducible: true
      generate_slsa: true
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;

    // Should fail due to absolute paths and empty attestation type
    assert!(result.is_err());

    // But let's test the comprehensive validation on a corrected version
    let corrected_yaml = r#"
version: "0.1"
name: "warning-pipeline"

env:
  API_TOKEN: "hardcoded-secret-123456789"

steps:
  dangerous:
    run: "rm -rf /tmp/* && chmod 777 file.txt"
    inputs: ["relative/path"]
    outputs: ["target/"]
    image: "latest"
    env:
      PASSWORD: "secret123"
    timeout_secs: 100000
    attestation:
      type: "cleanup"

  reproducible-but-date:
    run: "echo $(date) > timestamp.txt"
    attestation:
      type: "build"
      reproducible: true
      generate_slsa: true
"#;

    let temp_file2 = create_temp_pipeline(corrected_yaml)?;
    let pipeline = Pipeline::load(temp_file2.path().to_str().unwrap()).await?;
    let result = pipeline.validate_comprehensive();

    // Should have many warnings
    assert!(!result.warnings.is_empty());

    // Check for specific warnings
    let warning_messages: Vec<&str> = result.warnings.iter().map(|w| w.message.as_str()).collect();

    assert!(warning_messages
        .iter()
        .any(|m| m.contains("dangerous command")));
    assert!(warning_messages.iter().any(|m| m.contains("latest")));
    assert!(warning_messages.iter().any(|m| m.contains("PASSWORD")));
    assert!(warning_messages
        .iter()
        .any(|m| m.contains("Very long timeout")));
    assert!(warning_messages
        .iter()
        .any(|m| m.contains("reproducible but uses date")));

    Ok(())
}

#[tokio::test]
async fn test_dag_analysis() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "analysis-test"

steps:
  # Parallel group 1
  frontend:
    run: "npm run build"
    inputs: ["src/frontend/"]
    outputs: ["dist/frontend/"]

  backend:
    run: "cargo build"
    inputs: ["src/backend/"]
    outputs: ["target/release/"]

  docs:
    run: "mdbook build"
    inputs: ["docs/"]
    outputs: ["book/"]

  # Group 2 - depends on all above
  integration:
    run: "integration-test"
    needs: ["frontend", "backend", "docs"]
    inputs: ["dist/", "target/", "book/"]
    outputs: ["test-results/"]

  # Group 3 - final deployment
  deploy:
    run: "deploy-all"
    needs: ["integration"]
    inputs: ["dist/", "target/", "book/"]
    outputs: []
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let analysis = dag.analyze();

    // Check basic analysis
    assert_eq!(analysis.total_nodes, 5);
    assert_eq!(analysis.max_depth, 2); // 0: frontend/backend/docs, 1: integration, 2: deploy
    assert!(!analysis.is_linear); // Has parallelization

    // Check root nodes (no dependencies)
    assert_eq!(analysis.root_nodes.len(), 3);
    assert!(analysis.root_nodes.contains(&"frontend".to_string()));
    assert!(analysis.root_nodes.contains(&"backend".to_string()));
    assert!(analysis.root_nodes.contains(&"docs".to_string()));

    // Check leaf nodes (no dependents)
    assert_eq!(analysis.leaf_nodes.len(), 1);
    assert!(analysis.leaf_nodes.contains(&"deploy".to_string()));

    // Check parallelizable groups
    assert_eq!(analysis.parallelizable_groups.len(), 3);
    assert_eq!(analysis.parallelizable_groups[0].len(), 3); // frontend, backend, docs
    assert_eq!(analysis.parallelizable_groups[1].len(), 1); // integration
    assert_eq!(analysis.parallelizable_groups[2].len(), 1); // deploy

    Ok(())
}

#[tokio::test]
async fn test_linear_pipeline_detection() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "linear-test"

steps:
  step1:
    run: "echo 1"

  step2:
    run: "echo 2"
    needs: ["step1"]

  step3:
    run: "echo 3"  
    needs: ["step2"]

  step4:
    run: "echo 4"
    needs: ["step3"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let analysis = dag.analyze();

    assert!(analysis.is_linear);
    assert_eq!(analysis.max_depth, 3);
    assert_eq!(analysis.parallelizable_groups.len(), 4); // Each step in its own group

    Ok(())
}

#[tokio::test]
async fn test_topological_sort() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "topo-sort"

steps:
  c:
    run: "echo c"
    needs: ["a", "b"]

  a:
    run: "echo a"

  b:
    run: "echo b"
    needs: ["a"]

  d:
    run: "echo d"
    needs: ["c"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;
    let sorted = dag.topological_sort()?;

    // Check that dependencies come before dependents
    let a_pos = sorted.iter().position(|x| x == "a").unwrap();
    let b_pos = sorted.iter().position(|x| x == "b").unwrap();
    let c_pos = sorted.iter().position(|x| x == "c").unwrap();
    let d_pos = sorted.iter().position(|x| x == "d").unwrap();

    assert!(a_pos < b_pos); // a before b
    assert!(a_pos < c_pos); // a before c
    assert!(b_pos < c_pos); // b before c
    assert!(c_pos < d_pos); // c before d

    Ok(())
}

/// The fixture values below are shaped to trigger the validator's
/// prefix rules (`sk-`, `ghp_`) while being unmistakably synthetic. An
/// earlier version used realistic-looking tokens, which is a poor idea in
/// a public repository: secret scanners flag them, and every downstream
/// consumer of this source inherits a false positive.
#[tokio::test]
async fn test_security_validation() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "security-test"

env:
  DATABASE_PASSWORD: "placeholder"
  API_KEY: "sk-EXAMPLE-VALUE-NOT-A-REAL-KEY"

steps:
  injection-risk:
    run: "echo $1 && curl $URL"
    env:
      SECRET_TOKEN: "ghp_EXAMPLE_VALUE_NOT_A_REAL_TOKEN"

  network-access:
    run: "wget https://example.com/file && curl -X POST http://api.example.com"

  permission-changes:
    run: "chmod 755 script.sh && chown user:group file.txt"
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let result = pipeline.validate_comprehensive();

    // Should have multiple security warnings
    let security_warnings: Vec<&str> = result
        .warnings
        .iter()
        .filter(|w| {
            w.message.contains("shell injection")
                || w.message.contains("Sensitive")
                || w.message.contains("permission")
                || w.message.contains("hardcoded secret")
        })
        .map(|w| w.message.as_str())
        .collect();

    assert!(!security_warnings.is_empty());

    // Should also have info about network access
    let network_info: Vec<&str> = result
        .info
        .iter()
        .filter(|i| i.message.contains("Network access"))
        .map(|i| i.message.as_str())
        .collect();

    assert!(!network_info.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_performance_validation() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "performance-test"

steps:
  inefficient-search:
    run: "find / -name '*.log' | grep error"

  no-cache-many-inputs:
    run: "process-files"
    inputs: ["file1", "file2", "file3", "file4", "file5", "file6"]
    cache: false

  large-outputs:
    run: "build-project"
    outputs: ["target/", "node_modules/"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let result = pipeline.validate_comprehensive();

    // Should have performance suggestions
    let perf_info: Vec<&str> = result
        .info
        .iter()
        .filter(|i| {
            i.message.contains("performance")
                || i.message.contains("System-wide search")
                || i.message.contains("Caching disabled")
                || i.message.contains("Large directory")
        })
        .map(|i| i.message.as_str())
        .collect();

    assert!(!perf_info.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_attestation_validation() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "attestation-test"

attestation:
  require_reproducible: true
  sign_all_steps: false  # Warning: require_reproducible without signing

steps:
  no-outputs-slsa:
    run: "echo hello"
    attestation:
      type: "build"
      generate_slsa: true  # Warning: SLSA without outputs

  empty-type:
    run: "echo world"
    attestation:
      type: ""  # Error: empty type

  multiple-same-type:
    run: "echo build1"
    attestation:
      type: "build"

  another-build:
    run: "echo build2"
    attestation:
      type: "build"
"#;

    let temp_file = create_temp_pipeline(yaml)?;

    // NOTE: an empty `attestation.type` is not checked by `Step::validate`
    // (src/pipeline/step.rs) or `Pipeline::validate` (src/pipeline/parser.rs),
    // so `Pipeline::load` itself succeeds even with `type: ""`. The check
    // ("Attestation type is required") lives in the separate, opt-in
    // `Pipeline::validate_comprehensive` (src/pipeline/validation.rs), so
    // that's what this test exercises instead of expecting `load` to fail.
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let result = pipeline.validate_comprehensive();

    assert!(!result.is_valid);
    assert!(result
        .errors
        .iter()
        .any(|e| e.message.contains("Attestation type is required")));

    // Test with corrected version
    let corrected_yaml = r#"
version: "0.1"
name: "attestation-test"

attestation:
  require_reproducible: true
  sign_all_steps: false

steps:
  no-outputs-slsa:
    run: "echo hello"
    attestation:
      type: "build"
      generate_slsa: true

  valid-type:
    run: "echo world"
    attestation:
      type: "test"

  multiple-same-type:
    run: "echo build1"
    attestation:
      type: "build"

  another-build:
    run: "echo build2"
    attestation:
      type: "build"
"#;

    let temp_file2 = create_temp_pipeline(corrected_yaml)?;
    let pipeline = Pipeline::load(temp_file2.path().to_str().unwrap()).await?;
    let result = pipeline.validate_comprehensive();

    // Should have warnings about attestation configuration
    let attestation_warnings: Vec<&str> = result
        .warnings
        .iter()
        .filter(|w| {
            w.message.contains("without signing")
                || w.message.contains("SLSA generation enabled but no outputs")
        })
        .map(|w| w.message.as_str())
        .collect();

    assert!(!attestation_warnings.is_empty());

    // Should have info about type distribution
    let type_info: Vec<&str> = result
        .info
        .iter()
        .filter(|i| i.message.contains("Attestation type 'build' used by"))
        .map(|i| i.message.as_str())
        .collect();

    assert!(!type_info.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_dag_dependencies_and_dependents() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "deps-test"

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
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let dag = ExecutionDAG::build(&pipeline)?;

    // Test dependencies (what a node depends on)
    assert_eq!(dag.get_dependencies("a").len(), 0);
    assert_eq!(dag.get_dependencies("b"), vec!["a"]);
    assert_eq!(dag.get_dependencies("c"), vec!["a"]);

    let d_deps = dag.get_dependencies("d");
    assert_eq!(d_deps.len(), 2);
    assert!(d_deps.contains(&"b".to_string()));
    assert!(d_deps.contains(&"c".to_string()));

    // Test dependents (what depends on a node)
    let a_dependents = dag.get_dependents("a");
    assert_eq!(a_dependents.len(), 2);
    assert!(a_dependents.contains(&"b".to_string()));
    assert!(a_dependents.contains(&"c".to_string()));

    assert_eq!(dag.get_dependents("b"), vec!["d"]);
    assert_eq!(dag.get_dependents("c"), vec!["d"]);
    assert_eq!(dag.get_dependents("d").len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_validation_error_structure() -> Result<()> {
    let yaml = r#"
version: ""
name: "error-structure-test"

steps:
  bad-step:
    run: ""
    inputs: ["/absolute"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let result = Pipeline::load(temp_file.path().to_str().unwrap()).await;

    // Should fail during basic validation
    assert!(result.is_err());

    // Test with version fixed but other errors
    let partial_yaml = r#"
version: "0.1"
name: "error-structure-test"

steps:
  bad-step:
    run: ""
    inputs: ["/absolute"]
"#;

    let temp_file2 = create_temp_pipeline(partial_yaml)?;
    let result2 = Pipeline::load(temp_file2.path().to_str().unwrap()).await;

    // Should still fail due to empty run and absolute path
    assert!(result2.is_err());

    // Test comprehensive validation on a version that loads
    let loadable_yaml = r#"
version: "0.1"
name: "error-structure-test"

steps:
  bad-step:
    run: "   "
    inputs: ["relative"]
"#;

    let temp_file3 = create_temp_pipeline(loadable_yaml)?;
    let result3 = Pipeline::load(temp_file3.path().to_str().unwrap()).await;

    // Should still fail due to empty run command
    assert!(result3.is_err());

    // Finally test with a valid command
    let valid_yaml = r#"
version: "0.1"  
name: "error-structure-test"

steps:
  good-step:
    run: "echo hello"
    inputs: ["relative"]
"#;

    let temp_file4 = create_temp_pipeline(valid_yaml)?;
    let pipeline = Pipeline::load(temp_file4.path().to_str().unwrap()).await?;
    let result = pipeline.validate_comprehensive();

    // Should be valid now
    assert!(result.is_valid);
    assert!(result.errors.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_excessive_dependencies_warning() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "excessive-deps"

steps:
  dep1: { run: "echo 1" }
  dep2: { run: "echo 2" }
  dep3: { run: "echo 3" }
  dep4: { run: "echo 4" }
  dep5: { run: "echo 5" }
  dep6: { run: "echo 6" }
  dep7: { run: "echo 7" }
  dep8: { run: "echo 8" }
  dep9: { run: "echo 9" }
  dep10: { run: "echo 10" }
  dep11: { run: "echo 11" }

  many-deps:
    run: "echo many"
    needs: ["dep1", "dep2", "dep3", "dep4", "dep5", "dep6", "dep7", "dep8", "dep9", "dep10", "dep11"]
"#;

    let temp_file = create_temp_pipeline(yaml)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let result = pipeline.validate_comprehensive();

    // Should have warning about excessive dependencies
    assert!(result.warnings.iter().any(
        |w| w.message.contains("many dependencies") && w.step == Some("many-deps".to_string())
    ));

    Ok(())
}

#[tokio::test]
async fn test_deep_pipeline_warning() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "deep-pipeline"

steps:
"#;

    // Create a very deep pipeline programmatically
    let mut yaml_content = String::from(yaml);

    for i in 0..25 {
        if i == 0 {
            yaml_content.push_str(&format!("  step{}: {{ run: \"echo {}\" }}\n", i, i));
        } else {
            yaml_content.push_str(&format!(
                "  step{}: {{ run: \"echo {}\", needs: [\"step{}\"] }}\n",
                i,
                i,
                i - 1
            ));
        }
    }

    let temp_file = create_temp_pipeline(&yaml_content)?;
    let pipeline = Pipeline::load(temp_file.path().to_str().unwrap()).await?;
    let result = pipeline.validate_comprehensive();

    // Should have warning about deep pipeline
    assert!(result
        .warnings
        .iter()
        .any(|w| w.message.contains("Very deep pipeline")));

    Ok(())
}

/// A key `attest.yaml` does not define must be rejected, not ignored.
///
/// Before `deny_unknown_fields`, a misspelled `outputs:` parsed happily and
/// the step declared no outputs at all — the run succeeded, the receipt was
/// signed, and it silently said nothing about the artifact the author
/// believed they had attested. Failing loudly on the typo is the whole
/// point.
#[tokio::test]
async fn test_misspelled_step_key_is_rejected() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "typo-test"

steps:
  build:
    run: "true"
    inputs: []
    ouputs: ["target/app"]
"#;
    let file = create_temp_pipeline(yaml)?;
    let err = Pipeline::load(file.path().to_str().expect("temp path is utf-8"))
        .await
        .expect_err("a misspelled key must not parse");
    let message = format!("{err:#}");
    assert!(
        message.contains("ouputs"),
        "the error must name the offending key, got: {message}"
    );
    Ok(())
}

/// The same rule at the top level of the document.
#[tokio::test]
async fn test_unknown_top_level_key_is_rejected() -> Result<()> {
    let yaml = r#"
version: "0.1"
name: "unknown-key-test"
mode: "formal-proof"

steps:
  build:
    run: "true"
"#;
    let file = create_temp_pipeline(yaml)?;
    let err = Pipeline::load(file.path().to_str().expect("temp path is utf-8"))
        .await
        .expect_err("an unsupported top-level key must not parse");
    assert!(
        format!("{err:#}").contains("mode"),
        "the error must name the offending key"
    );
    Ok(())
}
