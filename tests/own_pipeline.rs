//! The project's own pipeline and shipped templates must parse.
//!
//! `attest.yaml` at the repository root is what CI runs and what every
//! reader copies first. Since the parser rejects unknown keys, any change to
//! the schema can make it unloadable — and the failure would surface as a
//! red CI run on an unrelated pull request rather than on the change that
//! caused it.

use attest::pipeline::Pipeline;

fn load(relative: &str) -> Pipeline {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{path} does not parse: {e}"))
}

#[test]
fn the_projects_own_pipeline_parses() {
    let pipeline = load("attest.yaml");
    assert_eq!(pipeline.name.as_deref(), Some("attest-ci"));
    for step in ["format-check", "clippy", "test", "build-release"] {
        assert!(pipeline.steps.contains_key(step), "missing step {step}");
    }
}

#[test]
fn the_shipped_sample_parses() {
    let pipeline = load("templates/sample.yaml");
    assert!(!pipeline.steps.is_empty());
}

/// Every step that resolves dependencies must declare the lockfile.
///
/// Without it a dependency change leaves the input hash untouched: the cache
/// serves a stale result, and the receipt describes a build that is not the
/// one that ran. This is the project's own pipeline making the claim its
/// tool exists to check.
#[test]
fn steps_that_resolve_dependencies_declare_the_lockfile() {
    let pipeline = load("attest.yaml");
    for (name, step) in &pipeline.steps {
        let resolves = step.run.contains("cargo test")
            || step.run.contains("cargo build")
            || step.run.contains("cargo clippy");
        if !resolves {
            continue;
        }
        assert!(
            step.inputs.iter().any(|p| p.ends_with("Cargo.lock")),
            "step '{name}' runs `{}` but does not declare Cargo.lock",
            step.run
        );
    }
}
