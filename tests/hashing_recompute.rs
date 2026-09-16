//! Issue #1, acceptance criterion 10: a receipt's input/output hashes are
//! recomputable by an independent caller of the public hashing API,
//! byte-identical to what the executor recorded.

use std::path::PathBuf;

use attest::executor::{Executor, ExecutorConfig};
use attest::hashing;
use attest::pipeline::Pipeline;
use attest::storage::Storage;

#[tokio::test]
async fn receipt_hashes_are_recomputable() {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join("in.txt"), "payload").unwrap();

    // The executor resolves declared paths against the process working
    // directory; pin it to the temp workspace for the duration of the run.
    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(workspace.path()).unwrap();

    let yaml = r#"
version: "1.0"
steps:
  copy:
    run: "cat in.txt > out.txt"
    inputs: ["in.txt"]
    outputs: ["out.txt"]
    cache: false
"#;
    let pipeline: Pipeline = serde_yaml::from_str(yaml).unwrap();
    pipeline.validate().unwrap();

    let mut storage = Storage::new(&workspace.path().join(".attest")).unwrap();
    let config = ExecutorConfig {
        isolated: false,
        sign_results: false,
        max_parallel: 1,
        deterministic: true,
        container_image: None,
        container_runtime: None,
        sandbox_config: None,
        hermetic_env: false,
    };
    let mut executor = Executor::new(&mut storage, config).unwrap();
    let receipt = executor.run(&pipeline).await.unwrap();

    std::env::set_current_dir(&original_dir).unwrap();

    assert_eq!(receipt.steps.len(), 1);
    let step_result = &receipt.steps[0];
    assert_eq!(step_result.exit_code, 0);

    let recomputed_input = hashing::hash_inputs(
        workspace.path(),
        "copy",
        "cat in.txt > out.txt",
        &[PathBuf::from("in.txt")],
    )
    .unwrap();
    let recomputed_output =
        hashing::hash_outputs(workspace.path(), "copy", &[PathBuf::from("out.txt")]).unwrap();

    assert_eq!(step_result.input_hash, recomputed_input);
    assert_eq!(step_result.output_hash, recomputed_output);
}
