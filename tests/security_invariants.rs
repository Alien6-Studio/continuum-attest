//! The security properties attest claims, written as the attacks that would
//! break them.
//!
//! Every defect this file guards against was real. Each was found after the
//! suite was green, because a passing test suite only covers the failures
//! somebody thought of. So the rule for this file is narrow and strict:
//!
//!   a test belongs here only if it *performs the forgery* and asserts it
//!   fails. Not "the happy path still works" -- an attacker's move, refused.
//!
//! Two consequences. Deleting a check here must break a test, which
//! `tools/mutation-gate.sh` proves by breaking each protection in turn and
//! requiring the matching test to fail. And a test that cannot be made to
//! fail by any mutation is not protecting anything, and should be deleted
//! rather than counted.
//!
//! Naming: `forging_<what>_is_refused`, so a reader scanning the list reads
//! a catalogue of attacks rather than a catalogue of functions.

use std::path::PathBuf;

use attest::hashing::{hash_outputs, output_manifest};

// ---------------------------------------------------------------------------
// Manifest encoding: distinct trees must have distinct hashes.
// ---------------------------------------------------------------------------

/// A manifest is line-delimited and paths are written into it verbatim, so a
/// filename carrying a newline used to close its own entry and open a forged
/// one. A tree of one file and a tree of two files hashed identically, which
/// forges provenance without touching BLAKE3.
#[test]
fn forging_a_manifest_entry_through_a_newline_in_a_filename_is_refused() {
    let content_a = b"content of a";
    let content_b = b"content of b";
    let hash_b = blake3::hash(content_b).to_hex().to_string();

    let tree = tempfile::tempdir().unwrap();
    let forged = format!("a\nf:{hash_b} b");
    std::fs::write(tree.path().join(&forged), content_a).unwrap();

    let result = output_manifest(tree.path(), "s", &[PathBuf::from(&forged)]);
    let err = result.expect_err("a newline in a path must not be hashable");
    let message = err.to_string();
    assert!(
        message.contains("control character"),
        "the refusal should name the cause, got: {message}"
    );
}

/// The same property stated positively, so a future "escape it instead"
/// rewrite is still held to injectivity rather than only to rejection.
#[test]
fn forging_a_collision_between_two_different_trees_is_refused() {
    let content_a = b"content of a";
    let content_b = b"content of b";
    let hash_b = blake3::hash(content_b).to_hex().to_string();

    let one = tempfile::tempdir().unwrap();
    let forged = format!("a\nf:{hash_b} b");
    std::fs::write(one.path().join(&forged), content_a).unwrap();

    let two = tempfile::tempdir().unwrap();
    std::fs::write(two.path().join("a"), content_a).unwrap();
    std::fs::write(two.path().join("b"), content_b).unwrap();

    let forged_hash = hash_outputs(one.path(), "s", &[PathBuf::from(&forged)]);
    let honest_hash = hash_outputs(two.path(), "s", &[PathBuf::from("a"), PathBuf::from("b")]);

    match (forged_hash, honest_hash) {
        // Refusing the input is one way to be injective.
        (Err(_), Ok(_)) => {}
        // Encoding it unambiguously is the other.
        (Ok(forged), Ok(honest)) => assert_ne!(
            forged, honest,
            "a one-file tree and a two-file tree must never share an output hash"
        ),
        (forged, honest) => panic!("unexpected outcome: {forged:?} / {honest:?}"),
    }
}

/// Every control character, not only the newline that happened to be found.
#[test]
fn forging_a_path_with_any_control_character_is_refused() {
    for (name, ch) in [("newline", '\n'), ("carriage return", '\r'), ("tab", '\t')] {
        let tree = tempfile::tempdir().unwrap();
        let path = format!("a{ch}b");
        if std::fs::write(tree.path().join(&path), b"x").is_err() {
            continue; // some filesystems refuse the name outright, which is fine
        }
        assert!(
            output_manifest(tree.path(), "s", &[PathBuf::from(&path)]).is_err(),
            "a path containing a {name} must not be hashable"
        );
    }
}

/// Ordinary paths must keep hashing exactly as before: this fix rejects
/// input, it does not change the encoding, so receipts written by earlier
/// versions stay verifiable.
#[test]
fn an_ordinary_tree_still_hashes_to_its_documented_manifest() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("a"), b"content of a").unwrap();
    std::fs::create_dir(tree.path().join("sub")).unwrap();
    std::fs::write(tree.path().join("sub/b c"), b"content of b").unwrap();

    let manifest = output_manifest(
        tree.path(),
        "s",
        &[PathBuf::from("a"), PathBuf::from("sub")],
    )
    .expect("an ordinary tree hashes");

    // A space in a filename stays legal: the fixed-width `f:<hex> ` prefix
    // leaves no ambiguity about where the path begins.
    assert!(manifest.contains(" sub/b c\n"), "{manifest}");
    assert_eq!(manifest.lines().count(), 3, "header plus two files");
}

// ---------------------------------------------------------------------------
// Execution: the receipt must describe the build that happened.
// ---------------------------------------------------------------------------

fn attest() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("attest").expect("binary builds")
}

fn workspace(pipeline: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    attest()
        .current_dir(dir.path())
        .arg("init")
        .assert()
        .success();
    // init writes its own starter pipeline; replace it with the case at hand.
    std::fs::write(dir.path().join("attest.yaml"), pipeline).unwrap();
    dir
}

/// A step that reads a file, produces its output, then rewrites that file
/// used to have the *rewritten* bytes recorded as its input hash. The
/// artifact came from "before", the receipt attested "after", and
/// verification passed on a pair that never existed together.
#[test]
fn forging_provenance_by_mutating_an_input_mid_step_is_refused() {
    let dir = workspace(
        "version: \"0.1\"\n\
         name: mutation\n\
         steps:\n  \
           build:\n    \
             run: \"cp in.txt out.txt && echo after > in.txt\"\n    \
             inputs: [\"in.txt\"]\n    \
             outputs: [\"out.txt\"]\n",
    );
    std::fs::write(dir.path().join("in.txt"), "before\n").unwrap();

    let output = attest()
        .current_dir(dir.path())
        .arg("run")
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "a step that rewrote its own declared input must not produce a receipt:\n{combined}"
    );
    assert!(
        combined.contains("modified its own declared inputs"),
        "the refusal should name the cause, got:\n{combined}"
    );
}

/// A cache entry is a record of a past run, not evidence that its outputs
/// still exist. Deleting the artifact and running again used to replay the
/// entry: exit zero, a fresh signed receipt, and no file on disk.
#[test]
fn forging_an_attestation_of_a_deleted_artifact_through_the_cache_is_refused() {
    let dir = workspace(
        "version: \"0.1\"\n\
         name: cached\n\
         steps:\n  \
           build:\n    \
             run: \"echo artifact > out.txt\"\n    \
             inputs: [\"in.txt\"]\n    \
             outputs: [\"out.txt\"]\n",
    );
    std::fs::write(dir.path().join("in.txt"), "source\n").unwrap();

    attest()
        .current_dir(dir.path())
        .arg("run")
        .assert()
        .success();
    assert!(dir.path().join("out.txt").exists(), "first run produces it");

    // The artifact disappears; the inputs do not change, so the cache key
    // still matches.
    std::fs::remove_file(dir.path().join("out.txt")).unwrap();

    let output = attest()
        .current_dir(dir.path())
        .arg("run")
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Either the run rebuilds the artifact, or it refuses. What it must
    // never do is succeed while attesting something that is not there.
    if output.status.success() {
        assert!(
            dir.path().join("out.txt").exists(),
            "a successful run must not attest an artifact that does not exist:\n{combined}"
        );
    }
}

// ---------------------------------------------------------------------------
// Encoding: what is hashed must determine what ran.
// ---------------------------------------------------------------------------

/// Wrap mode joined the argument vector with spaces before hashing it, so
/// `-- echo "a b"` and `-- echo a b` produced the same command hash and the
/// same input hash while running two different commands. A receipt that
/// cannot tell them apart attests neither.
#[test]
fn forging_a_matching_command_hash_by_shifting_argument_boundaries_is_refused() {
    let one = tempfile::tempdir().unwrap();
    let two = tempfile::tempdir().unwrap();

    let receipt_of = |dir: &std::path::Path, args: &[&str]| -> String {
        attest().current_dir(dir).arg("init").assert().success();
        let mut cmd = attest();
        cmd.current_dir(dir)
            .args(["run", "--wrap", "--name", "w", "--"]);
        cmd.args(args).assert().success();
        let dir = dir.join(".attest/receipts");
        let entry = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .find(|e| e.path().extension().is_some_and(|x| x == "yaml"))
            .expect("a receipt was written");
        std::fs::read_to_string(entry.path()).unwrap()
    };

    let a = receipt_of(one.path(), &["echo", "a b"]);
    let b = receipt_of(two.path(), &["echo", "a", "b"]);

    let field = |yaml: &str, key: &str| -> String {
        yaml.lines()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("no {key} in:\n{yaml}"))
            .trim()
            .to_string()
    };

    assert_ne!(
        field(&a, "pipeline_hash:"),
        field(&b, "pipeline_hash:"),
        "two different argument vectors must not share a command hash"
    );
    assert_ne!(
        field(&a, "input_hash:"),
        field(&b, "input_hash:"),
        "two different argument vectors must not share an input hash"
    );
}

// ---------------------------------------------------------------------------
// Causal ledger: an event's identity must follow from its contents.
// ---------------------------------------------------------------------------

/// The causal parents are the graph. They used to sit outside the event id
/// and outside the chain root, so rewriting who caused what changed neither,
/// and an archive of edited events verified cleanly.
#[test]
fn forging_the_causal_graph_by_rewriting_parents_is_refused() {
    use attest::storage::causal_ledger::{CausalEvent, CausalLedger};

    let event = CausalEvent {
        event_id: String::new(),
        step_name: "build".to_string(),
        causal_parents: vec!["parent-a".to_string()],
        input_hash: "1".repeat(64),
        output_hash: "2".repeat(64),
        timestamp: chrono::Utc::now(),
        exit_code: 0,
        pipeline_hash: "3".repeat(64),
        environment_hash: "4".repeat(64),
        signer_public_key: None,
        signature: None,
        metadata: Default::default(),
    };
    let honest = CausalEvent {
        event_id: CausalLedger::event_id_of(&event),
        ..event.clone()
    };
    assert!(CausalLedger::event_id_is_authentic(&honest));

    // Rewrite the graph, keep the id.
    let mut rewritten = honest.clone();
    rewritten.causal_parents = vec!["parent-b".to_string()];
    assert!(
        !CausalLedger::event_id_is_authentic(&rewritten),
        "changing an event's parents must invalidate its id"
    );
    assert_ne!(
        CausalLedger::chain_hash(&[honest.clone()]),
        CausalLedger::chain_hash(&[rewritten]),
        "changing an event's parents must change the chain root"
    );
}

/// Every other recorded fact, for the same reason.
#[test]
fn forging_a_recorded_fact_inside_a_causal_event_is_refused() {
    use attest::storage::causal_ledger::{CausalEvent, CausalLedger};

    let base = CausalEvent {
        event_id: String::new(),
        step_name: "build".to_string(),
        causal_parents: Vec::new(),
        input_hash: "1".repeat(64),
        output_hash: "2".repeat(64),
        timestamp: chrono::Utc::now(),
        exit_code: 0,
        pipeline_hash: "3".repeat(64),
        environment_hash: "4".repeat(64),
        signer_public_key: None,
        signature: None,
        metadata: Default::default(),
    };
    let honest = CausalEvent {
        event_id: CausalLedger::event_id_of(&base),
        ..base
    };

    let mutations: Vec<(&str, Box<dyn Fn(&mut CausalEvent)>)> = vec![
        (
            "a failing step reported as successful",
            Box::new(|e: &mut CausalEvent| e.exit_code = 0_i32.wrapping_add(1)),
        ),
        (
            "the inputs it claims to have read",
            Box::new(|e: &mut CausalEvent| e.input_hash = "9".repeat(64)),
        ),
        (
            "the outputs it claims to have produced",
            Box::new(|e: &mut CausalEvent| e.output_hash = "9".repeat(64)),
        ),
        (
            "which step it was",
            Box::new(|e: &mut CausalEvent| e.step_name = "other".to_string()),
        ),
        (
            "the pipeline it belonged to",
            Box::new(|e: &mut CausalEvent| e.pipeline_hash = "9".repeat(64)),
        ),
        (
            "the environment it ran in",
            Box::new(|e: &mut CausalEvent| e.environment_hash = "9".repeat(64)),
        ),
    ];

    for (what, mutate) in mutations {
        let mut forged = honest.clone();
        mutate(&mut forged);
        assert!(
            !CausalLedger::event_id_is_authentic(&forged),
            "forging {what} must invalidate the event id"
        );
        assert_ne!(
            CausalLedger::chain_hash(&[honest.clone()]),
            CausalLedger::chain_hash(&[forged]),
            "forging {what} must change the chain root"
        );
    }
}

// ---------------------------------------------------------------------------
// Verification: `--recompute` must mean what the README says it means.
// ---------------------------------------------------------------------------

/// Run a pipeline in `dir` and return the receipt it wrote.
fn run_and_receipt(dir: &std::path::Path) -> std::path::PathBuf {
    attest().current_dir(dir).arg("run").assert().success();
    let receipts = dir.join(".attest/receipts");
    std::fs::read_dir(&receipts)
        .expect("receipts directory")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "yaml"))
        .expect("a receipt was written")
}

fn recompute(dir: &std::path::Path, receipt: &std::path::Path) -> std::process::Output {
    attest()
        .current_dir(dir)
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--check-signatures",
            "false",
            "--recompute",
        ])
        .output()
        .expect("verify runs")
}

const ONE_STEP: &str = "version: \"0.1\"\n\
     name: recompute\n\
     steps:\n  \
       build:\n    \
         run: \"echo artifact > out.txt\"\n    \
         inputs: [\"in.txt\"]\n    \
         outputs: [\"out.txt\"]\n";

/// A receipt that simply omits a step used to pass: verification walked the
/// steps the receipt named and never asked whether the workspace pipeline
/// declared others. Stripping the step you would rather not account for left
/// every remaining hash correct, the pipeline untouched, and the receipt
/// attesting a smaller build than the one that is defined.
#[test]
fn forging_a_smaller_build_by_stripping_a_step_from_the_receipt_is_refused() {
    let two_steps = "version: \"0.1\"\n\
         name: recompute\n\
         steps:\n  \
           build:\n    \
             run: \"echo artifact > out.txt\"\n    \
             inputs: [\"in.txt\"]\n    \
             outputs: [\"out.txt\"]\n  \
           audit:\n    \
             run: \"echo audited > audit.txt\"\n    \
             inputs: [\"in.txt\"]\n    \
             outputs: [\"audit.txt\"]\n";
    let dir = workspace(two_steps);
    std::fs::write(dir.path().join("in.txt"), "source\n").unwrap();
    let receipt = run_and_receipt(dir.path());
    let baseline = recompute(dir.path(), &receipt);
    assert!(
        baseline.status.success(),
        "honest first:\n{}{}",
        String::from_utf8_lossy(&baseline.stdout),
        String::from_utf8_lossy(&baseline.stderr)
    );

    // Drop one step from the receipt. The pipeline file is untouched, so the
    // pipeline hash still matches and only the missing-step check can catch
    // this.
    let text = std::fs::read_to_string(&receipt).unwrap();
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
    let steps = doc["steps"].as_sequence().unwrap().clone();
    assert_eq!(
        steps.len(),
        2,
        "the fixture must have two steps to strip one"
    );
    let kept: Vec<_> = steps
        .into_iter()
        .filter(|s| s["name"].as_str() != Some("audit"))
        .collect();
    doc["steps"] = serde_yaml::Value::Sequence(kept);
    std::fs::write(&receipt, serde_yaml::to_string(&doc).unwrap()).unwrap();

    let out = recompute(dir.path(), &receipt);
    let combined = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !out.status.success(),
        "a receipt that omits a declared step must not pass --recompute:\n{combined}"
    );
    assert!(
        combined.contains("absent from the receipt"),
        "the failure should name the missing step, got:\n{combined}"
    );
}

/// Replacing the artifact left the receipt accepted, because only inputs
/// were recomputed. Inputs say the build started from the right source;
/// outputs are what someone actually ships.
#[test]
fn forging_an_artifact_after_the_build_is_refused() {
    let dir = workspace(ONE_STEP);
    std::fs::write(dir.path().join("in.txt"), "source\n").unwrap();
    let receipt = run_and_receipt(dir.path());
    assert!(
        recompute(dir.path(), &receipt).status.success(),
        "honest first"
    );

    std::fs::write(dir.path().join("out.txt"), "substituted\n").unwrap();

    let out = recompute(dir.path(), &receipt);
    let combined = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !out.status.success(),
        "a replaced artifact must fail --recompute:\n{combined}"
    );
    assert!(
        combined.contains("output hash mismatch"),
        "the failure should name the artifact, got:\n{combined}"
    );
}

/// The environment a pipeline declares is part of what produced the result,
/// and it lives in the pipeline hash rather than in any step's input hash.
#[test]
fn forging_a_different_environment_is_refused() {
    let dir = workspace(ONE_STEP);
    std::fs::write(dir.path().join("in.txt"), "source\n").unwrap();
    let receipt = run_and_receipt(dir.path());
    assert!(
        recompute(dir.path(), &receipt).status.success(),
        "honest first"
    );

    std::fs::write(
        dir.path().join("attest.yaml"),
        format!("env:\n  BUILD_FLAVOUR: \"changed\"\n{ONE_STEP}"),
    )
    .unwrap();

    let out = recompute(dir.path(), &receipt);
    let combined = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !out.status.success(),
        "changing the declared environment must fail --recompute:\n{combined}"
    );
    assert!(
        combined.contains("pipeline hash mismatch"),
        "the failure should name the pipeline, got:\n{combined}"
    );
}

/// An archive is meant to be checkable offline by someone who trusts none of
/// the machines involved. Its causal events were never checked against the
/// ids naming them, so editing an event inside the archive -- while leaving
/// its filename and recorded id untouched -- produced an archive that
/// verified cleanly while describing a different history.
#[test]
fn forging_a_causal_event_inside_an_archive_is_refused() {
    use attest::archive::{read_archive, write_archive};

    let dir = workspace(ONE_STEP);
    std::fs::write(dir.path().join("in.txt"), "source\n").unwrap();
    let receipt = run_and_receipt(dir.path());

    let archive = dir.path().join("evidence.attest.tar.zst");
    attest()
        .current_dir(dir.path())
        .args([
            "causal",
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let verify_archive = |path: &std::path::Path| {
        attest()
            .current_dir(dir.path())
            .args([
                "verify",
                "--archive",
                path.to_str().unwrap(),
                "--check-signatures",
                "false",
            ])
            .output()
            .expect("verify runs")
    };
    assert!(
        verify_archive(&archive).status.success(),
        "the honest archive verifies first"
    );

    // Rewrite one event's history, leaving its id and filename alone.
    let mut entries = read_archive(&archive).expect("archive reads");
    let mut rewrote = false;
    for entry in entries.iter_mut() {
        if !entry.path.starts_with("events/") {
            continue;
        }
        let mut event: serde_json::Value = serde_json::from_slice(&entry.bytes).unwrap();
        event["causal_parents"] = serde_json::json!(["fabricated-parent"]);
        entry.bytes = serde_json::to_vec_pretty(&event).unwrap();
        rewrote = true;
    }
    assert!(
        rewrote,
        "the archive must contain at least one event to forge"
    );

    let forged = dir.path().join("forged.attest.tar.zst");
    write_archive(entries, &forged).expect("forged archive writes");

    let out = verify_archive(&forged);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "an archive whose events were rewritten must not verify:\n{combined}"
    );
}

/// `pipeline_hash` is blake3 of the pipeline's serialization, and the steps
/// used to live in a HashMap -- whose iteration order Rust randomizes per
/// process. The hash was therefore not a function of the pipeline: two
/// identical runs of a two-step pipeline produced different hashes, and a
/// verifier comparing them rejected honest receipts at random.
///
/// Run in separate processes deliberately: within one process the random
/// seed is fixed, so the bug is invisible to a single-process test.
#[test]
fn a_pipeline_hash_is_the_same_in_every_process() {
    let pipeline = "version: \"0.1\"\n\
         name: canonical\n\
         env:\n  \
           B_SECOND: \"2\"\n  \
           A_FIRST: \"1\"\n\
         steps:\n  \
           zulu:\n    \
             run: \"echo z\"\n    \
             inputs: []\n    \
             outputs: []\n  \
           alpha:\n    \
             run: \"echo a\"\n    \
             inputs: []\n    \
             outputs: []\n";

    let hash_of_a_fresh_run = || {
        let dir = workspace(pipeline);
        let receipt = run_and_receipt(dir.path());
        let text = std::fs::read_to_string(&receipt).unwrap();
        text.lines()
            .find(|l| l.starts_with("pipeline_hash:"))
            .expect("receipt records a pipeline hash")
            .to_string()
    };

    // Each `attest run` is its own process, so each gets its own hash seed.
    let first = hash_of_a_fresh_run();
    let second = hash_of_a_fresh_run();
    let third = hash_of_a_fresh_run();

    assert_eq!(
        first, second,
        "the same pipeline must hash the same way twice"
    );
    assert_eq!(second, third, "and a third time");
}

/// SECURITY.md claims the causal root is anchored: the signature covers it,
/// and a timestamp token covers the signature. That claim rests entirely on
/// `causal_chain_hash` being inside the signed bytes. Moving it out -- or
/// adding it to the list of fields cleared before signing -- would make the
/// document false without breaking anything else, so the claim is pinned
/// here rather than left to a reader's memory.
#[test]
fn the_signature_covers_the_causal_root_and_the_events() {
    use attest::storage::{receipt_signing_bytes, Receipt, StepResult};

    let base = Receipt {
        schema_version: Some(3),
        pipeline_hash: "0".repeat(64),
        steps: vec![StepResult {
            name: "build".to_string(),
            input_hash: "1".repeat(64),
            output_hash: "2".repeat(64),
            duration_secs: 1,
            exit_code: 0,
            cache_hit: false,
            stdout: String::new(),
            stderr: String::new(),
            capsule_hash: None,
        }],
        timestamp: chrono::Utc::now(),
        total_duration_secs: 1,
        signature: None,
        signer_public_key: None,
        attest_version: "0.1.0".to_string(),
        causal_events: vec!["event-a".to_string()],
        causal_chain_hash: Some("3".repeat(64)),
        reproducibility: None,
        provenance: None,
        timestamp_token: None,
    };
    let signed = receipt_signing_bytes(&base).expect("canonical bytes");

    let mut other_root = base.clone();
    other_root.causal_chain_hash = Some("4".repeat(64));
    assert_ne!(
        signed,
        receipt_signing_bytes(&other_root).expect("canonical bytes"),
        "the causal root must be inside the signed bytes, or anchoring it proves nothing"
    );

    let mut other_events = base.clone();
    other_events.causal_events = vec!["event-b".to_string()];
    assert_ne!(
        signed,
        receipt_signing_bytes(&other_events).expect("canonical bytes"),
        "the event list must be inside the signed bytes"
    );

    // And the converse, which is what lets a receipt be signed and then
    // timestamped: attaching the token must not disturb the signed bytes.
    let mut timestamped = base.clone();
    timestamped.timestamp_token = Some("a token".to_string());
    assert_eq!(
        signed,
        receipt_signing_bytes(&timestamped).expect("canonical bytes"),
        "attaching a timestamp token must leave the signature valid"
    );
}

// ---------------------------------------------------------------------------
// Timestamping: holding a certificate is not the same as being allowed to use
// it for this.
// ---------------------------------------------------------------------------

/// RFC 3161 §2.3 requires a timestamping authority's certificate to carry the
/// id-kp-timeStamping extended key usage. The verifier ignored extensions
/// entirely, so any certificate the pinned issuer had ever signed would have
/// done -- a TLS server certificate from the same CA could stamp time. The
/// pinned issuer being a dedicated timestamping CA is an assumption about
/// someone else's operations; the leaf's own authorisation is checkable.
#[test]
fn a_certificate_not_authorised_to_timestamp_is_recognised_as_such() {
    use attest::crypto::timestamp::certificate_allows_timestamping;

    let fixture = |name: &str| {
        std::fs::read(format!(
            "{}/tests/fixtures/timestamp/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
    };

    // The issuing CA signs responders; it does not stamp time itself.
    assert!(
        !certificate_allows_timestamping(&fixture("digicert-tsa-ca.der")).unwrap(),
        "a CA certificate must not be treated as authorised to timestamp"
    );
    assert!(
        !certificate_allows_timestamping(&fixture("unrelated-root.der")).unwrap(),
        "an unrelated root must not be treated as authorised to timestamp"
    );
}

/// Events used to be signed with the producing machine's key and checked
/// against that same local key, so an archive carried signatures nobody else
/// could verify. The signer's public key is recorded now, which makes a
/// signature that does not hold detectable from the archive alone.
#[test]
fn forging_an_event_signature_inside_an_archive_is_refused() {
    use attest::archive::{read_archive, write_archive};
    use attest::storage::causal_ledger::{CausalEvent, CausalLedger};

    let dir = workspace(ONE_STEP);
    std::fs::write(dir.path().join("in.txt"), "source\n").unwrap();

    // Signing the run is what gives the events a signature to forge.
    attest()
        .current_dir(dir.path())
        .args(["keys", "generate", "--name", "ledger"])
        .assert()
        .success();
    attest()
        .current_dir(dir.path())
        .args(["run", "--sign"])
        .assert()
        .success();
    let receipt = std::fs::read_dir(dir.path().join(".attest/receipts"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "yaml"))
        .expect("a receipt was written");

    let archive = dir.path().join("evidence.attest.tar.zst");
    attest()
        .current_dir(dir.path())
        .args([
            "causal",
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut entries = read_archive(&archive).expect("archive reads");
    let mut signed_any = false;
    for entry in entries.iter_mut() {
        if !entry.path.starts_with("events/") {
            continue;
        }
        let event: CausalEvent = serde_json::from_slice(&entry.bytes).unwrap();
        if CausalLedger::event_signature_holds(&event) != Some(true) {
            continue; // unsigned run; nothing to forge here
        }
        signed_any = true;
        let mut doc: serde_json::Value = serde_json::from_slice(&entry.bytes).unwrap();
        // Flip one byte of the signature, leaving everything else intact.
        let sig = doc["signature"].as_str().unwrap().to_string();
        let flipped = format!(
            "{}{}",
            if sig.starts_with('0') { "1" } else { "0" },
            &sig[1..]
        );
        doc["signature"] = serde_json::json!(flipped);
        entry.bytes = serde_json::to_vec_pretty(&doc).unwrap();
    }
    assert!(
        signed_any,
        "the fixture must produce at least one signed event to forge"
    );

    let forged = dir.path().join("forged.attest.tar.zst");
    write_archive(entries, &forged).expect("forged archive writes");

    let out = attest()
        .current_dir(dir.path())
        .args([
            "verify",
            "--archive",
            forged.to_str().unwrap(),
            "--check-signatures",
            "false",
        ])
        .output()
        .expect("verify runs");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "an archive whose event signatures do not verify must be refused:\n{combined}"
    );
}

/// Deleting the key beside a forged signature used to disable the check
/// entirely: `event_signature_holds` returned None when the key was missing,
/// and the archive rejected only an explicit false. An event carries both or
/// neither; a signature nobody can examine is not an unsigned event.
#[test]
fn forging_an_event_signature_and_deleting_its_key_is_refused() {
    use attest::storage::causal_ledger::{CausalEvent, CausalLedger};

    let base = CausalEvent {
        event_id: String::new(),
        step_name: "build".to_string(),
        causal_parents: Vec::new(),
        input_hash: "1".repeat(64),
        output_hash: "2".repeat(64),
        timestamp: chrono::Utc::now(),
        exit_code: 0,
        signer_public_key: None,
        signature: None,
        pipeline_hash: "3".repeat(64),
        environment_hash: "4".repeat(64),
        metadata: Default::default(),
    };
    let mut event = CausalEvent {
        event_id: CausalLedger::event_id_of(&base),
        ..base
    };

    // Unsigned: nothing to check, and that is not a failure.
    assert_eq!(CausalLedger::event_signature_holds(&event), None);

    // A signature with no key beside it cannot be examined, so it must not
    // be treated as absent.
    event.signature = Some("00".repeat(64));
    assert_eq!(
        CausalLedger::event_signature_holds(&event),
        Some(false),
        "a signature with no key to check it against must not read as unsigned"
    );
}

// ---------------------------------------------------------------------------
// Revocation must not be escapable by changing format.
// ---------------------------------------------------------------------------

/// `attest verify` refuses a revoked key with no independent proof of when it
/// signed. Exporting the same receipt to in-toto and importing it back used
/// to pass, because the import path judged revocation on `finishedOn` -- a
/// field inside the payload the signature covers, chosen by whoever holds the
/// key. A signature the receipt path rejects must not become acceptable by
/// changing its envelope.
#[test]
fn forging_acceptance_by_round_tripping_a_revoked_signature_through_in_toto_is_refused() {
    let dir = workspace(ONE_STEP);
    std::fs::write(dir.path().join("in.txt"), "source\n").unwrap();

    let key_id = {
        let out = attest()
            .current_dir(dir.path())
            .args(["keys", "generate", "--name", "doomed"])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };

    attest()
        .current_dir(dir.path())
        .args(["run", "--sign", "--key", &key_id])
        .assert()
        .success();
    let receipt = std::fs::read_dir(dir.path().join(".attest/receipts"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "yaml"))
        .expect("a receipt was written");

    attest()
        .current_dir(dir.path())
        .args(["keys", "revoke", &key_id])
        .assert()
        .success();

    // The receipt path refuses: no timestamp token, so no evidence the
    // signature predates the revocation.
    let verified = attest()
        .current_dir(dir.path())
        .args(["verify", receipt.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !verified.status.success(),
        "the receipt path must refuse first, or this test proves nothing:\n{}",
        String::from_utf8_lossy(&verified.stdout)
    );

    let statement = dir.path().join("statement.json");
    let exported = attest()
        .current_dir(dir.path())
        .args([
            "export",
            "--receipt",
            receipt.to_str().unwrap(),
            "--format",
            "in-toto",
        ])
        .output()
        .unwrap();
    assert!(exported.status.success(), "export should still work");
    std::fs::write(&statement, &exported.stdout).unwrap();

    let imported = attest()
        .current_dir(dir.path())
        .args(["import", "--format", "in-toto", statement.to_str().unwrap()])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&imported.stdout),
        String::from_utf8_lossy(&imported.stderr)
    );
    assert!(
        !imported.status.success(),
        "a revoked signature must not become acceptable by changing envelope:\n{combined}"
    );
}

// ---------------------------------------------------------------------------
// The cache must not answer a question it was not asked.
// ---------------------------------------------------------------------------

/// The cache key covered the command, the declared inputs and the
/// environment, but not `working_dir`. A step pointed at a different
/// directory -- reading a different file of the same name -- was served the
/// previous directory's result, and that result was then signed into a
/// receipt describing the new configuration.
#[test]
fn forging_a_result_by_changing_where_a_step_runs_is_refused() {
    use attest::pipeline::Step;

    let step_in = |dir: &str| -> Step {
        serde_yaml::from_str(&format!(
            "run: \"cat value.txt > out.txt\"\n\
             inputs: [\"{dir}/value.txt\"]\n\
             outputs: [\"out.txt\"]\n\
             working_dir: \"{dir}\"\n"
        ))
        .expect("step parses")
    };

    assert_ne!(
        step_in("a").execution_shape(),
        step_in("b").execution_shape(),
        "two steps that run in different directories must not share a cache key"
    );

    // And the fields that were missing alongside it.
    let base: Step = serde_yaml::from_str("run: \"echo hi\"\ninputs: []\noutputs: []\n").unwrap();
    for (what, yaml) in [
        (
            "image",
            "run: \"echo hi\"\ninputs: []\noutputs: []\nimage: \"alpine@sha256:aaa\"\n",
        ),
        (
            "timeout",
            "run: \"echo hi\"\ninputs: []\noutputs: []\ntimeout_secs: 30\n",
        ),
    ] {
        let other: Step = serde_yaml::from_str(yaml).unwrap();
        assert_ne!(
            base.execution_shape(),
            other.execution_shape(),
            "changing {what} must change the cache key"
        );
    }
}

/// The audit's own reproduction, end to end, and isolated.
///
/// `inputs` is empty deliberately: with the file declared, changing the
/// directory also changes the declared-input hash, and the cache would miss
/// for that reason rather than because it noticed the step moved. Leaving it
/// undeclared makes `working_dir` the only difference between the two runs,
/// which is what has to be tested. That the command reads a file nobody
/// declared is a separate weakness -- the receipt simply does not cover it --
/// and it is exactly the situation in which the cache key has to carry the
/// weight on its own.
#[test]
fn forging_a_result_by_running_the_same_step_elsewhere_is_refused() {
    let pipeline = |dir: &str| {
        format!(
            "version: \"0.1\"\n\
             name: relocate\n\
             steps:\n  \
               read:\n    \
                 run: \"cat value.txt > ../out.txt\"\n    \
                 inputs: []\n    \
                 outputs: [\"out.txt\"]\n    \
                 working_dir: \"{dir}\"\n"
        )
    };

    let dir = workspace(&pipeline("a"));
    std::fs::create_dir(dir.path().join("a")).unwrap();
    std::fs::create_dir(dir.path().join("b")).unwrap();
    std::fs::write(dir.path().join("a/value.txt"), "A\n").unwrap();
    std::fs::write(dir.path().join("b/value.txt"), "B\n").unwrap();

    attest()
        .current_dir(dir.path())
        .arg("run")
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out.txt")).unwrap(),
        "A\n",
        "the first run reads from a/"
    );

    // Same command, same declared inputs, same output path. Only the
    // directory the step runs in has changed.
    std::fs::write(dir.path().join("attest.yaml"), pipeline("b")).unwrap();
    attest()
        .current_dir(dir.path())
        .arg("run")
        .assert()
        .success();

    assert_eq!(
        std::fs::read_to_string(dir.path().join("out.txt")).unwrap(),
        "B\n",
        "a step moved to another directory must not be served the previous \
         directory's cached result"
    );
}

/// Environment variables were hashed as newline-separated `key=value` lines,
/// so a value carrying a newline forged a variable: one pipeline declaring
/// `ZZ_A` as "one\nZZ_B=two" hashed identically to one declaring `ZZ_A=one`
/// and `ZZ_B=two`. The second run was served the first's cached result and
/// had it signed into a receipt describing an environment that never
/// produced it.
///
/// The step-shape digest does not help here: these variables are declared on
/// the pipeline, not the step.
#[test]
fn forging_an_environment_variable_through_a_newline_is_refused() {
    let pipeline = |env_block: &str| {
        format!(
            "version: \"0.1\"\n\
             name: envcollide\n\
             env:\n{env_block}\
             steps:\n  \
               show:\n    \
                 run: \"printf '%s' \\\"$ZZ_A\\\" > out.txt\"\n    \
                 inputs: []\n    \
                 outputs: [\"out.txt\"]\n"
        )
    };

    // One variable whose value smuggles a second one.
    let smuggled = "  ZZ_A: \"one\\nZZ_B=two\"\n";
    // Two genuinely separate variables.
    let honest = "  ZZ_A: \"one\"\n  ZZ_B: \"two\"\n";

    let dir = workspace(&pipeline(smuggled));
    attest()
        .current_dir(dir.path())
        .arg("run")
        .assert()
        .success();
    let first = std::fs::read_to_string(dir.path().join("out.txt")).unwrap();

    std::fs::write(dir.path().join("attest.yaml"), pipeline(honest)).unwrap();
    attest()
        .current_dir(dir.path())
        .arg("run")
        .assert()
        .success();
    let second = std::fs::read_to_string(dir.path().join("out.txt")).unwrap();

    assert_ne!(
        first, second,
        "two different environments must not share a cache entry: the first \
         run wrote {first:?} and the second was served the same result"
    );
    assert_eq!(second, "one", "the second pipeline's ZZ_A is plain 'one'");
}
