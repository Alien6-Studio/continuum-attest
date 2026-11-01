#[path = "support/evidence_proofs.rs"]
mod proof_fixture;
#[path = "support/release.rs"]
mod release_fixture;

use proof_fixture::ProofRelease;
use release_fixture::check;

#[test]
fn transferred_proofs_reject_missing_or_altered_required_material() {
    for (prefix, check_name, changed) in [
        ("capsules/", "capsule", false),
        ("events/", "chain-linkage", false),
        ("capsules/", "capsule", true),
        ("events/", "chain-linkage", true),
        ("artifacts/", "artifacts", true),
    ] {
        let fixture = ProofRelease::new();
        fixture.release.mutate_archive(|entries| {
            if changed {
                entries
                    .iter_mut()
                    .find(|entry| entry.path.starts_with(prefix))
                    .unwrap()
                    .bytes = b"altered proof".to_vec();
            } else {
                entries.retain(|entry| !entry.path.starts_with(prefix));
            }
        });
        let release_fixture::Release {
            producer,
            recipient,
            archive,
            ..
        } = fixture.release;
        producer.close().unwrap();
        let result = release_fixture::verify(
            recipient.path(),
            &archive,
            &recipient.path().join(".attest/trust"),
            &[],
            1,
        );
        assert_eq!(
            check(&result, check_name)["status"],
            if changed { "fail" } else { "skipped" }
        );
    }
}

#[test]
fn complete_conditional_proofs_survive_removal_of_producer_workspace() {
    let fixture = ProofRelease::new();
    let release_fixture::Release {
        producer,
        recipient,
        archive,
        ..
    } = fixture.release;
    producer.close().unwrap();
    let result = release_fixture::verify(
        recipient.path(),
        &archive,
        &recipient.path().join(".attest/trust"),
        &[],
        0,
    );
    assert_eq!(check(&result, "capsule")["status"], "pass");
    assert_eq!(check(&result, "chain-linkage")["status"], "pass");
    assert!(result["policy"]["required"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("capsule")));
    assert!(result["policy"]["required"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("linkage")));
}

#[test]
fn recipient_can_accept_explicitly_incomplete_optional_proofs() {
    let fixture = ProofRelease::new();
    fixture.release.mutate_archive(|entries| {
        entries.retain(|entry| {
            !entry.path.starts_with("capsules/") && !entry.path.starts_with("events/")
        })
    });
    let result = fixture
        .release
        .verify(&["--require", "signature,success,artifacts"], 0);
    for name in ["capsule", "chain-linkage"] {
        assert_eq!(check(&result, name)["status"], "skipped");
        assert!(check(&result, name)["detail"]
            .as_str()
            .unwrap()
            .contains("incomplete"));
    }
    assert_eq!(
        result["identity"]["principals"]["workflow"],
        serde_json::Value::Null
    );
    assert_eq!(
        result["identity"]["principals"]["artifact_signer"],
        serde_json::Value::Null
    );
    assert_eq!(
        result["identity"]["principals"]["evidence_producer"],
        result["signed_by"]
    );
}

#[test]
fn identity_requirements_are_machine_readable_when_evidence_is_absent() {
    let release = release_fixture::Release::new(0);
    let path = release.recipient.path().join("identity.json");
    let policy = serde_json::json!({"issuer":"https://token.actions.githubusercontent.com", "repository":"https://github.com/example/project", "workflow":"https://github.com/example/project/.github/workflows/release.yml@refs/heads/main", "revision":"a".repeat(40), "trusted_root":"root.json"});
    std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let result = release.verify(&["--identity-policy", path.to_str().unwrap()], 1);
    assert_eq!(
        result["identity"]["required"]["workflow"],
        policy["workflow"]
    );
    assert_eq!(result["identity"]["verified"], serde_json::Value::Null);
    assert!(result["policy"]["unmet"]
        .as_array()
        .unwrap()
        .iter()
        .any(|unmet| unmet["requirement"] == "identity"));
}
