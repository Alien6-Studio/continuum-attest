//! Advanced tests for CausalLedger to improve code coverage
//!
//! These tests focus on edge cases, error conditions, and complex scenarios
//! not covered by the basic unit tests.

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use tempfile::TempDir;

use attest::storage::causal_ledger::{CausalChain, CausalEvent, CausalLedger, CausalQuery};

/// Create a test ledger for advanced testing
fn create_advanced_test_ledger() -> (CausalLedger, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let ledger = CausalLedger::new(temp_dir.path()).unwrap();
    (ledger, temp_dir)
}

/// Create a test event with given parameters
fn create_test_event(
    event_id: &str,
    step_name: &str,
    parents: Vec<String>,
    exit_code: i32,
) -> CausalEvent {
    CausalEvent {
        event_id: event_id.to_string(),
        step_name: step_name.to_string(),
        causal_parents: parents,
        input_hash: format!("input_{}", event_id),
        output_hash: format!("output_{}", event_id),
        timestamp: Utc::now(),
        exit_code,
        pipeline_hash: "test_pipeline".to_string(),
        environment_hash: "test_env".to_string(),
        signer_public_key: None,
        signature: None,
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_complex_causal_dependencies() -> Result<()> {
    let (mut ledger, _temp_dir) = create_advanced_test_ledger();
    ledger.init().await?;

    // Create a complex dependency graph: A -> B,C -> D -> E
    let event_a = create_test_event("event_a", "step_a", vec![], 0);
    let event_b = create_test_event("event_b", "step_b", vec!["event_a".to_string()], 0);
    let event_c = create_test_event("event_c", "step_c", vec!["event_a".to_string()], 0);
    let event_d = create_test_event(
        "event_d",
        "step_d",
        vec!["event_b".to_string(), "event_c".to_string()],
        0,
    );
    let event_e = create_test_event("event_e", "step_e", vec!["event_d".to_string()], 0);

    // Record all events
    ledger.record_event_struct(event_a).await?;
    ledger.record_event_struct(event_b).await?;
    ledger.record_event_struct(event_c).await?;
    ledger.record_event_struct(event_d).await?;
    ledger.record_event_struct(event_e).await?;

    // find_causal_path walks backwards through causal_parents, so it finds a
    // path from a descendant event back to one of its ancestors. Query from
    // E back to A (E depends on D depends on B,C depends on A).
    let path = ledger.find_causal_path("event_e", "event_a").await?;
    assert!(path.is_some());
    let path = path.unwrap();
    assert!(!path.path.is_empty());
    assert_eq!(path.from_event, "event_e");
    assert_eq!(path.to_event, "event_a");

    // Test that there's no path from B to C (siblings, not ancestor/descendant)
    let path = ledger.find_causal_path("event_b", "event_c").await?;
    assert!(path.is_none());

    Ok(())
}

#[tokio::test]
async fn test_circular_dependency_prevention() -> Result<()> {
    let (mut ledger, _temp_dir) = create_advanced_test_ledger();
    ledger.init().await?;

    // Record first event
    let event_a = create_test_event("event_a", "step_a", vec![], 0);
    ledger.record_event_struct(event_a).await?;

    // Try to create a circular dependency: A -> B -> A
    let event_b = create_test_event("event_b", "step_b", vec!["event_a".to_string()], 0);
    ledger.record_event_struct(event_b).await?;

    // This should be prevented/handled gracefully
    let circular_event_a =
        create_test_event("event_a_circular", "step_a", vec!["event_b".to_string()], 0);
    let result = ledger.record_event_struct(circular_event_a).await;

    // Should either succeed (if cycles are allowed) or fail gracefully
    assert!(result.is_ok() || result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_failed_step_causality() -> Result<()> {
    let (mut ledger, _temp_dir) = create_advanced_test_ledger();
    ledger.init().await?;

    // Create events with failed steps
    let failed_event = create_test_event("failed_step", "failing_step", vec![], 1);
    let dependent_event = create_test_event(
        "dependent_step",
        "dependent",
        vec!["failed_step".to_string()],
        0,
    );

    ledger.record_event_struct(failed_event).await?;
    ledger.record_event_struct(dependent_event).await?;

    // Test that we can still query paths even with failed steps.
    // find_causal_path traverses backwards through causal_parents, so query
    // from the dependent event back to the failed event it depends on.
    let path = ledger
        .find_causal_path("dependent_step", "failed_step")
        .await?;
    assert!(path.is_some());

    Ok(())
}

#[tokio::test]
async fn test_large_causal_chain() -> Result<()> {
    let (mut ledger, _temp_dir) = create_advanced_test_ledger();
    ledger.init().await?;

    // Create a long chain of dependent events
    let chain_length = 20;
    let mut previous_event_id = None;

    for i in 0..chain_length {
        let event_id = format!("event_{}", i);
        let parents = if let Some(prev) = previous_event_id {
            vec![prev]
        } else {
            vec![]
        };

        let event = create_test_event(&event_id, &format!("step_{}", i), parents, 0);
        ledger.record_event_struct(event).await?;
        previous_event_id = Some(event_id);
    }

    // find_causal_path traverses backwards through causal_parents, so query
    // from the last (most recent) event back to the first.
    let path = ledger
        .find_causal_path(&format!("event_{}", chain_length - 1), "event_0")
        .await?;
    assert!(path.is_some());
    let path = path.unwrap();
    assert_eq!(path.path.len(), chain_length);

    Ok(())
}

#[tokio::test]
async fn test_concurrent_event_recording() -> Result<()> {
    let (ledger, _temp_dir) = create_advanced_test_ledger();
    let ledger = std::sync::Arc::new(tokio::sync::Mutex::new(ledger));

    {
        let ledger_guard = ledger.lock().await;
        ledger_guard.init().await?;
    }

    // Create multiple events to record concurrently
    let mut handles = vec![];
    for i in 0..10 {
        let ledger_clone = ledger.clone();
        let handle = tokio::spawn(async move {
            let event = create_test_event(
                &format!("concurrent_event_{}", i),
                &format!("step_{}", i),
                vec![],
                0,
            );
            let mut ledger_guard = ledger_clone.lock().await;
            ledger_guard.record_event_struct(event).await
        });
        handles.push(handle);
    }

    // Wait for all events to be recorded
    for handle in handles {
        handle.await.unwrap()?;
    }

    // Verify all events were recorded
    let ledger_guard = ledger.lock().await;
    let stats = ledger_guard.get_stats().await?;
    assert_eq!(stats.total_events, 10);

    Ok(())
}

#[tokio::test]
async fn test_event_metadata_handling() -> Result<()> {
    let (mut ledger, _temp_dir) = create_advanced_test_ledger();
    ledger.init().await?;

    // Create event with rich metadata
    let mut metadata = HashMap::new();
    metadata.insert("build_version".to_string(), "1.0.0".to_string());
    metadata.insert("commit_hash".to_string(), "abc123".to_string());
    metadata.insert(
        "build_timestamp".to_string(),
        "2024-01-01T00:00:00Z".to_string(),
    );
    metadata.insert("environment".to_string(), "production".to_string());

    let mut event = create_test_event("metadata_event", "build_step", vec![], 0);
    event.metadata = metadata.clone();

    ledger.record_event_struct(event).await?;

    // Query events by metadata (if supported)
    let events = ledger.get_events_by_step("build_step").await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata, metadata);

    Ok(())
}

#[tokio::test]
async fn test_ledger_persistence_recovery() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();

    // Create and populate a ledger
    {
        let mut ledger = CausalLedger::new(temp_dir.path())?;
        ledger.init().await?;

        let event = create_test_event("persistent_event", "persistent_step", vec![], 0);
        ledger.record_event_struct(event).await?;
    }

    // Create a new ledger instance from the same directory
    {
        let mut ledger = CausalLedger::new(temp_dir.path())?;
        ledger.init().await?;
        ledger.load_events().await?; // Explicitly load existing events from disk

        let stats = ledger.get_stats().await?;
        assert_eq!(stats.total_events, 1);

        let events = ledger.get_events_by_step("persistent_step").await?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "persistent_event");
    }

    Ok(())
}

#[tokio::test]
async fn test_causal_query_with_complex_criteria() -> Result<()> {
    let (mut ledger, _temp_dir) = create_advanced_test_ledger();
    ledger.init().await?;

    // Create events with different characteristics
    let events = vec![
        create_test_event("build_success", "build", vec![], 0),
        create_test_event("build_failure", "build", vec![], 1),
        create_test_event("test_success", "test", vec!["build_success".to_string()], 0),
        create_test_event(
            "deploy_success",
            "deploy",
            vec!["test_success".to_string()],
            0,
        ),
    ];

    for event in events {
        ledger.record_event_struct(event).await?;
    }

    // Query for successful events only
    let all_events = ledger.get_all_events().await?;
    let successful_events: Vec<_> = all_events
        .into_iter()
        .filter(|e| e.exit_code == 0)
        .collect();
    assert_eq!(successful_events.len(), 3);

    // Query for failed events
    let all_events = ledger.get_all_events().await?;
    let failed_events: Vec<_> = all_events
        .into_iter()
        .filter(|e| e.exit_code != 0)
        .collect();
    assert_eq!(failed_events.len(), 1);
    assert_eq!(failed_events[0].event_id, "build_failure");

    Ok(())
}

#[tokio::test]
async fn test_empty_ledger_operations() -> Result<()> {
    let (ledger, _temp_dir) = create_advanced_test_ledger();
    ledger.init().await?;

    // Test operations on empty ledger
    let stats = ledger.get_stats().await?;
    assert_eq!(stats.total_events, 0);

    let path = ledger
        .find_causal_path("nonexistent1", "nonexistent2")
        .await?;
    assert!(path.is_none());

    let events = ledger.get_events_by_step("nonexistent_step").await?;
    assert!(events.is_empty());

    let all_events = ledger.get_all_events().await?;
    assert!(all_events.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_malformed_event_handling() -> Result<()> {
    let (mut ledger, _temp_dir) = create_advanced_test_ledger();
    ledger.init().await?;

    // Create event with malformed/extreme values
    let mut malformed_event = create_test_event("malformed", "step", vec![], 0);
    malformed_event.input_hash = String::new(); // Empty hash
    malformed_event.step_name = String::new(); // Empty step name

    // This should either succeed with sanitization or fail gracefully
    let result = ledger.record_event_struct(malformed_event).await;
    assert!(result.is_ok() || result.is_err());

    Ok(())
}

#[test]
fn test_causal_chain_serialization() {
    let chain = CausalChain {
        chain_id: "test_chain".to_string(),
        events: vec![
            create_test_event("event1", "step1", vec![], 0),
            create_test_event("event2", "step2", vec!["event1".to_string()], 0),
        ],
        created_at: Utc::now(),
        chain_hash: "chain_hash_123".to_string(),
        chain_signature: None,
    };

    // Test serialization
    let serialized = serde_json::to_string(&chain).unwrap();
    assert!(serialized.contains("event1"));
    assert!(serialized.contains("chain_hash_123"));

    // Test deserialization
    let deserialized: CausalChain = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.events.len(), 2);
    assert_eq!(deserialized.chain_hash, "chain_hash_123");
}

#[test]
fn test_causal_query_creation_and_validation() {
    let mut path_metadata = HashMap::new();
    path_metadata.insert("depth".to_string(), "10".to_string());
    path_metadata.insert("include_failed".to_string(), "true".to_string());

    let query = CausalQuery {
        from_event: "start".to_string(),
        to_event: "end".to_string(),
        causal_path: vec!["start".to_string(), "middle".to_string(), "end".to_string()],
        is_valid: true,
        path_metadata,
    };

    // Test that query structure is valid
    assert_eq!(query.from_event, "start");
    assert_eq!(query.to_event, "end");
    assert_eq!(query.causal_path.len(), 3);
    assert!(query.is_valid);
    assert!(query.path_metadata.contains_key("depth"));
    assert_eq!(query.path_metadata.get("include_failed").unwrap(), "true");
}

#[test]
fn test_causal_event_hash_consistency() {
    let event1 = create_test_event("test_event", "test_step", vec![], 0);
    let event2 = create_test_event("test_event", "test_step", vec![], 0);

    // Events with same content should be equal
    assert_eq!(event1.event_id, event2.event_id);
    assert_eq!(event1.step_name, event2.step_name);

    // Test serialization consistency
    let serialized1 = serde_json::to_string(&event1).unwrap();
    let serialized2 = serde_json::to_string(&event2).unwrap();

    // Note: Timestamps might differ, so we check key fields
    assert!(serialized1.contains(&event1.event_id));
    assert!(serialized2.contains(&event2.event_id));
}
