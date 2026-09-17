//! Distinct structures must have distinct digests, on every surface.
//!
//! `hash_hygiene.rs` forbids the shape of code that loses a field boundary.
//! This is its behavioural counterpart: it does not care how an encoding is
//! written, only that two different structures cannot produce one digest.
//! A future encoder that avoids `format!` and is ambiguous anyway fails here.
//!
//! The adversarial values are the ones that broke this project: the
//! separator itself, the label names an encoder might use, and digit strings
//! that could be mistaken for a length prefix. Each surface is fed pairs that
//! differ in *structure* while looking alike to a naive encoder.

use std::collections::{BTreeMap, HashMap};

use attest::storage::Storage;

/// Values chosen to collide under an encoder that joins fields.
const HOSTILE: &[&str] = &[
    "\n",
    "=",
    ":",
    "\nZZ=x",
    "a=b\nc=d",
    "env-key",
    "env-value",
    "env-count",
    "3:x",
    "0:",
    "\u{0}",
];

fn cache_key(env: &HashMap<String, String>, step: &str, shape: &str) -> String {
    let workspace = tempfile::tempdir().expect("tempdir");
    let storage = Storage::new(workspace.path()).expect("storage");
    storage
        .compute_content_hash(workspace.path(), step, "cmd", &[], env, shape)
        .expect("cache key")
}

/// Two environments that differ must never share a cache key.
///
/// The attack has a shape, and generating hostile *characters* does not
/// produce it -- an earlier version of this test did exactly that and passed
/// against the very encoding it was written to reject. The collision needs a
/// value that contains the complete encoding of a *following* field: with
/// `key=value` lines, `ZZ_A` holding "one\nZZ_B=two" serialises to the same
/// bytes as `ZZ_A=one` plus `ZZ_B=two`.
///
/// So the pairs below are built that way, for every plausible separator and
/// assignment character an encoder might pick. The test does not need to know
/// which one is in use: if any of them is, one pair collides.
#[test]
fn distinct_environments_never_share_a_cache_key() {
    const SEPARATORS: &[&str] = &["\n", "\r\n", ";", ",", "\u{0}", " ", "\t"];
    const ASSIGNS: &[&str] = &["=", ":", "\u{0}"];

    for separator in SEPARATORS {
        for assign in ASSIGNS {
            // Two variables, honestly declared.
            let mut honest = HashMap::new();
            honest.insert("ZZ_A".to_string(), "one".to_string());
            honest.insert("ZZ_B".to_string(), "two".to_string());

            // One variable whose value smuggles the second.
            let mut smuggled = HashMap::new();
            smuggled.insert("ZZ_A".to_string(), format!("one{separator}ZZ_B{assign}two"));

            assert_ne!(
                cache_key(&honest, "step", "shape"),
                cache_key(&smuggled, "step", "shape"),
                "a value smuggling {separator:?}ZZ_B{assign:?}two forged a second \
                 variable: two different environments share a cache key"
            );

            // The mirror image: the smuggled text in the key rather than the
            // value.
            let mut keyed = HashMap::new();
            keyed.insert(format!("ZZ_A{assign}one{separator}ZZ_B"), "two".to_string());
            assert_ne!(
                cache_key(&honest, "step", "shape"),
                cache_key(&keyed, "step", "shape"),
                "a key smuggling a whole entry forged a second variable"
            );
        }
    }

    // And the plain count, which no separator trick is needed to confuse if
    // an encoder forgets it entirely.
    let mut one = HashMap::new();
    one.insert("A".to_string(), "".to_string());
    let mut two = HashMap::new();
    two.insert("A".to_string(), "".to_string());
    two.insert("B".to_string(), "".to_string());
    assert_ne!(
        cache_key(&one, "step", "shape"),
        cache_key(&two, "step", "shape"),
        "an empty second variable must still change the key"
    );

    // Hostile characters on their own, which cost nothing to keep.
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for hostile in HOSTILE {
        let mut env = HashMap::new();
        env.insert("A".to_string(), hostile.to_string());
        let key = cache_key(&env, "step", "shape");
        if let Some(previous) = seen.get(&key) {
            panic!("two different environments share a cache key: {previous} and {hostile:?}");
        }
        seen.insert(key, format!("{hostile:?}"));
    }
}

/// A step name is data too, and sits between two fields in the key.
#[test]
fn distinct_step_names_never_share_a_cache_key() {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let env = HashMap::new();
    for hostile in HOSTILE {
        for name in [format!("step{hostile}"), format!("{hostile}step")] {
            let key = cache_key(&env, &name, "shape");
            if let Some(previous) = seen.get(&key) {
                panic!("two different step names share a cache key: {previous:?} and {name:?}");
            }
            seen.insert(key, name);
        }
    }
}

/// The same property for causal event identity, which had the same defect.
#[test]
fn distinct_causal_events_never_share_an_identity() {
    use attest::storage::causal_ledger::{CausalEvent, CausalLedger};

    let base = CausalEvent {
        event_id: String::new(),
        step_name: "s".to_string(),
        causal_parents: Vec::new(),
        input_hash: "1".repeat(64),
        output_hash: "2".repeat(64),
        timestamp: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        exit_code: 0,
        signer_public_key: None,
        signature: None,
        pipeline_hash: "3".repeat(64),
        environment_hash: "4".repeat(64),
        metadata: Default::default(),
    };

    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut record = |description: String, event: CausalEvent| {
        let id = CausalLedger::event_id_of(&event);
        if let Some(previous) = seen.get(&id) {
            panic!("two different events share an identity:\n  {previous}\n  {description}");
        }
        seen.insert(id, description);
    };

    record("base".to_string(), base.clone());

    for hostile in HOSTILE {
        let mut named = base.clone();
        named.step_name = format!("s{hostile}");
        record(format!("step_name=s{hostile:?}"), named);

        // One parent carrying the separator, versus two parents.
        let mut one_parent = base.clone();
        one_parent.causal_parents = vec![format!("p{hostile}q")];
        record(format!("parents=[p{hostile:?}q]"), one_parent);

        let mut two_parents = base.clone();
        two_parents.causal_parents = vec!["p".to_string(), format!("{hostile}q")];
        record(format!("parents=[p, {hostile:?}q]"), two_parents);
    }
}

/// And for a step's execution shape, which decides whether a cached result
/// belongs to this run.
#[test]
fn distinct_step_configurations_never_share_a_shape() {
    use attest::pipeline::Step;

    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for hostile in HOSTILE {
        // serde_yaml would refuse some of these inside a quoted scalar, so
        // build the step through YAML only where the value survives a round
        // trip, and compare what does.
        let yaml = format!(
            "run: \"echo hi\"\ninputs: []\noutputs: []\nworking_dir: {}\n",
            serde_json::to_string(&format!("d{hostile}")).unwrap()
        );
        let Ok(step) = serde_yaml::from_str::<Step>(&yaml) else {
            continue;
        };
        let shape = step.execution_shape();
        if let Some(previous) = seen.get(&shape) {
            panic!("two different step configurations share a shape: {previous} and {hostile:?}");
        }
        seen.insert(shape, format!("working_dir=d{hostile:?}"));
    }
    assert!(
        seen.len() >= 5,
        "the fixture must exercise several hostile values, got {}",
        seen.len()
    );
}

/// The encoder itself must be injective, label included.
///
/// A length prefix only works if it precedes what it measures. Writing the
/// label *before* its own length let the label absorb the markers: label "a"
/// with value "z:7:0:" produced the same bytes as label "a:1:6:z" with an
/// empty value. That defect lived in the very function written to eliminate
/// this class of bug. Every call site passes a constant label, so nothing in
/// the product reaches the case -- which is exactly why it needs a test and
/// not an argument.
#[test]
fn no_pair_of_label_and_value_can_be_confused_for_another() {
    fn digest(label: &str, value: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new();
        attest::hashing::hash_field(&mut hasher, label, value);
        hasher.finalize().to_hex().to_string()
    }

    // A label long enough to contain its own length marker.
    assert_ne!(
        digest("a", b"z:7:0:"),
        digest("a:1:6:z", b""),
        "a label must not be able to absorb its own length marker"
    );

    // And a sweep over the alphabet that makes such confusions possible:
    // the separator, digits, and the empty string.
    let pieces = ["a", ":", "0", "1", "2", ""];
    let mut words: Vec<String> = Vec::new();
    for n in 0..=3 {
        let mut stack = vec![String::new()];
        for _ in 0..n {
            let mut next = Vec::new();
            for prefix in &stack {
                for piece in pieces {
                    next.push(format!("{prefix}{piece}"));
                }
            }
            stack = next;
        }
        words.extend(stack);
    }
    words.sort();
    words.dedup();

    let mut seen: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    for label in &words {
        for value in &words {
            let d = digest(label, value.as_bytes());
            if let Some(previous) = seen.get(&d) {
                assert_eq!(
                    previous,
                    &(label.clone(), value.clone()),
                    "two different (label, value) pairs share a digest: \
                     {previous:?} and {:?}",
                    (label, value)
                );
            }
            seen.insert(d, (label.clone(), value.clone()));
        }
    }
    assert!(
        seen.len() > 1000,
        "the sweep must be substantial, got {}",
        seen.len()
    );
}
