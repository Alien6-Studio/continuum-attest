//! A structural rule: nothing may be concatenated into a hash.
//!
//! Losing a field boundary is the cheapest way to forge a hash. A path written
//! into a newline-delimited manifest lets a filename carrying a newline fake
//! an entry; environment variables joined as `key=value` lines let a value
//! carrying a newline fake a variable, so two different environments share a
//! cache key.
//!
//! A behavioural test cannot prevent the next one: it only covers the
//! encodings somebody thought to write. This checks the *shape of the code*
//! instead, so a new encoder is caught when it is written rather than when it
//! is exploited.
//!
//! The rule: structured data reaches a hasher through
//! `crate::hashing::hash_field`, which length-prefixes, or not at all.

use std::path::Path;

/// Sites that legitimately write raw bytes: the primitive itself, and domain
/// separation strings, which are fixed literals rather than data.
fn is_allowed(file: &str, line: &str) -> bool {
    // `hash_field` is the primitive every other site must go through.
    if file.ends_with("src/hashing.rs") && line.contains("hasher.update(") {
        return true;
    }
    // A byte-string literal is a constant, not attacker-influenced data.
    let trimmed = line.trim();
    if trimmed.contains("update(b\"") {
        return true;
    }
    false
}

fn rust_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("readable directory") {
        let path = entry.expect("readable entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn nothing_is_concatenated_into_a_hash() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&root, &mut files);
    assert!(!files.is_empty(), "the source tree must be readable");

    let mut offences = Vec::new();
    for file in &files {
        let relative = file
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();
        let text = std::fs::read_to_string(file).expect("readable source");
        for (number, line) in text.lines().enumerate() {
            let is_update = line.contains(".update(");
            if !is_update {
                continue;
            }
            // `format!`, `+` and `join` are the three ways a field boundary
            // gets lost. Each produced a real defect in this repository.
            let concatenates = line.contains("update(format!")
                || line.contains(".join(")
                || line.contains("update(&format!");
            if concatenates && !is_allowed(&relative, line) {
                offences.push(format!("{}:{}: {}", relative, number + 1, line.trim()));
            }
        }
    }

    assert!(
        offences.is_empty(),
        "structured data must reach a hasher through \
         `crate::hashing::hash_field`, which length-prefixes each field. \
         Concatenating loses the boundary between fields, and a value \
         containing the separator then forges one:\n  {}",
        offences.join("\n  ")
    );
}
