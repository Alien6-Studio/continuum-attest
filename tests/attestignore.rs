//! Regression tests for .attestignore glob matching.
//!
//! Patterns must follow gitignore semantics: `*.ext` at any depth,
//! `dir/` ignoring a directory and its contents, `**/name`, literal
//! names, and `!` negations.

use anyhow::Result;
use attest::ignore::AttestIgnore;
use tempfile::TempDir;

fn ignore_with(patterns: &str) -> Result<(TempDir, AttestIgnore)> {
    let dir = TempDir::new()?;
    let ignore_file = dir.path().join(".attestignore");
    std::fs::write(&ignore_file, patterns)?;
    let ignore = AttestIgnore::new(&ignore_file)?;
    Ok((dir, ignore))
}

#[test]
fn test_extension_glob_matches_at_any_depth() -> Result<()> {
    let (dir, ignore) = ignore_with("*.log\n")?;
    let root = dir.path();
    std::fs::create_dir_all(root.join("nested/deep"))?;
    std::fs::write(root.join("top.log"), "")?;
    std::fs::write(root.join("nested/deep/inner.log"), "")?;
    std::fs::write(root.join("keep.txt"), "")?;

    assert!(ignore.is_ignored(&root.join("top.log")));
    assert!(
        ignore.is_ignored(&root.join("nested/deep/inner.log")),
        "*.log must match below the top level"
    );
    assert!(!ignore.is_ignored(&root.join("keep.txt")));
    Ok(())
}

#[test]
fn test_directory_pattern_ignores_contents() -> Result<()> {
    let (dir, ignore) = ignore_with("target/\n")?;
    let root = dir.path();
    std::fs::create_dir_all(root.join("target/debug"))?;
    std::fs::write(root.join("target/debug/binary"), "")?;
    std::fs::write(root.join("targets.txt"), "")?;

    assert!(ignore.is_ignored(&root.join("target")));
    assert!(
        ignore.is_ignored(&root.join("target/debug/binary")),
        "files inside an ignored directory must be ignored"
    );
    assert!(
        !ignore.is_ignored(&root.join("targets.txt")),
        "'target/' must not match the file 'targets.txt'"
    );
    Ok(())
}

#[test]
fn test_double_star_pattern() -> Result<()> {
    let (dir, ignore) = ignore_with("**/generated.rs\n")?;
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/proto"))?;
    std::fs::write(root.join("generated.rs"), "")?;
    std::fs::write(root.join("src/proto/generated.rs"), "")?;
    std::fs::write(root.join("src/proto/handwritten.rs"), "")?;

    assert!(ignore.is_ignored(&root.join("generated.rs")));
    assert!(ignore.is_ignored(&root.join("src/proto/generated.rs")));
    assert!(!ignore.is_ignored(&root.join("src/proto/handwritten.rs")));
    Ok(())
}

#[test]
fn test_literal_name_and_negation() -> Result<()> {
    let (dir, ignore) = ignore_with("*.tmp\n!keep.tmp\n.DS_Store\n")?;
    let root = dir.path();
    std::fs::write(root.join("scratch.tmp"), "")?;
    std::fs::write(root.join("keep.tmp"), "")?;
    std::fs::write(root.join(".DS_Store"), "")?;

    assert!(ignore.is_ignored(&root.join("scratch.tmp")));
    assert!(
        !ignore.is_ignored(&root.join("keep.tmp")),
        "negated pattern must re-include the file"
    );
    assert!(ignore.is_ignored(&root.join(".DS_Store")));
    Ok(())
}

// Without an ignore file the defaults apply, including directory patterns.
#[test]
fn test_default_patterns_without_file() -> Result<()> {
    let dir = TempDir::new()?;
    let root = dir.path();
    std::fs::create_dir_all(root.join(".attest/receipts"))?;
    std::fs::write(root.join(".attest/receipts/r.yaml"), "")?;
    std::fs::write(root.join("app.log"), "")?;
    std::fs::write(root.join("main.rs"), "")?;

    let ignore = AttestIgnore::new(&root.join(".attestignore"))?;
    assert!(ignore.is_ignored(&root.join(".attest/receipts/r.yaml")));
    assert!(ignore.is_ignored(&root.join("app.log")));
    assert!(!ignore.is_ignored(&root.join("main.rs")));
    Ok(())
}
