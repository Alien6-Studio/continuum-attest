use anyhow::{Context, Result};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::fs;
use std::path::{Path, PathBuf};

/// Matches paths against `.attestignore` with gitignore semantics:
/// `*.ext` applies at any depth, `dir/` ignores a directory and its
/// contents, `**/name` and `!negation` behave as in git.
#[derive(Debug)]
pub struct AttestIgnore {
    matcher: Gitignore,
    root: PathBuf,
}

impl AttestIgnore {
    pub fn new(ignore_file: &Path) -> Result<Self> {
        let root = ignore_file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        let mut builder = GitignoreBuilder::new(&root);
        if ignore_file.exists() {
            if let Some(err) = builder.add(ignore_file) {
                return Err(err)
                    .with_context(|| format!("invalid pattern in {}", ignore_file.display()));
            }
        } else {
            for pattern in Self::default_patterns() {
                builder
                    .add_line(None, &pattern)
                    .with_context(|| format!("Invalid glob pattern: {}", pattern))?;
            }
        }

        let matcher = builder.build().context("Failed to build ignore matcher")?;

        Ok(Self { matcher, root })
    }

    fn default_patterns() -> Vec<String> {
        vec![
            ".attest/".to_string(),
            "*.attest-receipt".to_string(),
            ".git/".to_string(),
            "target/".to_string(),
            "build/".to_string(),
            "node_modules/".to_string(),
            "__pycache__/".to_string(),
            "*.pyc".to_string(),
            ".DS_Store".to_string(),
            "*.tmp".to_string(),
            "*.log".to_string(),
        ]
    }

    pub fn is_ignored(&self, path: &Path) -> bool {
        // Callers pass paths from walking the workspace; match them
        // relative to the ignore file's directory, like git does.
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        let is_dir = path.is_dir();
        self.matcher
            .matched_path_or_any_parents(rel, is_dir)
            .is_ignore()
    }

    pub fn create_default(path: &Path) -> Result<()> {
        let content = include_str!("../templates/attestignore.template");
        fs::write(path, content).with_context(|| format!("Failed to create {}", path.display()))?;
        Ok(())
    }
}
