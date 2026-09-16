//! Manifest-based input/output hashing (`attest-manifest/v1`).
//!
//! Both input and output hashes are `blake3(manifest_bytes)` where the
//! manifest is a canonical text document:
//!
//! ```text
//! attest-manifest/v1\n
//! run:<blake3-hex-of-step.run-utf8-bytes>\n          (input manifests only)
//! f:<blake3-hex-of-file-content> <normalized-relative-path>\n
//! l:<blake3-hex-of-symlink-target-string> <normalized-relative-path>\n
//! ```
//!
//! Entries are sorted by byte-wise lexicographic order of the normalized
//! path. Symlinks are never followed; a symlink escaping the workspace root
//! is an error. A declared path that does not exist is a hard error, never a
//! silent skip. Directories contribute no line themselves (empty directories
//! are invisible to the manifest).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// Manifest format header, first line of every manifest.
pub const MANIFEST_HEADER: &str = "attest-manifest/v1";

#[derive(Debug, Error)]
pub enum HashingError {
    #[error("step '{step}': declared input not found: {path}")]
    MissingInput { step: String, path: PathBuf },

    #[error("step '{step}': declared output not found: {path}")]
    MissingOutput { step: String, path: PathBuf },

    #[error("symlink '{path}' escapes the workspace root (target: {target})")]
    SymlinkEscape { path: PathBuf, target: String },

    #[error("path '{path}' cannot be represented in a manifest: {reason}")]
    InvalidPath { path: PathBuf, reason: String },

    #[error("I/O error on '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Which kind of declared path set is being hashed. Controls the `run:` line
/// and which missing-path error is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestKind {
    Input,
    Output,
}

/// Hash the declared inputs of a step. The `run` command participates in the
/// hash via a dedicated `run:` line (domain-separated from file contents).
pub fn hash_inputs(
    workspace: &Path,
    step: &str,
    run: &str,
    inputs: &[PathBuf],
) -> Result<String, HashingError> {
    let manifest = input_manifest(workspace, step, run, inputs)?;
    Ok(blake3::hash(manifest.as_bytes()).to_hex().to_string())
}

/// Hash the declared outputs of a step (no `run:` line).
pub fn hash_outputs(
    workspace: &Path,
    step: &str,
    outputs: &[PathBuf],
) -> Result<String, HashingError> {
    let manifest = output_manifest(workspace, step, outputs)?;
    Ok(blake3::hash(manifest.as_bytes()).to_hex().to_string())
}

/// Build the input manifest text. Exposed so callers (e.g. reproducibility
/// diff reports) can show *which* entries diverged, not just that hashes do.
pub fn input_manifest(
    workspace: &Path,
    step: &str,
    run: &str,
    inputs: &[PathBuf],
) -> Result<String, HashingError> {
    let entries = collect_entries(workspace, step, inputs, ManifestKind::Input)?;
    let run_hash = blake3::hash(run.as_bytes()).to_hex().to_string();
    let mut manifest = format!("{MANIFEST_HEADER}\nrun:{run_hash}\n");
    for (path, line) in &entries {
        push_entry(&mut manifest, line, path);
    }
    Ok(manifest)
}

/// Build the output manifest text.
pub fn output_manifest(
    workspace: &Path,
    step: &str,
    outputs: &[PathBuf],
) -> Result<String, HashingError> {
    let entries = collect_entries(workspace, step, outputs, ManifestKind::Output)?;
    let mut manifest = format!("{MANIFEST_HEADER}\n");
    for (path, line) in &entries {
        push_entry(&mut manifest, line, path);
    }
    Ok(manifest)
}

fn push_entry(manifest: &mut String, line: &str, path: &str) {
    manifest.push_str(line);
    manifest.push(' ');
    manifest.push_str(path);
    manifest.push('\n');
}

/// Collect `(normalized-path, "<kind>:<hex>")` pairs for every declared path.
/// The BTreeMap keys give byte-wise lexicographic ordering and deduplicate
/// overlapping declarations.
fn collect_entries(
    workspace: &Path,
    step: &str,
    declared: &[PathBuf],
    kind: ManifestKind,
) -> Result<BTreeMap<String, String>, HashingError> {
    let workspace = lexical_normalize(workspace);
    let mut entries = BTreeMap::new();

    for path in declared {
        let abs = workspace.join(path);
        let meta = match std::fs::symlink_metadata(&abs) {
            Ok(meta) => meta,
            Err(_) => {
                return Err(match kind {
                    ManifestKind::Input => HashingError::MissingInput {
                        step: step.to_string(),
                        path: path.clone(),
                    },
                    ManifestKind::Output => HashingError::MissingOutput {
                        step: step.to_string(),
                        path: path.clone(),
                    },
                });
            }
        };

        if meta.is_dir() {
            let walker = walkdir::WalkDir::new(&abs)
                .follow_links(false)
                .sort_by_file_name();
            for entry in walker {
                let entry = entry.map_err(|e| {
                    let err_path = e
                        .path()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| abs.clone());
                    HashingError::Io {
                        path: err_path,
                        source: e.into(),
                    }
                })?;
                let file_type = entry.file_type();
                if file_type.is_dir() {
                    continue;
                }
                add_entry(&workspace, entry.path(), &mut entries)?;
            }
        } else {
            add_entry(&workspace, &abs, &mut entries)?;
        }
    }

    Ok(entries)
}

fn add_entry(
    workspace: &Path,
    abs: &Path,
    entries: &mut BTreeMap<String, String>,
) -> Result<(), HashingError> {
    let normalized = normalize_relative(workspace, abs)?;
    let meta = std::fs::symlink_metadata(abs).map_err(|source| HashingError::Io {
        path: abs.to_path_buf(),
        source,
    })?;

    let line = if meta.file_type().is_symlink() {
        let target = std::fs::read_link(abs).map_err(|source| HashingError::Io {
            path: abs.to_path_buf(),
            source,
        })?;
        let target_str = target
            .to_str()
            .ok_or_else(|| HashingError::InvalidPath {
                path: abs.to_path_buf(),
                reason: "symlink target is not valid UTF-8".to_string(),
            })?
            .to_string();
        check_symlink_containment(workspace, abs, &target, &target_str)?;
        format!("l:{}", blake3::hash(target_str.as_bytes()).to_hex())
    } else {
        format!("f:{}", hash_file_streaming(abs)?)
    };

    entries.insert(normalized, line);
    Ok(())
}

/// Hash a file's content without loading it entirely into memory.
fn hash_file_streaming(path: &Path) -> Result<String, HashingError> {
    let file = std::fs::File::open(path).map_err(|source| HashingError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, file);
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut reader, &mut hasher).map_err(|source| HashingError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    hasher.flush().ok();
    Ok(hasher.finalize().to_hex().to_string())
}

/// Reject symlinks whose target resolves (lexically, without following
/// further links) outside the workspace root.
fn check_symlink_containment(
    workspace: &Path,
    link: &Path,
    target: &Path,
    target_str: &str,
) -> Result<(), HashingError> {
    let resolved = if target.is_absolute() {
        lexical_normalize(target)
    } else {
        let parent = link.parent().unwrap_or(workspace);
        lexical_normalize(&parent.join(target))
    };
    if !resolved.starts_with(workspace) {
        return Err(HashingError::SymlinkEscape {
            path: link.to_path_buf(),
            target: target_str.to_string(),
        });
    }
    Ok(())
}

/// Purely lexical normalization: removes `.` and resolves `..` against the
/// path itself, never touching the filesystem.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Workspace-relative path with `/` separators, raw UTF-8, no `.`/`..`.
fn normalize_relative(workspace: &Path, abs: &Path) -> Result<String, HashingError> {
    let normalized_abs = lexical_normalize(abs);
    let rel = normalized_abs
        .strip_prefix(workspace)
        .map_err(|_| HashingError::InvalidPath {
            path: abs.to_path_buf(),
            reason: "path is outside the workspace root".to_string(),
        })?;

    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(|| HashingError::InvalidPath {
                    path: abs.to_path_buf(),
                    reason: "path component is not valid UTF-8".to_string(),
                })?;
                parts.push(part);
            }
            _ => {
                return Err(HashingError::InvalidPath {
                    path: abs.to_path_buf(),
                    reason: "path contains non-normal components after normalization".to_string(),
                });
            }
        }
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn boundary_attack() {
        let t1 = tempfile::tempdir().unwrap();
        write(t1.path(), "a", "ab");
        write(t1.path(), "b", "c");
        let t2 = tempfile::tempdir().unwrap();
        write(t2.path(), "a", "a");
        write(t2.path(), "b", "bc");

        let h1 = hash_inputs(t1.path(), "s", "cmd", &paths(&["a", "b"])).unwrap();
        let h2 = hash_inputs(t2.path(), "s", "cmd", &paths(&["a", "b"])).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn rename_detected() {
        let t1 = tempfile::tempdir().unwrap();
        write(t1.path(), "a", "x");
        write(t1.path(), "b", "y");
        let t2 = tempfile::tempdir().unwrap();
        write(t2.path(), "a", "y");
        write(t2.path(), "b", "x");

        let h1 = hash_inputs(t1.path(), "s", "cmd", &paths(&["a", "b"])).unwrap();
        let h2 = hash_inputs(t2.path(), "s", "cmd", &paths(&["a", "b"])).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn order_independent() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a", "x");
        write(t.path(), "b", "y");

        let h1 = hash_inputs(t.path(), "s", "cmd", &paths(&["a", "b"])).unwrap();
        let h2 = hash_inputs(t.path(), "s", "cmd", &paths(&["b", "a"])).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn deterministic_across_runs() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "dir/a", "x");
        write(t.path(), "dir/sub/b", "y");

        let h1 = hash_inputs(t.path(), "s", "cmd", &paths(&["dir"])).unwrap();
        let h2 = hash_inputs(t.path(), "s", "cmd", &paths(&["dir"])).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn missing_input_is_error() {
        let t = tempfile::tempdir().unwrap();
        let err = hash_inputs(t.path(), "build", "cmd", &paths(&["nope.txt"])).unwrap_err();
        assert!(matches!(err, HashingError::MissingInput { .. }));
        assert!(err.to_string().contains("build"));
        assert!(err.to_string().contains("nope.txt"));
    }

    #[test]
    fn missing_output_is_error() {
        let t = tempfile::tempdir().unwrap();
        let err = hash_outputs(t.path(), "build", &paths(&["nope.bin"])).unwrap_err();
        assert!(matches!(err, HashingError::MissingOutput { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_not_followed() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a", "v1");
        std::os::unix::fs::symlink("a", t.path().join("s")).unwrap();

        let h1 = hash_inputs(t.path(), "s", "cmd", &paths(&["s"])).unwrap();
        write(t.path(), "a", "v2");
        let h2 = hash_inputs(t.path(), "s", "cmd", &paths(&["s"])).unwrap();
        assert_eq!(
            h1, h2,
            "symlink line must hash the target string, not content"
        );

        let target_line_hash = blake3::hash(b"a").to_hex().to_string();
        let manifest = input_manifest(t.path(), "s", "cmd", &paths(&["s"])).unwrap();
        assert!(manifest.contains(&format!("l:{target_line_hash} s")));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_rejected() {
        let t = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("../../etc/passwd", t.path().join("evil")).unwrap();
        let err = hash_inputs(t.path(), "s", "cmd", &paths(&["evil"])).unwrap_err();
        assert!(matches!(err, HashingError::SymlinkEscape { .. }));
    }

    #[test]
    fn empty_file_vs_absent() {
        let t1 = tempfile::tempdir().unwrap();
        write(t1.path(), "dir/a", "x");
        write(t1.path(), "dir/empty", "");
        let t2 = tempfile::tempdir().unwrap();
        write(t2.path(), "dir/a", "x");

        let h1 = hash_inputs(t1.path(), "s", "cmd", &paths(&["dir"])).unwrap();
        let h2 = hash_inputs(t2.path(), "s", "cmd", &paths(&["dir"])).unwrap();
        assert_ne!(h1, h2);

        let manifest = input_manifest(t1.path(), "s", "cmd", &paths(&["dir"])).unwrap();
        assert!(manifest.contains("dir/empty"));
    }

    #[test]
    fn run_command_participates_in_input_hash_only() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "a", "x");

        let h1 = hash_inputs(t.path(), "s", "cmd-1", &paths(&["a"])).unwrap();
        let h2 = hash_inputs(t.path(), "s", "cmd-2", &paths(&["a"])).unwrap();
        assert_ne!(h1, h2);

        let out = output_manifest(t.path(), "s", &paths(&["a"])).unwrap();
        assert!(!out.contains("run:"));
    }

    #[test]
    fn manifest_sorted_by_byte_order() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "dir/Z", "1");
        write(t.path(), "dir/a", "2");
        write(t.path(), "b", "3");

        let manifest = input_manifest(t.path(), "s", "cmd", &paths(&["dir", "b"])).unwrap();
        let entry_paths: Vec<&str> = manifest
            .lines()
            .filter(|l| l.starts_with("f:"))
            .map(|l| l.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(entry_paths, vec!["b", "dir/Z", "dir/a"]);
    }

    #[test]
    #[ignore = "allocates a 100 MB file; run explicitly"]
    fn large_file_streaming() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("big");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(100 * 1024 * 1024).unwrap();
        drop(file);
        hash_inputs(t.path(), "s", "cmd", &paths(&["big"])).unwrap();
    }
}

/// Hash and describe outputs from a single filesystem snapshot.
pub fn outputs_with_artifacts(
    workspace: &Path,
    step: &str,
    outputs: &[PathBuf],
) -> Result<(String, Vec<crate::storage::ArtifactInfo>), HashingError> {
    let entries = collect_entries(workspace, step, outputs, ManifestKind::Output)?;
    let mut manifest = format!("{MANIFEST_HEADER}\n");
    let mut artifacts = Vec::new();
    for (path, line) in entries {
        push_entry(&mut manifest, &line, &path);
        artifacts.push(crate::storage::ArtifactInfo {
            step: step.into(),
            path,
            kind: if line.starts_with("l:") {
                "symlink"
            } else {
                "file"
            }
            .into(),
            digest: line[2..].into(),
            algorithm: "blake3".into(),
        });
    }
    Ok((
        blake3::hash(manifest.as_bytes()).to_hex().to_string(),
        artifacts,
    ))
}
