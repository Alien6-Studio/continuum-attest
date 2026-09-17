//! Minimal signed execution context. No environment dump or command arguments.
use crate::storage::{CiInfo, ExecutionProvenance, SourceInfo, StepProvenance};
use std::path::Path;
use std::process::{Command, Stdio};

fn git(workspace: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-C")
        .arg(workspace)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 8192 {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}
fn repository_url(raw: &str) -> Option<String> {
    if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let raw = raw.split(['?', '#']).next()?;
    if let Some((scheme, rest)) = raw.split_once("://") {
        if !["https", "http", "ssh"].contains(&scheme) {
            return None;
        }
        let (authority, path) = rest.split_once('/')?;
        let host = authority.rsplit('@').next()?;
        if host.is_empty() {
            return None;
        }
        return Some(format!("{scheme}://{host}/{path}"));
    }
    let (_, remote) = raw.split_once('@')?;
    let (host, path) = remote.split_once(':')?;
    Some(format!("ssh://{host}/{path}"))
}
fn numeric_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_digit()))
}
pub fn collect(
    workspace: &Path,
    pipeline_name: Option<String>,
    deterministic: bool,
) -> ExecutionProvenance {
    let source = git(workspace, &["rev-parse", "HEAD"]).and_then(|commit| {
        if ![40, 64].contains(&commit.len()) || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(SourceInfo {
            repository: git(workspace, &["config", "--get", "remote.origin.url"])
                .and_then(|s| repository_url(&s)),
            commit,
            branch: git(workspace, &["symbolic-ref", "--short", "-q", "HEAD"]),
            tracked_dirty: !git(
                workspace,
                &["status", "--porcelain", "--untracked-files=no"],
            )
            .unwrap_or_else(|| "unknown".into())
            .is_empty(),
        })
    });
    let ci = if deterministic {
        None
    } else if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        Some(CiInfo {
            provider: "github".into(),
            run_id: numeric_env("GITHUB_RUN_ID"),
            job_id: None,
        })
    } else if std::env::var("GITLAB_CI").as_deref() == Ok("true") {
        Some(CiInfo {
            provider: "gitlab".into(),
            run_id: numeric_env("CI_PIPELINE_ID"),
            job_id: numeric_env("CI_JOB_ID"),
        })
    } else {
        None
    };
    ExecutionProvenance {
        invocation_id: (!deterministic).then(|| uuid::Uuid::new_v4().to_string()),
        started_at: (!deterministic).then(chrono::Utc::now),
        pipeline_name,
        source,
        runner_os: std::env::consts::OS.into(),
        runner_arch: std::env::consts::ARCH.into(),
        ci,
        steps: vec![],
        artifacts: vec![],
    }
}
pub fn step(
    name: &str,
    run: &str,
    needs: &[String],
    inputs: &[std::path::PathBuf],
    outputs: &[std::path::PathBuf],
) -> StepProvenance {
    StepProvenance {
        name: name.into(),
        needs: needs.to_vec(),
        command_hash: blake3::hash(run.as_bytes()).to_hex().to_string(),
        inputs: inputs
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        outputs: outputs
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repository_credentials_are_never_recorded() {
        assert_eq!(
            repository_url("https://user:secret@example.com/team/repo.git?token=secret#frag")
                .as_deref(),
            Some("https://example.com/team/repo.git")
        );
        assert_eq!(
            repository_url("git@example.com:team/repo.git").as_deref(),
            Some("ssh://example.com/team/repo.git")
        );
        assert_eq!(repository_url("/private/repo"), None);
    }
}
