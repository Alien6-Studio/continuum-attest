//! Explicit, optional delivery. Configuration and credentials live outside the
//! repository. No config means no network calls, queue scans, or subscriptions.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const LIMIT: u64 = 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    endpoint: String,
    organization: String,
    token: String,
}

fn home() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("ATTEST_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(dir).join("attest"));
    }
    Ok(PathBuf::from(
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .context("user configuration directory unavailable")?,
    )
    .join(".config/attest"))
}
fn directory(workspace: &Path) -> Result<PathBuf> {
    let canonical = workspace.canonicalize()?;
    let id = blake3::hash(canonical.to_string_lossy().as_bytes())
        .to_hex()
        .to_string();
    Ok(home()?.join("connections").join(id))
}
fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("missing parent")?;
    private_dir(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path)?;
    Ok(())
}
fn endpoint(value: &str) -> Result<String> {
    let url = reqwest::Url::parse(value).context("invalid API endpoint")?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("endpoint must be an HTTPS origin without credentials, path, query or fragment (HTTP allowed on loopback only)");
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}
fn read_limited(path: &Path) -> Result<Vec<u8>> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("refusing symbolic link");
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("receipt exceeds the SaaS limit of 1 MiB; local receipt retained");
    }
    Ok(bytes)
}
fn connection(workspace: &Path) -> Result<Option<Connection>> {
    let path = directory(workspace)?.join("connection.json");
    if !path.exists() {
        return Ok(None);
    }
    let config: Connection = serde_json::from_slice(&read_limited(&path)?)?;
    endpoint(&config.endpoint)?;
    Ok(Some(config))
}
fn queue(workspace: &Path, config: &Connection) -> Result<PathBuf> {
    // Reconnecting to another destination never redirects an existing queue.
    let destination =
        blake3::hash(format!("{}\n{}", config.endpoint, config.organization).as_bytes())
            .to_hex()
            .to_string();
    Ok(directory(workspace)?.join("pending").join(destination))
}
pub fn connect(workspace: &Path, url: &str, org: &str) -> Result<()> {
    let url = endpoint(url)?;
    uuid::Uuid::parse_str(org).context("organization must be its UUID")?;
    if std::io::stdin().is_terminal() {
        bail!("provide the token through redirected stdin or a secrets-manager pipe; do not place it in command arguments");
    }
    let mut token = String::new();
    std::io::stdin().take(256).read_to_string(&mut token)?;
    let token = token.trim();
    if !token.starts_with("attest_ingest_")
        || token.len() != 57
        || !token[14..]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        bail!("invalid ingestion token");
    }
    let config = Connection {
        endpoint: url,
        organization: org.to_string(),
        token: token.to_string(),
    };
    private_write(
        &directory(workspace)?.join("connection.json"),
        &serde_json::to_vec(&config)?,
    )?;
    eprintln!("attest: connected. New signed receipts, including captured logs and provenance, will be sent to {} (organization {}). Private signing keys remain local. Use 'attest disconnect' to stop.",config.endpoint,config.organization);
    Ok(())
}
pub fn disconnect(workspace: &Path) -> Result<()> {
    let file = directory(workspace)?.join("connection.json");
    if file.exists() {
        fs::remove_file(file)?;
    }
    eprintln!("attest: disconnected; local receipts and pending deliveries retained. Revoke the token in the dashboard if it is no longer needed.");
    Ok(())
}
fn enqueue(workspace: &Path, path: &Path, config: &Connection) -> Result<()> {
    let raw = read_limited(path)?;
    let receipt: crate::storage::Receipt = serde_yaml::from_slice(&raw)?;
    if receipt.signature.is_none() {
        bail!("receipt is unsigned; run with --sign to enable SaaS delivery");
    }
    let id = blake3::hash(&raw).to_hex().to_string();
    private_write(&queue(workspace, config)?.join(format!("{id}.yaml")), &raw)
}
pub fn after_receipt(workspace: &Path, path: &Path) {
    if std::env::var("ATTEST_OFFLINE").is_ok_and(|v| v == "1" || v == "true") {
        return;
    }
    let result = (|| -> Result<()> {
        let Some(config) = connection(workspace)? else {
            return Ok(());
        };
        enqueue(workspace, path, &config)?;
        let root = workspace.to_path_buf();
        // Blocking HTTP runs outside Tokio. Delivery never changes execution's exit code.
        std::thread::spawn(move || flush(&root, 3))
            .join()
            .map_err(|_| anyhow::anyhow!("delivery worker failed"))?
    })();
    if let Err(error) = result {
        eprintln!("attest: SaaS delivery incomplete: {error}. Local receipt retained; use 'attest sync' to retry queued receipts.");
    }
}
pub fn flush(workspace: &Path, max: usize) -> Result<()> {
    if std::env::var("ATTEST_OFFLINE").is_ok_and(|v| v == "1" || v == "true") {
        bail!("ATTEST_OFFLINE disables delivery");
    }
    let config = connection(workspace)?
        .context("workspace is not connected; local operation remains available")?;
    let dir = queue(workspace, &config)?;
    if !dir.exists() {
        return Ok(());
    }
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut paths: Vec<_> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    paths.sort();
    for path in paths.into_iter().take(max) {
        let raw = read_limited(&path)?;
        let response = client
            .post(format!("{}/api/v1/receipts", config.endpoint))
            .bearer_auth(&config.token)
            .header("X-Attest-Organization", &config.organization)
            .header("Content-Type", "application/octet-stream")
            .body(raw)
            .send()
            .map_err(|_| anyhow::anyhow!("API unreachable; delivery stays queued"))?;
        if !response.status().is_success() {
            bail!(
                "API returned HTTP {}; delivery stays queued",
                response.status().as_u16()
            );
        }
        let mut bytes = Vec::new();
        response.take(8193).read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            bail!("unexpected API response; delivery stays queued");
        }
        let result: serde_json::Value =
            serde_json::from_slice(&bytes).context("invalid API response")?;
        if result["organization_id"].as_str() != Some(config.organization.as_str()) {
            bail!("token belongs to a different organization; check connection settings");
        }
        let id = result["id"]
            .as_str()
            .filter(|id| id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()))
            .context("missing receipt identifier")?;
        fs::remove_file(path)?;
        eprintln!("attest: delivered {}/receipts/{}", config.endpoint, id);
    }
    Ok(())
}

pub fn publish(workspace: &Path, path: &Path) -> Result<()> {
    let config = connection(workspace)?.context("workspace is not connected")?;
    enqueue(workspace, path, &config)?;
    flush(workspace, 100)
}
