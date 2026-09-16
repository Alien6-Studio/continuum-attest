use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    time::Duration,
};
use tempfile::tempdir;
fn cli(root: &std::path::Path, config: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_attest"));
    c.current_dir(root)
        .env("ATTEST_CONFIG_DIR", config)
        .env_remove("ATTEST_OFFLINE");
    c
}
#[test]
fn offline_default_explicit_connection_retry_disconnect_and_no_redirects() {
    let root = tempdir().unwrap();
    let config = tempdir().unwrap();
    let org = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let token = format!("attest_ingest_{}", "x".repeat(43));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    // Running without a connection creates no delivery state and uses no API.
    let run = cli(root.path(), config.path())
        .args([
            "run",
            "--wrap",
            "--name",
            "offline",
            "--sign",
            "--",
            "sh",
            "-c",
            "echo autonomous",
        ])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(std::fs::read_dir(config.path()).unwrap().count(), 0);
    let mut connect = cli(root.path(), config.path())
        .args([
            "connect",
            "--endpoint",
            &endpoint,
            "--organization",
            org,
            "--token-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    connect
        .stdin
        .take()
        .unwrap()
        .write_all(token.as_bytes())
        .unwrap();
    assert!(connect.wait_with_output().unwrap().status.success());
    let api = std::thread::spawn(move || {
        for status in [503, 200, 307] {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut data = Vec::new();
            let mut chunk = [0; 4096];
            let end;
            loop {
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                data.extend_from_slice(&chunk[..n]);
                if let Some(index) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    end = index + 4;
                    break;
                }
            }
            let headers = String::from_utf8_lossy(&data[..end]).to_lowercase();
            assert!(headers.contains("authorization: bearer attest_ingest_"));
            assert!(headers.contains(&format!("x-attest-organization: {org}")));
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .trim()
                .parse::<usize>()
                .unwrap();
            while data.len() < end + length {
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                data.extend_from_slice(&chunk[..n]);
            }
            let receipt: attest::Receipt = serde_yaml::from_slice(&data[end..]).unwrap();
            assert!(receipt.signature.is_some());
            assert!(!String::from_utf8_lossy(&data[end..]).contains("attest_ingest_"));
            let body = format!(
                "{{\"id\":\"{}\",\"organization_id\":\"{}\"}}",
                "a".repeat(64),
                org
            );
            write!(socket,"HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nLocation: https://must-not-follow.invalid/\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        }
    });
    let run = cli(root.path(), config.path())
        .args([
            "run",
            "--wrap",
            "--name",
            "connected",
            "--sign",
            "--",
            "sh",
            "-c",
            "echo connected",
        ])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(String::from_utf8_lossy(&run.stderr).contains("503"));
    assert!(cli(root.path(), config.path())
        .arg("sync")
        .output()
        .unwrap()
        .status
        .success());
    assert!(
        cli(root.path(), config.path())
            .arg("sync")
            .output()
            .unwrap()
            .status
            .success(),
        "queue was drained"
    );
    let run = cli(root.path(), config.path())
        .args([
            "run", "--wrap", "--name", "redirect", "--sign", "--", "sh", "-c", "exit 7",
        ])
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&run.stderr).contains("307"));
    api.join().unwrap();
    assert!(cli(root.path(), config.path())
        .arg("disconnect")
        .output()
        .unwrap()
        .status
        .success());
    assert!(cli(root.path(), config.path())
        .args(["run", "--wrap", "--name", "again", "--sign", "--", "sh", "-c", "true"])
        .output()
        .unwrap()
        .status
        .success());
    let receipt = std::fs::read_dir(root.path().join(".attest/receipts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(cli(root.path(), config.path())
        .arg("verify")
        .arg(receipt)
        .output()
        .unwrap()
        .status
        .success());
    assert!(!cli(root.path(), config.path())
        .arg("sync")
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn legacy_key_is_private_and_reloading_preserves_identity() {
    let root = tempdir().unwrap();
    let keys = root.path().join("keys");
    let first = attest::AttestKeypair::load_or_generate(&keys)
        .unwrap()
        .public_key_hex();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(keys.join("private.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    std::fs::remove_file(keys.join("public.key")).unwrap();
    assert_eq!(
        attest::AttestKeypair::load_or_generate(&keys)
            .unwrap()
            .public_key_hex(),
        first
    );
    std::fs::remove_file(keys.join("private.key")).unwrap();
    assert!(attest::AttestKeypair::load_or_generate(&keys).is_err());
}
