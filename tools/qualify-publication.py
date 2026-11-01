#!/usr/bin/env python3
"""Exercise a real Tessera writer and an offline recipient with fresh test keys.

The server listens only on loopback. All leaves contain synthetic test data.
The caller supplies checksum/revision-pinned binaries; this tool downloads none.
"""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request


ENTRY_PREFIX = b"attest-causal-root/v1\n"


def command(arguments, cwd, expected=0, env=None):
    completed = subprocess.run([str(a) for a in arguments], cwd=cwd, capture_output=True,
                               text=True, env=env, timeout=150)
    if completed.returncode != expected:
        raise RuntimeError(f"{arguments[1:3]}: expected {expected}, got {completed.returncode}\n"
                           + completed.stdout + completed.stderr)
    return completed


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def certificates(control):
    config = control / "certificates.cnf"
    config.write_text("""[req]
distinguished_name=dn
prompt=no
[dn]
CN=Attest ephemeral publication qualification
[root]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
[server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
""")
    for name in ["ca", "server"]:
        command(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                 "-out", control / (name + ".key")], control)
        (control / (name + ".key")).chmod(0o600)
    command(["openssl", "req", "-new", "-x509", "-sha256", "-days", "1", "-key", "ca.key",
             "-out", "ca.pem", "-config", config, "-extensions", "root"], control)
    command(["openssl", "req", "-new", "-key", "server.key", "-out", "server.csr", "-config", config], control)
    command(["openssl", "x509", "-req", "-sha256", "-days", "1", "-in", "server.csr",
             "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem",
             "-extfile", config, "-extensions", "server"], control)


class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body=b"", headers=None):
        try:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def forward(self, method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.backend, timeout=5)
        try:
            connection.request(method, path, body=body)
            response = connection.getresponse()
            self.reply(response.status, response.read())
        finally:
            connection.close()

    def do_GET(self):
        if not self.path.startswith("/read/"):
            self.server.forbidden_reads.append(self.path)
            return self.reply(404)
        self.forward("GET", self.path.removeprefix("/read"))

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 1024:
            return self.reply(413)
        body = self.rfile.read(size)
        self.server.captures.append({"path": self.path, "entry": body.hex()})
        intent = json.loads(self.server.intent.read_text())
        if intent["entry"] != body.hex() or not intent["submissions"]:
            self.server.intent_failures.append(self.path)
            return self.reply(500)
        if not body.startswith(ENTRY_PREFIX) or len(body) != len(ENTRY_PREFIX) + 32:
            return self.reply(400)
        if self.path == "/refused/add":
            return self.reply(503)
        if self.path == "/unconfirmed/add":
            return self.reply(200, b"999999")
        if self.path == "/redirect/add":
            return self.reply(302, headers={"Location": self.server.base + "/forbidden"})
        if self.path == "/slow/add":
            time.sleep(3)
            return self.reply(200, b"999999")
        if self.path == "/wrong-entry/add":
            body = body[:-1] + bytes([body[-1] ^ 1])
        elif self.path != "/normal/add":
            return self.reply(404)
        self.forward("POST", "/add", body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attest", type=Path, required=True)
    parser.add_argument("--tessera", type=Path, required=True)
    parser.add_argument("--keygen", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runner", type=Path,
                        default=Path(__file__).resolve().parents[1] / "ci-templates/github/attest-action/run.py")
    parser.add_argument("--offline-mode", choices=["auto", "none"], default="auto")
    args = parser.parse_args()
    attest, tessera, keygen = [path.resolve() for path in [args.attest, args.tessera, args.keygen]]
    root = args.output.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise RuntimeError("qualification output must be empty")
    root.chmod(0o700)
    control, producer, recipient, audit = [root / name for name in ["control", "producer", "recipient", "audit"]]
    for directory in [control, producer, recipient, audit]:
        directory.mkdir(mode=0o700)
    origin = "attest-publication.test/log"
    command([keygen, "-keygen", "-origin", origin, "-output", control / "log-key"], control)
    verifier = (control / "log-key.public").read_text().strip()
    certificates(control)
    backend_port = free_port()
    server_log = (control / "tessera.log").open("w")
    backend = subprocess.Popen([str(tessera), "--storage_dir", str(control / "log-store"),
                                "--listen", f"127.0.0.1:{backend_port}",
                                "--private_key", str(control / "log-key.private")],
                               stdout=server_log, stderr=server_log)
    proxy = None
    try:
        for _ in range(100):
            if backend.poll() is not None:
                raise RuntimeError("Tessera exited: " + (control / "tessera.log").read_text())
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{backend_port}/checkpoint", timeout=0.2).close()
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise RuntimeError("Tessera did not publish its first checkpoint")
        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        proxy.daemon_threads = True
        proxy.backend = backend_port
        proxy.base = f"https://127.0.0.1:{proxy.server_port}"
        proxy.captures, proxy.forbidden_reads, proxy.intent_failures = [], [], []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(control / "server.pem", control / "server.key")
        proxy.socket = context.wrap_socket(proxy.socket, server_side=True)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        config = {"format": "attest-log/v1", "origin": origin, "verifier_key": verifier,
                  "read_url": proxy.base + "/read/", "submit_url": proxy.base + "/normal/add",
                  "tls_ca": str(control / "ca.pem")}
        config_file = control / "producer-log.json"
        write_json(config_file, config)
        write_json(recipient / "log-trust.json", {k: config[k] for k in ["format", "origin", "verifier_key"]})
        command([attest, "init"], producer)
        command([attest, "keys", "generate", "--name", "qualification"], producer)
        (producer / "src").mkdir()
        (producer / "src/input.txt").write_text("private-input-for-publication-qualification\n")
        command([attest, "run", "--wrap", "--name", "build", "--input", "src/", "--output", "dist/",
                 "--sign", "--report", "build.json", "--", "sh", "-c",
                 "mkdir -p dist && cp src/input.txt dist/artifact.txt"], producer)
        receipt = Path(json.loads((producer / "build.json").read_text())["receipt"])
        if not receipt.is_absolute():
            receipt = producer / receipt

        def publish(name, mode="normal", policy="required", timeout=10, expected=None):
            config["submit_url"] = proxy.base + f"/{mode}/add"
            write_json(config_file, config)
            output = producer / (name + ".json")
            proxy.intent = output
            code = expected if expected is not None else (0 if mode == "normal" or policy == "optional" else 3)
            started = time.monotonic()
            completed = command([attest, "causal", "publish", "--receipt", receipt, "--log-config", config_file,
                                 "--output", output, "--publication-policy", policy,
                                 "--timeout-secs", str(timeout), "--format", "json"], producer, code)
            record = json.loads(output.read_text())
            summary = json.loads(completed.stdout)
            assert record["opening_nonce"] not in completed.stdout + completed.stderr
            assert record["causal_root"] not in completed.stdout + completed.stderr
            assert (output.stat().st_mode & 0o077) == 0
            assert len(record["submissions"]) <= 3
            assert time.monotonic() - started < timeout + 5
            assert summary["status"] == record["outcome"]["status"]
            return output, record

        first_file, first = publish("first")
        before = len(proxy.captures)
        _, resumed = publish("first")
        assert resumed == first and len(proxy.captures) == before
        before = len(proxy.captures)
        config.pop("tls_ca")
        _, untrusted_tls = publish("untrusted-tls", expected=3)
        assert untrusted_tls["outcome"]["status"] == "unconfirmed" and len(proxy.captures) == before
        config["tls_ca"] = str(control / "ca.pem")
        config["submit_url"] = proxy.base.replace("https:", "http:") + "/normal/add"
        write_json(config_file, config)
        command([attest, "causal", "publish", "--receipt", receipt, "--log-config", config_file,
                 "--output", producer / "unsafe-transport.json", "--publication-policy", "required"], producer, 2)
        assert len(proxy.captures) == before and not (producer / "unsafe-transport.json").exists()
        second_file, second = publish("second")
        assert first["outcome"]["status"] == second["outcome"]["status"] == "confirmed"
        assert first["entry"] != second["entry"] and first["opening_nonce"] != second["opening_nonce"]
        (recipient / "reference.note").write_text(first["outcome"]["checkpoint"])
        (recipient / "publication.note").write_text(second["outcome"]["checkpoint"])
        command([attest, "causal", "fetch-consistency", "--first-checkpoint", recipient / "reference.note",
                 "--second-checkpoint", recipient / "publication.note", "--log-config", config_file,
                 "--output", recipient / "comparison.json"], producer)
        command([attest, "evidence", "pack", receipt, "--workspace", producer, "--publication", second_file,
                 "--log-consistency", recipient / "comparison.json", "--output", recipient / "release.attest.tar.zst"], producer)
        before = len(proxy.captures)
        command([attest, "causal", "publish", "--receipt", receipt, "--log-config", config_file,
                 "--output", producer / "missing-parent/record.json", "--publication-policy", "required"], producer, 2)
        assert len(proxy.captures) == before, "a failed intent write must prevent disclosure"
        refused_file = None
        for mode in ["refused", "unconfirmed", "redirect", "wrong-entry"]:
            for policy in ["required", "optional"]:
                output, record = publish(mode + "-" + policy, mode, policy, 3)
                assert record["outcome"]["status"] == "unconfirmed"
                if mode == "refused":
                    assert len(record["submissions"]) == 3
                    refused_file = output
        publish("deadline", "slow", "required", 1)
        before = len(proxy.captures)
        publish("refused-optional", "refused", "optional", 3)
        assert len(proxy.captures) == before, "resume exceeded its retained submission limit"
        assert not proxy.forbidden_reads, "the publisher followed a redirect"
        command([attest, "evidence", "pack", receipt, "--workspace", producer, "--publication", refused_file,
                 "--output", recipient / "unconfirmed.attest.tar.zst"], producer)
        config["submit_url"] = proxy.base + "/refused/add"
        write_json(config_file, config)
        for policy, code in [("required", 3), ("optional", 0)]:
            directory = producer / ("ci-" + policy)
            proxy.intent = directory / "publication.json"
            environment = {**os.environ, "PATH": str(attest.parent) + os.pathsep + os.environ["PATH"],
                           "ATTEST_EVIDENCE_DIR": str(directory), "ATTEST_STEP_NAME": "build",
                           "ATTEST_COMMAND": "mkdir -p dist && rm -f dist/artifact.txt && cp src/input.txt dist/artifact.txt",
                           "ATTEST_INPUTS": "src/", "ATTEST_OUTPUTS": "dist/", "ATTEST_IDENTITY": "false",
                           "ATTEST_PUBLISHER": "none", "ATTEST_EVIDENCE_POLICY": "optional",
                           "ATTEST_LOG_CONFIG": str(config_file), "ATTEST_LOG_PUBLICATION_POLICY": policy,
                           "ATTEST_LOG_TIMEOUT_SECS": "3"}
            environment.pop("GITHUB_OUTPUT", None)
            completed = command([sys.executable, args.runner.resolve()], producer, code, env=environment)
            status = json.loads((directory / "status.json").read_text())
            assert status["build_exit_code"] == 0 and status["evidence_status"] == "produced"
            assert status["log_publication_status"] == "unconfirmed"
            assert status["log_publication_reason"] and status["publication_status"] == "skipped"
            intent = json.loads(proxy.intent.read_text())
            assert intent["opening_nonce"] not in completed.stdout + completed.stderr
        directory = producer / "ci-failed-build"
        environment.update(ATTEST_EVIDENCE_DIR=str(directory), ATTEST_LOG_PUBLICATION_POLICY="required",
                           ATTEST_COMMAND="exit 37", ATTEST_OUTPUTS="")
        before = len(proxy.captures)
        command([sys.executable, args.runner.resolve()], producer, 37, env=environment)
        status = json.loads((directory / "status.json").read_text())
        assert status["build_exit_code"] == 37 and status["log_publication_status"] == "skipped"
        assert len(proxy.captures) == before
        assert not proxy.intent_failures, "disclosure preceded durable intent"
        for item in proxy.captures:
            entry = bytes.fromhex(item["entry"])
            assert entry.startswith(ENTRY_PREFIX) and len(entry) == len(ENTRY_PREFIX) + 32
            assert bytes.fromhex(first["causal_root"]) not in entry
            assert b"private-input-for-publication-qualification" not in entry
        shutil.copytree(producer / ".attest/trust", recipient / "receipt-trust")
        for record in producer.glob("*.json"):
            if record.name != "build.json":
                shutil.copy2(record, audit / record.name)
        write_json(audit / "submitted-entries.json", proxy.captures)
    finally:
        if proxy is not None:
            proxy.shutdown()
            proxy.server_close()
        backend.terminate()
        try:
            backend.wait(timeout=10)
        except subprocess.TimeoutExpired:
            backend.kill()
            backend.wait()
        server_log.close()

    # Remove the producer and all temporary signing keys before recipient use.
    shutil.rmtree(producer)
    for key in [control / "log-key.private", control / "ca.key", control / "server.key"]:
        key.unlink()
    prefix = []
    if args.offline_mode == "auto":
        if sys.platform == "darwin":
            prefix = ["/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)"]
        elif sys.platform.startswith("linux"):
            prefix = ["sudo", "-n", "unshare", "--net", "--"]
        else:
            raise RuntimeError("no configured kernel network isolation for this platform")
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
    common = [attest, "evidence", "verify", "release.attest.tar.zst", "--trust-store", "receipt-trust",
              "--log-trust", "log-trust.json", "--log-checkpoint", "reference.note",
              "--require", "signature,success,artifacts,capsule,linkage,log-inclusion,log-consistency", "--format", "json"]
    verdict = json.loads(command(prefix + common, recipient, env=environment).stdout)
    assert verdict["verdict"] == "pass"
    assert all(next(c for c in verdict["checks"] if c["name"] == name)["status"] == "pass"
               for name in ["log-inclusion", "log-consistency"])
    refused = [attest, "evidence", "verify", "unconfirmed.attest.tar.zst", "--trust-store", "receipt-trust",
               "--log-trust", "log-trust.json", "--require", "log-inclusion", "--format", "json"]
    refusal = json.loads(command(prefix + refused, recipient, expected=1, env=environment).stdout)
    assert refusal["verdict"] == "fail"
    assert next(c for c in refusal["checks"] if c["name"] == "log-inclusion")["status"] == "skipped"
    write_json(root / "qualification.json", {
        "kernel_network_isolation": bool(prefix), "producer_removed": True,
        "temporary_signing_keys_removed": True, "intact_delivery": "accepted",
        "unconfirmed_required_inclusion": "refused",
        "publication_scenarios": ["confirmed", "service-refused", "unconfirmed-index", "redirect", "wrong-entry", "deadline", "untrusted-tls", "plaintext-refused"],
        "public_entry_bytes": len(ENTRY_PREFIX) + 32, "ci_required_and_optional": "passed",
        "intent_persisted_before_disclosure": True, "confirmed_resume_without_resubmission": True,
        "attest_binary_sha256": hashlib.sha256(attest.read_bytes()).hexdigest(),
        "tessera_binary_sha256": hashlib.sha256(tessera.read_bytes()).hexdigest(),
        "source_revision": os.environ.get("GITHUB_SHA"),
        "artifact_sha256": hashlib.sha256((recipient / "release.attest.tar.zst").read_bytes()).hexdigest(),
    })
    print(json.dumps({"qualification": str(root / "qualification.json"), "offline": bool(prefix), "result": "passed"}))


if __name__ == "__main__":
    main()
