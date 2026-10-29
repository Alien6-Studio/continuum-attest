"""Real CLI + TLS publication integration tests; no fake attest executable.

Set ATTEST_REAL_BINARY to the freshly built CLI. The HTTPS fixture implements
GitLab's documented PUT response contract; hosted GitLab identity is exercised
by ci-templates/gitlab/acceptance.yml, not simulated by this server.
"""

import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "ci-templates/github/attest-action/run.py"
BINARY = os.environ.get("ATTEST_REAL_BINARY")


@unittest.skipUnless(BINARY, "set ATTEST_REAL_BINARY for real CLI and TLS publication tests")
class RealIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = tempfile.TemporaryDirectory(prefix="attest-ci-tls-")
        cls.cert = Path(cls.authority.name) / "cert.pem"
        cls.private = Path(cls.authority.name) / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(cls.private), "-out", str(cls.cert),
        ], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.authority.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="attest-ci-real-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "bin").mkdir()
        (self.root / "bin/attest").symlink_to(Path(BINARY).resolve())
        (self.root / "source.txt").write_text("declared input\n")
        result = subprocess.run([BINARY, "keys", "generate", "--name", "ci-test"],
                                cwd=self.root, capture_output=True, text=True, check=True)
        self.key = result.stdout.strip()
        self.uploads = []
        self.http_status = 201
        case = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_PUT(self):
                payload = self.rfile.read(int(self.headers["Content-Length"]))
                # Record only whether the credential arrived, never the token.
                case.uploads.append({"path": self.path, "payload": payload,
                                     "authenticated": bool(self.headers.get("JOB-TOKEN"))})
                self.send_response(case.http_status)
                if case.http_status == 302:
                    self.send_header("Location", "/credential-must-not-follow")
                self.end_headers()
                self.wfile.write(b'{"message":"test response"}')

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.private)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        origin = f"https://localhost:{self.server.server_port}"
        self.env = {**os.environ, "PATH": str(self.root / "bin") + os.pathsep + os.environ["PATH"],
                    "ATTEST_EVIDENCE_DIR": ".attest-ci/current", "ATTEST_STEP_NAME": "build",
                    "ATTEST_INPUTS": "source.txt", "ATTEST_OUTPUTS": "artifact.txt",
                    "ATTEST_COMMAND": "cp source.txt artifact.txt", "ATTEST_KEY": self.key,
                    "ATTEST_IDENTITY": "false", "ATTEST_PUBLISHER": "gitlab",
                    "ATTEST_EVIDENCE_POLICY": "required", "CI_API_V4_URL": origin + "/api/v4",
                    "CI_SERVER_URL": origin, "CI_PROJECT_ID": "42", "CI_JOB_ID": "1234",
                    "CI_JOB_TOKEN": "public-test-only", "SSL_CERT_FILE": str(self.cert)}
        for name in ("GITHUB_OUTPUT", "ATTEST_KEYS_DIR", "ATTEST_EXTRA_ARGS", "ATTEST_TRUST_STORE",
                     "ATTEST_IDENTITY_POLICY"):
            self.env.pop(name, None)

    def run_case(self, expected, **changes):
        result = subprocess.run([sys.executable, str(RUNNER)], cwd=self.root,
                                env={**self.env, **changes}, capture_output=True, text=True)
        self.last_result = result
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        status = json.loads((self.root / ".attest-ci/current/status.json").read_text())
        self.assertEqual(status["exit_code"], expected)
        return status

    def test_published_archive_contains_the_real_build_and_verifies(self):
        status = self.run_case(0)
        self.assertEqual(status["build_exit_code"], 0)
        self.assertEqual(status["evidence_status"], "produced")
        self.assertEqual(status["verification_status"], "passed")
        self.assertEqual(status["publication_status"], "published")
        self.assertEqual(len(self.uploads), 1)
        self.assertTrue(self.uploads[0]["authenticated"])
        self.assertEqual(self.uploads[0]["path"], "/api/v4/projects/42/packages/generic/attest-evidence/1234/release.attest.tar.zst")
        archive = Path(status["evidence"])
        self.assertEqual(self.uploads[0]["payload"], archive.read_bytes())
        delivered = self.root / "delivered.attest.tar.zst"
        delivered.write_bytes(self.uploads[0]["payload"])
        shutil.rmtree(self.root / ".attest/keys")
        (self.root / "source.txt").unlink()
        verified = subprocess.run([BINARY, "evidence", "verify", str(delivered),
                                   "--trust-store", ".attest/trust", "--format", "json"],
                                  cwd=self.root, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(verified.stdout)["verdict"], "pass")

    def test_failed_build_remains_failed_when_signing_also_fails(self):
        status = self.run_case(37, ATTEST_COMMAND="cp source.txt artifact.txt; exit 37", ATTEST_KEY="missing")
        self.assertEqual(status["build_exit_code"], 37)
        self.assertEqual(status["error_code"], "signing_failed")
        self.assertEqual(status["publication_status"], "skipped")

    def test_wrapped_signal_preserves_native_shell_exit_semantics(self):
        status = self.run_case(143, ATTEST_COMMAND="cp source.txt artifact.txt; kill -TERM $$")
        self.assertEqual(status["build_exit_code"], 143)
        self.assertEqual(status["build_status"], "failed")

    def test_receipt_generation_failure_after_success_is_distinct(self):
        status = self.run_case(2, ATTEST_COMMAND="true")
        self.assertEqual(status["build_exit_code"], 0)
        self.assertEqual(status["error_code"], "receipt_failed")
        self.assertIsNone(status["receipt"])
        self.assertEqual(status["verification_status"], "skipped")

    def test_required_signing_failure_fails_successful_build(self):
        status = self.run_case(2, ATTEST_KEY="missing")
        self.assertEqual(status["build_exit_code"], 0)
        self.assertEqual(status["error_code"], "signing_failed")
        self.assertEqual(status["evidence_status"], "failed")

    def test_optional_signing_failure_is_visible_but_not_fatal(self):
        status = self.run_case(0, ATTEST_KEY="missing", ATTEST_EVIDENCE_POLICY="optional")
        self.assertEqual(status["error_code"], "signing_failed")
        self.assertEqual(status["evidence_policy"], "optional")

    def test_timestamp_failure_keeps_native_build_exit(self):
        status = self.run_case(39, ATTEST_COMMAND="cp source.txt artifact.txt; exit 39",
                               ATTEST_EXTRA_ARGS="--timestamp --tsa http://127.0.0.1:9")
        self.assertEqual(status["build_exit_code"], 39)
        self.assertEqual(status["error_code"], "timestamping_failed")
        self.assertIn("http://127.0.0.1:9", self.last_result.stderr)

    def test_produced_archive_can_fail_later_verification(self):
        (self.root / "untrusted").mkdir()
        status = self.run_case(2, ATTEST_TRUST_STORE=str(self.root / "untrusted"))
        self.assertEqual(status["build_exit_code"], 0)
        self.assertEqual(status["evidence_status"], "produced")
        self.assertEqual(status["verification_status"], "failed")
        self.assertEqual(status["error_code"], "verification_failed")
        self.assertEqual(status["publication_status"], "published")
        verdict = json.loads((self.root / ".attest-ci/current/verification.json").read_text())
        self.assertEqual(verdict["verdict"], "fail")
        self.assertTrue(any(c["name"] == "signature" and c["status"] == "fail" for c in verdict["checks"]))

    def test_required_publication_failure_is_separate_from_production(self):
        self.http_status = 503
        status = self.run_case(2)
        self.assertEqual(status["build_exit_code"], 0)
        self.assertEqual(status["evidence_status"], "produced")
        self.assertEqual(status["verification_status"], "passed")
        self.assertEqual(status["publication_status"], "failed")
        self.assertEqual(status["error_code"], "publication_failed")
        self.assertIsNone(status["publication_url"])

    def test_optional_publication_failure_is_visible_but_not_fatal(self):
        self.http_status = 503
        status = self.run_case(0, ATTEST_EVIDENCE_POLICY="optional")
        self.assertEqual(status["publication_status"], "failed")
        self.assertEqual(status["error_code"], "publication_failed")

    def test_publication_failure_never_hides_build_failure(self):
        self.http_status = 503
        status = self.run_case(41, ATTEST_COMMAND="cp source.txt artifact.txt; exit 41")
        self.assertEqual(status["build_exit_code"], 41)
        self.assertEqual(status["publication_status"], "failed")

    def test_publication_redirect_does_not_forward_job_token(self):
        self.http_status = 302
        status = self.run_case(2)
        self.assertEqual(status["publication_status"], "failed")
        self.assertEqual(len(self.uploads), 1)

    def test_untrusted_tls_certificate_is_rejected(self):
        status = self.run_case(2, SSL_CERT_FILE="/missing/independent-ca.pem")
        self.assertEqual(status["publication_status"], "failed")
        self.assertEqual(self.uploads, [])

    def test_non_https_publication_is_rejected_before_sending_token(self):
        status = self.run_case(2, CI_API_V4_URL="http://localhost/api/v4")
        self.assertEqual(status["publication_status"], "failed")
        self.assertEqual(self.uploads, [])


if __name__ == "__main__":
    unittest.main()
