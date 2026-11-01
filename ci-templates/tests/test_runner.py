"""Exercise the actual CI orchestration with a deterministic attest process."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "ci-templates/github/attest-action/run.py"
STUB = r'''
import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
with open("invocations.jsonl", "a") as trace:
    trace.write(json.dumps(args) + "\n")
if args[0] == "run":
    code = subprocess.run(args[args.index("--") + 1:]).returncode
    if os.environ.get("MISSING_REPORT"):
        sys.exit(code or 2)
    path = pathlib.Path(".attest/receipts/current.yaml")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("current receipt\n")
    report = {
        "build_exit_code": code,
        "evidence_status": "failed" if os.environ.get("RECEIPT_FAILURE") else "produced",
        "receipt": None if os.environ.get("RECEIPT_FAILURE") else str(path),
        "error": "receipt failed" if os.environ.get("RECEIPT_FAILURE") else None,
    }
    pathlib.Path(args[args.index("--report") + 1]).write_text(json.dumps(report))
    if os.environ.get("STATUS_REPORT_FAILURE"):
        pathlib.Path(args[args.index("--report") + 1]).parent.joinpath("status.json").mkdir()
    sys.exit(code or (2 if os.environ.get("RECEIPT_FAILURE") else 0))
elif args[0] in ("sign", "timestamp"):
    sys.exit(2 if os.environ.get("SIGN_FAILURE") else 0)
elif args[:2] == ["identity", "sign"]:
    if os.environ.get("IDENTITY_FAILURE"):
        sys.exit(2)
    pathlib.Path(args[args.index("--bundle") + 1]).write_text("public Sigstore bundle")
elif args[:2] == ["evidence", "pack"]:
    if os.environ.get("PACK_FAILURE"):
        sys.exit(2)
    if "--identity-bundle" in args:
        assert pathlib.Path(args[args.index("--identity-bundle") + 1]).is_file()
    pathlib.Path(args[args.index("--output") + 1]).write_bytes(b"evidence archive")
elif args[:2] == ["evidence", "verify"]:
    failed = bool(os.environ.get("VERIFY_FAILURE"))
    print(json.dumps({"verdict": "fail" if failed else "pass", "checks": []}))
    sys.exit(1 if failed else 0)
else:
    sys.exit(2)
'''


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        binary = self.root / "bin/attest"
        binary.parent.mkdir()
        binary.write_text(f"#!{sys.executable}\n" + textwrap.dedent(STUB))
        binary.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(binary.parent) + os.pathsep + os.environ["PATH"],
            "ATTEST_EVIDENCE_DIR": ".attest-ci",
            "ATTEST_STEP_NAME": "build",
            "ATTEST_COMMAND": "printf artifact > artifact.txt",
            "ATTEST_INPUTS": "source.txt",
            "ATTEST_OUTPUTS": "artifact.txt",
            "ATTEST_IDENTITY": "false",
        }
        self.env.pop("GITHUB_OUTPUT", None)
        self.env.pop("ATTEST_EXTRA_ARGS", None)
        self.env.pop("ATTEST_KEY", None)
        (self.root / "source.txt").write_text("source")

    def invoke(self, **changes):
        return subprocess.run(
            [sys.executable, str(RUNNER)], cwd=self.root,
            env={**self.env, **changes}, capture_output=True, text=True,
        )

    def status(self):
        return json.loads((self.root / ".attest-ci/status.json").read_text())

    def invocations(self):
        return [json.loads(line) for line in (self.root / "invocations.jsonl").read_text().splitlines()]

    def test_success_packs_current_receipt_and_keeps_upload_pending(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        status = self.status()
        self.assertEqual(status["build_exit_code"], 0)
        self.assertEqual(status["evidence_status"], "produced")
        self.assertEqual(status["publication_status"], "skipped")
        self.assertTrue(Path(status["evidence"]).is_file())
        self.assertNotIn("--sign", self.invocations()[0])
        self.assertEqual(self.invocations()[1][0], "sign")
        self.assertEqual(self.invocations()[2][2], ".attest/receipts/current.yaml")

    def test_build_failure_wins_over_pack_failure(self):
        result = self.invoke(ATTEST_COMMAND="exit 37", PACK_FAILURE="1")
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertEqual(self.status()["evidence_status"], "failed")

    def test_build_failure_wins_over_sign_failure(self):
        result = self.invoke(ATTEST_COMMAND="exit 39", SIGN_FAILURE="1")
        self.assertEqual(result.returncode, 39, result.stderr)
        self.assertEqual(self.status()["error_code"], "signing_failed")
        self.assertEqual(len(self.invocations()), 2)

    def test_failed_build_can_still_publish_diagnostic_evidence(self):
        result = self.invoke(ATTEST_COMMAND="exit 41")
        self.assertEqual(result.returncode, 41, result.stderr)
        self.assertEqual(self.status()["evidence_status"], "produced")

    def test_successful_build_with_failed_pack_is_operational_failure(self):
        result = self.invoke(PACK_FAILURE="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.status()["build_exit_code"], 0)

    def test_identity_failure_never_falls_back_to_key_only_evidence(self):
        result = self.invoke(ATTEST_IDENTITY="true", IDENTITY_FAILURE="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.status()["evidence_status"], "failed")
        self.assertEqual(len(self.invocations()), 3)
        self.assertFalse((self.root / ".attest-ci/release.attest.tar.zst").exists())

    def test_gitlab_identity_uses_token_environment_name(self):
        result = self.invoke(ATTEST_IDENTITY="true", ATTEST_IDENTITY_TOKEN_ENV="ATTEST_CI_ID_TOKEN")
        self.assertEqual(result.returncode, 0, result.stderr)
        identity = self.invocations()[2]
        self.assertEqual(identity[-2:], ["--identity-token-env", "ATTEST_CI_ID_TOKEN"])
        self.assertIn("--identity-bundle", self.invocations()[3])

    def test_missing_report_cannot_select_an_old_receipt(self):
        stale = self.root / ".attest/receipts/old.yaml"
        stale.parent.mkdir(parents=True)
        stale.write_text("older invocation")
        result = self.invoke(MISSING_REPORT="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIsNone(self.status()["receipt"])
        self.assertEqual(len(self.invocations()), 1)

    def test_existing_output_directory_is_refused_before_build(self):
        (self.root / ".attest-ci").mkdir()
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root / "invocations.jsonl").exists())

    def test_github_defers_build_failure_until_after_publication(self):
        output = self.root / "github-output"
        result = self.invoke(GITHUB_OUTPUT=str(output), ATTEST_COMMAND="exit 43", PACK_FAILURE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(values["exit-code"], "43")
        self.assertEqual(values["build-exit-code"], "43")
        self.assertEqual(values["evidence-status"], "failed")

    def test_declared_paths_never_expand_shell_metacharacters(self):
        result = self.invoke(ATTEST_INPUTS="* $(touch-injected) ;")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.invocations()[0]
        self.assertIn("*", args)
        self.assertIn("$(touch-injected)", args)
        self.assertIn(";", args)

    def test_invalid_identity_setting_is_refused(self):
        result = self.invoke(ATTEST_IDENTITY="treu")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root / "invocations.jsonl").exists())

    def test_failed_status_write_preserves_build_failure(self):
        result = self.invoke(ATTEST_COMMAND="exit 37", STATUS_REPORT_FAILURE="1")
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn("cannot write status report", result.stderr)

    def test_failed_status_write_is_reported_to_github_without_masking_build(self):
        output = self.root / "github-output"
        result = self.invoke(
            GITHUB_OUTPUT=str(output), ATTEST_COMMAND="exit 37", STATUS_REPORT_FAILURE="1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("exit-code=37\n", output.read_text())

    def test_failed_status_write_fails_a_successful_build(self):
        result = self.invoke(STATUS_REPORT_FAILURE="1")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_failed_github_output_write_preserves_build_failure(self):
        output = self.root / "not-a-writable-output-file"
        output.mkdir()
        result = self.invoke(GITHUB_OUTPUT=str(output), ATTEST_COMMAND="exit 37")
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn("cannot write action outputs", result.stderr)

    def test_subdirectory_workspace_is_forwarded_to_pack(self):
        result = self.invoke(ATTEST_EXTRA_ARGS='--workspace="project with spaces"')
        self.assertEqual(result.returncode, 0, result.stderr)
        pack = self.invocations()[2]
        self.assertEqual(pack[pack.index("--workspace") + 1], "project with spaces")

    def test_gitlab_artifact_path_cannot_publish_a_previous_job(self):
        component = (ROOT / "templates/attest.yml").read_text()
        variable = component.split("    ATTEST_EVIDENCE_DIR: ", 1)[1].splitlines()[0]
        artifact_path = component.split("  artifacts:\n", 1)[1].split("      - ", 1)[1].splitlines()[0]
        self.assertEqual(variable, ".attest-ci/$CI_JOB_ID")
        self.assertEqual(artifact_path, variable + "/")
        stale = self.root / variable.replace("$CI_JOB_ID", "101") / "release.attest.tar.zst"
        stale.parent.mkdir(parents=True)
        stale.write_text("previous job's evidence")
        current = artifact_path.replace("$CI_JOB_ID", "102")
        # This is also the runner's upload selection if installation fails
        # before Python starts: the previous job does not match the path.
        self.assertEqual(list(self.root.glob(current + "**/*")), [])
        result = self.invoke(ATTEST_EVIDENCE_DIR=current.rstrip("/"), MISSING_REPORT="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        published = list(self.root.glob(current + "**/*"))
        self.assertNotIn(stale, published)
        self.assertFalse(any(path.name == "release.attest.tar.zst" for path in published))

    def test_optional_signing_failure_is_visible(self):
        result = self.invoke(ATTEST_EVIDENCE_POLICY="optional", SIGN_FAILURE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.status()["error_code"], "signing_failed")
        self.assertEqual(self.status()["evidence_policy"], "optional")

    def test_receipt_failure_and_later_verification_failure_are_distinct(self):
        result = self.invoke(VERIFY_FAILURE="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.status()["evidence_status"], "produced")
        self.assertEqual(self.status()["verification_status"], "failed")
        self.assertEqual(self.status()["error_code"], "verification_failed")



class ComponentTests(unittest.TestCase):
    def test_gitlab_requires_identity_token_from_consuming_project(self):
        component = (ROOT / "templates/attest.yml").read_text()
        self.assertNotIn("  id_tokens:", component)
        self.assertIn("ATTEST_IDENTITY_TOKEN_ENV: ATTEST_CI_ID_TOKEN", component)

    def test_gitlab_embeds_the_same_tested_runner(self):
        component = (ROOT / "templates/attest.yml").read_text()
        embedded = component.split("      python3 - <<'ATTEST_RUNNER'\n", 1)[1]
        embedded = embedded.split("      ATTEST_RUNNER\n", 1)[0]
        source = "".join(line[6:] + "\n" for line in embedded.splitlines())
        self.assertEqual(source, RUNNER.read_text())


class PublicationTests(unittest.TestCase):
    def finalize(self, code, outcome, build_outcome="success", output_failure=False, policy="required"):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "output"
            if output_failure:
                output.mkdir()
            if code != "":
                status = {
                    "build_exit_code": int(code), "wrapper_exit_code": int(code),
                    "build_status": "failed" if int(code) else "succeeded",
                    "evidence_policy": policy, "evidence_status": "produced",
                    "verification_status": "passed", "publication_status": "pending",
                    "publication_url": None, "receipt": "receipt.yaml", "evidence": "archive.zst",
                    "failure_stage": None, "error_code": None, "error": None, "errors": [],
                }
                (directory / "status.json").write_text(json.dumps(status))
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--finalize", "--directory", str(directory),
                 "--publication-outcome", outcome, "--build-outcome", build_outcome],
                capture_output=True, text=True,
                env={**os.environ, "GITHUB_OUTPUT": str(output), "ATTEST_EXIT_CODE": str(code)},
            )
            values = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.is_file() else {}
            publication = values.get("publication-status")
            return result.returncode, "publication-status=" + publication + "\n" if publication else None

    def test_optional_upload_failure_is_visible_without_failing_build(self):
        self.assertEqual(self.finalize(0, "failure", policy="optional"), (0, "publication-status=failed\n"))

    def test_upload_failure_fails_a_successful_build(self):
        code, output = self.finalize(0, "failure")
        self.assertEqual(code, 2)
        self.assertIn("publication-status=failed", output)

    def test_upload_failure_does_not_mask_a_build_failure(self):
        code, output = self.finalize(37, "failure")
        self.assertEqual(code, 37)
        self.assertIn("publication-status=failed", output)

    def test_only_successful_upload_reports_published(self):
        self.assertEqual(self.finalize(0, "success"), (0, "publication-status=published\n"))
        self.assertEqual(self.finalize(0, "skipped"), (2, "publication-status=skipped\n"))

    def test_final_step_leaves_failed_build_outcome_when_outputs_are_unavailable(self):
        self.assertEqual(
            self.finalize("", "skipped", build_outcome="failure"),
            (0, None),
        )

    def test_publication_output_error_does_not_mask_build_failure(self):
        self.assertEqual(self.finalize(37, "success", output_failure=True), (37, None))

    def test_publication_output_error_fails_successful_build(self):
        self.assertEqual(self.finalize(0, "success", output_failure=True), (2, None))


if __name__ == "__main__":
    unittest.main()
