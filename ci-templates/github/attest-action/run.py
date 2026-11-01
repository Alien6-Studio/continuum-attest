#!/usr/bin/env python3
"""Build, attest, verify and publish with independent machine-readable outcomes.

Embedded verbatim in the GitLab component. GitHub completes publication with
--finalize after upload-artifact; GitLab confirms its package upload in-process.
"""

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


class StageFailure(Exception):
    pass


def failure(status, stage, code, detail):
    item = {"stage": stage, "code": code, "detail": str(detail)}
    status["errors"].append(item)
    if status["error_code"] is None:
        status.update(failure_stage=stage, error_code=code, error=str(detail))


def outcome(status):
    build = status["build_exit_code"]
    if build is not None and build != 0:
        return build
    if build is None:
        return status["wrapper_exit_code"] or 2
    if (status.get("log_publication_policy") == "required"
            and status.get("log_publication_status") != "confirmed"):
        return 3
    errors = [error for error in status["errors"]
              if error["stage"] != "log_publication"
              or status.get("log_publication_policy") != "optional"]
    if status["evidence_policy"] == "required" and (
        status["evidence_status"] != "produced"
        or status["verification_status"] == "failed"
        or status["publication_status"] == "failed"
        or errors
    ):
        return 2
    return 0


def command(arguments):
    completed = subprocess.run(arguments, check=False)
    if completed.returncode:
        raise StageFailure(f"{arguments[0]} {arguments[1]} exited {completed.returncode}")


def save_status(directory, status):
    status["exit_code"] = outcome(status)
    try:
        (directory / "status.json").write_text(json.dumps(status, indent=2) + "\n")
        exported = {"ATTEST_" + key.upper(): status[key] for key in (
            "build_exit_code", "build_status", "evidence_policy", "evidence_status",
            "verification_status", "publication_status", "publication_url", "error_code", "exit_code",
            "log_publication_policy", "log_publication_status", "log_publication_reason")}
        (directory / "status.env").write_text("".join(
            f"{key}={'' if value is None else value}\n" for key, value in exported.items()))
    except OSError as error:
        failure(status, "reporting", "status_write_failed", error)
        # Reporting errors must never replace a known failed build's code.
        status["exit_code"] = status["build_exit_code"] or 2
        print(f"attest-ci: cannot write status report: {error}", file=sys.stderr)


def outputs(directory, status):
    if not os.environ.get("GITHUB_OUTPUT"):
        return True
    values = {
        "build-exit-code": status["build_exit_code"],
        "build-status": status["build_status"],
        "evidence-status": status["evidence_status"],
        "evidence-policy": status["evidence_policy"],
        "verification-status": status["verification_status"],
        "publication-status": status["publication_status"],
        "publication-url": status["publication_url"],
        "log-publication-policy": status["log_publication_policy"],
        "log-publication-status": status["log_publication_status"],
        "log-publication-reason": status["log_publication_reason"],
        "log-publication-record": status["log_publication_record"],
        "failure-stage": status["failure_stage"],
        "error-code": status["error_code"],
        "receipt": status["receipt"],
        "evidence": status["evidence"],
        "directory": str(directory),
        "exit-code": status["exit_code"],
        "status": json.dumps(status, separators=(",", ":")),
    }
    try:
        lines = []
        for key, value in values.items():
            value = "" if value is None else str(value)
            if "\n" in value or "\r" in value:
                raise ValueError("an action output contains a newline")
            lines.append(f"{key}={value}\n")
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.writelines(lines)
        return True
    except (OSError, ValueError) as error:
        print(f"attest-ci: cannot write action outputs: {error}", file=sys.stderr)
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        # Never forward a CI job credential to a redirect destination.
        raise StageFailure(f"publication refused HTTP redirect {code}")


def publish_gitlab(archive):
    api = os.environ["CI_API_V4_URL"].rstrip("/")
    server = urllib.parse.urlsplit(os.environ["CI_SERVER_URL"])
    parsed = urllib.parse.urlsplit(api)
    if (parsed.scheme != "https" or server.scheme != "https"
            or parsed.netloc != server.netloc or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise StageFailure("GitLab package API must use the CI server's HTTPS origin")
    token = os.environ.get("CI_JOB_TOKEN")
    if not token:
        raise StageFailure("CI_JOB_TOKEN is required for package publication")
    components = [os.environ["CI_PROJECT_ID"], os.environ.get("ATTEST_PACKAGE_NAME", "attest-evidence"),
                  os.environ["CI_JOB_ID"], archive.name]
    encoded = [urllib.parse.quote(value, safe="") for value in components]
    url = f"{api}/projects/{encoded[0]}/packages/generic/{encoded[1]}/{encoded[2]}/{encoded[3]}"
    request = urllib.request.Request(url, data=archive.read_bytes(), method="PUT",
                                     headers={"JOB-TOKEN": token, "Content-Type": "application/octet-stream"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            if response.status != 201:
                raise StageFailure(f"GitLab package upload returned HTTP {response.status}, expected 201")
    except urllib.error.HTTPError as error:
        raise StageFailure(f"GitLab package upload returned HTTP {error.code}") from None
    except urllib.error.URLError as error:
        raise StageFailure("GitLab package upload transport failed") from error
    return url


def run():
    policy = os.environ.get("ATTEST_EVIDENCE_POLICY", "required")
    if policy not in ("required", "optional"):
        raise ValueError("ATTEST_EVIDENCE_POLICY must be required or optional")
    if os.environ.get("ATTEST_IDENTITY", "false") not in ("true", "false"):
        raise ValueError("ATTEST_IDENTITY must be true or false")
    log_policy = os.environ.get("ATTEST_LOG_PUBLICATION_POLICY", "off")
    log_config = os.environ.get("ATTEST_LOG_CONFIG", "")
    if log_policy not in ("off", "required", "optional"):
        raise ValueError("ATTEST_LOG_PUBLICATION_POLICY must be off, required or optional")
    if bool(log_config) != (log_policy != "off"):
        raise ValueError("log publication requires both an explicit policy and a log configuration")
    log_timeout = int(os.environ.get("ATTEST_LOG_TIMEOUT_SECS", "30"))
    if not 1 <= log_timeout <= 120:
        raise ValueError("ATTEST_LOG_TIMEOUT_SECS must be between 1 and 120")
    if log_config and not Path(log_config).is_file():
        raise ValueError("log configuration file is missing")
    configured = os.environ.get("ATTEST_EVIDENCE_DIR")
    if configured:
        directory = Path(configured).absolute()
        directory.mkdir(parents=True, exist_ok=False)
    else:
        directory = Path(tempfile.mkdtemp(prefix="attest-evidence-", dir=os.environ.get("RUNNER_TEMP")))
    report_path = directory / "wrap.json"
    archive = directory / "release.attest.tar.zst"
    status = {
        "schema_version": 1, "build_status": "not_started", "build_exit_code": None,
        "wrapper_exit_code": None, "evidence_policy": policy, "evidence_status": "failed",
        "verification_status": "skipped", "publication_status": "pending",
        "publication_url": None, "receipt": None, "evidence": None,
        "log_publication_policy": log_policy, "log_publication_status": "skipped",
        "log_publication_reason": None, "log_publication_record": None,
        "failure_stage": None, "error_code": None, "error": None, "errors": [],
    }
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--timestamp", action="store_true")
    parser.add_argument("--tsa")
    known, extra = parser.parse_known_args(shlex.split(os.environ.get("ATTEST_EXTRA_ARGS", "")))
    args = ["attest", "run", "--wrap", "--name", os.environ["ATTEST_STEP_NAME"],
            "--workspace", known.workspace]
    for name, flag in [("ATTEST_INPUTS", "--input"), ("ATTEST_OUTPUTS", "--output")]:
        for path in os.environ.get(name, "").split():
            args.extend([flag, path])
    # Signing runs after the build, so generation/signing/timestamping errors
    # have distinct statuses. No evidence failure can hide the build result.
    if "--sign" in extra or "--key" in extra or "--report" in extra or "--" in extra:
        raise ValueError("use the key input; extra-args must not override signing, report or command")
    if known.tsa and not known.timestamp:
        raise ValueError("--tsa requires --timestamp")
    args.extend(extra)
    args.extend(["--report", str(report_path), "--", "sh", "-c", os.environ["ATTEST_COMMAND"]])
    stage = "receipt"
    try:
        completed = subprocess.run(args, check=False)
        status["wrapper_exit_code"] = completed.returncode
        report = json.loads(report_path.read_text())
        code = report.get("build_exit_code")
        if code is not None and (type(code) is not int or not 0 <= code <= 255):
            raise ValueError("wrap report has an invalid build exit code")
        status["build_exit_code"] = code
        status["build_status"] = "not_started" if code is None else ("succeeded" if code == 0 else "failed")
        status["receipt"] = report.get("receipt")
        if report.get("evidence_status") != "produced" or not status["receipt"]:
            raise StageFailure(report.get("error") or "wrap did not produce a receipt")
        receipt = Path(status["receipt"])
        if not receipt.is_file():
            raise StageFailure("wrap reported a missing receipt")
        signing = ["attest", "sign", str(receipt), "--workspace", known.workspace]
        if os.environ.get("ATTEST_KEY"):
            signing.extend(["--key", os.environ["ATTEST_KEY"]])
        stage = "signing"
        command(signing)
        if known.timestamp:
            stage = "timestamping"
            timestamp = ["attest", "timestamp", str(receipt)]
            if known.tsa:
                timestamp.extend(["--tsa", known.tsa])
            command(timestamp)
        pack = ["attest", "evidence", "pack", str(receipt), "--output", str(archive),
                "--workspace", known.workspace]
        if os.environ.get("ATTEST_IDENTITY", "false") == "true":
            stage = "identity"
            bundle = directory / "identity.sigstore.json"
            identity = ["attest", "identity", "sign", str(receipt), "--bundle", str(bundle)]
            if os.environ.get("ATTEST_IDENTITY_TOKEN_ENV"):
                identity.extend(["--identity-token-env", os.environ["ATTEST_IDENTITY_TOKEN_ENV"]])
            command(identity)
            pack.extend(["--identity-bundle", str(bundle)])
        # Explicit opt-in only, after signing. A failed build retains its own
        # code and diagnostic evidence without disclosing a log entry.
        if log_policy != "off" and code == 0:
            stage = "log_publication"
            publication = directory / "publication.json"
            publish = ["attest", "causal", "publish", "--receipt", str(receipt),
                       "--log-config", log_config, "--output", str(publication),
                       "--publication-policy", log_policy, "--timeout-secs", str(log_timeout),
                       "--trust-store", os.environ.get("ATTEST_TRUST_STORE")
                       or str(Path(known.workspace) / ".attest/trust"), "--format", "json"]
            published = subprocess.run(publish, capture_output=True, text=True, timeout=135)
            summary = json.loads(published.stdout)
            state = summary.get("status")
            if state not in ("confirmed", "unconfirmed", "error"):
                raise StageFailure("publisher returned an invalid status")
            status["log_publication_status"] = state
            reason = summary.get("reason")
            # Only fixed protocol reasons are exported; no opening or server body.
            if reason not in (None, "prepared", "request-failed", "service-refused",
                              "awaiting-inclusion", "invalid-proof", "deadline", "attempt-limit"):
                raise StageFailure("publisher returned an invalid reason")
            status["log_publication_reason"] = reason
            if published.returncode not in (0, 3) or not publication.is_file():
                raise StageFailure("publisher could not retain publication evidence")
            if state == "confirmed" and published.returncode != 0:
                raise StageFailure("publisher reported inconsistent confirmation")
            status["log_publication_record"] = str(publication)
            pack.extend(["--publication", str(publication)])
            if state != "confirmed":
                failure(status, stage, "log_publication_unconfirmed", reason or "unconfirmed")
        stage = "packaging"
        command(pack)
        if not archive.is_file():
            raise StageFailure("pack reported success without an evidence archive")
        status.update(evidence_status="produced", evidence=str(archive))
        stage = "verification"
        verify = ["attest", "evidence", "verify", str(archive), "--trust-store",
                  os.environ.get("ATTEST_TRUST_STORE") or str(Path(known.workspace) / ".attest/trust"),
                  "--format", "json"]
        if os.environ.get("ATTEST_IDENTITY_POLICY"):
            verify.extend(["--identity-policy", os.environ["ATTEST_IDENTITY_POLICY"]])
        if status["log_publication_record"]:
            verify.extend(["--log-trust", log_config])
            if log_policy == "required":
                verify.extend(["--require", "log-inclusion"])
        checked = subprocess.run(verify, capture_output=True, text=True)
        (directory / "verification.json").write_text(checked.stdout)
        verdict = json.loads(checked.stdout)
        if checked.returncode or verdict.get("verdict") != "pass":
            status["verification_status"] = "failed"
            raise StageFailure(f"evidence verification failed (exit {checked.returncode})")
        status["verification_status"] = "passed"
    except (OSError, ValueError, KeyError, StageFailure, subprocess.TimeoutExpired) as error:
        if stage == "verification":
            status["verification_status"] = "failed"
        if stage == "log_publication":
            status["log_publication_status"] = "error"
        failure(status, stage, stage + "_failed", error)

    publisher = os.environ.get("ATTEST_PUBLISHER", "github" if os.environ.get("GITHUB_OUTPUT") else "none")
    if not status["evidence"] or publisher == "none":
        status["publication_status"] = "skipped"
    elif publisher == "gitlab":
        try:
            status["publication_url"] = publish_gitlab(archive)
            status["publication_status"] = "published"
        except (OSError, ValueError, KeyError, StageFailure) as error:
            status["publication_status"] = "failed"
            failure(status, "publication", "publication_failed", error)
    elif publisher != "github":
        status["publication_status"] = "failed"
        failure(status, "publication", "publication_failed", "unsupported publication provider")
    save_status(directory, status)
    print("attest-ci: " + json.dumps(status))
    if not outputs(directory, status):
        return status["build_exit_code"] or 2
    return 0 if publisher == "github" else status["exit_code"]


def finalize(directory, publication_outcome, build_outcome):
    # If the runner could not report, its own failing step remains authoritative.
    if not directory:
        return 0 if build_outcome != "success" else 2
    directory = Path(directory)
    try:
        status = json.loads((directory / "status.json").read_text())
    except (OSError, ValueError):
        code = os.environ.get("ATTEST_EXIT_CODE", "")
        return int(code) if code and int(code) != 0 else (0 if build_outcome != "success" else 2)
    for key, value in {"log_publication_policy": "off", "log_publication_status": "skipped",
                       "log_publication_reason": None, "log_publication_record": None}.items():
        status.setdefault(key, value)
    status["publication_status"] = {"success": "published", "failure": "failed"}.get(publication_outcome, "skipped")
    status["publication_url"] = os.environ.get("ATTEST_PUBLICATION_URL") if publication_outcome == "success" else None
    if status["evidence"] and status["publication_status"] != "published":
        failure(status, "publication", "publication_failed", "CI artifact upload " + publication_outcome)
    save_status(directory, status)
    print("attest-ci: " + json.dumps(status))
    if not outputs(directory, status):
        return status["build_exit_code"] or 2
    return status["exit_code"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--finalize", action="store_true")
    parser.add_argument("--directory", default="")
    parser.add_argument("--publication-outcome", default="skipped")
    parser.add_argument("--build-outcome", default="failure")
    arguments = parser.parse_args()
    try:
        sys.exit(finalize(arguments.directory, arguments.publication_outcome, arguments.build_outcome)
                 if arguments.finalize else run())
    except (OSError, ValueError, KeyError) as error:
        print(f"attest-ci: setup failed: {error}", file=sys.stderr)
        sys.exit(2)
