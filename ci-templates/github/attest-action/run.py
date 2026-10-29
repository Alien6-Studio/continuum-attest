#!/usr/bin/env python3
"""Run one existing build and retain separate build/evidence outcomes.

This file is also embedded verbatim in the self-contained GitLab component.
The CI runner publishes the directory afterwards; publication cannot be
reported as successful until that separate operation has completed.
"""

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def run():
    if os.environ.get("ATTEST_IDENTITY", "false") not in ("true", "false"):
        raise ValueError("ATTEST_IDENTITY must be true or false")
    configured = os.environ.get("ATTEST_EVIDENCE_DIR")
    if configured:
        directory = Path(configured).absolute()
        # Never publish an earlier invocation's evidence after this one fails.
        directory.mkdir(parents=True, exist_ok=False)
    else:
        directory = Path(tempfile.mkdtemp(prefix="attest-evidence-", dir=os.environ.get("RUNNER_TEMP")))
    report_path = directory / "wrap.json"
    archive = directory / "release.attest.tar.zst"
    bundle = directory / "identity.sigstore.json"
    status = {
        "build_exit_code": None,
        "wrapper_exit_code": None,
        "evidence_status": "failed",
        "publication_status": "pending",
        "receipt": None,
        "evidence": None,
        "error": None,
    }
    args = ["attest", "run", "--wrap", "--name", os.environ["ATTEST_STEP_NAME"]]
    # Whitespace-separated paths match the original action contract. Splitting
    # never performs shell expansion: '*', '$()' and ';' stay literal paths.
    for name, flag in [("ATTEST_INPUTS", "--input"), ("ATTEST_OUTPUTS", "--output")]:
        for path in os.environ.get(name, "").split():
            args.extend([flag, path])
    args.append("--sign")
    if os.environ.get("ATTEST_KEY"):
        args.extend(["--key", os.environ["ATTEST_KEY"]])
    extra_args = shlex.split(os.environ.get("ATTEST_EXTRA_ARGS", ""))
    workspace_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    workspace_parser.add_argument("--workspace")
    extra_options, _ = workspace_parser.parse_known_args(extra_args)
    args.extend(extra_args)
    args.extend(["--report", str(report_path), "--", "sh", "-c", os.environ["ATTEST_COMMAND"]])
    try:
        completed = subprocess.run(args, check=False)
        status["wrapper_exit_code"] = completed.returncode
        report = json.loads(report_path.read_text())
        code = report.get("build_exit_code")
        if code is not None and (type(code) is not int or not 0 <= code <= 255):
            raise ValueError("wrap report has an invalid build exit code")
        status["build_exit_code"] = code
        status["receipt"] = report.get("receipt")
        if report.get("evidence_status") != "produced" or not status["receipt"]:
            raise ValueError(report.get("error") or "wrap did not produce a receipt")
        receipt = Path(status["receipt"])
        if not receipt.is_file():
            raise ValueError("wrap reported a missing receipt")
        pack = ["attest", "evidence", "pack", str(receipt), "--output", str(archive)]
        if extra_options.workspace:
            pack.extend(["--workspace", extra_options.workspace])
        if os.environ.get("ATTEST_IDENTITY", "false") == "true":
            identity = ["attest", "identity", "sign", str(receipt), "--bundle", str(bundle)]
            token_env = os.environ.get("ATTEST_IDENTITY_TOKEN_ENV")
            if token_env:
                identity.extend(["--identity-token-env", token_env])
            subprocess.run(identity, check=True)
            pack.extend(["--identity-bundle", str(bundle)])
        subprocess.run(pack, check=True)
        if not archive.is_file():
            raise ValueError("pack reported success without an evidence archive")
        status["evidence_status"] = "produced"
        status["evidence"] = str(archive)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        status["error"] = str(error)
        print(f"attest: evidence production failed: {error}", file=sys.stderr)

    # A failed build always wins, including when signing or packaging also
    # failed. A successful build with failed evidence is an operational error.
    code = status["build_exit_code"]
    if code is None:
        code = status["wrapper_exit_code"] or 2
    if code == 0 and status["evidence_status"] != "produced":
        code = 2
    status["exit_code"] = code
    try:
        (directory / "status.json").write_text(json.dumps(status, indent=2) + "\n")
    except OSError as error:
        print(f"attest-ci: cannot write status report: {error}", file=sys.stderr)
        code = code or 2
        status["exit_code"] = code
    print("attest-ci: " + json.dumps(status))
    if os.environ.get("GITHUB_OUTPUT"):
        outputs = {
            "build-exit-code": status["build_exit_code"],
            "evidence-status": status["evidence_status"],
            "receipt": status["receipt"],
            "evidence": status["evidence"],
            "directory": str(directory),
            "exit-code": code,
        }
        try:
            lines = []
            for key, value in outputs.items():
                value = "" if value is None else str(value)
                if "\n" in value or "\r" in value:
                    raise ValueError("an action output contains a newline")
                lines.append(f"{key}={value}\n")
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.writelines(lines)
        except (OSError, ValueError) as error:
            print(f"attest-ci: cannot write action outputs: {error}", file=sys.stderr)
            # With no reliable outputs the action's build step itself must
            # carry the failure; its final step leaves that outcome intact.
            return code or 2
        # The final action step restores this code after the upload attempt.
        return 0
    return code


if __name__ == "__main__":
    try:
        sys.exit(run())
    except (OSError, ValueError, KeyError) as error:
        print(f"attest-ci: setup failed: {error}", file=sys.stderr)
        sys.exit(2)
