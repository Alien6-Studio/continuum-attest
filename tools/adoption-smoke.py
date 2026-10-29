#!/usr/bin/env python3
"""Exercise the packaged CLI's 0.3 handoff, including rejection cases.

Run the entire script in a network namespace in release CI. The build has
no signing key: a throwaway key is created only after its command has exited.
The recipient receives its public trust anchor separately from the package.
This checks local signing; the real Sigstore fixture has its own CI gate.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def smoke(binary):
    environment = os.environ.copy()
    environment.pop("ATTEST_KEYS_DIR", None)

    def command(workspace, arguments, expected=0):
        result = subprocess.run(
            [str(binary), *arguments], cwd=workspace, env=environment,
            capture_output=True, text=True,
        )
        if result.returncode != expected:
            raise RuntimeError(
                f"attest {arguments[0]} exited {result.returncode}, expected {expected}:\n"
                f"{result.stdout}{result.stderr}"
            )
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="attest-adoption-") as temporary:
        root = Path(temporary)
        producer = root / "producer"
        recipient = root / "recipient"
        delivery = root / "delivery"
        for directory in (producer, recipient, delivery):
            directory.mkdir()
        original = b"a release built from declared input\n"
        (producer / "source.txt").write_bytes(original)
        report = producer / "wrap.json"
        command(producer, [
            "run", "--wrap", "--name", "release-smoke",
            "--input", "source.txt", "--output", "artifact.bin",
            "--report", str(report), "--", "sh", "-c",
            'test ! -d .attest/keys && test -z "${ATTEST_KEYS_DIR:-}" && cp source.txt artifact.bin',
        ])
        wrapped = json.loads(report.read_text())
        assert wrapped["build_exit_code"] == 0
        assert wrapped["evidence_status"] == "produced"
        receipt = Path(wrapped["receipt"])
        if not receipt.is_absolute():
            receipt = producer / receipt
        assert not (producer / ".attest/keys").exists(), "build unexpectedly created a signing key"

        # Production has finished. No private key existed while it ran.
        key_id = command(producer, ["keys", "generate", "--name", "release-smoke"]).strip()
        public_key = recipient / "approved-release.pub"
        command(producer, ["keys", "export", key_id, "--output", str(public_key)])
        command(producer, ["sign", str(receipt), "--key", key_id])
        archive = delivery / "release.attest.tar.zst"
        command(producer, ["evidence", "pack", str(receipt), "--output", str(archive)])
        shutil.copyfile(producer / "artifact.bin", delivery / "artifact.bin")

        # This explicit import is the recipient's independent trust decision;
        # no key or policy from inside the evidence is automatically trusted.
        command(recipient, ["keys", "import", str(public_key), "--name", "approved-release"])
        assert not (recipient / ".attest/keys").exists(), "recipient received private keys"
        shutil.rmtree(producer)
        verify = [
            "evidence", "verify", str(archive), "--trust-store", ".attest/trust",
            "--artifact-root", str(delivery), "--format", "json",
        ]
        accepted = json.loads(command(recipient, verify))
        assert accepted["verdict"] == "pass", accepted
        checks = {check["name"]: check["status"] for check in accepted["checks"]}
        assert checks["signature"] == checks["artifacts"] == "pass", checks

        (delivery / "artifact.bin").write_bytes(b"substituted artifact\n")
        substituted = json.loads(command(recipient, verify, expected=1))
        assert substituted["verdict"] == "fail", substituted
        assert any(
            check["name"] == "artifacts" and check["status"] == "fail"
            for check in substituted["checks"]
        ), substituted
        (delivery / "artifact.bin").write_bytes(original)

        # Local evidence may not satisfy a recipient requiring CI identity.
        policy = recipient / "required-workflow.json"
        policy.write_text(json.dumps({
            "issuer": "https://token.actions.githubusercontent.com",
            "repository": "https://github.com/example/approved",
            "workflow": "https://github.com/example/approved/.github/workflows/release.yml@refs/heads/main",
            "revision": "1" * 40,
            "trusted_root": "independently-provisioned-root.json",
        }))
        missing = json.loads(command(
            recipient, [*verify, "--identity-policy", str(policy)], expected=1,
        ))
        assert any(
            check["name"] == "identity" and check["status"] == "fail"
            and "missing" in check["detail"]
            for check in missing["checks"]
        ), missing
        assert json.loads(command(recipient, verify))["verdict"] == "pass"
    print("0.3 adoption smoke passed: separate signer, offline handoff, artifact substitution and missing identity")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attest", type=Path, help="Path to the packaged attest binary")
    options = parser.parse_args()
    smoke(options.attest.resolve(strict=True))
