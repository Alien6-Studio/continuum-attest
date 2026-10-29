#!/usr/bin/env python3
"""Exercise the packaged CLI's 0.3 handoff, including rejection cases.

Run the entire script in a network namespace in release CI. The build has
no signing key: a throwaway key is created only after its command has exited.
The recipient receives its public trust anchor separately from the package.
The default mode checks local signing. Identity mode creates a fresh GitHub
OIDC proof online, then transfers it to a separate offline verification phase.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def identity_smoke(binary, phase, state, source, trusted_root):
    environment = os.environ.copy()
    environment.pop("ATTEST_KEYS_DIR", None)
    producer, recipient, delivery = (state / name for name in ("producer", "recipient", "delivery"))

    def run(arguments, cwd, expected=0):
        result = subprocess.run([str(binary), *arguments], cwd=cwd, env=environment,
                                capture_output=True, text=True)
        assert result.returncode == expected, result.stdout + result.stderr
        return result.stdout

    policy_path = recipient / "workflow-policy.json"
    archive = delivery / "release.attest.tar.zst"
    if phase == "produce":
        state.mkdir()
        recipient.mkdir()
        delivery.mkdir()
        # Copy git objects instead of sharing the checkout or touching its trust store.
        subprocess.run(["git", "clone", "--no-hardlinks", "--no-checkout", str(source), str(producer)], check=True)
        subprocess.run(["git", "-C", str(producer), "checkout", "--detach", environment["GITHUB_SHA"]], check=True)
        report = producer / "wrap.json"
        run(["run", "--wrap", "--name", "github-oidc-smoke", "--input", "Cargo.toml",
             "--output", "artifact.bin", "--report", str(report), "--", "sh", "-c",
             'test ! -d .attest/keys && cp Cargo.toml artifact.bin'], producer)
        receipt = Path(json.loads(report.read_text())["receipt"])
        if not receipt.is_absolute():
            receipt = producer / receipt
        assert not (producer / ".attest/keys").exists()
        key = run(["keys", "generate", "--name", "oidc-smoke"], producer).strip()
        public = recipient / "approved-release.pub"
        run(["keys", "export", key, "--output", str(public)], producer)
        run(["sign", str(receipt), "--key", key], producer)
        bundle = state / "identity.sigstore.json"
        run(["identity", "sign", str(receipt), "--bundle", str(bundle)], producer)
        run(["evidence", "pack", str(receipt), "--identity-bundle", str(bundle), "--output", str(archive)], producer)
        run(["keys", "import", str(public), "--name", "approved-release"], recipient)
        shutil.copyfile(producer / "artifact.bin", delivery / "artifact.bin")
        # Supplied by the separate TUF bootstrap, never read from the bundle.
        shutil.copyfile(trusted_root, recipient / "trusted-root.json")
        policy_path.write_text(json.dumps({
            "issuer": "https://token.actions.githubusercontent.com",
            "repository": "https://github.com/" + environment["GITHUB_REPOSITORY"],
            "workflow": "https://github.com/" + environment["GITHUB_WORKFLOW_REF"],
            "revision": environment["GITHUB_SHA"], "trusted_root": "trusted-root.json",
        }))
        shutil.rmtree(producer)
        print("Fresh native receipt and GitHub OIDC identity prepared; producer removed")
        return

    assert not producer.exists() and not (recipient / ".attest/keys").exists()
    environment["TUF_ROOT"] = str(state / "empty-offline-tuf")
    verify = ["evidence", "verify", str(archive), "--trust-store", ".attest/trust",
              "--identity-policy", str(policy_path), "--artifact-root", str(delivery), "--format", "json"]
    accepted = json.loads(run(verify, recipient))
    checks = {check["name"]: check["status"] for check in accepted["checks"]}
    assert accepted["verdict"] == "pass" and all(checks[name] == "pass" for name in ("signature", "identity", "artifacts")), accepted
    original = (delivery / "artifact.bin").read_bytes()
    (delivery / "artifact.bin").write_bytes(b"substituted artifact\n")
    replaced = json.loads(run(verify, recipient, expected=1))
    assert any(c["name"] == "artifacts" and c["status"] == "fail" for c in replaced["checks"]), replaced
    (delivery / "artifact.bin").write_bytes(original)
    approved = policy_path.read_text()
    unauthorized = json.loads(approved)
    unauthorized["workflow"] = "https://github.com/unapproved/project/.github/workflows/release.yml@refs/heads/main"
    policy_path.write_text(json.dumps(unauthorized))
    refused = json.loads(run(verify, recipient, expected=1))
    assert any(c["name"] == "identity" and c["status"] == "fail" for c in refused["checks"]), refused
    policy_path.write_text(approved)
    assert json.loads(run(verify, recipient))["verdict"] == "pass"
    print("Fresh GitHub OIDC receipt verified offline; replaced artifact and unauthorized workflow rejected")


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
    parser.add_argument("--identity-phase", choices=("produce", "verify"))
    parser.add_argument("--state", type=Path, help="Transfer directory shared by the two identity phases")
    parser.add_argument("--source", type=Path, default=Path.cwd(), help="Checkout to clone at GITHUB_SHA")
    parser.add_argument("--trusted-root", type=Path, help="Independent TUF-authenticated Sigstore root")
    options = parser.parse_args()
    if options.identity_phase:
        if not options.state or (options.identity_phase == "produce" and not options.trusted_root):
            parser.error("identity mode requires --state; production also requires --trusted-root")
        identity_smoke(options.attest.resolve(strict=True), options.identity_phase,
                       options.state.resolve(), options.source.resolve(), options.trusted_root)
    else:
        smoke(options.attest.resolve(strict=True))
