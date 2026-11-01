# 0.3.1 — Ember Sky

**Keep your build. Deliver the evidence with it.**

A software delivery should give its recipient something they can check,
alongside the files they receive. Ember Sky brings that handoff into an
existing CI job: produce a signed record of the build, keep the evidence with
the artifact, and let the recipient decide whether the delivery meets their
requirements.

**0.3.1 is the recommended Ember Sky release.** It replaces 0.3.0, whose
incomplete verification path could leave recipients without the checks they
needed. If you installed 0.3.0, upgrade to this version.

## Install

Available on Linux and macOS, for x86-64 and arm64. Download a binary below,
or install the published crate:

```console
cargo install continuum-attest --version 0.3.1 --locked
```

The installed command is `attest`. Building from source requires Rust 1.89 or
later. Apache-2.0.

## Sixty seconds

Start with one build command you already use. Replace the command and paths
below with your own:

```console
attest keys generate --name release
attest run --wrap --name build --input src/ --output dist/ --sign -- make dist
```

You get a signed receipt covering the declared files. The
[producer and recipient guide](https://github.com/Alien6-Studio/continuum-attest/blob/v0.3.1/docs/ci-adoption.md)
shows how to add this to GitHub Actions or GitLab CI, deliver the evidence,
and verify it on another machine.

## What is new

**Adopt Attest one job at a time.** Keep your existing build command and CI.
Add evidence to the job you want to cover, then expand when it is useful.
The CI result distinguishes a failed build from missing required evidence,
so teams can act on the actual delivery problem.

**Give recipients a delivery they can check independently.** Send the artifact
with its supporting evidence. Once their trust is configured, recipients can
check the delivered files without access to your CI, including on a machine
with no network. If you also provide the declared source files, they can
recompute their fingerprints without rebuilding the software.

**Make acceptance a recipient decision.** A recipient can require an approved
workflow, the expected source revision and the evidence needed for that
delivery. A replaced file, unexpected origin or missing required proof leads
to a refusal that explains what was not established. Sharing provenance in
another supported format also retains the original evidence for review.

## Before upgrading

Upgrade the tools used by recipients before sending new evidence packages:
older verifiers cannot read the new packages. Existing receipt signatures
remain valid. The
[adoption guide](https://github.com/Alien6-Studio/continuum-attest/blob/v0.3.1/docs/ci-adoption.md)
explains the handoff and trust setup.

## Check this release before you run it

Check the downloaded files and their origin. For the Linux x86-64 binary:

```console
shasum -a 256 -c SHA256SUMS
gh attestation verify attest-v0.3.1-linux-x86_64.tar.gz \
  --repo Alien6-Studio/continuum-attest \
  --signer-workflow Alien6-Studio/continuum-attest/.github/workflows/release.yml \
  --source-ref refs/tags/v0.3.1
```

The release includes signatures and signed, timestamped receipts connecting
the published files to this build.

## What a receipt does not establish

Verification checks declared files and evidence against the recipient's trust
and requirements. It does not prove that the runner was uncompromised or that
the software is correct. An offline recipient also cannot learn about trust
updates they have not received.

The handoff has been exercised on GitHub Actions and self-managed GitLab,
including offline acceptance and both refusal cases in
[#25](https://github.com/Alien6-Studio/continuum-attest/issues/25).
Self-managed GitLab needs signing infrastructure that recognizes its issuer.
The GitLab qualification used temporary test trust; it does not provide a
production signing service.

[ROADMAP.md](https://github.com/Alien6-Studio/continuum-attest/blob/v0.3.1/ROADMAP.md)
describes the remaining milestones.

Apache-2.0.
