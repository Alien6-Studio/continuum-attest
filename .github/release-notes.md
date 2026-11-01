# 0.4.0 — Glass Ocean

**Give your delivery an independently recorded point of reference.**

A recipient can already check the files and signed evidence you deliver.
Glass Ocean adds an observation outside the producer's own history: choose a
log you trust, publish a commitment to the build's causal record, and deliver
the proof with the software. Your recipient can check that proof offline.

## Install

Available on Linux and macOS, for x86-64 and arm64. Download a binary below
or install the published crate:

```console
cargo install continuum-attest --version 0.4.0 --locked
```

The installed command is `attest`. Building from source requires Rust 1.89 or
later. Apache-2.0.

## Sixty seconds

Keep your existing build command and create its signed receipt:

```console
attest keys generate --name release
attest run --wrap --name build --input src/ --output dist/ --sign -- make dist
```

Then explicitly publish a commitment using the log you have configured:

```console
attest causal publish --receipt <EXACT_RECEIPT_PATH> --log-config producer-log.json --output publication.json --publication-policy required
```

Publication is irreversible. Review the
[publication guide](https://github.com/Alien6-Studio/continuum-attest/blob/v0.4.0/docs/publication.md)
before enabling it; the guide covers operator choice, disclosure, delivery
and independent recipient trust. Building alone does not publish an entry.

## What is new

**Give recipients evidence beyond the producer's own record.** Deliver the
log's inclusion proof alongside the artifact and receipt. A recipient can
check the association against a log key they chose, even after the build
machine and its keys are gone and without a network connection.

**Make missing publication an explicit delivery decision.** Teams can require
confirmed inclusion before accepting a successful build, or continue with a
clearly unconfirmed record and its reason. A service acknowledgement alone
never becomes proof. Failed builds retain their own result, and recipients
can always demand stronger evidence than the producer required.

**Compare what different observers received.** Keep an independently obtained
log checkpoint and compare it with the delivery's checkpoint. The result
distinguishes a missing comparison from an authenticated conflict. A valid
comparison covers those observations; it is not a guarantee about every log
view or the correctness of the build.

## Before upgrading

Upgrade recipient tools before sending evidence with publication proofs:
older verifiers refuse that package format. Existing receipts and packages
remain verifiable. GitHub and GitLab integrations keep log publication off
until explicitly configured. The
[adoption guide](https://github.com/Alien6-Studio/continuum-attest/blob/v0.4.0/docs/ci-adoption.md)
explains the build and artifact handoff; the publication guide adds the log
decision and its separate outcomes.

## Check this release before you run it

Check downloaded files and their origin. For the Linux x86-64 binary:

```console
shasum -a 256 -c SHA256SUMS
gh attestation verify attest-v0.4.0-linux-x86_64.tar.gz --repo Alien6-Studio/continuum-attest --signer-workflow Alien6-Studio/continuum-attest/.github/workflows/release.yml --source-ref refs/tags/v0.4.0
```

Release signatures and signed, timestamped receipts accompany the published
files. The
[roadmap](https://github.com/Alien6-Studio/continuum-attest/blob/v0.4.0/ROADMAP.md)
describes the remaining milestones.

Apache-2.0.
