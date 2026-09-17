# 0.1.0 — Amber Drift

attest runs your build, hashes every declared input and output, and writes a
signed receipt of what happened. Anyone holding that receipt can re-derive the
hashes from your source and confirm the artifact came from the code claimed —
without trusting your CI, your runner, or us.

This is the first public release.

## Install

```console
cargo install continuum-attest
```

Or take a binary from the assets below. Linux and macOS, x86-64 and arm64.
The command is `attest`; the crate is `continuum-attest` because `attest` was
already taken.

## Sixty seconds

```console
attest init
attest keys generate --name laptop
attest run --sign
attest verify .attest/receipts/*.yaml --recompute
```

`--recompute` is the part that matters: it re-derives the pipeline hash and
every step's input and output hashes from your workspace and compares them
with what the receipt claims. A mismatch fails.

To attest one job in a CI you already have, without moving your pipeline:

```console
attest run --wrap --name build --input src/ --output dist/ -- make dist
```

## Check this release before you run it

```console
shasum -a 256 -c SHA256SUMS

cosign verify-blob \
  --bundle attest-__VERSION__-<target>.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Alien6-Studio/continuum-attest/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  attest-__VERSION__-<target>.tar.gz

gh attestation verify attest-__VERSION__-<target>.tar.gz \
  --repo Alien6-Studio/continuum-attest
```

The `.yaml` file in the assets is attest's own receipt of this build, signed
and timestamped. Once you trust one release, it checks the next.

## What is in it

- Pipeline execution with declared inputs and outputs, and a cache keyed on
  everything that shapes a step.
- Ed25519 receipts, a trust store, and revocation that takes account of when
  a signature was made.
- RFC 3161 timestamps, checked offline against an authority you pin. Without
  one, a receipt's time is written by whoever signed it.
- Capsules pinned to an image digest, never a tag.
- in-toto and SLSA export and import, and archives that verify with no
  network and no workspace.

## What a receipt does not establish

- **Revoking a key does not reach anyone else.** There is no distribution
  mechanism, so someone verifying your receipt reads their own trust store
  and cannot learn that you revoked one.
- **The causal root is anchored, not published.** A timestamp keeps an
  anchored history from being rewritten, but nothing records that a receipt
  existed, so a withheld one goes unnoticed.
- **The signer is a key, not a person.**
- **Matching hashes prove consistency with signed claims.** They do not prove
  the runner was uncompromised.

[ROADMAP.md](ROADMAP.md) says what comes next and in which order.

Apache-2.0.
