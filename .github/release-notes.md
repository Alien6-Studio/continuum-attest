# 0.2.0 — Paper Moon

attest runs your build, hashes every declared input and output, and writes a
signed receipt of what happened. Anyone holding that receipt can re-derive the
hashes from your source and confirm the artifact came from the code claimed —
without trusting your CI, your runner, or us.

0.2 is about trust that can be shared, and about a verdict that says what it
checked. The receipt format is unchanged: every 0.1 receipt still verifies,
signature included, and the test suite holds the parser to that.

## Install

```console
cargo install continuum-attest --locked
```

Or take a binary from the assets below. Linux and macOS, x86-64 and arm64,
each tested in CI before it ships. The command is `attest`; the crate is
`continuum-attest` because `attest` was already taken. Building from source
needs Rust 1.89.

## Trust you can hand over

```console
attest trust bundle --output trust.json --key <issuer>      # producer
attest trust import trust.json --issuer <issuer-key-id>     # recipient, once
attest trust refresh trust-2.json                           # recipient, later
```

A bundle carries the keys an issuer vouches for and the ones it revoked, each
revocation dated, a validity window, a sequence number and the issuer's
signature. `attest trust show` tells a recipient who issued it, until when,
and whether a byte of it changed. The first bundle is accepted only against an
issuer the recipient names through another channel; an older bundle than the
one accepted is a replay and is refused; a bundle from an authority the
recipient revoked is refused whatever it says; an authority stepping down
names its successor in its own signed bundle. Every verdict states the bundle
its revocations are current up to, judged by the local clock and saying so.

## A verdict that says what it checked

```console
attest verify receipt.yaml --require signature,timestamp,recompute
```

A check that did not run is reported as skipped and never satisfies a
requirement. `--require` names what must be established; the refusal names
what was not, in text and in the JSON contract, which gains `policy`,
`execution` and `trust_material`. The same names apply to archives
(`linkage`), to `attest import`, and to `attest image verify`, which now runs
under one policy: keyless needs a pinned identity and issuer, a required
revision with no evidence fails, and a verification that checks nothing does
not run.

## What the receipt now says about the build

- An `isolation` block names each control — network, filesystem,
  capabilities, environment, memory, open files, cpu, timeout, inputs — as
  enforced, not enforced or not available on that platform. `--verify` is
  process isolation: resource limits, not network or filesystem control, and
  the receipt says so.
- Declared inputs are unwritable while a step runs, by permission bits
  locally and by read-only mounts in a capsule; what the bits cannot prevent,
  the re-hash after the step detects.
- The signing key is loaded only after the last step has exited. `attest
  sign` signs receipts in a process that ran no project command, and
  `ATTEST_KEYS_DIR` keeps private keys outside the workspace.

## Fail closed

- A key status outside `trusted`/`revoked` does not load; a `.pub` file is
  presence, not trust; a revoked key cannot sign new evidence.
- `--timestamp` without `--sign`, `--key` without `--sign`, and every other
  option that could not take effect are refused before anything runs.
- Archives are refused before parsing past 64 MiB on disk, 512 MiB unpacked,
  10 000 entries or 64 MiB per entry; receipts and envelopes past 16 MiB
  likewise, with `resource-limit` set apart from a verdict in JSON.

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

The `.yaml` files in the assets are attest's own receipts: one of this
build, and one over every file published here — binaries, checksums,
`build-info.json` per platform, SBOM, source package — signed and
timestamped in a job that built nothing. The publish step recomputed that
receipt's input manifest over the files it was about to publish and would
have refused the release on any difference.

## What a receipt does not establish

- **The causal root is anchored, not published.** A timestamp keeps an
  anchored history from being rewritten, but nothing records that a receipt
  existed, so a withheld one goes unnoticed. That is 0.4.
- **The signer is a key, not a person.**
- **Matching hashes prove consistency with signed claims.** They do not prove
  the runner was uncompromised; the isolation block says what was controlled.

[ROADMAP.md](ROADMAP.md) says what comes next and in which order.

Apache-2.0.
