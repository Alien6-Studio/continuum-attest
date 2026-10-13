# Continuum Attest

**Run a build. Get a signed receipt. Let anyone check it.**

[![crates.io](https://img.shields.io/crates/v/continuum-attest.svg)](https://crates.io/crates/continuum-attest)
[![CI](https://github.com/Alien6-Studio/continuum-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/Alien6-Studio/continuum-attest/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/crates/msrv/continuum-attest.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`attest` runs your pipeline, hashes every declared input and output, and writes
a signed receipt of what actually happened. Anyone holding that receipt can
re-derive the hashes from the source and confirm that the artifact you shipped
came from the code you claim — without trusting your CI, your runner, or you.

It is a single binary. It works on a laptop, in an existing GitHub Actions or
GitLab CI job, or disconnected from any network.

Everything needed to verify a receipt is in this repository, under Apache-2.0.
That is a commitment, not a description of the current state: no future
component, open or otherwise, will ever be required to reach a verdict.

---

## Sixty seconds

```console
$ attest init
created: .attest/receipts/
created: .attest/cache/
created: .attest/objects/
created: attest.yaml
created: .gitignore (.attest/keys/ entry)

$ attest keys generate --name release
2100ff92696f36a68642a5cc48ca4c71

$ attest run --sign
$ attest verify .attest/receipts/*.yaml --recompute
```

`keys generate` prints the key id, derived from the public key. With a single
key in the store `--sign` picks it up on its own; once there are several, pass
`--key <id>`.

The last command re-reads your workspace, recomputes the input hashes from the
files on disk, and checks them against what the receipt claims. It exits 0 only
if no check fails:

| Check | Question it answers |
|---|---|
| `schema` | Is this a well-formed receipt of a version I understand? |
| `consistency` | Do the receipt's internal references hold together? |
| `signature` | Was it signed by a key in the trust store, before that key was revoked? |
| `timestamp` | Does the independent timestamp satisfy the configured trust policy? |
| `recompute` | Do the declared inputs still hash to what the receipt recorded? |

A check that did not run is reported as `skipped`, with its reason, and a
verdict without a policy passes when nothing failed. `--require` turns that
into a policy: `attest verify --require signature,timestamp,recompute` refuses
unless each named property was established by a check that ran and passed.
Skipped never satisfies a requirement, and the refusal names what was missing.
`linkage` (archives), `trust` (a current trust bundle on record) and `success`
(every step exited 0) can be required the same way; the verdict reports the
execution outcome separately from the validity of the evidence, because a
receipt of a failed build is still evidence.

Exit codes are `0` pass, `1` verification failure, `2` operational error — the
same convention across every command, so CI can branch on them.

Evidence is untrusted input, and its size is the sender's choice. An archive is
refused before anything in it is parsed if it is over 64 MiB on disk, expands
past 512 MiB, holds more than 10 000 entries or an entry over 64 MiB; a receipt
or a DSSE envelope over 16 MiB is refused the same way. The refusal is exit
`2`, not a verdict, and `--format json` reports it as `resource-limit` so a
consumer can tell "too big to look at" from "looked at and wrong". The archive
limits are flags on `attest verify` (`--max-archive-bytes`,
`--max-unpacked-bytes`, `--max-entries`, `--max-entry-bytes`) for the rare
legitimate archive that needs more.

`attest verify --format json RECEIPT` emits one NDJSON record per receipt file. The
[verification result v1 schema](schemas/verification-result-v1.schema.json)
defines its fields and five named checks (archive and interop results have
separate contracts). Rust clients can load it from
`attest::verify::VERDICT_JSON_SCHEMA`. Schema validity is structural, not
permission to accept an artifact: a `pass` can include skipped checks or warnings.
Consumers must bind the receipt and signer they expect and enforce their own
required checks and warning policy. Operational errors use stderr and exit 2,
not a fabricated JSON verification result.

## A pipeline

`attest.yaml` declares steps, their dependencies, and — the part that matters —
what each step reads and writes:

```yaml
version: "0.1"
name: my-service

steps:
  build:
    run: "cargo build --release"
    inputs: ["src/", "Cargo.toml", "Cargo.lock"]
    outputs: ["target/release/my-service"]

  test:
    run: "cargo test"
    inputs: ["src/", "tests/"]
    outputs: []
    needs: ["build"]
```

Declared inputs and outputs are what gets hashed, what gets cached, and what
ends up in the receipt. A step that reads something it did not declare is a step
whose receipt does not describe it — which is the point.

## What else it does

- **Hermetic capsules.** `attest capsule` pins a step's execution environment to
  an OCI image *digest* — tag references are rejected. The capsule's hash is
  recorded per step in the receipt.
- **Reproducibility, checked rather than claimed.** `attest run
  --check-reproducibility` runs the pipeline twice in fresh workspaces with a
  normalized environment (`SOURCE_DATE_EPOCH`, `TZ`, `LC_ALL`) and compares
  output hashes. The verdict goes in the receipt.
- **Trusted timestamps.** `attest run --sign --timestamp` asks an RFC 3161
  authority to countersign the signature, and stores the token in the
  receipt. Verification is offline and checks it against an authority you
  pinned yourself with `attest keys trust-tsa`.
- **Trust you can hand over.** `attest trust bundle` signs the keys your store
  trusts and has revoked, each revocation dated, into one file with an issuer
  and a validity window. `attest trust show` tells a recipient who issued it,
  until when, and whether a byte of it changed; `attest trust import` takes it
  into their store, naming the issuer they expect the first time, refuses an
  older bundle than the one already accepted, and says which keys arrived and
  which were revoked. An authority stepping down names its successor in its
  own signed bundle, so the recipient sees the handover rather than a
  stranger; a bundle from an authority the recipient revoked is refused
  whatever it says. Verification stays offline: trust material travels as a
  file, it is never fetched.
- **Causal ledger.** An append-only Merkle DAG of execution events with
  inclusion proofs, queryable with `attest causal path|chain|stats`.
- **Standard interop.** `attest export --format in-toto` emits an in-toto
  Statement v1 carrying a SLSA Provenance v1 predicate in a DSSE envelope.
  `attest import` verifies one against your trust store.
- **Offline archives.** `attest causal export` writes a self-contained
  `.attest.tar.zst` — reproducible, sorted paths, zeroed mtimes — that
  `attest verify --archive` checks with no network and no repository.
- **Wrap anything.** `attest run --wrap --name build -- make all` attests a
  single command, no pipeline file needed. This is how you adopt it inside an
  existing CI job without rewriting it.
- **Container images.** `attest image sign|verify` wraps cosign and checks SBOM
  (SPDX), SLSA provenance, and revision binding, under one policy: every
  property a flag asks for must be established, a required check is never
  skipped, and a verification that checks nothing does not run. Signatures are
  verified against a key, or keyless against a named `--certificate-identity`
  from a named `--certificate-oidc-issuer`; never against "any valid identity".

## What it does not claim

A receipt establishes **internal consistency**, verifiable by a third party
against your source. Two properties are still missing, and we would rather
say so here than let you discover them during an audit:

- **The causal root is anchored, but never published.** The root is covered by
  the receipt's signature, and `--timestamp` puts an RFC 3161 authority over
  that signature, so an anchored history cannot be rewritten afterwards. What
  is missing is a public log: nobody can query anything to learn that a root
  existed, so a withheld receipt, or two different histories shown to two
  different people, would go unnoticed. Anchoring and transparency are
  different properties and this has only the first.
- **The signer is a public key, not a person.** An Ed25519 key in a trust store
  has no binding to a legal identity.
- **A key file is not trust, and trust is not permission to sign.** A `.pub`
  in the trust directory only says the key exists; `trust.toml` says whether
  anyone vouches for it, and only a key it lists as `trusted` can sign new
  receipts, even when its private half is local. A policy with a status
  outside `trusted`/`revoked`, or naming a key whose file is missing or
  holds another key, does not load at all.
- **Revoking a key does not reach anyone else.** `attest keys revoke` writes to
  your local trust store. A third party verifying your receipt reads their own
  copy, and nothing tells them it is out of date — there is no distribution
  mechanism and no notion of freshness. Revocation protects a verifier who
  already has it; it does not travel on its own.

**Time is worth what `--timestamp` makes it worth.** Without it, a receipt's
timestamp is written by the runner and covered by the runner's own signature,
so it asserts nothing to anyone who does not already trust the runner — and
revocation, which compares against that time, is no stronger. With
`--timestamp`, the time comes from an RFC 3161 authority the signer does not
control, revocation is judged against that, and `attest verify` refuses a
revoked key's signature that carries no such proof. That is the only check
that uses a time the signer did not choose. Whether a trust bundle has expired
is judged by the verifier's own clock, and the verdict says so: it states the
bundle its revocations are current up to, and warns when that bundle has
expired, because a verifier offline for a year cannot honestly claim to know
about revocations issued last week.

Attestation is also not compliance. A green `attest verify` says the artifact
matches the source; it says nothing about whether either is any good.

## Install

Linux and macOS, x86-64 and arm64. Each of the four runs the test suite in CI
before a release ships a binary for it. Windows is not supported: the permission
hardening that protects private keys is Unix-specific and has no Windows
equivalent yet, so a Windows build would write key material with inherited
ACLs.

Building from source requires Rust **1.89** or later (the MSRV is declared in
`Cargo.toml` and tested in CI):

```console
$ cargo install continuum-attest --locked
```

The crate is published as `continuum-attest` — `attest` was taken on crates.io
by an unrelated project — but the installed command is `attest`. `--locked`
installs the dependency graph that was tested and reviewed for that version,
from the `Cargo.lock` shipped in the package; without it cargo resolves
whatever is newest today, which is a graph nobody tested. CI installs every
release from its own package this way.

Three things are reproducible, and they are not the same thing. The *source
dependencies* are: the lock pins every crate by version and checksum. The
*toolchain* is: release artifacts are built with the compiler version pinned in
the workflows, and each binary ships with a `build-info.json` naming the
`rustc` release and commit, the target, and the lock's digest. The *artifact
bytes* are reproducible per platform for the same tag and toolchain, which the
release workflow holds itself to; across platforms they differ by nature.

Signed release binaries are published on the
[releases page](https://github.com/Alien6-Studio/continuum-attest/releases) with
checksums, an SBOM, and SLSA provenance. It would be strange for this project in
particular to ask you to trust an unattested download.

## Status

Version 0.1. The core — pipelines, hashing, capsules, receipts, trust store,
verification, causal ledger, in-toto/SLSA interop — is implemented and covered
by the test suite, and `attest` attests its own CI on every commit.

Interfaces that carry a `schema_version` (receipts, `attest.yaml`) follow a
documented compatibility policy: older receipts stay verifiable, and a receipt
from a newer version tells you to upgrade rather than failing obscurely.

Product documentation lives at
[attest.continuu.ms](https://attest.continuu.ms/en/docs/). This repository holds
the source, the tests and the CI templates. The normative specifications are
published there too:

- [Receipt format](https://attest.continuu.ms/en/docs/receipt-format/) — the receipt wire format, the `attest-manifest/v1`
  hashing rules, the canonical signing bytes and the trust store. Specified in
  enough detail to write an independent verifier without reading the Rust,
  which is what "anyone can check it" has to mean.
- [Plugin protocol](https://attest.continuu.ms/en/docs/plugin-protocol/) — the
  boundary a plugin may not cross. A specification, not a feature of this
  release: `attest` spawns nothing.

What is shipped and what comes next is in [ROADMAP.md](ROADMAP.md).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
the development setup, the commit conventions, and the DCO sign-off we ask for.

To report a vulnerability, please read [SECURITY.md](SECURITY.md) — do not open
a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright 2025-2026 Alien6.
