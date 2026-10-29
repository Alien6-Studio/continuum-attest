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

Verification exit codes are `0` pass, `1` verification failure, and `2`
operational error. `run --wrap` preserves the build command's nonzero exit
code, including when signing, storage or reporting also fails. Its optional
`--report FILE` separates `build_exit_code` from `evidence_status`, records
the exact new receipt path, and keeps the build's stdout unchanged.

Evidence is untrusted input, and its size is the sender's choice. An archive is
refused before anything in it is parsed if it is over 64 MiB on disk, expands
past 512 MiB, holds more than 10 000 entries or an entry over 64 MiB; a receipt
or a DSSE envelope over 16 MiB is refused the same way, before the YAML or JSON
parser sees a byte. Receipts are parsed with `serde_norway`, the maintained
fork of `serde_yaml`; attest writes no anchors or aliases, and the size cap is
what bounds a hostile document, not the parser. The refusal is exit
`2`, not a verdict, and `--format json` reports it as `resource-limit` so a
consumer can tell "too big to look at" from "looked at and wrong". The archive
limits are flags on `attest verify` (`--max-archive-bytes`,
`--max-unpacked-bytes`, `--max-entries`, `--max-entry-bytes`) for the rare
legitimate archive that needs more.

`attest verify --format json RECEIPT` emits one NDJSON record per receipt file. The
[verification result v1 schema](schemas/verification-result-v1.schema.json)
defines its fields: five named checks, and the optional `policy`, `execution`
and `trust_material` objects that 0.2 added (archive and interop results have
separate contracts). Rust clients can load it from
`attest::verify::VERDICT_JSON_SCHEMA`. Schema validity is structural, not
permission to accept an artifact: a `pass` can include skipped checks or warnings.
Consumers must bind the receipt and signer they expect and enforce their own
required checks and warning policy. An operational error is exit 2 and a line
on stderr; in JSON mode it is also one record with `"verdict": "error"` and the
error kind (`resource-limit` or `operational`), never a fabricated verification
result.

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
  receipt. Timestamp requests require HTTPS, including custom `--tsa` URLs.
  The default authority is `https://timestamp.sectigo.com/rfc3161`.
  Verification is offline and checks the token against an authority you
  pinned yourself with `attest keys trust-tsa`.
  For scripted signing, [Sectigo requests at least 15 seconds between
  signatures](https://www.sectigo.com/knowledge-base/detail/Time-Stamp-Server-Stamping-Protocols-for-Digital-Signatures-Code-Signing).
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
against your source. Some properties are still missing, and several guarantees
are narrower than their names suggest; we would rather say so here than let
you discover it during an audit:

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
- **Inputs are held still only inside a capsule, and the receipt says so.**
  A capsule step reads its declared inputs from a snapshot copied and hashed
  when the receipt's input hash was taken, mounted read-only at the input's
  top-level directory: a mount point cannot be renamed or replaced from
  inside, and under that directory the step sees the declared inputs only, so
  outputs cannot be written there. The snapshot is outside the writable
  workspace, so a step cannot reach it through another writable path. The runtime refuses writes from inside, and changes to the
  original workspace during the step never reach its view. Capsule input paths
  must name paths below the workspace root, relative without `..` (`.` and
  empty paths are refused), and symbolic links must use relative targets
  covered by the declared inputs. That is enforced, and the `inputs` row of the
  receipt's isolation block says `enforced` only when every step ran in a
  capsule. A local step gets its inputs' write bits dropped while it runs, which
  refuses a plain write and nothing more: a step that puts the bits back,
  changes an input, uses it and restores it before it ends is not caught,
  because the re-hash after the step sees the restored file. The row says
  `not-enforced` for such runs and says why. Changes still present after the
  step are detected and the run refuses to write a receipt. Symbolic links
  among declared inputs are recorded as links, never followed; a link pointing
  outside the workspace is refused, and so is one whose target is not itself
  declared, because the bytes behind it would not be attested.
- **The build never holds the key.** `attest run --sign` loads the signing
  key only after the last step has exited, so no step runs in a process that
  holds it. The key file itself is another matter: `.attest/keys/` is in the
  workspace, readable by anything running as you, which is why
  `ATTEST_KEYS_DIR` can point outside it and why a release signs in a separate
  job. There, `attest sign` signs receipts produced by a job that had no key,
  in a job that runs nothing the project controls. The signing boundary is
  that job: it is the one component trusted to authorize a receipt.
- **"Isolated" is a list, not a word.** `--verify` runs steps under process
  isolation, which enforces memory and open-file limits and timeouts when they
  are configured, and nothing else: no network control, no filesystem control,
  no capability drop. A capsule is the container path: `--network none`, a
  read-only root, declared-only environment, declared inputs mounted
  read-only. The library's container and strict-container modes (seccomp
  profile, dropped capabilities) are not exposed on the command line in this
  release. Every receipt carries an `isolation` block naming each control as
  enforced, not enforced or not available on that platform, so a recipient
  reads what was in force rather than inferring it from a mode's name.
- **Revocation travels only as far as a bundle is carried.** `attest keys
  revoke` writes to your local trust store; a recipient learns of it when
  they import a bundle you issued afterwards. Nothing pushes that bundle to
  them, and nothing fetches it: trust material moves as a file, by a channel
  you both chose. A revocation only ever moves earlier: a later bundle that
  dates it sooner tightens it, one that dates it later changes nothing. A local
  revocation without a date rejects every signature and stays in force when a
  dated revocation arrives. What the verifier can say is how current its material is,
  the bundle its revocations are known up to and whether that bundle has
  expired, and it says so in every verdict. Revocation protects a verifier
  who has refreshed; it does not reach one who has not.

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
checksums, an SBOM, build inputs, the source package and SLSA provenance. One
signed, timestamped attest receipt covers that whole set, byte for byte: the
publish step recomputes the receipt's input manifest over the files it is about
to publish and refuses the release on any difference, so the checksums, the
SBOM, the provenance and the receipt describe the same artifacts, not merely
the same source revision. It would be strange for this project in particular
to ask you to trust an unattested download.

## Status

Version 0.3 — Ember Sky. Existing GitHub and GitLab jobs can wrap their
build command, sign its receipt, and publish a release evidence archive. The
recipient verifies artifact bytes and successful execution offline against
independently configured keys. An optional Sigstore bundle establishes the
workflow's issuer, repository, workflow identity and source revision; this
path requires Cosign 3 and a separately provisioned Sigstore trusted root.
See the [producer and recipient guide](docs/ci-adoption.md) for both CI systems,
policy examples and rejection scenarios.

The receipt format and its signing bytes are unchanged. Local key signing,
trust bundles, capsules, causal archives and in-toto/SLSA interop remain
available. The new release archive has its own `attest-evidence/v1` format;
its verdict adds `artifacts` and `identity` checks and is separate from the
receipt-file JSON schema.

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
  which is what "anyone can check it" has to mean. The trust bundle format
  and the receipt's `isolation` block are new in 0.2; until their pages are
  published there, `src/trust.rs` and `src/sandbox/mod.rs` carry the
  normative description, and `schemas/` the JSON contract.
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
