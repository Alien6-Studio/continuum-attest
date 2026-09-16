# Changelog

All notable changes to attest are documented here. Format versioning and
stability guarantees are described in
[the compatibility policy](https://attest.continuu.ms/en/docs/compatibility/).

## Unreleased

Preparation for the first public release.

### Licence

- **Relicensed to Apache-2.0**, replacing the CoopyrightCode Light
  non-commercial licence. Apache-2.0 carries an explicit patent grant and
  a retaliation clause, which is what a supply-chain tool should offer the
  people who depend on it.
- Added `NOTICE`.

### Packaging

- The crate is published as **`continuum-attest`**; `attest` is taken on
  crates.io by an unrelated project. The library and the binary keep the
  short name, so `use attest::…` and the `attest` command are unchanged.
- 20 dependencies removed. `nix`, `regex`, `url`, `git2`, `tera`,
  `handlebars` and `wasmtime` were declared but used nowhere; `futures`
  and `globset` moved to dev-dependencies, where they were always used.
- **All cargo features removed.** None of them gated a single `cfg` in the
  source. Every capability is compiled unconditionally, so
  `attest --version` fully determines what a binary can do.
- The `Dockerfile` now pins both stages by digest. A tool that rejects tag
  references for capsules should not use them for its own image.
- **MSRV declared: Rust 1.88.** Determined from the locked dependency
  graph, not guessed: `time`, `ignore`, `globset` and the `icu_*` family
  require it. Verified both ways — 1.88 builds, 1.87 is refused. A CI job
  reads `rust-version` straight from `Cargo.toml`, so the declared and the
  tested version cannot drift.

### Added

- **RFC 3161 trusted timestamps.** `attest run --sign --timestamp` asks a
  timestamp authority to countersign the receipt's signature and stores the
  token in the receipt; `attest verify` checks it offline as a fifth check.
  `attest keys trust-tsa` pins the authority.

  This closes a defect, not just a gap. Revocation compared against the
  receipt's own `timestamp` — a field the runner writes and signs — so
  whoever stole a signing key could backdate a receipt past the revocation
  meant to stop them. With a token, revocation is judged against a time the
  signer did not choose, and verification warns explicitly when it has to
  fall back.

  The token covers the *signature*, not the receipt body: timestamping the
  body would prove the content existed but say nothing about when it was
  signed. `timestamp_token` sits outside the signed bytes, so a receipt can
  be signed, then timestamped, without disturbing its signature.
  `RECEIPT_SCHEMA_VERSION` accordingly moves from 2 to 3.

  Verification pins the *issuing* authority rather than the certificate that
  signs tokens, and checks exactly one signature between them. It builds no
  X.509 path — no discovery, no name constraints, no CRL or OCSP. Responder
  certificates rotate yearly; pinning one would stop verification of every
  receipt issued after the rotation.

  Signature checking uses `ring`, already present under rustls, so this adds
  no new supply-chain surface.

- **The causal ledger now records what runs actually do.** It never did:
  `Storage::record_causal_event` existed and no caller reached it, the
  executor set `causal_events: vec![]` behind a comment saying it would be
  populated "when causal ledger is integrated", and every `attest causal`
  subcommand queried a store nothing ever wrote to — while the README
  advertised an append-only Merkle DAG and SECURITY.md listed breaking its
  append-only property as an in-scope vulnerability.

  A run now writes one event per executed step, with parents taken from
  `needs`, and records the chain root in the receipt. Both are inside the
  signed bytes, so a receipt cannot be re-pointed at a different history
  without breaking its signature.

  The chain root is computed over the execution order the receipt publishes
  rather than a re-derived topological sort, which makes it recomputable by
  anyone holding the events. `attest causal export` carries those events, so
  `attest verify --archive` recomputes the root offline and fails on a
  tampered event even though the receipt itself still verifies.

  `attest causal events` also lists events now. It used to print a count and
  suggest another command.

### Changed

- **`attest.yaml` now rejects keys it does not define**, at every level of
  the document. Previously an unknown key was silently ignored, so a
  misspelled `ouputs:` produced a step declaring no outputs at all: the run
  succeeded, the receipt was signed, and it said nothing about the artifact
  its author believed they had attested. That is precisely the class of
  quiet discrepancy this tool exists to prevent, and it is how the removed
  `mode:` templates managed to look like they configured something.

  A file that was valid stays valid; a file that was silently wrong now
  fails with the offending key named. No `schema_version` bump: the format
  did not change, only our willingness to accept what it never defined.

### Fixed

- **`Cargo.lock` is now committed.** It was listed in `.gitignore` and had
  never been tracked — for a crate that ships a binary, and for a project
  whose subject is reproducible builds, that was a contradiction. It also
  meant the `--locked` invocations in the release and MSRV jobs would have
  failed on a fresh checkout.
- The GitHub composite action under `ci-templates/` downloaded
  `attest-vX.Y.Z-linux-x86_64` as a raw binary, while releases publish a
  `.tar.gz`. It now fetches, checksums and extracts the actual asset, and
  defaults to the GitHub release store instead of a placeholder URL. It
  also passes its inputs through the environment rather than interpolating
  them into the shell body, and pins its own `upload-artifact` by SHA.

### Removed

- `scripts/` in full. Every script was stale, internal, or duplicated the
  Makefile: `build.sh` was built around a feature-selection API that no
  longer exists, `validate-project.sh` required an `examples/` directory
  that does not, `install.sh` only printed that installation was
  unavailable, and the packaging and repository-setup scripts target
  internal infrastructure.
- The Makefile drops from 40 targets to 24 — no distro packaging, no
  repository provisioning, no HTML security report. It is a convenience
  wrapper around cargo; the authoritative gates live in CI.
- `ci-templates/gitlab/`. The public repository targets GitHub; a GitLab
  adoption template shipped from here would be maintained blind, since
  nothing in CI ever exercises it.
- `.gitlab-ci.yml`. It carried a second, complete release pipeline that
  would have raced GitHub Actions on the same tag, and it exposed the
  internal key handling, the signing key id and the GitLab package registry
  upload. It belongs to the internal mirror, not to the public repository.

### Supply chain of the project itself

- **Every GitHub Action is pinned by commit SHA**, with the version as a
  trailing comment. A tag is mutable: whoever controls an action's
  repository can repoint `@v4` at different code, which then runs with our
  workflow token. Pinning also surfaced that several actions were being
  used at outdated majors.
- `cargo-deny` enforced on every pull request: advisories, a stated licence
  allow-list, no second TLS stack, and no git dependencies.
- Dependabot watches crates and actions alike.

### Scope

- Governance (`policy`), cluster reconciliation (`gitops`) and telemetry
  (`monitoring`) moved out of this repository. They become separate plugin
  programs speaking the protocol in
  [the plugin protocol](https://attest.continuu.ms/en/docs/plugin-protocol/), published on the
  documentation site as a draft.
- Everything required to verify a receipt stays in this repository, under
  Apache-2.0. A plugin can add checks; it can never sign, never alter a
  recorded fact, and can never be required to reach a verdict.

## 0.1.0 — 2026-08-28

First versioned release. attest attests its own CI end to end (build →
signed run → independent verification with recomputed hashes).

### Core

- `attest run`: pipeline execution from `attest.yaml` with DAG ordering
  (`needs`), per-step declared inputs/outputs hashed into a signed
  receipt, content-addressed step caching, and sandboxed execution
  (process isolation with RLIMIT-based memory/file limits; optional
  container image or hermetic capsule per step).
- `attest verify`: four-check verification (schema, consistency, Ed25519
  signature against the committed trust store, opt-in `--recompute`
  against the workspace), 0/1/2 exit-code convention, text or NDJSON
  output, fully offline archive verification (`--archive`).
- `attest keys`: Ed25519 key generation, committed trust store,
  public-only export, import, and time-aware revocation (receipts signed
  before revocation stay valid; later signatures fail).
- `attest run --wrap`: attest a single command without a pipeline file.
- `attest hash`: canonical `attest-manifest/v1` digests for declared paths.
- `attest export` / `attest import`: in-toto Statement/DSSE interop.
- `attest capsule`: hermetic execution capsules pinned to image digests,
  recorded in the receipt (`capsule_hash`).
- `attest run --check-reproducibility`: double-build comparison recorded
  in the receipt.
- Image signing/verification (`attest image`) via cosign, causal ledger,
  GitOps CRDs and OPA policy integration.

### Execution semantics (hardened in this release)

- Failing steps are reported with name, exit code and output tail; the
  run exits non-zero.
- Failed step results are never cached.
- Steps whose dependencies failed are skipped, reported, and excluded
  from the receipt rather than silently "succeeding".
- `cache: false` is honored end to end.
- `timeout_secs` is enforced: the step's whole process group is killed on
  expiry and the step fails with exit code 124. No default timeout, and
  no default memory limit — enforced limits are opt-in.

### Formats

- Receipts and `attest.yaml` carry an explicit `schema_version` (current:
  1). Pre-versioning receipts remain readable and their signatures remain
  valid; newer-than-supported versions are rejected with an upgrade
  message. Policy: [the compatibility policy](https://attest.continuu.ms/en/docs/compatibility/).

### Documentation

- Quickstart, `attest.yaml` reference, trust model, key management guide,
  compatibility policy, GitLab CI adoption templates.

### License

- CoopyrightCode Light v1.1 (free non-commercial use; commercial licensing
  via contact@alien6.com).
