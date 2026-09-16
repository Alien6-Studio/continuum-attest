# Contributing

Thanks for considering it. Issues, reproductions and pull requests are all
welcome.

## What belongs in this repository

Everything needed to **produce and verify a receipt**: pipeline execution,
hashing, capsules, the trust store, signing, verification, the causal ledger,
and in-toto/SLSA interop.

Governance engines, Kubernetes controllers and telemetry do not belong here.
They belong in separate programs speaking the protocol in
[the plugin protocol](https://attest.continuu.ms/en/docs/plugin-protocol/). If your idea would make
verification depend on something outside this repository, it belongs in a
plugin — that boundary is deliberate and we will not move it.

## Setting up

You need a Rust toolchain. Either install one locally:

```console
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

…or build in the same pinned image CI uses, which needs nothing but Docker:

```console
$ docker run --rm -v "$(pwd)":/w -w /w \
    -v attest-cargo-registry:/usr/local/cargo/registry \
    -v attest-target-linux:/target -e CARGO_TARGET_DIR=/target \
    rust:1.93-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 \
    cargo test
```

The separate `CARGO_TARGET_DIR` keeps container builds from colliding with a
host `target/`.

## The gates

Four you can run yourself, before pushing:

```console
$ cargo fmt --all -- --check
$ cargo clippy --lib --bins -- -D warnings
$ cargo test
$ cargo deny check                      # needs cargo-deny; `make audit` installs it
```

`clippy` runs on `--lib --bins`, not `--all-targets`: the workspace enables
`clippy::unwrap_used`, which is expected in test code and denied in the
library.

Two more run in CI and can fail a pull request that passed locally:

- **MSRV** — `cargo check --all-targets --locked` on the exact toolchain named
  by `rust-version` in `Cargo.toml`. Code that needs a newer compiler fails
  here even though it builds on your stable.
- **Self-attestation** — the project runs its own pipeline and verifies the
  receipt. You can reproduce it with `attest run --verify`; do not add
  `--sign`, which needs the release key. Pull requests from forks run it
  unsigned by design, since forks have no access to secrets.

## Things that will get a PR sent back

**Do not break receipt signatures.** Receipts are signed artifacts. A new field
must be `Option`, `#[serde(default, skip_serializing_if = "Option::is_none")]`,
so that receipts written without it — and their signatures — stay byte for byte
identical. Follow the existing pattern of `capsule_hash`, `reproducibility` and
`provenance` in `src/storage/receipt_format.rs`. A breaking change to the wire
format means bumping `RECEIPT_SCHEMA_VERSION`, updating
the [receipt format specification](https://attest.continuu.ms/en/docs/receipt-format/) in the same change,
and saying so in the changelog. The specification is the contract other
implementations verify against; code that drifts from it is a bug in the code.

**No `unwrap()` or `expect()` in verification, signing, or hashing paths.** A
panic there is a denial of service on the one operation users depend on. Return
a typed error and let the caller decide.

**Keep the exit-code convention.** `0` success, `1` a verification-meaningful
failure, `2` an operational error. CI pipelines branch on these.

**New behaviour needs a test.** Integration tests live in `tests/` and drive the
real binary through `assert_cmd`. If you are fixing a bug, the test should fail
before your fix.

**Say what the code does, not what it is.** Comments here explain *why* a
non-obvious choice was made — a security property, a compatibility constraint, a
rejected alternative. Comments restating the line below them get removed.

## Our own supply chain

This project makes claims about build integrity, so it holds its own inputs
to the same standard.

**GitHub Actions are pinned by commit SHA, never by tag.** A tag is mutable:
whoever controls the action's repository can repoint `@v4` at different code,
and that code runs with your workflow's token. Every `uses:` in
`.github/workflows/` therefore looks like:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

The trailing comment is the human-readable version; the SHA is what runs.
Dependabot proposes bumps and updates both. A pull request that adds a
tag-pinned action will be asked to resolve it.

**Dependencies are checked by `cargo-deny`** on every pull request:
advisories, the licence allow-list, banned crates (nothing may pull in a
second TLS stack), and sources (no git dependencies). The policy is
[`deny.toml`](deny.toml). Adding an entry to `advisories.ignore` needs a
comment saying why, who decided, and when it is revisited.

**The MSRV is declared in `Cargo.toml` and tested in CI** against the
committed `Cargo.lock`. Raising it is a deliberate change, not a side effect
of a dependency bump: if a bump forces a newer compiler, say so in the pull
request.

## Commits and sign-off

We use the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off every commit:

```console
$ git commit -s -m "Reject capsule references given by tag"
```

`-s` adds `Signed-off-by: Your Name <you@example.com>`, which certifies you
wrote the patch or have the right to submit it. There is no CLA — we do not ask
you to assign copyright.

Write the subject in the imperative, under 72 characters. Use the body to
explain the reasoning and the consequence, not the diff; the diff is already in
the commit.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Licence

By contributing, you agree that your contribution is licensed under the
Apache License 2.0, as stated in [LICENSE](LICENSE).
