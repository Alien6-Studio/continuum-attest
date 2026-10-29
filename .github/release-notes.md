# 0.3.0 — Ember Sky

Attest can wrap one existing GitHub or GitLab build job and transfer its
signed receipt together with the declared output bytes for offline checking.
The native receipt format and canonical signing bytes are unchanged; existing
0.1 and 0.2 receipts remain verifiable.

## Adopt in an existing build

The GitHub composite action and GitLab CI component declare inputs, outputs
and the build command, sign the resulting receipt, and publish evidence.
`attest run --wrap --report FILE` reports the build exit code separately from
evidence production and names the exact receipt. A failed build retains its
exit code even if signing, storage or reporting also fails.

```console
attest evidence pack receipt.yaml --output release.attest.tar.zst
attest evidence verify release.attest.tar.zst --trust-store /trusted/keys
```

Verification requires a trusted receipt signature, successful execution and
artifact bytes matching the signed output inventory. `--artifact-root DIR`
also checks files delivered outside the archive. Archives never supply their
own trust anchors and verification does not extract untrusted paths.

## Require an approved workflow

`attest identity sign receipt.yaml --bundle identity.sigstore.json` uses
Cosign 3 to bind a CI-issued identity to the exact receipt bytes. Include the
bundle with `evidence pack --identity-bundle identity.sigstore.json`, then
verify with `--identity-policy policy.json`. The recipient pins the issuer,
repository, complete workflow identity, source revision and a local Sigstore
trusted root. Verification uses Cosign's offline proof checks and authenticated
Fulcio certificate claims; environment variables alone establish no identity.
The local Ed25519 signature is still required, and disconnected producers can
continue using it without Sigstore.

The [CI adoption guide](https://github.com/Alien6-Studio/continuum-attest/blob/v__VERSION__/docs/ci-adoption.md) contains both producer/recipient
examples and rejection cases. Workflow identity authenticates the signer and
source claims, not the integrity of the runner. Signing publishes metadata and
the receipt digest to Sigstore's transparency log; it does not publish the
receipt body or artifact bytes.

## Dependencies

Dependabot updates include jsonschema, zstd, libc, rust-cache and the crates.io
authentication action. Patch updates to tokio, rustls-webpki and webpki-roots
resolve RUSTSEC-2026-0386, RUSTSEC-2026-0382 and RUSTSEC-2026-0381. The MSRV
remains Rust 1.89.

Timestamp requests now require HTTPS, including custom `--tsa` URLs, and
refuse a redirect to an insecure transport. The default endpoint is now
`https://timestamp.sectigo.com/rfc3161`; recipients must independently pin
the chosen authority with `attest keys trust-tsa`. Existing timestamped
receipts remain verifiable offline with their pinned authorities.
Timestamp signatures support SHA-256 and SHA-384 with explicit algorithm checks.
Timestamping also works when called from the CLI's asynchronous runtime;
transport failures are reported as errors instead of triggering a panic.

## Check this release before you run it

```console
shasum -a 256 -c SHA256SUMS

cosign verify-blob \
  --bundle attest-v__VERSION__-<target>.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Alien6-Studio/continuum-attest/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  attest-v__VERSION__-<target>.tar.gz

gh attestation verify attest-v__VERSION__-<target>.tar.gz \
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

[ROADMAP.md](https://github.com/Alien6-Studio/continuum-attest/blob/v__VERSION__/ROADMAP.md) says what comes next and in which order.

Apache-2.0.
