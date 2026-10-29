# Offline Sigstore verification fixture

`artifact.txt` and `github.sigstore.json` are the public Sigstore conformance
`a.txt` / `happy-path-v0.3-new-mediaType` fixture at commit
[`acb38c9ee4274fa058127e6a5a4cdb9e94e449e1`](https://github.com/sigstore/sigstore-conformance/tree/acb38c9ee4274fa058127e6a5a4cdb9e94e449e1/test/assets/bundle-verify).
They carry an intentionally public test workflow identity, which must never
be used to authorize a release.

`trusted-root.json` comes from
[`sigstore/cosign` v3.1.4](https://github.com/sigstore/cosign/blob/v3.1.4/pkg/cosign/testdata/trusted_root_pgi.json).
Both upstream projects use Apache-2.0. These files are test data, not the
application's trust configuration.

Run the real signature, certificate, transparency proof and policy rejection
tests with an independently installed Cosign 3:

```sh
ATTEST_TEST_COSIGN=/absolute/path/to/cosign \
  cargo test --locked --lib identity::tests::real_sigstore_verification -- --ignored
```

The test uses the same verifier function as workflow receipts. Its artifact
is upstream test data rather than a native receipt, so receipt parsing is
covered separately. No network or cached TUF state is needed. It checks the
valid fixture and refuses changed bytes, an unauthorized workflow, issuer,
repository or revision, an empty trusted root and a damaged signature.
It also refuses a damaged inclusion proof and missing transparency evidence.
