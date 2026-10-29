# Attesting an existing CI build (0.3 — Ember Sky)

The GitHub action and GitLab component wrap one existing command, sign its
receipt with a local Ed25519 key, and package the declared output files with
that receipt. Set `identity: true` to also attach a Sigstore bundle identifying
the CI workflow. A recipient verifies the resulting `release.attest.tar.zst`
on another machine with its own trust configuration and no network.

The producer needs Attest 0.3, Linux x86_64, Python 3, Bash, curl, tar and
sha256sum. Identity signing also needs a separately installed, pinned Cosign 3
binary and network access to its signing services. The integrations download
the Attest tarball and install it only after checking the supplied SHA-256.
Before the 0.3 release assets
exist, use the CLI sequence below with a locally built binary or a verified
internal release mirror. Replace every `<...>` placeholder before using an
example.

Identity signing publishes the receipt digest and signing metadata to the
configured Sigstore transparency log. It does not upload the source tree or
the packaged artifacts. This identity proof does not publish the receipt's
causal ledger root as specified by the separate 0.4 milestone.

## Producer trust and signing boundary

Provision the release key before the job: its private PEM is
`$ATTEST_KEYS_DIR/<key-id>.key`, while the checkout's `.attest/trust/` holds
the corresponding public PEM and a `trust.toml` entry authorizing that key.
Use `attest keys generate --name release` during your controlled setup and
`attest keys export <key-id> --output release.pub` to export only its public
half. The action/component's `key` input selects that key explicitly.

Recipients obtain `release.pub` or a signed trust bundle through their own
trusted channel. They must not automatically trust a key arriving with the
release. Sigstore trust roots and workflow policy are also supplied separately.

Wrapping a command does not sandbox it. A build running as the same OS user
can read local key files and CI credentials; moving a key outside the checkout
does not enforce isolation. Use these one-job integrations only for commands
you authorize to run in that signing environment. For a stronger boundary,
build without a key in one job, then use `attest sign`, `attest identity sign`
and `attest evidence pack` in a separate trusted job that executes no project
code. The identity then describes that signing job. None of these signatures
prove that the runner itself was uncompromised.

## GitHub Actions producer

This example assumes the dedicated runner already has Cosign 3 and the
release key provisioned, and that the checkout contains the authorized public
trust store. The workflow must grant `id-token: write` when identity is enabled.
GitHub documents this permission in its
[OIDC reference](https://docs.github.com/en/actions/reference/security/oidc).

```yaml
name: release
on:
  push:
    tags: ['v*']
permissions:
  contents: read
  id-token: write
jobs:
  release:
    runs-on: [self-hosted, Linux, X64, attest-release]
    env:
      ATTEST_KEYS_DIR: /run/attest-release-keys
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - id: attest
        uses: Alien6-Studio/continuum-attest/ci-templates/github/attest-action@<AUDITED_COMMIT_SHA>
        with:
          version: '0.3.0'
          sha256: '<PINNED_LINUX_X86_64_TARBALL_SHA256>'
          step-name: build
          inputs: 'src Cargo.toml Cargo.lock'
          outputs: 'target/release/my-service'
          command: 'cargo build --release --locked'
          key: '<RELEASE_KEY_ID>'
          identity: 'true'
      - if: ${{ always() }}
        env:
          BUILD: ${{ steps.attest.outputs.build-exit-code }}
          EVIDENCE: ${{ steps.attest.outputs.evidence-status }}
          PUBLICATION: ${{ steps.attest.outputs.publication-status }}
        run: printf 'build=%s evidence=%s publication=%s\n' "$BUILD" "$EVIDENCE" "$PUBLICATION"
```

Download the `attest-evidence-build` workflow artifact. Its archive contains
the actual declared output bytes, receipt and optional identity bundle. A
failed build still attempts to publish its report and any evidence it could
produce. A failed upload fails the action even when the build succeeded.

The `inputs` and `outputs` strings are whitespace-separated literal paths;
they do not expand globs and cannot name a path containing whitespace. Use the
CLI's repeatable `--input`/`--output` flags directly for those paths. `extra-args`
accepts shell-style quoting for additional flags but does not evaluate shell
code. A `--workspace` argument is also forwarded to packaging so it reads
the same output files. Signing is enabled by the integration itself; do not repeat `--sign`,
`--report` or the command separator there.

## GitLab producer

Mirror this repository to the same GitLab instance as the consuming project.
The component is `templates/attest.yml`, named `attest`; a component reference
contains the instance, project path, component name and pinned revision, as
specified by [GitLab's component documentation](https://docs.gitlab.com/ci/components/).

The build image must include the prerequisites above, with Cosign 3 if identity
is enabled. Provision the private key and public trust store before the job,
for example through a dedicated runner and protected release configuration.
When `identity: true`, declare an ID token named `ATTEST_CI_ID_TOKEN` with
audience `sigstore` on the generated job in your project's own configuration.
GitLab's signing integration requires that local declaration; declaring the
token in external component configuration can produce unsupported identity
claims. See [GitLab's signing examples](https://docs.gitlab.com/ci/yaml/signing_examples/).
The token is passed by environment-variable name to Attest and is not copied
into the evidence bundle.

```yaml
stages: [build]

variables:
  ATTEST_KEYS_DIR: /run/attest-release-keys

include:
  - component: $CI_SERVER_FQDN/continuum-ms/continuum-attest/attest@<AUDITED_COMMIT_SHA>
    inputs:
      job-name: release-build
      stage: build
      image: '<YOUR_BUILD_IMAGE>@sha256:<PINNED_IMAGE_DIGEST>'
      version: '0.3.0'
      sha256: '<PINNED_LINUX_X86_64_TARBALL_SHA256>'
      step-name: build
      inputs: 'src Cargo.toml Cargo.lock'
      outputs: 'target/release/my-service'
      command: 'cargo build --release --locked'
      key: '<RELEASE_KEY_ID>'
      identity: true

# This local definition merges with the job generated by the component.
release-build:
  id_tokens:
    ATTEST_CI_ID_TOKEN:
      aud: sigstore
```

The job publishes only `.attest-ci/$CI_JOB_ID/` with `artifacts: when: always`. Its
`release.attest.tar.zst` has the same format as the GitHub output. The component
uses GitLab's unique job ID, including a new ID for a retried job, so an
installation or build failure cannot publish an earlier job's directory.
It also refuses an existing directory for the current invocation. Exclude
`.attest-ci/` from restored caches. The component embeds its runner, so it does not
fetch an unpinned helper script at runtime.

The provided identity-signing command uses Cosign's default signing services,
which support particular issuers including GitLab.com. It does not expose
private Fulcio endpoints or a custom signing configuration. For a private
GitLab instance, configure a compatible Sigstore service separately, produce
the receipt bundle with your configured Cosign invocation, and pass that
bundle to `attest evidence pack --identity-bundle`. Recipients must separately
provision the matching trust roots. The provided component does not automate
that private-service setup. A local-key-only job (`identity: false`) works on
private GitLab without Cosign or a signing-service connection; an
identity-required recipient will refuse its evidence.

## Recipient: verify without the producer's workspace

Set up the recipient's trust before processing a release:

```sh
mkdir recipient
cd recipient
# release.pub was authenticated through your independent trusted channel.
attest keys import /trusted-channel/release.pub --name approved-release
```

Alternatively import an updated signed trust bundle using the 0.2 trust
workflow. Keep an independently authenticated Sigstore `trusted-root.json`
beside the following policy when workflow identity is required.

For a GitHub producer, `github-policy.json` is:

```json
{
  "issuer": "https://token.actions.githubusercontent.com",
  "repository": "https://github.com/example/my-service",
  "workflow": "https://github.com/example/my-service/.github/workflows/release.yml@refs/tags/v1.2.3",
  "revision": "<EXPECTED_SOURCE_COMMIT_SHA>",
  "trusted_root": "trusted-root.json"
}
```

For a GitLab producer, `gitlab-policy.json` is:

```json
{
  "issuer": "https://gitlab.com",
  "repository": "https://gitlab.com/example/my-service",
  "workflow": "https://gitlab.com/example/my-service//.gitlab-ci.yml@refs/tags/v1.2.3",
  "revision": "<EXPECTED_SOURCE_COMMIT_SHA>",
  "trusted_root": "trusted-root.json"
}
```

Use the exact certificate identity of the approved workflow, including the
ref. Reusable workflows can have a different certificate identity; explicitly
approve the actual signing workflow. The revision is an expected immutable
source commit, not a branch name. Repository and revision must agree with
the authenticated certificate extensions; the revision must also match the
receipt's source commit. The receipt's reported remote URL is not used to
establish repository identity, since a checkout can use a mirror. The root
path is resolved relative to the policy file. This JSON and its roots are
recipient configuration, never assertions to accept from inside an archive.

For the GitHub release:

```sh
attest evidence verify /delivery/github/release.attest.tar.zst \
  --trust-store .attest/trust \
  --identity-policy /trusted-channel/github-policy.json --format json
```

For the GitLab release:

```sh
attest evidence verify /delivery/gitlab/release.attest.tar.zst \
  --trust-store .attest/trust \
  --identity-policy /trusted-channel/gitlab-policy.json --format json
```

Both commands require a valid trusted receipt signature, successful execution,
matching packaged artifacts and, when requested, the exact approved workflow
identity. Cosign validates the attached bundle offline against the configured
roots; the verifier does not download new trust material. Without an identity
policy, the local-key path remains available and no workflow approval is
established.

If an artifact also travels separately from the evidence, preserve its declared
relative path under `/delivery/artifacts/`, then add
`--artifact-root /delivery/artifacts` to verify those delivered bytes too.
For the example build that means
`/delivery/artifacts/target/release/my-service`. Checking only the archive says
nothing about another file someone distributes beside it.

To demonstrate the network boundary on Linux, prepare a local verifier image
containing Attest 0.3 and Cosign 3, then run:

```sh
docker run --rm --pull=never --network none \
  -v "$PWD/delivery:/delivery:ro" \
  -v "$PWD/recipient-trust:/trust:ro" \
  --entrypoint attest '<LOCAL_VERIFIER_IMAGE>@sha256:<PINNED_DIGEST>' \
  evidence verify /delivery/release.attest.tar.zst \
  --trust-store /trust/keys --identity-policy /trust/workflow-policy.json \
  --artifact-root /delivery/artifacts --format json
```

The archive and trust material must already be present, and the image must
already be loaded. The local test suite checks the verifier and orchestration;
it is not a claim that this repository has executed your hosted jobs or this
container experiment.

## Rejection exercises for both producers

First verify an accepted release from each producer with its matching policy.
Then perform these checks on a disposable delivery directory:

1. Replace the separately delivered executable while leaving the evidence
   untouched. Verification with `--artifact-root` must exit 1 and report an
   artifact mismatch. Changing an artifact inside the evidence archive must
   also fail its recorded digest check.
2. Use a policy naming an unapproved workflow path, or a different revision.
   Verification with that policy must exit 1. Generate another release from
   that unapproved workflow to exercise the same boundary with real issuer
   evidence; its valid certificate must not satisfy the approved workflow
   policy.
3. Remove the identity bundle or substitute one from another receipt. An
   identity-required verification must fail; it must not fall back to the
   local receipt signature alone.
4. Run a build that exits 37. The CI runner script must preserve exit 37 even
   if evidence production also fails. If outputs are missing, the diagnostic
   report explains why no receipt/archive could be produced.

For example, on the disposable artifact copy:

```sh
printf 'substituted artifact\n' > delivery/artifacts/target/release/my-service
attest evidence verify delivery/release.attest.tar.zst \
  --trust-store recipient/.attest/trust \
  --identity-policy recipient-trust/workflow-policy.json \
  --artifact-root delivery/artifacts --format json
# Expected: exit 1, artifacts check failed.
```

## Build, evidence and publication outcomes

`attest run --wrap --report FILE` writes a machine-readable report carrying
`build_exit_code`, `evidence_status`, `receipt` and `error`. The integrations
read the exact receipt path from that invocation; they never select the newest
receipt from a directory of previous runs.

The integration's `status.json` adds the wrapper exit code, packaged evidence
path, overall exit code and publication status. `evidence_status: produced`
means an archive was created; a failed build may still have valid diagnostic
evidence, which release verification rejects for lack of success.

| Situation | Integration exit code | Evidence status |
|---|---:|---|
| Build succeeds and evidence is produced | 0 before publication | `produced` |
| Build exits N | N, even if evidence also fails | `produced` or `failed` |
| Build succeeds but signing, identity or packaging fails | 2 | `failed` |
| Build never starts | Nonzero operational/wrapper code | `failed` |
| GitHub upload fails after a successful build | 2 | Production status unchanged |

Publication happens after evidence production. The uploaded `status.json`
therefore records `publication_status: pending`; it cannot certify its own
future transfer. GitHub exposes the actual result through the action output
`publication-status` (`published`, `failed`, `skipped`) and its upload step.
GitLab performs artifact transfer after the script exits, so its runner's
artifact-upload result is authoritative. Check that result as well as the
script status; the component does not claim to turn a post-script GitLab
upload failure into a particular build exit code. Cancellation can prevent
publication on either platform.

## Equivalent commands without a CI template

This is also the path for disconnected local producers; omit identity signing
when no OIDC/signing service is available:

```sh
attest run --wrap --name build --sign --key '<RELEASE_KEY_ID>' \
  --input src --input Cargo.toml --input Cargo.lock \
  --output target/release/my-service --report wrap.json \
  -- cargo build --release --locked
receipt=$(python3 -c 'import json; print(json.load(open("wrap.json"))["receipt"])')
attest identity sign "$receipt" --bundle identity.sigstore.json
attest evidence pack "$receipt" --output release.attest.tar.zst \
  --identity-bundle identity.sigstore.json
```

Use `--identity-token-env ATTEST_CI_ID_TOKEN` on the identity command for a
GitLab token. For the local-only path, omit that command and `--identity-bundle`.
Packing includes the declared outputs from the current workspace, so preserve
those bytes until the archive has been produced.

## Evidence format and resource bounds

The `attest-evidence/v1` package is a deterministic tar.zst containing the
receipt, declared artifact payloads and optional workflow bundle. Verification
reads entries without extracting them onto the filesystem. Symlink artifacts
store the UTF-8 bytes of the link target path; those bytes establish the recorded link, not
the contents of an undeclared file it might point to. The receipt remains the
signed authority for artifact paths, kinds, sizes and digests.

Archive entries use mode 0644; original executable permissions are not part
of this package format. Distribute executable files in your native release
package and check them using `--artifact-root` when those permissions matter.

The reader caps compressed archives and individual entries at 64 MiB,
decompressed archives at 512 MiB and entry count at 10,000. Packing caps total
artifact payloads at 256 MiB. A resource-limit refusal is an operational error,
not a passing or failing assessment of the build. These packages therefore
target bounded release artifacts; larger distributions need a different
packaging strategy.
