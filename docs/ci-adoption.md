# Attesting an existing CI build (0.3 — Ember Sky)

The GitHub action and GitLab component wrap one existing command, sign its
receipt with a local Ed25519 key, and package the declared output files with
that receipt. Set `identity: true` to also attach a Sigstore bundle identifying
the CI workflow. A recipient verifies the resulting `release.attest.tar.zst`
on another machine with its own trust configuration and no network.

The producer needs Attest 0.3.1 or newer, Linux x86_64, Python 3, Bash, curl, tar and
sha256sum. Identity signing also needs a separately installed, pinned Cosign 3
binary and network access to its signing services. The integrations download
the Attest tarball and install it only after checking the supplied SHA-256.
Use the version and digest of the release you audited, or a verified internal
release mirror. Replace every `<...>` placeholder before using an example.
Use 0.3.1 or newer for the complete-evidence contract and separate
`attest timestamp` phase.

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
          version: '0.3.1'
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
code. `evidence-policy` is `required` by default; use `optional` to report
evidence failures without failing a successful build. `trust-store` and
`identity-policy` select independent verification policy. A `--workspace` argument is also forwarded to packaging so it reads
the same output files. The integration signs after the command exits; do not repeat `--sign`,
`--key`, `--report` or the command separator there. With `--timestamp`, the
existing signature is timestamped separately, without re-signing it.

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
      version: '0.3.1'
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

The component uploads `release.attest.tar.zst` to the project's Generic
Package Registry using the job's short-lived `CI_JOB_TOKEN`. The package is
`attest-evidence/<CI_JOB_ID>` by default; `package-name` changes its name.
The archive includes the actual output artifacts and their evidence together.
Publication is `published` only after the API confirms HTTP 201. Transfers
require the CI server's HTTPS origin, validate its TLS certificate, and refuse
redirects so the job token cannot be forwarded elsewhere. The project must
have the Package Registry enabled and permit this job token to upload.
[GitLab documents this upload contract](https://docs.gitlab.com/user/packages/generic_packages/).

The final `status.json` contains the package URL and actual publication result.
The job also exports scalar outcomes through `status.env` as a GitLab dotenv
report (`ATTEST_BUILD_EXIT_CODE`, `ATTEST_EVIDENCE_STATUS`,
`ATTEST_VERIFICATION_STATUS`, `ATTEST_PUBLICATION_STATUS`,
`ATTEST_EVIDENCE_POLICY`, `ATTEST_ERROR_CODE`, `ATTEST_PUBLICATION_URL`,
`ATTEST_EXIT_CODE`). Downstream jobs can use these variables without parsing
console output. The runner's later job-artifact upload retains diagnostics;
it is separate from the confirmed package publication.

Only `.attest-ci/$CI_JOB_ID/` is selected for diagnostic artifacts. GitLab
assigns a new job ID on retry, so an installation or build failure cannot
publish an earlier job's directory. Exclude `.attest-ci/` from caches. The
component embeds the same tested runner as GitHub and fetches no helper script
at runtime.

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

Both integrations expose the same final JSON status. GitHub provides it as
`steps.attest.outputs.status`, with individual build/evidence/verification/
publication outputs. GitLab retains it as `.attest-ci/$CI_JOB_ID/status.json`
and exports the scalar fields as dotenv variables. Its publication URL points
to the archive whose upload was confirmed by the package API.

| Field | Meaning |
|---|---|
| `build_status`, `build_exit_code` | `not_started`, `succeeded` or `failed`, plus the original exit code |
| `evidence_policy` | `required` (default) or `optional` |
| `evidence_status` | `produced` means the archive exists; `failed` means production failed |
| `verification_status` | `passed`, `failed` or `skipped`; produced evidence can fail verification |
| `publication_status` | `published`, `failed` or `skipped`; `pending` exists only before transfer completion |
| `error_code`, `failure_stage`, `errors` | Stable phase code and all failures, separate from the build result |
| `receipt`, `evidence`, `publication_url` | Exact paths/URL from this invocation, never an older receipt |
| `exit_code` | Integration outcome after applying the policy below |

The phases are `receipt`, `signing`, `timestamping`, `identity`, `packaging`,
`verification`, `publication` and `reporting`. Failure codes use the suffix
`_failed`, for example `signing_failed` or `publication_failed`.
`verification.json` retains the verifier's detailed machine-readable checks.
A missing receipt has `evidence_status: failed` and verification `skipped`;
a produced archive refused by the verifier has evidence `produced` and
verification `failed`.

| Situation | Final exit code |
|---|---:|
| Build exits N | N, even when later evidence or publication also fails |
| Build succeeds; required evidence fails in any phase | 2 |
| Build succeeds; optional evidence fails | 0, with failed status and explicit error code |
| Build and all requested evidence operations succeed | 0 |
| Build never starts, or machine reporting cannot be written | Nonzero operational code |

Signing, identity, timestamps and archive verification are required when
requested under `evidence-policy: required`; disabling an operation differs
from allowing its failure. `optional` never converts a failed build into a
successful one. A failed build may publish diagnostic evidence, but its
verification cannot establish successful execution.

GitHub's artifact upload completes before its finalizer reports publication.
The archive's earlier status snapshot may say `pending`; consume the action's
final JSON output. GitLab's package upload completes inside the runner before
its final JSON/dotenv report is written. Neither provider claims successful
publication before an upload acknowledgement. Cancellation or an unavailable
reporting channel can prevent delivery of a report; the CI job's failure must
then remain visible.

## Executable acceptance and refusal examples

[CI adoption contract](../.github/workflows/ci-adoption.yml) runs the actual
GitHub composite action and upload service for acceptance, a failed build,
missing receipt, required/optional signing failures and required/optional
publication failures. The publication refusal uses an invalid artifact name;
it asserts the real upload failure, the final JSON reason and exit code.
This includes a successful build whose required signature cannot be completed.

The same workflow tests the current native binary against a local HTTPS
implementation of GitLab's package-upload contract: successful transfer,
HTTP failure, redirect refusal, invalid TLS, optional failures, receipt
failure, signing failure and verification failure. The fixture does not claim
to be a hosted GitLab identity test. Complete-evidence tests and the recipient
for fresh GitHub OIDC evidence run in network namespaces with no network.
The unauthorized-workflow case retains valid signatures and artifact bytes;
only recipient authorization changes, and the identity-specific refusal is
asserted alongside a passing receipt signature.

For the GitLab identity example, copy
[`ci-templates/gitlab/acceptance.yml`](../ci-templates/gitlab/acceptance.yml)
to `.gitlab-ci.yml` in a GitLab.com checkout of this repository. It declares
its ID token locally, obtains a fresh native workflow-bound receipt, removes
the producer, and runs the identical offline recipient assertions. It needs a
Linux x86_64 runner that permits network namespaces. An inability to disconnect
fails the job; it never retries verification online. A private GitLab issuer
also needs a compatible private Sigstore service and independently supplied
trust roots; merely having a private GitLab server does not provide that
signing service. The GitLab hosted run remains a separate acceptance task;
local contract tests and the GitHub run do not substitute for it.

To recompute a wrapped receipt's command identity and declared input/output
hashes without `attest.yaml`, see [Wrapped recomputation](wrapped-recomputation.md).
Deliver the input source files as well as the archive's output artifacts.

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

The `attest-evidence/v2` package is a deterministic tar.zst containing the
receipt, declared artifact payloads, referenced capsule manifests and causal
events, and optional workflow bundle. See the normative
[evidence format and completeness rules](evidence-format.md). Verification
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
