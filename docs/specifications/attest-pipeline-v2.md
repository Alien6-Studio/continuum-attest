# Attest pipeline projection, version 2

This document is the normative definition of the build type
`https://github.com/Alien6-Studio/continuum-attest/blob/main/docs/specifications/attest-pipeline-v2.md`.
Normative changes that invalidate existing statements require a new versioned
build-type identifier and a new document; this v2 identifier is never repurposed.
The terms MUST, MUST NOT, SHOULD and MAY describe requirements of this profile.

The profile uses [in-toto Statement v1](https://github.com/in-toto/attestation/blob/v1.2.0/spec/v1/statement.md)
and [SLSA Build Provenance v1](https://slsa.dev/spec/v1.2/build-provenance), carried
in a DSSE envelope. Its `predicateType` is `https://slsa.dev/provenance/v1`.
These formats are **projections**, not replacements for the original Attest
trust decision. No SLSA build level, uncompromised runner or correct build is
implied by this profile. Consumers that ignore its original-evidence extension
have verified a different, narrower assertion.

## Build and parameter semantics

An Attest invocation executes either the dependency-ordered steps of an evaluated
pipeline or a wrapped command. It hashes the declared inputs and outputs and
records the outcome in a native receipt. The native receipt is independently
signed; optional RFC 3161 evidence timestamps that signature. Export is a later
operation and can be performed by a different signer.

`buildDefinition.externalParameters` is exactly an object with `pipelineHash`,
a lowercase 64-character BLAKE3 digest of the evaluated native pipeline
definition, or the domain-separated canonical wrapped-command descriptor for
wrapped execution, using the native receipt's hashing rules.
It is a commitment to configuration, not a file digest or a complete recipe.
`internalParameters` is absent. `resolvedDependencies` is empty: the step input
manifests are carried in the original receipt, and MUST NOT be misrepresented
as digests of individual dependency files. Completeness of dependency discovery
is not asserted. Source and CI observations remain producer-controlled unless
separately supported by the workflow certificate.

To repeat a native build, obtain the referenced source and evaluated pipeline
through the producer's delivery channel, verify their commitments against the
original receipt and run `attest run --pipeline PATH`. For a wrapped build, obtain
the source tree and use the original receipt's `provenance.execution.command`
argv and `provenance.steps` declarations with `attest run --wrap --name NAME`,
repeating `--input` and `--output` for each declared path, followed by `--` and
that argv. The receipt does not contain source bytes or the full native pipeline;
without those external inputs the projection alone is not a reproducible build
recipe. Legacy receipts may also lack the execution descriptor. This missing
information is not inferred from step names or from environment variables.

## Subjects and execution metadata

Each `subject` is one regular artifact file, named by its relative output path.
Its `digest.blake3` is BLAKE3 over **that file's raw bytes**. Export MUST read the
workspace bytes and verify them against the original signed file inventory,
including its agreement with every step's output manifest. Duplicate paths with
different digests are refused. Symbolic links are not dereferenced or presented
as file subjects; their exact link targets remain in the original inventory.

An older receipt without a file inventory is exportable as a historical
projection. It has an empty `subject` array and explicit
`artifactBinding: "unavailable"`; no artifact acceptance can be derived from
it. Otherwise `artifactBinding` is `signed-file-inventory`. Import verifies
actual delivered bytes only when `--artifact-root` is supplied. A recipient
accepting artifacts MUST require the `artifacts` check as well.

`runDetails.metadata.invocationId` is SHA-256 of the exact original receipt
bytes, including its signature, timestamp token, whitespace and comments.
`finishedOn` is the producer-reported receipt completion time. `startedOn` is
that time minus its total duration. Neither is independent trusted time; trusted
time remains the original RFC 3161 token and is verified separately.

## Builder, producer and signers

When export is given both `--identity-bundle` and an independent
`--identity-policy`, it MUST verify the Sigstore proof over the exact original
receipt, issuer and certificate SAN, and certified repository/revision before
using the verified workflow SAN as `runDetails.builder.id`. This identifies the
authorizing workflow and the trust boundary the recipient must evaluate. It
includes the platform, runner and other entities whose correct operation that
workflow relies upon; it does not certify that this trust was justified.
A separate signing job authorizes a build performed elsewhere: the certificate
identifies that signing workflow and does not prove which physical runner
executed the build. Hosted and self-hosted runner security cannot be inferred
from the SAN, and this profile assigns no SLSA level to either.

Without that proof, the builder is `urn:attest:builder:unverified`. This sentinel
means that the platform/workflow was not established. It MUST NOT be treated as
an approved builder or as a shared trust identity for unrelated local builds.
The Attest tool name and version occur only in the evidence-producer metadata;
the version is never a builder identity.

The original receipt signer, exporting DSSE signer and approved workflow can be
different principals. None is automatically a separate artifact signer. A
recipient MUST authorize signer/builder relationships through independent
configuration, and MUST NOT infer them solely from a valid DSSE signature.

## Original-evidence extension

The namespaced `predicate.attest_evidence` object is required for this build type.
Removing it is an invalid v2 projection. It carries these fields:

| Field | Meaning |
| --- | --- |
| `format` | Exactly `attest-original-evidence/v1`. |
| `artifactBinding` | `signed-file-inventory` or `unavailable`, as defined above. |
| `receipt` | Exact native receipt: `{content, mediaType, sha256}`; content is base64, mediaType is `application/yaml`, sha256 is the digest of decoded bytes. |
| `originalSigner` | Original receipt's Ed25519 public-key hex, or null for an unsigned receipt. |
| `producer` | Exporting tool `{name, version}`, not a workflow or platform identity. |
| `workflow` | Verified-at-export `{issuer, repository, workflow, revision}`, or null. These are assertions until independently checked by the recipient. |
| `workflowBundle` | Original Sigstore bundle in the same blob representation, or null. Must accompany any workflow claims. |
| `trustMaterial` | Named public trust files in the same blob representation: public keys, trust policy, TSA certificates, accepted signed trust bundles and optional Sigstore root. Informative producer context only. |
| `semantics` | Explicit list of the projection's limitations and fields preserved only in the original. |

All blob digests MUST match their decoded bytes. The original receipt retains
its native signature, signer, RFC 3161 token, source observations, step manifests,
causal references, reproducibility and isolation statements byte-for-byte.
External causal objects, capsules, source and artifact files are not embedded in
this projection; they remain independently delivered evidence, and corresponding
properties cannot be inferred from the statement alone. The original receipt
and its hashes make that boundary explicit.

The transported public trust files MUST NOT be installed or used as trust
anchors automatically. They preserve the producer's context, including signed
trust-bundle provenance, but a recipient supplies its own current trusted keys,
revocations, TSA pins, Sigstore root and workflow policy. No private key is
exported. Trust directories, symlinks and payloads are bounded and checked.

## Verification and policy

A v2 import MUST perform separate checks:

1. Validate the DSSE envelope and the profile's structure. Exactly one DSSE
   signature is supported; multiple signatures MUST be rejected explicitly.
2. Check that signature against independently configured recipient trust,
   reporting `dsse-signature` and its signer.
3. Decode and hash the original receipt; verify its own signature, trust and
   timestamp under the native verifier. Re-signing with an approved exporter
   MUST NOT rescue an unknown or revoked original signer, invalid original
   signature or invalid timestamp.
4. Recompute the projection from the original receipt and require agreement
   of subjects, parameters, metadata, original signer and builder claims.
5. If an identity policy is supplied, verify the original workflow bundle
   against its independent trust root and exact identities; missing or changed
   proof MUST fail. With no policy, identity is explicitly skipped and the
   projected workflow is not approved.
6. If delivered artifacts are supplied, verify them against the original signed
   inventory. Without their bytes, artifact verification is explicitly skipped.

The machine verdict includes `interop.envelope_signer`,
`interop.original_signer`, `interop.original_receipt_sha256`,
`interop.original_verdict` and explicit projection semantics. `identity` reports
the requested policy, verified claims and distinct principal roles. The top-level
`signature` property requires both the trusted envelope and trusted original
receipt. `timestamp`, `trust` and `success` refer to the original evidence;
`artifacts` refers to delivered files. Properties such as recomputation or
capsule enforcement are not granted by a format conversion.

The old `https://alien6.com/attest/pipeline/v1` import remains supported for
historical DSSE envelopes. Its verdict always warns that the original evidence
and artifact binding are unavailable. It cannot satisfy an identity policy or
requirements for the omitted properties. New exports never generate that old
mapping. `--trust-statement-time` applies only to the legacy/envelope revocation
choice; it does not weaken native original-receipt timestamp verification.

## Complete example and CLI

[The complete example statement](attest-pipeline-v2.example.json) contains a
native receipt, different original/exporter principals, actual raw-file digest,
and the explicit unverified-builder marker. Its keys are public test identities,
not release trust anchors.

```sh
# Build and sign a native receipt first. Existing approved key setup is assumed.
attest run --wrap --name build --input src --output dist/app --sign \
  --report report.json -- ./build.sh
# RECEIPT is the exact path in report.json, not an arbitrary newest receipt.
attest export --format in-toto --receipt "$RECEIPT" --key "$EXPORTER_KEY" \
  --identity-bundle workflow.sigstore.json --identity-policy producer-policy.json \
  --output statement.dsse.json
# Transfer statement plus dist/app; configure recipient trust independently.
attest import --format in-toto statement.dsse.json \
  --trust-store /trusted/keys --identity-policy /trusted/workflow-policy.json \
  --artifact-root /delivery --require signature,identity,artifacts,success \
  --report json
```

For a local build, omit both identity export arguments and the recipient identity
requirement. Identity signing, when desired, is performed before export with
`attest identity sign "$RECEIPT" --bundle workflow.sigstore.json` in the approved
signing workflow. An unsigned export remains explicitly unsigned and cannot
satisfy normal import signature requirements.
