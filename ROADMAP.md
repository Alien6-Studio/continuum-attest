# Roadmap

Attest should let a maintainer attach verifiable evidence to a software
release, and let its recipient inspect that evidence with a local tool.
The next steps focus on the handoff between those two people: what to trust,
what to distribute, and what a successful verification actually establishes.

This is the proposed development order for the open-source CLI and formats.
The 0.1 baseline is implemented; later milestones describe planned work.
There are no target dates. Each milestone has a completion criterion, and
security fixes can ship independently of this sequence.

## 0.1 — Amber Drift: the working foundation

The repository already provides:

- Pipeline execution and single-command wrapping, with declared inputs and
  outputs, canonical hashing, and a content-addressed cache.
- Signed receipts, a local trust store, key revocation, and optional RFC 3161
  timestamps checked against a pinned authority.
- Offline receipt verification, with optional recomputation against a
  workspace, and self-contained evidence archives.
- Capsules pinned to OCI image digests and checks comparing the outputs of
  two executions.
- A local causal ledger and in-toto/SLSA import and export.

The starting limits matter: trust and revocation are local, CI metadata is
reported by the runner, and causal roots are not published to an external
log. Matching hashes and a valid signature establish consistency with signed
claims; they do not independently prove execution on an uncompromised runner.

## 0.2 — Paper Moon: trust that can be shared

**Outcome:** a recipient can verify a release using an explicitly trusted,
updatable set of keys and revocations.

- Define a signed, versioned trust bundle containing public keys, revocation
  records, validity periods, and the authority that issued it.
- Add export, import, and explicit refresh of that bundle. Verification
  remains offline; fetching trust material is a separate operation.
- Define bootstrap and rotation: recipients pin the initial authority through
  a separate trusted channel, and updates cannot silently replace it.
- Detect expired bundles and rollback to an older accepted version. Report
  the freshness of available evidence and define which checks require a
  trusted clock or previously stored state.
- Make verification requirements explicit: required signature, trusted time,
  acceptable trust-bundle age, and whether recomputation is required. A
  missing required check must prevent acceptance, with a readable explanation
  and a machine-readable result.

**Complete when:** a producer can rotate or revoke a key, transfer an updated
bundle to a disconnected verifier, and demonstrate acceptance and rejection
of the appropriate receipts. Tests cover tampered bundles, stale updates,
unauthorized authority replacement, and backdated signatures. The verifier
states the trust information's validity window; it cannot claim knowledge of
revocations issued after its last update.

## 0.3 — Ember Sky: adoption in existing CI

**Outcome:** a team can attest one existing build job and hand its output to
a recipient without migrating its pipeline to Attest.

- Give the existing GitHub action and a new GitLab component the same
  adoption path: declare inputs and outputs, wrap the build command, sign the
  receipt, and publish the evidence alongside the artifact.
- Preserve build exit codes and distinguish a build failure from a failure
  to produce or publish evidence.
- Add verifiable workflow identity for receipts. Define which issuer,
  repository, workflow, and revision the recipient accepts, and bind the
  identity evidence to the signed receipt. Environment variables alone do
  not establish that identity.
- Package the material needed for offline verification, while keeping the
  recipient's trust anchors independently configured.
- Provide a producer/recipient example for each CI integration, including
  artifact substitution and an unauthorized workflow as rejection cases.

**Complete when:** a GitHub job and a GitLab job each produce a release whose
evidence is checked on a separate machine with the network disabled. The
recipient can require an approved workflow and detect a replaced artifact.
Local key-based signing remains available for disconnected producers.

## 0.4 — Glass Ocean: externally recorded evidence

**Outcome:** a recipient can check that a receipt's causal root was included
in an external append-only log.

- Define the publication unit, log trust model, and privacy boundary before
  selecting an implementation. Publishing a root must not require uploading
  source files, build logs, or private artifacts.
- Add explicit publication and retain the log's signed checkpoint and
  inclusion proof in the evidence package.
- Verify those proofs offline against a separately trusted log identity.
  Report publication separately from signature and timestamp checks.
- Specify consistency checking between checkpoints and how verifiers or
  monitors exchange checkpoints to detect conflicting log views.
- Define failure behavior when publication is required but the log is
  unavailable. Missing evidence must remain visible in the result.

**Complete when:** a transferred evidence package proves inclusion under a
trusted checkpoint, and adversarial tests reject changed roots, invalid
proofs, and inconsistent checkpoints where the required comparison evidence
is available. Document the remaining limits: inclusion alone cannot expose
every withheld receipt or detect split views without external comparison.

## 1.0 — Distant Bloom: a stable verification contract

**Outcome:** recipients can retain evidence and continue verifying it as
Attest evolves.

- Keep normative receipt, hashing, signing, trust-bundle, and proof formats
  versioned with the source, with fixtures and expected verification results.
- Exercise those fixtures with an independent verifier implementation to
  expose assumptions hidden in the Rust implementation.
- Define compatibility and migration rules for evidence formats, CLI options,
  exit codes, and machine-readable results. Unsupported evidence must produce
  an explicit diagnostic.
- Document the threat model and the guarantees of command wrapping,
  capsules, and reproducibility checks separately.
- Complete an external security review of signing, trust updates, verification,
  and archive handling; resolve blocking findings before the stable release.
- Establish supported platforms, maintenance policy, and measured performance
  baselines for representative repositories and evidence archives.

**Complete when:** the previous milestones pass their acceptance scenarios,
compatibility fixtures remain verifiable, the independent implementation
agrees on shared cases, and the security review has no unresolved release
blockers.

## Work to evaluate after the core milestones

- **Dagger and other build engines:** first establish what evidence their
  interfaces expose and which claims Attest can independently check. Preserve
  the source and meaning of imported digests; an imported result must not be
  presented as an execution observed by Attest.
- **Plugin host:** implement when a concrete integration needs it. Version
  the protocol, constrain capabilities, and isolate failures. Plugins may
  supply additional reports; core verification remains usable without them.
- **Organization services:** shared storage, access management, policy
  administration, and deployment integrations can build on the public
  formats. They are outside this CLI roadmap and must not become prerequisites
  for verifying exported evidence.

These are candidates, not release commitments. Their priority should follow
demonstrated usage and a defined verification model.
