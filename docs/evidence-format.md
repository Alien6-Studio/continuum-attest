# Offline evidence packages

`attest-evidence/v2` is a deterministic tar.zst handoff. It carries evidence;
it never supplies authority to trust that evidence. The recipient provisions
the key trust store, timestamp authorities, Sigstore trusted root and policy
independently. Verification performs no network fetch and does not extract
archive paths. Resource limits and duplicate/path checks apply before use.

| Entry | Condition | Binding |
| --- | --- | --- |
| `manifest.json` | Required; contains only `format: "attest-evidence/v2"` | Format discriminator, not a trust or completeness assertion |
| `receipt.yaml` | Required | Original signed receipt, including optional timestamp token |
| `artifacts/<path>` | Every artifact in signed provenance | Per-file BLAKE3 (link-target bytes for symlinks); complete inventory must reproduce each signed step output manifest |
| `identity.sigstore.json` | Required by recipient workflow policy | Sigstore signature over the exact `receipt.yaml` bytes; independently pinned root, issuer, repository, workflow and revision |
| `capsules/<hash>.yaml` | Every capsule hash referenced by a step | Valid capsule manifest whose canonical hash equals the signed reference and stored manifest hash |
| `events/<id>.json` | Every causal event referenced by the receipt | Authentic event ID, valid event signature when present, recorded parent references and ordered chain root matching the signed receipt |

Unreferenced capsule/event entries and unrelated files are refused. Missing
fields or unknown proof fields cannot add unauthenticated claims. Legacy causal
event `metadata` is not covered by its event ID, chain root or signature; packing
therefore projects it to an empty object without changing those cryptographic
values. Verification refuses non-empty metadata in packaged causal proofs.
The original ledger is not modified. Missing
capsule or causal entries produce `skipped` checks naming the missing proofs,
with `incomplete` in their details. Invalid material produces `fail`, even
when its completeness was optional. A chain root without event references is
invalid. Sender flags cannot declare a package complete.

`attest evidence pack` includes available referenced events from
`<workspace>/.attest/causal_ledger/events`. Supply each capsule manifest using
repeatable `--capsule-manifest <path>` arguments. A missing proof can therefore
be handed over explicitly as incomplete; it cannot satisfy a recipient's
required completeness checks. Packing rejects unrelated capsule manifests.

The default recipient policy requires `signature,success,artifacts,capsule,linkage`.
Here `capsule` and `linkage` mean completeness of the references present in the
receipt; they pass when the receipt references none. Use an explicit
`--require signature,success,artifacts` to permit incomplete optional proofs.
Their `skipped` results remain visible. Signature, successful execution and
artifact matching remain mandatory for release evidence. Supplying
`--identity-policy` always adds the `identity` requirement. Additional supported
requirements, such as `timestamp` or `trust`, must also be established to pass.

The JSON verdict exposes `policy.required`, `policy.unmet`, all checks, and
`identity.required`/`identity.verified`. The `identity.principals` object keeps
the verified receipt signer (`evidence_producer`) separate from the verified
workflow SAN (`workflow`). `artifact_signer` is null: a receipt's artifact
digest is not a detached artifact signature. Verified workflow origin and
authorization do not establish that the runner was uncompromised or the build
correct.

V1 archives remain readable and receive the same completeness checks. New
archives use v2 so a verifier from 0.3.0, which does not assess capsule/causal
completeness, refuses the new format instead of silently accepting less
evidence than the recipient intended. The receipt wire schema is unchanged.

## Publication extension in 0.4

An explicit `--publication <record.json>` selects `attest-evidence/v3`.
Without it, packing continues to produce v2. V3 adds `publication.json` and,
optionally, `log-consistency.json`; all v2 entries and checks still apply.
Verifiers before 0.4 reject v3. Upgrade recipients before sending it.

The publication record retains a private opening nonce, the causal root,
the exact opaque entry, log identifier, attempted submissions and either
confirmed inclusion material or a fixed reason for non-confirmation. Handle
the archive as private evidence: possession of the opening reveals the
association between receipt and public entry. It does not contain a log
private key. A bundled public key never establishes recipient trust.

`attest evidence verify --log-trust <independent-config.json>` checks the
opening against the signed receipt, the pinned log signature and the complete
inclusion path. `--require log-inclusion` refuses missing, skipped or invalid
inclusion. Optional producer publication cannot override this requirement.

`--log-checkpoint <independent-reference.note>` enables comparison against a
recipient's observation. An archived comparison is used only when it covers
that reference and the publication checkpoint. An explicit `--log-consistency`
file overrides the archived copy. Both signed checkpoints and every proof node
are checked locally. Missing comparison is `skipped`; authenticated unequal
roots at the same size are a conflict and `fail`. `--require log-consistency`
accepts only a passed comparison. Success covers those two checkpoints, not
every observer's view. No command in evidence verification fetches a proof.

The exact encodings, bounds and trust model are specified in
[attest-publication-v1](specifications/attest-publication-v1.md). The ordinary
receipt-verification JSON contract remains unchanged; these two additional
checks belong to evidence verification.
