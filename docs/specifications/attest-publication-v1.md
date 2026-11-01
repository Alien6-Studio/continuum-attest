# External publication of causal roots

Status: **implementation contract for 0.4 — Glass Ocean**. This document does
not claim that the published 0.3.1 binary implements publication. It resolves
the disclosure and trust decisions in [#26](https://github.com/Alien6-Studio/continuum-attest/issues/26)
before adding the publisher. The remaining acceptance work is tracked in
[#27–#31](https://github.com/Alien6-Studio/continuum-attest/milestone/3).

The recipient should be able to establish that a commitment to the causal
root in their signed receipt was included under a checkpoint signed by a log
they independently trust. Publication, receipt signatures, trusted time and
comparison of log histories are separate checks.

## 1. What leaves the producer

Publication is irreversible from the producer's point of view. A log or an
observer can retain an entry indefinitely, even if the operator later stops
serving it. Neither deleting the local record nor requesting deletion from an
operator retracts copies already observed.

The publication unit is a commitment to the receipt's `causal_chain_hash`.
That field is the BLAKE3 root over the receipt's ordered causal events; its
meaning is unchanged. Publication does not re-execute those events.

Let `root` be the 32 decoded bytes of that field, and `nonce` be 32 fresh bytes
from the operating system's cryptographic random source. The exact public
entry is:

```text
commitment = SHA-256(UTF8("attest-causal-root/v1\0") || nonce || root)
entry      = UTF8("attest-causal-root/v1\n") || commitment
```

`\0` denotes one zero byte, `\n` one line-feed byte, and `||` concatenation.
The entry contains the raw 32-byte commitment, without hex, JSON or base64.
Its length is constant. No receipt identifier, project name, source revision,
signing key, source file, build output, artifact or build log is added to it.
The root and nonce are retained with the evidence, not uploaded to the log.

The producer generates a fresh nonce for each explicit publication operation.
Retries within that operation reuse the exact entry and nonce. Reusing an
entry is observable; creating several entries can therefore happen if a
server accepted a request whose response was lost. A response timeout is not
evidence that nothing was published.

Without the opening nonce, an observer cannot efficiently test guesses about
a low-entropy private root by recomputing this commitment. This protection
depends on fresh randomness and keeping the opening out of public logs. A
recipient who receives the opening can test candidate roots, and can disclose
the association. The evidence archive must use the delivery channel appropriate
for its contents.

The entry's prefix reveals use of this protocol. The operator observes the
requested URL, connection's source address, timing, request headers and
repeated requests. Attest sets `User-Agent: continuum-attest/<version>` and
`Content-Type: application/octet-stream`. Deployment-chosen hostnames and
URL paths can themselves disclose identifiers; they are outside the opaque
entry and must be included in the deployment's disclosure assessment.
Readers can observe log ordering, indices, checkpoints, entry bytes and any
operator metadata. Network observers can correlate traffic. The protocol
does not provide traffic anonymity, conceal the number of publication
attempts, or require an operator to forget access logs. Deployments must
assess their operator's retention and access policies separately.

## 2. Independent trust and verification

Recipients obtain their log configuration through a channel independent of
the evidence sender. It pins the checkpoint origin and an Ed25519 signed-note
verifier key. A key or URL carried in an archive never creates trust. TLS
certificate validation protects transport; it does not replace the log key.
Replacing that key requires a deliberate trust-configuration update.

The initial profile uses [C2SP signed notes](https://c2sp.org/signed-note@v1.1.0)
with Ed25519 signature type `0x01`. The verifier checks canonical encodings,
the key identifier and the signature using the pinned full public key. An
identifier match alone is insufficient. Unknown signers cannot authorize a
checkpoint. Duplicate signer tuples, malformed notes and an invalid signature
from the pinned signer are refused. Parsing is bounded, while allowing at
least sixteen signatures.

The signed text is a [C2SP checkpoint](https://c2sp.org/tlog-checkpoint@v1.1.0).
Its origin, tree size and root are authenticated before they are used. Signed
extension lines remain part of the retained text. This Ed25519 profile supplies
no authenticated wall-clock time. It does not claim witness approval from
signatures whose identities or algorithms the recipient has not configured.

Verification checks the opening against the receipt's causal root, then the
entry's inclusion against that checkpoint. The external log uses the SHA-256
Merkle tree in [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962#section-2.1),
including separate leaf and internal-node prefixes. This is distinct from the
receipt's BLAKE3 causal root. Indices, tree sizes, path lengths and hashes are
validated; extra proof nodes are refused.

## 3. Implementation choice

The requirements above determine the choice, rather than an existing service
determining what must be disclosed.

| Candidate | Assessment for this publication unit |
| --- | --- |
| Tessera with C2SP tiled reads | Arbitrary entry bytes allow this fixed opaque entry without a producer identity field. Standard checkpoints and tree data support local proof construction and disconnected verification. Selected for the first adapter. |
| Rekor | Its signed-metadata model is useful for the existing workflow-identity feature. Adapting this opaque root to an accepted signed entry type would add a signature and its associated metadata. Kept separate from root publication. |
| Sigsum | Its key-usage model deliberately associates signatures with signing keys. That is useful for monitoring a release key, but is an additional disclosure and a different publication unit. |
| A new Attest log server | Would make Attest responsible for operating and securing another service and defining its storage behavior. Not required for this CLI feature. |

Sources: [Tessera](https://github.com/transparency-dev/tessera),
[Rekor](https://docs.sigstore.dev/logging/overview/) and
[Sigsum](https://www.sigsum.org/).

The adapter reads [C2SP tlog-tiles v1](https://c2sp.org/tlog-tiles@v1.0.0).
It reconstructs the required Merkle proofs from bounded hash tiles. Historical
partial tiles may be replaced by their full tile; fetched material is never
trusted without checking the resulting proof against the signed checkpoint.
Verification itself performs no HTTP request.

Writing is an explicitly configured integration endpoint: POST the exact entry
as `application/octet-stream`, receive its decimal leaf index. This matches
[Tessera's POSIX conformance writer](https://github.com/transparency-dev/tessera/blob/97031af5a3c83a4dddde0675879207eb17c9ec22/cmd/conformance/posix/main.go).
It is not part of the C2SP read standard. The conformance server is a test
target, not a production deployment supplied by Attest. Operators remain
responsible for service access, admission, capacity and retention.

## 4. Explicit publication and its audit record

Executing `attest run`, signing a receipt and verifying evidence do not publish
anything. The producer invokes a separate publication command and explicitly
selects `required` or `optional` publication. CI integrations may invoke that
command only when publication has been explicitly configured.

Before the first request, the publisher validates the signed receipt and root,
creates the opening, and persists a private local record of the exact entry,
destination, local attempt time and unconfirmed state. If recording fails, no
request is made. Updates are atomic. The local time is an audit aid, not a
trusted publication timestamp.

Transport requires HTTPS, validates certificates, refuses redirects and applies
response-size limits. A configured private CA may supplement TLS trust without
disabling validation. URLs containing credentials, fragments or query secrets
are not supported. Retrying and polling share an overall deadline and bounded
attempt count. An unavailable service cannot stall the command indefinitely.

A returned index, an HTTP success or a submission promise does not confirm
publication. The publisher obtains a signed checkpoint covering that index,
constructs an inclusion proof and verifies the complete binding before marking
the record `confirmed`. The exact entry, opening, log identity, checkpoint and
proof are retained. Other outcomes remain `unconfirmed`, with a reason and
attempt information; the record must not claim that a timed-out submission
did not reach the operator.

Required publication returns a distinct non-zero publication result when
confirmation cannot be established. Optional publication may continue packaging,
but preserves the unconfirmed state and reason. Neither setting alters the
recorded build result. A failed build retains its original exit code.

## 5. Evidence and recipient requirements

A package carrying publication material uses `attest-evidence/v3`. Packages
without that extension retain v2; the new verifier continues reading v1 and
v2. Publication does not change receipt signing bytes. A producer cannot
weaken the recipient's requirements by selecting optional publication.

The recipient receives the exact publication material, but supplies log trust
independently. Inclusion has its own passed, failed or skipped result, apart
from signature, timestamp and workflow-identity checks. Missing or unconfirmed
material cannot satisfy `log-inclusion`. A malformed or non-binding proof is
refused even if the log signature is valid.

These requirements are exposed by `attest evidence verify`. Ordinary receipt
verification retains its existing result contract; it neither obtains log
evidence nor contacts a publication service. An explicit comparison file
supplied by the recipient overrides an archived copy, but still needs their
independently supplied reference checkpoint.

The evidence does not prove which person submitted the entry, when the build
executed, or whether execution was correct. Inclusion establishes the entry's
membership under the identified checkpoint. It does not reveal withheld
receipts or prove that every observer sees the same history.

## 6. Comparing observations

Recipients can retain a previously authenticated checkpoint or receive one
through an independent observer. They explicitly supply that comparison
reference. A sender-chosen older checkpoint does not establish an independent
observation merely because it accompanies the evidence.

Both checkpoints are authenticated against the same configured log identity
before comparison. Equal tree sizes with unequal roots demonstrate a conflict.
Different sizes need a valid consistency proof from the smaller tree to the
larger tree. Matching roots at the same size require no path. Empty trees use
the defined empty-tree root. Extra, missing or invalid path nodes are refused.

Observers exchange both signed checkpoint texts and the consistency path as a
file. Proof acquisition is a separate online operation; receipt and archive
verification never fetch missing material. The verifier matches the exchange
to the recipient's reference and the publication checkpoint.

Missing comparison evidence reports consistency as not established, rather
than reporting a conflict. `log-consistency` cannot pass in either case. A
successful comparison covers only those two authenticated checkpoints; it is
not a claim about every log view or the absence of all split views.

## 7. Acceptance before release

Tests must bind independent trust, receipt root, opening, exact entry, inclusion
path and signed checkpoint. They cover altered roots, malformed paths, unsigned
or untrusted checkpoints, conflicting roots, missing comparison evidence and
valid comparisons across differing tree sizes. Required and optional publication
are exercised against unavailable services and unconfirmed submissions, with
bounded attempts and separate build/publication outcomes.

An end-to-end qualification uses the independently implemented Tessera writer,
transfers the resulting evidence and verifies it with recipient networking
disabled. Log trust is transferred separately. Security-sensitive refusal
tests are registered in the mutation gate and must fail when their protection
is removed. No qualification uploads private project material to a public log.

## 8. Retained file encodings and limits

Files use UTF-8 JSON with unknown fields refused. JSON member order and
whitespace carry no authority: bindings are checked from decoded values.
All hexadecimal digests and openings use exactly 64 lower-case characters.
The binary entry is 54 bytes and its retained hex representation is 108
characters. These files are private evidence, not a log submission payload.

`attest-publication/v1` has these mandatory fields:

| Field | Meaning |
| --- | --- |
| `format` | Literal `attest-publication/v1` |
| `causal_root` | Must equal the signed receipt's causal root |
| `opening_nonce` | The private 32-byte commitment opening, hex encoded |
| `entry` | Exact submitted binary entry, lower-case hex encoded |
| `log_id` | SHA-256 of UTF-8 `attest-log/v1\n` + configured origin + `\n` + configured verifier key |
| `submit_url` | Producer's configured submission endpoint; audit context, never recipient authority |
| `created_at` | Producer-clock RFC 3339 timestamp; no trusted-time claim |
| `submissions` | At most three objects with producer-clock `started_at` and nullable `returned_index` |
| `outcome` | One of the two objects below |

A confirmed outcome contains `status: "confirmed"`, unsigned integer
`leaf_index`, the complete UTF-8 signed note in `checkpoint`, and
`inclusion_path`, an ordered array of hex SHA-256 nodes. An unconfirmed
outcome contains only `status: "unconfirmed"` and `reason`, one of `prepared`,
`request-failed`, `service-refused`, `awaiting-inclusion`, `invalid-proof`,
`deadline` or `attempt-limit`. These reasons are not operator-supplied text.
Neither audit timestamps nor submission indices authenticate the submitter
or establish inclusion.

`attest-log-comparison/v1` contains `format`, `log_id`, `first_checkpoint`,
`second_checkpoint` and `consistency_path`. Both checkpoints are complete
signed notes, ordered by increasing tree size, and the path is an ordered
array of hex SHA-256 nodes. The verifier authenticates both, verifies the path
and matches the pair to the publication and recipient reference. Equal-size
roots and signatures are still checked; an exchange never supplies trust or
selects the recipient's independent reference.

Publication records are bounded at 512 KiB and comparisons at 1 MiB. Each
signed note is bounded at 128 KiB and 32 signatures. Tree sizes and leaf
indices are unsigned 64-bit integers; inclusion requires a nonempty tree and
an index strictly smaller than its size. Inclusion paths have at most 64
nodes and consistency paths at most 65. Every node is consumed. C2SP hash
tiles are bounded at 8,192 bytes; the online reader caches at most 512 tiles
and permits at most 2,048 HTTP requests within the overall deadline.
