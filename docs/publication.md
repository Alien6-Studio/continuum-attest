# Publish a commitment, deliver its proof (0.4 — Glass Ocean)

This guide describes the development version. Use the published 0.3.1 release
until 0.4 is qualified and released.

Glass Ocean lets a producer publish a commitment to a receipt's causal root
in an independently operated log. A recipient can then check inclusion and
compare two observed log checkpoints without contacting that log. Receipt
signing, trusted time, workflow identity and log publication remain separate.

## Choose the operator and provision trust

The first adapter supports a Tessera-compatible raw-entry writer and C2SP
tlog-tiles reads with an Ed25519 signed-note checkpoint. Attest does not select
or operate a public service for you. Obtain the endpoints, checkpoint origin
and verifier key from the operator through your trusted provisioning channel.
HTTPS is mandatory; redirects are refused. An optional `tls_ca` file adds
your internal CA to transport trust. Relative paths resolve beside the config.

```json
{
  "format": "attest-log/v1",
  "origin": "<OPERATOR_CHECKPOINT_ORIGIN>",
  "verifier_key": "<NAME+KEY_ID+BASE64_NOTE_VERIFIER_KEY>",
  "read_url": "https://<LOG_READ_ENDPOINT>/",
  "submit_url": "https://<LOG_WRITE_ENDPOINT>/add"
}
```

Recipients need only `format`, `origin` and `verifier_key`. Supply this
configuration independently of the evidence sender. No log API credential is
supported in this profile; do not put a token in a URL or repository.

Publication is an irreversible disclosure. The fixed-length entry contains
a fresh randomized commitment, not the root, source, artifacts or build logs.
The operator still sees source address, timing and headers; observers can see
entries, order and retries. The retained evidence contains the opening and
therefore reveals the association to recipients. Review the
[disclosure contract](specifications/attest-publication-v1.md) before enabling it.

## Produce and publish explicitly

```console
attest run --wrap --name build --input src/ --output dist/ --sign -- make dist
attest causal publish --receipt <EXACT_RECEIPT_PATH> \
  --log-config producer-log.json --output publication.json \
  --publication-policy required --timeout-secs 30 --format json
attest evidence pack <EXACT_RECEIPT_PATH> --workspace . \
  --publication publication.json --output release.attest.tar.zst
```

`attest run` writes local evidence and never publishes a log entry. Both wrap
and pipeline receipts contain causal events. Existing receipts without a
causal root cannot be published; produce a new receipt rather than editing it.
Supply any referenced capsule manifests when packing, as described in the
[evidence guide](evidence-format.md).

Before a POST, Attest durably records the exact intent in `publication.json`
with private file permissions. Keep this record. Repeating the publish command
with the same output resumes the same entry; it never silently chooses a new
opening. A confirmed record is rechecked without resubmission. At most three
submission attempts are retained per record. A timeout can mean the entry was
accepted but not yet confirmed. Removing a stale `.lock` after a crash requires
inspection; do not run two publishers against one record.

Only verified inclusion under an authenticated checkpoint yields `confirmed`.
A returned index alone does not. The explicit deadline is 1–120 seconds;
individual requests and retries are bounded. `required` returns exit 3 when
confirmation is missing. `optional` returns 0 with an `unconfirmed` record and
reason so packaging can continue. Local invocation, trust and storage errors
return 2. JSON summaries omit the private root and opening.

## Hand off and verify without network

Deliver the archive through the channel appropriate for its contents. The
recipient provides receipt trust and log trust independently:

```console
attest evidence verify release.attest.tar.zst \
  --trust-store recipient-trust/ --log-trust recipient-log.json \
  --require signature,artifacts,capsule,linkage,log-inclusion --format json
```

An unconfirmed publication can be packaged but cannot satisfy `log-inclusion`.
Missing trust gives a skipped check, never authority derived from the archive.
Altered entries, invalid signatures and invalid paths give failed checks.

## Compare observations

Keep a signed checkpoint obtained independently of this delivery. Proof
acquisition is an explicit online operation; copy both signed notes and the
resulting exchange to the recipient:

```console
attest causal fetch-consistency --first-checkpoint observed.note \
  --second-checkpoint publication.note --log-config producer-log.json \
  --output comparison.json
attest evidence verify release.attest.tar.zst \
  --trust-store recipient-trust/ --log-trust recipient-log.json \
  --log-checkpoint observed.note --log-consistency comparison.json \
  --require log-inclusion,log-consistency --format json
```

The exact signed publication note is retained at `outcome.checkpoint` in a
confirmed record. A matching same-size checkpoint needs no path; unequal
same-size authenticated roots demonstrate conflict. Different nonempty sizes
need a valid consistency path. Missing proof is distinct from conflict and
cannot satisfy a required comparison. A successful comparison establishes
consistency only between those observations. It supplies no authenticated
build time and does not establish correct execution or universal log honesty.

## Opt in from CI

The GitHub action and GitLab component add `log-publication-policy` (default
`off`), `log-config` and `log-timeout-secs`. Use an audited 0.4 integration and
binary. Configuring an endpoint without an explicit policy is refused before
the build. A failed build preserves its exit code and does not publish a log
entry. A successful signed build publishes before packing its evidence.

`log-publication-status`, `log-publication-reason` and `log-publication-record`
are separate from `publication-status`, which still describes CI artifact
upload. Required log publication fails with exit 3 even if the evidence policy
is optional. Optional unconfirmed publication retains its reason in the v3
archive and status report. Artifact-upload and verification failures retain
their existing evidence-policy behavior.
