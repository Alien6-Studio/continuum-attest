# Recomputing a wrapped build

A wrapped receipt records the exact command argument vector, declared input
and output paths, and their hashes. A recipient can check those declarations
against a delivered workspace without an `attest.yaml` file and without
executing the command again. The GitHub action and GitLab component use this
same receipt and verifier contract.

```sh
# Producer: keep the declared inputs and outputs for the recipient.
attest run --wrap --name build --input src --input Makefile --output dist \
  --report build-report.json -- make release
# Sign the exact receipt reported in build-report.json in the trusted job.
attest sign '<RECEIPT_PATH>' --key '<RELEASE_KEY_ID>'

# Recipient: delivery contains the receipt and the declared paths above.
# Configure recipient-trust independently of that delivery.
attest verify delivery/receipt.yaml --workspace delivery \
  --trust-store recipient-trust --recompute --offline \
  --require signature,recompute,success --format json
```

Transfer all declared inputs and outputs with their original relative paths.
The release evidence archive contains output artifacts; input source files
must also be delivered when a recipient requires input recomputation. The
command may be inspected in the receipt but verification never executes it.
Arguments are recorded in signed evidence: pass secrets through controlled
environment or credential mechanisms rather than placing literal secrets in
the command line or an inline shell program. The receipt does not dump the
inherited environment, resolve the executable behind `PATH`, or attest
undeclared inputs.

## Command and execution identity

New receipts distinguish execution using the signed
`provenance.execution.mode`: `native` or `wrapped`. A wrapped descriptor also
contains `command`, an array of strings retaining every argument boundary.
Its canonical representation is the compact UTF-8 JSON array emitted by
`serde_json`, without whitespace between elements. These bytes determine:

- `provenance.steps[0].command_hash`: BLAKE3 of the canonical array.
- `pipeline_hash`: BLAKE3 of `attest-wrap/v1\n` followed by that array.
- The `run:` line of the `attest-manifest/v1` input manifest: the command hash.

Recomputation requires one wrapped step and matching declarations. It checks
the command against both recorded command identities, reconstructs the input
manifest from the declared paths and delivered bytes, and reconstructs the
output manifest independently. Changing the command, a declared input or an
output fails the `recompute` check. A native receipt instead uses the pipeline
declaration and its whole-pipeline hash. Neither mode alone establishes that
the execution host was trustworthy.

Old receipts retain their exact signing bytes and remain verifiable. They may
lack an execution descriptor. A matching native `attest.yaml` can establish
their native recomputation. Without that file, recomputation is explicitly
`skipped` with a missing-description reason; a supplied pipeline that does not
match produces `fail`. `--require recompute` refuses either result.
Missing declarations in a new wrapped receipt, unreadable declared files and
hash mismatches produce a `recompute: fail` result. JSON reports both the
check and the unmet recipient policy requirement; exit status is `1` when a
required property was not established.

## Input integrity and limits

Wrap uses the same input permission guard as a native local step. Declared
files and directories lose their write bits while the command runs, and their
original permissions are restored afterwards. Attest hashes the inputs again
after execution and refuses to produce a receipt if a declared input changed
or disappeared. A failed command retains its original exit code even when
this integrity check also fails; the report records the evidence failure.

Permission bits are not a sandbox. The same user can change permissions,
modify an input and restore its original bytes before the final hash; root
can ignore the permissions entirely. Wrapped receipts therefore report the
`inputs` control as `not-enforced`, explain whether the permission guard was
available, and record the other controls as unisolated. A capsule provides
the stronger read-only input snapshot boundary. A native pipeline also adds
its declared dependency graph and execution configuration. Workflow identity
adds independently verified issuer, repository, workflow and revision claims;
it does not turn a wrapped process into a capsule or prove runner integrity.
