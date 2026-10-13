#!/usr/bin/env bash
#
# Prove the security invariants have teeth.
#
# A green test suite is not evidence. Every defect this project has shipped
# was found while the suite was green, because a test only covers the failure
# somebody thought of -- and a test can silently stop covering even that, when
# a refactor moves the check it was watching.
#
# So this gate inverts the question. It breaks each protection in turn and
# requires the matching invariant to fail. A protection whose removal breaks
# nothing is not protected; a test that survives its own protection being
# deleted is decoration, and should be deleted rather than counted.
#
# Run from the repository root. It edits tracked files and restores them,
# so it refuses to start on a dirty tree.
#
#   tools/mutation-gate.sh
#
# Give it a checkout nothing else is using. It rewrites sources for minutes at
# a time, and anything that changes the tree underneath it -- a parallel job,
# a scratch directory reused by a script, an editor saving a file -- produces
# results about a tree that no longer exists. The checks below refuse to
# conclude in that case rather than scoring it as protections verified.
#
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "mutation-gate: refusing to run on a dirty tree (it edits and restores sources)" >&2
  exit 2
fi

CARGO=${CARGO:-cargo}
FAILURES=0
CHECKED=0

restore () { git checkout -- src/ >/dev/null 2>&1; }
trap restore EXIT

# mutate <name> <file> <test-binary> <expected-failing-test> <python-replacement>
#
# Applies a textual mutation, runs the named test, and requires it to FAIL.
#
# The replacement script must assert what it expects to find before replacing
# it. A script whose patterns no longer match -- because rustfmt rewrapped a
# line, say -- otherwise applies in part, leaves the protection standing, and
# reports the invariant as toothless when the fault is in the mutation. An
# assertion turns that into "the mutation no longer applies", which is the
# truth and names the fix.
mutate () {
  local name=$1 file=$2 suite=$3 expect=$4 script=$5
  CHECKED=$((CHECKED + 1))

  if ! python3 - "$file" <<PY
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
$script
if new == s:
    sys.exit(3)
p.write_text(new)
PY
  then
    echo "FAIL  ${name}: the mutation no longer applies -- the code moved, so this gate is stale" >&2
    FAILURES=$((FAILURES + 1))
    restore
    return
  fi

  # Three distinct outcomes hide behind cargo's exit code, and only one of
  # them means the protection is tested. Treating any non-zero exit as
  # success -- which this script used to do -- would score a mutation that
  # merely broke the build as a protection verified. That is the exact
  # failure this gate exists to catch, so it is checked for here first.
  local output
  if ! output=$($CARGO test --locked --no-run --test "$suite" 2>&1); then
    echo "FAIL  ${name}: the mutated tree does not build, so nothing was tested" >&2
    echo "$output" | grep -E "^error" | head -3 >&2
    FAILURES=$((FAILURES + 1))
    restore
    return
  fi

  output=$($CARGO test --locked --test "$suite" "$expect" 2>&1)
  local status=$?

  # A filter that matches nothing runs zero tests and exits zero, which would
  # otherwise read as "the invariant passed" and be reported as a failure for
  # the wrong reason -- or, worse, a renamed test would quietly stop being a
  # gate at all.
  if echo "$output" | grep -qE "running 0 tests"; then
    echo "FAIL  ${name}: no test matched '${expect}' -- renamed or removed?" >&2
    FAILURES=$((FAILURES + 1))
    restore
    return
  fi

  if [ "$status" -eq 0 ]; then
    echo "FAIL  ${name}: '${expect}' still passed with the protection removed" >&2
    FAILURES=$((FAILURES + 1))
    restore
    return
  fi

  # Non-zero is not enough. Cargo exits non-zero for a test that failed, and
  # also for a harness that could not start, a panic before any test ran, a
  # missing binary. Only the first means the protection is tested, and only
  # cargo's own summary distinguishes them.
  if ! echo "$output" | grep -q "^test result: FAILED"; then
    echo "FAIL  ${name}: cargo failed without reporting a test failure -- the" >&2
    echo "      test did not run, so nothing was verified" >&2
    echo "$output" | tail -5 >&2
    FAILURES=$((FAILURES + 1))
    restore
    return
  fi

  echo "ok    ${name} -> ${expect}"
  restore
}

echo "Breaking each protection in turn; each must fail its invariant."
echo

mutate "manifest rejects control characters" src/hashing.rs \
  security_invariants forging_a_manifest_entry_through_a_newline_in_a_filename_is_refused \
  'new = s.replace("if let Some(bad) = part.chars().find(|c| c.is_control()) {", "if let Some(bad) = part.chars().find(|_| false) {")'

mutate "input hash pinned before execution" src/executor/mod.rs \
  security_invariants forging_provenance_by_mutating_an_input_mid_step_is_refused \
  'new = s.replace("if inputs_after != input_hash {", "if false {")'

mutate "cached outputs verified on disk" src/executor/mod.rs \
  security_invariants forging_an_attestation_of_a_deleted_artifact_through_the_cache_is_refused \
  'new = s.replace("    match crate::hashing::hash_outputs(workspace, step_name, &step.outputs) {", "    if true { return true; }\n    match crate::hashing::hash_outputs(workspace, step_name, &step.outputs) {")'

mutate "causal identity covers the parents" src/storage/causal_ledger.rs \
  security_invariants forging_the_causal_graph_by_rewriting_parents_is_refused \
  'old = """        for parent in &event.causal_parents {
            crate::hashing::hash_field(&mut hasher, "parent", parent.as_bytes());
        }"""
assert s.count(old) == 1, "parent loop moved"
new = s.replace(old, "")'

mutate "chain root covers event content" src/storage/causal_ledger.rs \
  security_invariants forging_a_recorded_fact_inside_a_causal_event_is_refused \
  'old = "            hasher.update(&Self::event_content(event));"
assert s.count(old) == 1, "chain_hash body moved"
new = s.replace(old, "            hasher.update(event.event_id.as_bytes());")'

mutate "wrap encodes the argument vector" src/wrap.rs \
  security_invariants forging_a_matching_command_hash_by_shifting_argument_boundaries_is_refused \
  'new = s.replace("serde_json::to_string(command).context(\"cannot encode the wrapped command\")?", "Ok::<String, anyhow::Error>(command.join(\" \"))?")'

mutate "revocation refuses without attested time" src/verify.rs \
  keys_cli revocation_semantics \
  'new = s.replace("None if opts.trust_receipt_timestamp => {", "None if true => {")'

mutate "recompute checks the pipeline hash" src/verify.rs \
  security_invariants forging_a_different_environment_is_refused \
  'new = s.replace("if recomputed != receipt.pipeline_hash {", "if false {")'

mutate "recompute checks step outputs" src/verify.rs \
  security_invariants forging_an_artifact_after_the_build_is_refused \
  'new = s.replace("                if recomputed != step_result.output_hash {", "                if false {")'

mutate "recompute notices a step the receipt omits" src/verify.rs \
  security_invariants forging_a_smaller_build_by_stripping_a_step_from_the_receipt_is_refused \
  'new = s.replace("        if !attested.contains(name.as_str()) {", "        if false {")'

mutate "timestamping certificates must be authorised" src/crypto/timestamp.rs \
  security_invariants a_certificate_not_authorised_to_timestamp_is_recognised_as_such \
  'new = s.replace("                allows_timestamping =\n                    critical && found.len() == 1 && found[0] == OID_KP_TIMESTAMPING;", "                allows_timestamping = true;")'

mutate "import refuses a revoked key on the signer's own word" src/interop.rs \
  security_invariants forging_acceptance_by_round_tripping_a_revoked_signature_through_in_toto_is_refused \
  'new = s.replace("            if !options.trust_statement_time {", "            if false {")'

mutate "signing refuses a revoked key" src/keys.rs \
  security_invariants forging_a_receipt_with_a_revoked_signing_key_is_refused \
  'old = "            Some(entry) => match entry.status {"
assert s.count(old) == 1, "authorize_signing match moved"
new = s.replace(old, "            Some(entry) => match KeyStatus::Trusted {")'

mutate "a public key file alone is not trust" src/verify.rs \
  security_invariants forging_trust_by_dropping_a_public_key_into_the_trust_store_is_refused \
  'old = "                None => KeyTrust::Unknown,\n            });"
assert s.count(old) == 1, "presence-is-not-trust arm moved"
new = s.replace(old, "                None => KeyTrust::Trusted,\n            });")'

mutate "a bundle's signature binds its contents" src/trust.rs \
  security_invariants forging_trust_by_editing_a_revocation_out_of_a_bundle_is_refused \
  'old = "let intact = verifying_key.verify(&bytes, &signature).is_ok();"
assert s.count(old) == 1, "bundle signature check moved"
new = s.replace(old, "let intact = verifying_key.verify(&bytes, &signature).is_ok() || true;")'

mutate "an older bundle than the accepted one is a replay" src/trust.rs \
  security_invariants forging_freshness_by_replaying_an_older_bundle_is_refused \
  'old = "Some(previous) if bundle.sequence < previous.sequence => bail!("
assert s.count(old) == 1, "bundle sequence check moved"
new = s.replace(old, "Some(previous) if false && bundle.sequence < previous.sequence => bail!(")'

mutate "a revoked authority cannot update the store" src/trust.rs \
  security_invariants forging_a_trust_update_with_a_revoked_authority_is_refused \
  'old = ".is_some_and(|entry| entry.status == KeyStatus::Revoked)"
assert s.count(old) == 1, "revoked-issuer check moved"
new = s.replace(old, ".is_some_and(|entry| false && entry.status == KeyStatus::Revoked)")'

mutate "a skipped check does not satisfy a requirement" src/verify.rs \
  security_invariants forging_acceptance_by_leaving_a_required_check_unperformed_is_refused \
  'old = "        Some(c) if c.status == CheckStatus::Pass => None,"
assert s.count(old) == 1, "check_reason pass arm moved"
new = s.replace(old, "        Some(c) if c.status != CheckStatus::Fail => None,")'

mutate "a bundle's signature binds every field" src/trust.rs \
  security_invariants forging_any_signed_field_of_a_bundle_is_refused \
  'old = "let intact = verifying_key.verify(&bytes, &signature).is_ok();"
assert s.count(old) == 1, "bundle signature check moved"
new = s.replace(old, "let intact = verifying_key.verify(&bytes, &signature).is_ok() || true;")'

mutate "a stranger's first bundle needs a pin" src/trust.rs \
  security_invariants forging_trust_with_a_well_formed_bundle_from_an_unpinned_authority_is_refused \
  'old = "        None if expected_issuer.is_none() => {"
assert s.count(old) == 1, "unpinned-issuer arm moved"
new = s.replace(old, "        None if false => {")'

mutate "a required revision with no evidence is a failure" src/crypto/supply_chain.rs \
  image_verify_cli a_required_revision_with_no_evidence_fails \
  'old = """                Ok(None) => CheckResult::fail(
                    "revision","""
assert s.count(old) == 1, "revision no-evidence arm moved"
new = s.replace(old, """                Ok(None) => CheckResult::skipped(
                    "revision",""")'

mutate "process isolation does not claim a network control" src/sandbox/mod.rs \
  security_invariants forging_isolation_by_claiming_a_network_control_process_isolation_lacks_is_refused \
  'old = """                            "network",
                            NotEnforced,
                            format!(
                                "process isolation has no network control"""
assert s.count(old) == 1, "process-mode network row moved"
new = s.replace(old, """                            "network",
                            Enforced,
                            format!(
                                "process isolation has no network control""")'

mutate "signing authority is loaded after the steps" src/executor/mod.rs \
  security_invariants forging_a_signature_with_authority_available_during_the_build_is_refused \
  'old = """        let start_time = Instant::now();
        let mut provenance = crate::provenance::collect("""
assert s.count(old) == 1, "start of Executor::run moved"
new = s.replace(old, """        let start_time = Instant::now();
        self.load_signing_key()?;
        let mut provenance = crate::provenance::collect(""")'

mutate "declared inputs are unwritable while the step runs" src/executor/mod.rs \
  security_invariants forging_a_declared_input_from_inside_the_step_is_refused \
  'old = "let guard = InputGuard::hold(&workspace, &step.inputs)?;"
assert s.count(old) == 1, "input guard moved"
new = s.replace(old, "let guard = InputGuard::hold(&workspace, &[])?;")'

mutate "a symlink's target must be declared" src/hashing.rs \
  security_invariants forging_an_input_through_a_symlink_to_an_undeclared_file_is_refused \
  'old = "        if !covered {"
assert s.count(old) == 1, "symlink coverage check moved"
new = s.replace(old, "        if false {")'

mutate "trust freshness follows the signer" src/verify.rs \
  security_invariants forging_trust_freshness_with_another_issuers_bundle_is_refused \
  'old = "        .filter(|b| b.keys.iter().any(|k| k.id == signer_id))"
assert s.count(old) == 1, "per-signer bundle filter moved"
new = s.replace(old, "        .filter(|b| b.keys.iter().any(|k| k.id == signer_id || true))")'

mutate "a hermetic sandbox clears the ambient environment" src/sandbox/mod.rs \
  security_invariants forging_a_hermetic_environment_by_inheriting_the_ambient_one_is_refused \
  'old = """        if !self.config.inherit_environment {
            // Hermetic: nothing ambient reaches the step. PATH is kept only"""
assert s.count(old) == 1, "unix-path env_clear moved"
new = s.replace(old, """        if false {
            // Hermetic: nothing ambient reaches the step. PATH is kept only""")'

mutate "sign holds the receipt to the verifier's checks" src/core.rs \
  sign_cli sign_refuses_a_receipt_the_verifier_would_refuse \
  'old = "    if !failed.is_empty() {\n        eprintln!(\n            \"error: refusing to sign {}: {}\","
assert s.count(old) == 1, "sign scrutiny moved"
new = s.replace(old, "    if false {\n        eprintln!(\n            \"error: refusing to sign {}: {}\",")'

mutate "tar extension records are refused on the wire" src/archive.rs \
  archive_limits gnu_long_link_records_are_refused_on_the_wire \
  'old = "            if matches!(kind, b\x27L\x27 | b\x27K\x27 | b\x27x\x27 | b\x27g\x27) {"
assert s.count(old) == 1, "physical extension check moved"
new = s.replace(old, "            if false {")'

mutate "a length precedes what it measures" src/hashing.rs \
  encoding_injectivity no_pair_of_label_and_value_can_be_confused_for_another \
  'old = """    hasher.update(label.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(label.as_bytes());"""
assert s.count(old) == 1, "hash_field ordering moved"
new = s.replace(old, """    hasher.update(label.as_bytes());
    hasher.update(b":");
    hasher.update(label.len().to_string().as_bytes());""")'

mutate "environment encoding is unambiguous" src/storage/mod.rs \
  encoding_injectivity distinct_environments_never_share_a_cache_key \
  'a = """        crate::hashing::hash_field(
            &mut hasher,
            "env-count",
            env_entries.len().to_string().as_bytes(),
        );
"""
b = """            crate::hashing::hash_field(&mut hasher, "env-key", key.as_bytes());
            crate::hashing::hash_field(&mut hasher, "env-value", value.as_bytes());"""
assert s.count(a) == 1, "env-count block moved"
assert s.count(b) == 1, "env key/value block moved"
new = s.replace(a, "").replace(b, """            hasher.update(format!("{}={}\\n", key, value).as_bytes());""")'

mutate "cache key covers where and how a step runs" src/storage/mod.rs \
  security_invariants forging_a_result_by_running_the_same_step_elsewhere_is_refused \
  'old = """        crate::hashing::hash_field(&mut hasher, "shape", step_shape.as_bytes());
"""
assert s.count(old) == 1, "shape field moved"
new = s.replace(old, "")'

mutate "a signature with no key is a failure, not a silence" src/storage/causal_ledger.rs \
  security_invariants forging_an_event_signature_and_deleting_its_key_is_refused \
  'new = s.replace("            return Some(false);", "            return None;")'

mutate "archive rejects event signatures that do not hold" src/archive.rs \
  security_invariants forging_an_event_signature_inside_an_archive_is_refused \
  'new = s.replace("    if !unverifiable.is_empty() {", "    if false {")'

# Deliberately not mutated: the archive's per-event id check is diagnostics,
# not an independent protection. Since the chain root covers each event's full
# content, a rewritten event already fails on the root; the id check exists so
# the failure names the event that moved instead of reporting a root mismatch
# with no indication of where. Removing it changes the message, not the
# verdict, so no invariant can be made to fail by removing it -- and claiming
# one did would be exactly the decoration this gate exists to catch.

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "mutation-gate: ${CHECKED} protections, every one caught by its invariant."
else
  echo "mutation-gate: ${FAILURES} of ${CHECKED} protections are NOT actually tested." >&2
fi
exit $((FAILURES > 0))
