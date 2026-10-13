#!/usr/bin/env bash
#
# Bind a release to the exact bytes it publishes, and check that binding
# before anything is published.
#
# A release carries several kinds of evidence -- checksums, an SBOM, GitHub's
# build provenance, attest's own receipt -- and nothing forced them to
# describe the same bytes: the receipt attested a build of its own, on its own
# runner, not the tarballs a recipient downloads. This script closes that gap
# with one wrapped step whose declared input is the directory of everything
# the release will publish. The receipt's input manifest then covers every
# published file byte for byte, and the publish job recomputes that manifest
# over what it is about to publish and refuses on any difference.
#
#   tools/release-binding.sh attest              in the evidence job
#   tools/release-binding.sh check <receipt>     in the publish job
#
# Both run from the repository root with the artifacts under ./artifacts, in
# the layout actions/download-artifact produces. `attest` writes an unsigned
# receipt: the job that produces evidence holds no key, and `attest sign`
# signs it in the job that does. `check` needs the receipt to be signed by a
# key in .attest/trust and to carry a timestamp token, and it needs ATTEST to
# point at a binary it can run.
set -euo pipefail

ATTEST=${ATTEST:-./target/release/attest}
NAME=release-artifacts
# The wrapped command. What the receipt binds is this command's JSON argv,
# so `check` hands `attest hash` the same string; the two must not drift.
RUN='find artifacts -type f | sort | xargs sha256sum'
RUN_ARGV='["sh","-c","find artifacts -type f | sort | xargs sha256sum"]'

case "${1:-}" in
  attest)
    [ -d artifacts ] || { echo "no ./artifacts to attest" >&2; exit 2; }
    "$ATTEST" run --wrap --name "$NAME" --input artifacts -- sh -c "$RUN"
    ;;
  check)
    receipt=${2:?receipt path}
    [ -d artifacts ] || { echo "no ./artifacts to check" >&2; exit 2; }
    # The receipt itself first: signed by a trusted key, timestamped by a
    # pinned authority, every requirement established.
    "$ATTEST" verify "$receipt" --trust-store .attest/trust \
      --require signature,timestamp --format text
    expected=$(grep -m1 '^ *input_hash:' "$receipt" | awk '{print $2}')
    [ -n "$expected" ] || { echo "$receipt carries no input_hash" >&2; exit 2; }
    actual=$("$ATTEST" hash --input artifacts --name "$NAME" --run "$RUN_ARGV")
    if [ "$expected" != "$actual" ]; then
      echo "refusing to publish: the artifacts about to be published do not match the attested set" >&2
      echo "  attested manifest  $expected" >&2
      echo "  published manifest $actual" >&2
      exit 1
    fi
    echo "release artifacts match the attested manifest $actual"
    ;;
  *)
    echo "usage: $0 attest | check <receipt>" >&2
    exit 2
    ;;
esac
