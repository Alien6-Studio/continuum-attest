# Security Policy

`attest` produces evidence about software supply chains. A flaw that lets
someone forge, alter, or bypass that evidence is the most serious class of bug
this project can have, and we would rather hear about it from you than from an
incident.

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting on this repository
(*Security* → *Report a vulnerability*), or email **security@alien6.com**.

Please include, as far as you can:

- the version (`attest --version`) and platform;
- what an attacker gains, not only what misbehaves;
- a reproduction — a minimal receipt, pipeline, or command sequence is ideal;
- whether you have disclosed it anywhere else, and any deadline you intend to
  hold us to.

You will get an acknowledgement within **5 working days** and an initial
assessment within **15 working days**. We will keep you updated at least
monthly until the issue is closed, and we will tell you plainly if we decide
something is not a vulnerability and why.

These are deliberately modest. A small team that publishes a deadline it misses
does more damage to a reporter's trust than one that promises less and keeps
its word.

## Disclosure

We practise coordinated disclosure. Our default is to publish a fix and an
advisory within **90 days** of the report, sooner when a fix is ready. We will
agree the timing with you, and we will credit you in the advisory unless you
ask us not to.

If a vulnerability is being exploited in the wild, we will ship and disclose as
fast as we can, regardless of the 90 days.

## Supported versions

Until 1.0, only the latest released version receives security fixes. After 1.0
this section will state a support window.

## In scope

- Forging or altering a receipt so that `attest verify` accepts it.
- Bypassing signature verification, trust-store checks, or key revocation.
- Causing a receipt to record inputs, outputs, or hashes that do not match what
  actually ran.
- Breaking the tamper-evidence of the causal ledger: altering a recorded event
  without the chain root or the event's identity changing.
- Escaping a capsule — the one execution boundary this release enforces, by
  pinning an image digest — in a way that changes the recorded result. Steps
  outside a capsule run directly and are not isolated; that is not a bypass.
- Leaking private key material into a receipt, a log, or an archive.

## Known limits

These are documented properties of this release, not vulnerabilities. They
are listed in the README under *What it does not claim*.

- **A receipt's own timestamp proves nothing.** It is written by the runner
  and covered by the runner's signature. `--timestamp` replaces it with an
  RFC 3161 authority's attestation, which is what makes the revocation check
  meaningful; without it, verification says so.
- **Revocation does not travel.** `attest keys revoke` writes to a local
  trust store. There is no distribution mechanism and no notion of freshness,
  so a third party verifying your receipt cannot learn that you revoked a
  key. This is the gap that most limits the guarantees above, and closing it
  is on the roadmap.
- **The causal root is anchored, not published.** The signature covers it and
  a timestamp token covers the signature, so an anchored history cannot be
  rewritten. There is no public log, so a withheld receipt — or two histories
  shown to two people — goes unnoticed.
- **A signing key is bound to no identity.** It proves that whoever held the
  private half signed, nothing more.

Reports that one of these is worse than described, or that a stated mitigation
does not hold, are in scope and welcome.

## Also out of scope

Vulnerabilities in third-party tools we shell out to — report those upstream
to cosign, docker or git.

Anything plugin-related. The plugin protocol is a published draft and this
release implements none of it; reports against that design belong in issues.

## One exclusion we do not make

**Write access to the workspace is not a reason to dismiss a report.** A
pipeline step has write access by definition, and so does anything that step
runs; a build machine is a place where untrusted code executes on purpose. A
step rewriting an input it has already been credited with reading, a cached
result outliving the artifact it describes, a filename chosen so that two
different trees hash alike — those are the attacks this tool exists to catch.

If a finding needs write access to the *trust store* or to private key
material, say so in the report and we will judge it on its merits rather than
on a rule.

## Our own supply chain

Releases are built in CI, signed, and published with checksums, an SBOM, and
SLSA provenance. Every release is itself attested by `attest`, and the receipt
is published alongside the binaries. If you cannot verify a release you
downloaded, treat that as a security report and tell us.
