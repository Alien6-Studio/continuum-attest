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
- Breaking the append-only property of the causal ledger, or producing a valid
  inclusion proof for an event that is not in it.
- Escaping the step sandbox or the capsule boundary in a way that affects the
  recorded result.
- Leaking private key material into a receipt, a log, or an archive.

## Out of scope

These are known and documented properties, not vulnerabilities. They are listed
in the README under *What it does not claim*:

- **Receipt timestamps come from the runner's clock.** There is no RFC 3161
  timestamp. A wrong or hostile clock producing a misleading timestamp is a
  known limitation.
- **The causal root is not published anywhere.** There is no transparency log
  and no external anchor, so append-only holds only against an attacker who
  does not control the machine holding the ledger.
- **A signing key is not bound to a legal identity.** A key in the trust store
  proves only that whoever held the private key signed.

Nothing plugin-related is in scope yet. The plugin protocol is a published
draft and this release implements none of it: there is no `.attest/plugins.toml`
and `attest` spawns no plugin. Reports against that design are welcome as
issues, not as vulnerabilities.

Also out of scope: vulnerabilities in third-party tools we shell out to (report
those upstream — cosign, docker, git), and findings that require an attacker who
already has write access to your workspace or your trust store.

## Our own supply chain

Releases are built in CI, signed, and published with checksums, an SBOM, and
SLSA provenance. Every release is itself attested by `attest`, and the receipt
is published alongside the binaries. If you cannot verify a release you
downloaded, treat that as a security report and tell us.
