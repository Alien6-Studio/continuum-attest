# Timestamp authority certificates

`sectigo-tsa-ca.der` is the issuing CA certificate for the default HTTPS
RFC 3161 endpoint, `https://timestamp.sectigo.com/rfc3161`. The same certificate
is committed as PEM in `.attest/trust/tsa/sectigo.crt`.

- Subject: `C=GB, O=Sectigo Limited, CN=Sectigo Public Time Stamping CA R41`
- Issuer: `C=GB, O=Sectigo Limited, CN=Sectigo Public Time Stamping Root R46`
- Validity: 2026-03-25 through 2041-03-24.
- SHA-256 of the DER certificate:
  `38b52fe70bdde4ecf34d77498d7cbfe48efd83294dca04de01868f7735d2db79`
- Independent HTTPS download: <https://crt.sh/?d=25231772085>.
  Sectigo links this certificate service from its
  [official support page](https://www.sectigo.com/support).

On 2026-10-29, an HTTPS request to the endpoint returned a granted RFC 3161
response for a public test imprint. Its signer was `Sectigo Public Time
Stamping Signer R37`, issued by the CA above. The downloaded certificate was
byte-for-byte identical to that issuer. Both the token and issuing CA were
verified with OpenSSL against the macOS system root bundle `/etc/ssl/cert.pem`,
using the embedded R46 cross-certificate only as an untrusted intermediate.
The embedded certificates were not used as trust anchors.

`sectigo-token.der` contains that public test token, issued at
2026-10-29T13:55:14Z. `sectigo-fixture-imprint.txt` records its SHA-256 imprint,
computed over the UTF-8 bytes `Continuum Attest public RFC3161 HTTPS transport
probe\n` (one line, including the final newline). Its CMS content digest and
RSA signature use SHA-384, as does the signature on the responder certificate;
the timestamped message imprint uses SHA-256. This fixture exercises the
provider's real encoding without making a network request during unit tests.

[Sectigo documents RFC 3161 support and its request pacing](https://www.sectigo.com/knowledge-base/detail/Time-Stamp-Server-Stamping-Protocols-for-Digital-Signatures-Code-Signing).
That page advertises HTTP; HTTPS availability was checked directly with TLS
certificate verification enabled and without following redirects. Space live
timestamp requests at least 15 seconds apart, as the provider requests.

The legacy `digicert-token.der`, `digicert-tsa-ca.der`, and `fixture-imprint.txt`
remain for offline verification regression tests. The DigiCert issuing CA has
DER SHA-256
`ca0b1554ecd901ea19dcad8749e9f2648c8d6dfcea1add9d2c2109415bb82ccd`.
Its existing `.attest/trust/tsa/digicert.crt` pin is retained so previously
issued timestamps continue to verify. New timestamp requests require HTTPS;
verification of existing tokens is entirely offline and does not depend on
the transport originally used to obtain them.
