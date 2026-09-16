//! RFC 3161 trusted timestamps.
//!
//! A receipt's own `timestamp` field is written by the runner and covered by
//! the runner's signature, so it proves nothing to anyone who does not
//! already trust the runner. Worse, the trust store's revocation rule
//! compares against it: whoever steals a signing key can backdate a receipt
//! and slip past a revocation that exists precisely to stop them.
//!
//! A timestamp token fixes that. The token is issued by a third party over
//! the *signature* — not over the receipt body — so it attests that the
//! signature existed at a time the signer did not choose. Forging one means
//! holding the timestamp authority's private key.
//!
//! Only the request and response handling live here. Verification is a
//! separate concern and deliberately does not build an X.509 path: the
//! authority's certificate is pinned in the trust store, the same way signer
//! keys are.

use std::time::Duration;

use chrono::{DateTime, Utc};

use thiserror::Error;

/// DER of the `AlgorithmIdentifier` for SHA-256 with an explicit NULL
/// parameter. RFC 4055 permits omitting the parameter, but timestamp
/// authorities in practice expect it present, and openssl emits it.
const SHA256_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0d, // SEQUENCE, 13 bytes
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, // OID 2.16.840.1.101.3.4.2.1
    0x05, 0x00, // NULL
];

/// `id-signedData`, the only content type a timestamp token may carry.
const OID_SIGNED_DATA: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

/// `id-ct-TSTInfo`, the only payload a timestamp token may encapsulate.
const OID_TST_INFO: [u8; 11] = [
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
];

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_GENERALIZED_TIME: u8 = 0x18;
/// Context-specific constructed [0], used for `content` in a ContentInfo and
/// for `certificates` in a SignedData.
const TAG_CONTEXT_0: u8 = 0xa0;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_UTC_TIME: u8 = 0x17;

/// `id-messageDigest`, the signed attribute binding the attributes to the
/// TSTInfo they describe.
const OID_MESSAGE_DIGEST: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

/// Default timestamp authority. Overridable, and deliberately so: a single
/// hard-coded authority would be a single point of failure for a property
/// the whole product rests on.
pub const DEFAULT_TSA_URL: &str = "http://timestamp.digicert.com";

/// Refuse anything larger than this from a timestamp authority. Tokens are a
/// few kilobytes; a multi-megabyte response is a misbehaving or hostile
/// server, not a timestamp.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Error)]
pub enum TimestampError {
    #[error("timestamp authority rejected the request: status {status}{}", .detail.as_deref().map(|d| format!(" ({d})")).unwrap_or_default())]
    Rejected { status: u64, detail: Option<String> },

    #[error("timestamp authority returned no token")]
    NoToken,

    #[error("malformed response from the timestamp authority: {0}")]
    Malformed(&'static str),

    #[error("response exceeds {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,

    #[error("timestamp token does not cover this signature")]
    ImprintMismatch,

    #[error("unsupported timestamp token: {0}")]
    Unsupported(&'static str),

    #[error("timestamp token signature is not valid")]
    BadSignature,

    #[error("no certificate in the token is issued by a pinned authority")]
    UntrustedAuthority,

    #[error("the signing certificate was not valid at the stated time {0}")]
    CertificateNotValidThen(String),

    #[error("cannot reach the timestamp authority at {url}: {source}")]
    Transport {
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

/// Build the DER of a `TimeStampReq` over `digest`.
///
/// `certReq` is set so the authority embeds its certificate chain in the
/// token: verification has to work offline later, which it cannot do if the
/// certificate has to be fetched.
///
/// No nonce. A nonce protects against replay of a *response* within one
/// exchange, which matters for an interactive protocol. Here the token is
/// stored and re-verified for years, so the message imprint is the binding
/// that counts, and omitting the nonce keeps the request deterministic.
pub fn build_request(digest: &[u8; 32]) -> Vec<u8> {
    let mut imprint = Vec::with_capacity(51);
    imprint.extend_from_slice(&SHA256_ALGORITHM_ID);
    imprint.push(TAG_OCTET_STRING);
    imprint.push(digest.len() as u8);
    imprint.extend_from_slice(digest);

    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(&[TAG_INTEGER, 0x01, 0x01]); // version v1
    body.push(TAG_SEQUENCE);
    body.push(imprint.len() as u8);
    body.extend_from_slice(&imprint);
    body.extend_from_slice(&[TAG_BOOLEAN, 0x01, 0xff]); // certReq TRUE

    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(TAG_SEQUENCE);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

/// Extract the `TimeStampToken` from a `TimeStampResp`.
///
/// Returns the token's own DER, ready to store: a CMS `ContentInfo` that is
/// self-contained and verifiable without the surrounding response.
pub fn token_from_response(der: &[u8]) -> Result<Vec<u8>, TimestampError> {
    let mut response = Der::new(der).sequence()?;

    // PKIStatusInfo ::= SEQUENCE { status INTEGER, statusString OPTIONAL, ... }
    let mut status_info = response.sequence()?;
    let status = status_info.integer()?;

    // 0 granted, 1 grantedWithMods. Anything else is a refusal, and the
    // optional statusString is the only explanation we will ever get.
    if status > 1 {
        return Err(TimestampError::Rejected {
            status,
            detail: status_info.utf8_text(),
        });
    }

    let token = response.rest();
    if token.is_empty() {
        return Err(TimestampError::NoToken);
    }

    // Confirm it really is a signedData ContentInfo before storing it, so a
    // malformed token is caught at issue time rather than years later.
    let mut content_info = Der::new(token).sequence()?;
    let oid = content_info.oid()?;
    if oid != OID_SIGNED_DATA {
        return Err(TimestampError::Malformed("token is not a signedData"));
    }

    Ok(token.to_vec())
}

/// Ask `url` to timestamp `digest` and return the token's DER.
pub fn request_token(
    url: &str,
    digest: &[u8; 32],
    timeout: Duration,
) -> Result<Vec<u8>, TimestampError> {
    let transport = |source| TimestampError::Transport {
        url: url.to_string(),
        source,
    };

    let response = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(transport)?
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .body(build_request(digest).to_vec())
        .send()
        .map_err(transport)?
        .error_for_status()
        .map_err(transport)?;

    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES)
    {
        return Err(TimestampError::TooLarge);
    }
    let body = response.bytes().map_err(transport)?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(TimestampError::TooLarge);
    }

    token_from_response(&body)
}

/// What a token asserts, once parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampInfo {
    /// The instant the authority states it received the imprint.
    pub gen_time: DateTime<Utc>,
    /// The authority's policy OID, dotted. Identifies the practices the
    /// authority claims to follow; worth surfacing because two tokens from
    /// the same authority under different policies do not mean the same
    /// thing.
    pub policy: String,
    /// Token serial, hex. The only handle for asking an authority about a
    /// specific token.
    pub serial: String,
}

/// Parse a token and check that it covers `expected_imprint`.
///
/// This establishes *what* the token says and *that it is about our
/// signature*. It does not establish that the authority really said it —
/// that needs the signature check, which is a separate step on purpose:
/// a caller must not be able to get the time without also getting the
/// proof.
pub fn parse_token(
    token_der: &[u8],
    expected_imprint: &[u8; 32],
) -> Result<TimestampInfo, TimestampError> {
    let tst_info = encapsulated_tst_info(token_der)?;
    let mut info = Der::new(tst_info).sequence()?;

    let _version = info.integer()?;
    let policy = oid_to_dotted(info.oid()?)?;

    // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
    let mut imprint = info.sequence()?;
    let algorithm = imprint.sequence()?;
    if algorithm.rest() != &SHA256_ALGORITHM_ID[2..] {
        return Err(TimestampError::Unsupported(
            "timestamp uses a digest algorithm other than SHA-256",
        ));
    }
    let hashed = imprint.octet_string()?;
    // Constant-time is not needed: the imprint is public, and an attacker
    // learns nothing from timing a comparison of values they already hold.
    if hashed != expected_imprint {
        return Err(TimestampError::ImprintMismatch);
    }

    let serial = hex::encode(info.integer_bytes()?);
    let gen_time = parse_generalized_time(info.take(TAG_GENERALIZED_TIME)?)?;

    Ok(TimestampInfo {
        gen_time,
        policy,
        serial,
    })
}

/// Walk ContentInfo -> SignedData -> encapContentInfo and return the DER of
/// the encapsulated `TSTInfo`.
fn encapsulated_tst_info(token_der: &[u8]) -> Result<&[u8], TimestampError> {
    let mut content_info = Der::new(token_der).sequence()?;
    if content_info.oid()? != OID_SIGNED_DATA {
        return Err(TimestampError::Malformed("token is not a signedData"));
    }

    let mut explicit = Der::new(content_info.take(TAG_CONTEXT_0)?);
    let mut signed_data = explicit.sequence()?;

    let version = signed_data.integer()?;
    if version == 0 {
        return Err(TimestampError::Unsupported("SignedData version 0"));
    }
    let _digest_algorithms = signed_data.set()?;

    // EncapsulatedContentInfo ::= SEQUENCE { eContentType, [0] eContent }
    let mut encap = signed_data.sequence()?;
    if encap.oid()? != OID_TST_INFO {
        return Err(TimestampError::Malformed(
            "token does not encapsulate a TSTInfo",
        ));
    }
    let mut explicit_content = Der::new(encap.take(TAG_CONTEXT_0)?);
    explicit_content.octet_string()
}

/// RFC 3161 requires `GeneralizedTime` in UTC with no fractional seconds
/// offered by any authority we accept: `YYYYMMDDHHMMSSZ`. Fractional forms
/// exist in the wild, so a trailing `.sss` is tolerated and truncated —
/// sub-second precision changes nothing we assert.
fn parse_generalized_time(raw: &[u8]) -> Result<DateTime<Utc>, TimestampError> {
    let text =
        std::str::from_utf8(raw).map_err(|_| TimestampError::Malformed("genTime is not ASCII"))?;
    let stripped = text
        .strip_suffix('Z')
        .ok_or(TimestampError::Unsupported("genTime is not UTC"))?;
    let seconds = stripped.split('.').next().unwrap_or(stripped);
    chrono::NaiveDateTime::parse_from_str(seconds, "%Y%m%d%H%M%S")
        .map(|naive| naive.and_utc())
        .map_err(|_| TimestampError::Malformed("genTime is not a valid instant"))
}

/// `UTCTime` carries a two-digit year. RFC 5280 fixes the pivot at 50:
/// 50-99 are 1950-1999, 00-49 are 2000-2049. Certificates outliving that
/// window must use `GeneralizedTime`, which this reader also accepts.
fn parse_utc_time(raw: &[u8]) -> Result<DateTime<Utc>, TimestampError> {
    let text =
        std::str::from_utf8(raw).map_err(|_| TimestampError::Malformed("UTCTime is not ASCII"))?;
    let stripped = text
        .strip_suffix('Z')
        .ok_or(TimestampError::Unsupported("UTCTime is not UTC"))?;
    if stripped.len() != 12 {
        return Err(TimestampError::Unsupported("unsupported UTCTime form"));
    }
    let two_digit: i32 = stripped[..2]
        .parse()
        .map_err(|_| TimestampError::Malformed("UTCTime year is not a number"))?;
    let century = if two_digit >= 50 { 1900 } else { 2000 };
    let full = format!("{}{}", century + two_digit, &stripped[2..]);
    chrono::NaiveDateTime::parse_from_str(&full, "%Y%m%d%H%M%S")
        .map(|naive| naive.and_utc())
        .map_err(|_| TimestampError::Malformed("UTCTime is not a valid instant"))
}

/// Render an OID's DER contents as dotted decimal.
fn oid_to_dotted(raw: &[u8]) -> Result<String, TimestampError> {
    let (&first, rest) = raw
        .split_first()
        .ok_or(TimestampError::Malformed("empty OID"))?;
    let mut parts = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut value: u64 = 0;
    for &byte in rest {
        value = value
            .checked_shl(7)
            .ok_or(TimestampError::Malformed("OID arc overflows"))?
            | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            parts.push(value.to_string());
            value = 0;
        }
    }
    if value != 0 {
        return Err(TimestampError::Malformed("truncated OID arc"));
    }
    Ok(parts.join("."))
}

/// A reader for exactly the DER this module needs: definite-length, no BER,
/// no indefinite forms, no recursion beyond what the grammar above requires.
struct Der<'a> {
    bytes: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn rest(&self) -> &'a [u8] {
        self.bytes
    }

    /// Read one TLV, returning its contents and advancing past it.
    fn take(&mut self, expected_tag: u8) -> Result<&'a [u8], TimestampError> {
        let (tag, rest) = self
            .bytes
            .split_first()
            .ok_or(TimestampError::Malformed("truncated"))?;
        if *tag != expected_tag {
            return Err(TimestampError::Malformed("unexpected tag"));
        }

        let (&first, rest) = rest
            .split_first()
            .ok_or(TimestampError::Malformed("truncated length"))?;
        let (len, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            // Long form. Four bytes covers any token we accept, and refusing
            // more keeps the length itself from being an attack surface.
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return Err(TimestampError::Malformed("unsupported length form"));
            }
            if rest.len() < count {
                return Err(TimestampError::Malformed("truncated length"));
            }
            let (raw, rest) = rest.split_at(count);
            let len = raw.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (len, rest)
        };

        if rest.len() < len {
            return Err(TimestampError::Malformed("truncated contents"));
        }
        let (contents, remainder) = rest.split_at(len);
        self.bytes = remainder;
        Ok(contents)
    }

    fn sequence(&mut self) -> Result<Der<'a>, TimestampError> {
        Ok(Der::new(self.take(TAG_SEQUENCE)?))
    }

    fn oid(&mut self) -> Result<&'a [u8], TimestampError> {
        self.take(TAG_OID)
    }

    fn set(&mut self) -> Result<Der<'a>, TimestampError> {
        Ok(Der::new(self.take(TAG_SET)?))
    }

    fn octet_string(&mut self) -> Result<&'a [u8], TimestampError> {
        self.take(TAG_OCTET_STRING)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    /// Consume the next TLV whatever its tag. Used to step over fields this
    /// verifier deliberately does not interpret.
    fn skip_any(&mut self) -> Result<(), TimestampError> {
        let tag = self.peek().ok_or(TimestampError::Malformed("truncated"))?;
        self.take(tag)?;
        Ok(())
    }

    /// Read one TLV and return it whole, header included.
    ///
    /// Needed wherever the encoded bytes *are* the object: a
    /// `tbsCertificate` is what an issuer signed, and two `Name`s are
    /// compared as DER rather than by decoding them, because decoding
    /// introduces choices about normalisation that a comparison should not
    /// have to make.
    fn element(&mut self, expected_tag: u8) -> Result<&'a [u8], TimestampError> {
        let start = self.bytes;
        self.take(expected_tag)?;
        let consumed = start.len() - self.bytes.len();
        Ok(&start[..consumed])
    }

    fn bit_string(&mut self) -> Result<&'a [u8], TimestampError> {
        let raw = self.take(TAG_BIT_STRING)?;
        let (&unused, rest) = raw
            .split_first()
            .ok_or(TimestampError::Malformed("empty bit string"))?;
        if unused != 0 {
            return Err(TimestampError::Unsupported(
                "bit string is not byte-aligned",
            ));
        }
        Ok(rest)
    }

    /// `Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }`.
    fn time(&mut self) -> Result<DateTime<Utc>, TimestampError> {
        match self.peek() {
            Some(TAG_UTC_TIME) => parse_utc_time(self.take(TAG_UTC_TIME)?),
            Some(TAG_GENERALIZED_TIME) => parse_generalized_time(self.take(TAG_GENERALIZED_TIME)?),
            _ => Err(TimestampError::Malformed("expected a time")),
        }
    }

    /// Raw contents of an INTEGER. Token serials routinely exceed 64 bits,
    /// so they are never narrowed to a number.
    fn integer_bytes(&mut self) -> Result<&'a [u8], TimestampError> {
        let raw = self.take(TAG_INTEGER)?;
        if raw.is_empty() {
            return Err(TimestampError::Malformed("empty integer"));
        }
        // Strip the leading zero DER adds to keep a value positive.
        Ok(raw.strip_prefix(&[0x00]).unwrap_or(raw))
    }

    fn integer(&mut self) -> Result<u64, TimestampError> {
        let raw = self.take(TAG_INTEGER)?;
        if raw.is_empty() || raw.len() > 8 {
            return Err(TimestampError::Malformed("integer out of range"));
        }
        if raw[0] & 0x80 != 0 {
            return Err(TimestampError::Malformed("negative integer"));
        }
        Ok(raw.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
    }

    /// Best-effort read of a `PKIFreeText`, used only to quote an authority's
    /// refusal back to the user. A missing or unreadable string is not an
    /// error: the status code already carries the verdict.
    fn utf8_text(&mut self) -> Option<String> {
        let sequence = self.take(TAG_SEQUENCE).ok()?;
        let mut inner = Der::new(sequence);
        // UTF8String is tag 0x0c.
        let raw = inner.take(0x0c).ok()?;
        String::from_utf8(raw.to_vec()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: [u8; 32] = [0xab; 32];

    #[test]
    fn request_matches_the_reference_encoding() {
        let req = build_request(&DIGEST);

        // 59 bytes is what `openssl ts -query -sha256 -cert -no_nonce`
        // produces for a 32-byte imprint; a difference here means the
        // structure drifted.
        assert_eq!(req.len(), 59);
        assert_eq!(req[0], TAG_SEQUENCE);
        assert_eq!(req[1] as usize, req.len() - 2);
        assert_eq!(&req[2..5], &[TAG_INTEGER, 0x01, 0x01]);
        assert!(req.windows(15).any(|w| w == SHA256_ALGORITHM_ID));
        assert!(req.windows(32).any(|w| w == DIGEST));
        assert_eq!(&req[req.len() - 3..], &[TAG_BOOLEAN, 0x01, 0xff]);
    }

    /// Build a minimal well-formed TimeStampResp around `token`.
    fn response(status: u8, token: &[u8]) -> Vec<u8> {
        let status_info = vec![TAG_SEQUENCE, 0x03, TAG_INTEGER, 0x01, status];
        let mut body = status_info;
        body.extend_from_slice(token);
        let mut out = vec![TAG_SEQUENCE, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    fn signed_data_content_info() -> Vec<u8> {
        let mut inner = vec![TAG_OID, OID_SIGNED_DATA.len() as u8];
        inner.extend_from_slice(&OID_SIGNED_DATA);
        let mut out = vec![TAG_SEQUENCE, inner.len() as u8];
        out.extend_from_slice(&inner);
        out
    }

    #[test]
    fn granted_response_yields_the_token() {
        let token = signed_data_content_info();
        let extracted = token_from_response(&response(0, &token)).expect("granted");
        assert_eq!(extracted, token);
    }

    #[test]
    fn granted_with_mods_is_accepted() {
        let token = signed_data_content_info();
        token_from_response(&response(1, &token)).expect("grantedWithMods");
    }

    #[test]
    fn a_refusal_is_reported_with_its_status() {
        let err = token_from_response(&response(2, &[])).expect_err("rejection");
        assert!(matches!(err, TimestampError::Rejected { status: 2, .. }));
    }

    #[test]
    fn a_granted_response_without_a_token_is_an_error() {
        let err = token_from_response(&response(0, &[])).expect_err("no token");
        assert!(matches!(err, TimestampError::NoToken));
    }

    #[test]
    fn a_token_that_is_not_signed_data_is_refused() {
        // A ContentInfo carrying id-data rather than id-signedData.
        let mut inner = vec![
            TAG_OID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
        ];
        let mut token = vec![TAG_SEQUENCE, inner.len() as u8];
        token.append(&mut inner);
        let err = token_from_response(&response(0, &token)).expect_err("wrong content type");
        assert!(matches!(err, TimestampError::Malformed(_)));
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let full = response(0, &signed_data_content_info());
        for cut in 0..full.len() {
            let _ = token_from_response(&full[..cut]);
        }
    }

    #[test]
    fn an_absurd_length_is_refused_rather_than_allocated() {
        // SEQUENCE with a five-byte long-form length.
        let der = [TAG_SEQUENCE, 0x85, 0xff, 0xff, 0xff, 0xff, 0xff];
        let err = token_from_response(&der).expect_err("length refused");
        assert!(matches!(err, TimestampError::Malformed(_)));
    }
}

/// The digest a receipt's timestamp token is requested over.
///
/// The token covers the **signature**, not the receipt body. Signing binds
/// the body; timestamping binds the signature; together they place a
/// specific signature by a specific key at a time the signer did not
/// choose. Timestamping the body instead would prove the content existed,
/// which is true but useless — it says nothing about when it was signed,
/// and that is the question revocation turns on.
pub fn signature_imprint(signature_hex: &str) -> Result<[u8; 32], TimestampError> {
    let raw = hex::decode(signature_hex)
        .map_err(|_| TimestampError::Malformed("receipt signature is not hex"))?;
    Ok(ring::digest::digest(&ring::digest::SHA256, &raw)
        .as_ref()
        .try_into()
        .expect("SHA-256 produces 32 bytes"))
}

/// A token whose authority has been proven, not merely read.
#[derive(Debug, Clone)]
pub struct VerifiedTimestamp {
    pub info: TimestampInfo,
    /// Subject of the certificate that signed the token, as a readable
    /// string. For display only; trust comes from the pinned issuer.
    pub signer: String,
}

/// Verify a timestamp token end to end.
///
/// In order: the token covers `expected_imprint`; the signed attributes
/// really describe the TSTInfo we read; the authority's signature over
/// those attributes is valid; the signing certificate was issued by one of
/// `pinned_issuers`; and that certificate was valid at the time the token
/// states.
///
/// What this deliberately does **not** do is build an X.509 path. There is
/// no discovery, no intermediate fetching, no name constraints, no CRL or
/// OCSP. The issuer is pinned in the trust store, exactly as signer keys
/// are, and exactly one signature is checked between it and the leaf.
/// General path validation is a large and subtle thing to get right, and
/// getting it wrong inside a verifier is worse than not offering it.
///
/// The practical consequence: timestamping authorities rotate their
/// responder certificates, often yearly. Pinning the issuing CA rather than
/// the responder is what keeps a receipt verifiable after that rotation.
pub fn verify_token(
    token_der: &[u8],
    expected_imprint: &[u8; 32],
    pinned_issuers: &[Vec<u8>],
) -> Result<VerifiedTimestamp, TimestampError> {
    let info = parse_token(token_der, expected_imprint)?;
    let signed_data = SignedDataParts::parse(token_der)?;

    // The attributes must be about the TSTInfo we just read, or the
    // signature would be proving something else.
    let expected_digest = ring::digest::digest(&ring::digest::SHA256, signed_data.econtent);
    if signed_data.message_digest_attr != expected_digest.as_ref() {
        return Err(TimestampError::Malformed(
            "signed attributes do not describe this TSTInfo",
        ));
    }

    // RFC 5652: the signature covers the attributes re-encoded as a SET OF,
    // not as the implicit [0] they appear as on the wire.
    let signed_bytes = retag_as_set(signed_data.signed_attrs);

    // The signer is whichever embedded certificate verifies the signature.
    // Trying them is simpler than matching issuer-and-serial, and no less
    // safe: a wrong certificate simply fails.
    let signer = signed_data
        .certificates
        .iter()
        .map(|der| Certificate::parse(der))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|cert| rsa_pkcs1_sha256_verify(cert.public_key, &signed_bytes, signed_data.signature))
        .ok_or(TimestampError::BadSignature)?;

    // …and that certificate must come from an authority we pinned.
    let issued_by_pinned = pinned_issuers.iter().any(|issuer_der| {
        Certificate::parse(issuer_der).is_ok_and(|issuer| {
            issuer.subject == signer.issuer
                && rsa_pkcs1_sha256_verify(issuer.public_key, signer.tbs, signer.signature)
        })
    });
    if !issued_by_pinned {
        return Err(TimestampError::UntrustedAuthority);
    }

    if info.gen_time < signer.not_before || info.gen_time > signer.not_after {
        return Err(TimestampError::CertificateNotValidThen(
            info.gen_time.to_rfc3339(),
        ));
    }

    Ok(VerifiedTimestamp {
        signer: common_name(signer.subject),
        info,
    })
}

fn rsa_pkcs1_sha256_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        public_key,
    )
    .verify(message, signature)
    .is_ok()
}

/// Re-encode an implicitly tagged `[0]` attribute block as the `SET OF` the
/// signature was computed over.
fn retag_as_set(contents: &[u8]) -> Vec<u8> {
    let mut out = vec![TAG_SET];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let significant = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let trimmed = &bytes[significant..];
        out.push(0x80 | trimmed.len() as u8);
        out.extend_from_slice(trimmed);
    }
    out.extend_from_slice(contents);
    out
}

/// The parts of a `SignedData` the verifier needs, gathered in one pass.
struct SignedDataParts<'a> {
    econtent: &'a [u8],
    certificates: Vec<&'a [u8]>,
    signed_attrs: &'a [u8],
    message_digest_attr: &'a [u8],
    signature: &'a [u8],
}

impl<'a> SignedDataParts<'a> {
    fn parse(token_der: &'a [u8]) -> Result<Self, TimestampError> {
        let mut content_info = Der::new(token_der).sequence()?;
        if content_info.oid()? != OID_SIGNED_DATA {
            return Err(TimestampError::Malformed("token is not a signedData"));
        }
        let mut signed_data = Der::new(content_info.take(TAG_CONTEXT_0)?).sequence()?;

        let _version = signed_data.integer()?;
        let _digest_algorithms = signed_data.set()?;

        let mut encap = signed_data.sequence()?;
        if encap.oid()? != OID_TST_INFO {
            return Err(TimestampError::Malformed("not a TSTInfo"));
        }
        let econtent = Der::new(encap.take(TAG_CONTEXT_0)?).octet_string()?;

        // certificates [0] IMPLICIT, optional in CMS but always present here
        // because the request sets certReq: offline verification needs them.
        let mut certificates = Vec::new();
        let mut certs_reader = Der::new(signed_data.take(TAG_CONTEXT_0)?);
        while let Ok(element) = certs_reader.element(TAG_SEQUENCE) {
            certificates.push(element);
        }
        if certificates.is_empty() {
            return Err(TimestampError::Unsupported(
                "token carries no certificate; it cannot be verified offline",
            ));
        }

        let mut signer_infos = signed_data.set()?;
        let mut signer = signer_infos.sequence()?;
        let _version = signer.integer()?;
        signer.skip_any()?; // sid: issuerAndSerialNumber or [0] keyIdentifier
        let _digest_algorithm = signer.sequence()?;

        let signed_attrs = signer.take(TAG_CONTEXT_0)?;
        let message_digest_attr = message_digest_attribute(signed_attrs)?;

        let _signature_algorithm = signer.sequence()?;
        let signature = signer.octet_string()?;

        Ok(Self {
            econtent,
            certificates,
            signed_attrs,
            message_digest_attr,
            signature,
        })
    }
}

/// Pull the `message-digest` value out of a signed-attribute block.
fn message_digest_attribute(signed_attrs: &[u8]) -> Result<&[u8], TimestampError> {
    let mut attrs = Der::new(signed_attrs);
    while let Ok(mut attr) = attrs.sequence() {
        let oid = attr.oid()?;
        let mut values = attr.set()?;
        if oid == OID_MESSAGE_DIGEST {
            return values.octet_string();
        }
    }
    Err(TimestampError::Malformed("no message-digest attribute"))
}

/// The fields of an X.509 certificate this verifier reads. Everything else
/// — extensions, key usage, policies — is deliberately not interpreted.
struct Certificate<'a> {
    /// DER of `tbsCertificate`, the bytes the issuer signed.
    tbs: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    /// Contents of the `subjectPublicKey` BIT STRING: for RSA, the PKCS#1
    /// `RSAPublicKey` that `ring` expects.
    public_key: &'a [u8],
    signature: &'a [u8],
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl<'a> Certificate<'a> {
    fn parse(der: &'a [u8]) -> Result<Self, TimestampError> {
        let mut certificate = Der::new(der).sequence()?;
        let tbs = certificate.element(TAG_SEQUENCE)?;
        let _signature_algorithm = certificate.sequence()?;
        let signature = certificate.bit_string()?;

        let mut fields = Der::new(tbs).sequence()?;
        if fields.peek() == Some(TAG_CONTEXT_0) {
            fields.take(TAG_CONTEXT_0)?; // version, absent in v1
        }
        fields.skip_any()?; // serialNumber
        fields.skip_any()?; // signature algorithm
        let issuer = fields.element(TAG_SEQUENCE)?;

        let mut validity = fields.sequence()?;
        let not_before = validity.time()?;
        let not_after = validity.time()?;

        let subject = fields.element(TAG_SEQUENCE)?;

        let mut spki = fields.sequence()?;
        let _algorithm = spki.sequence()?;
        let public_key = spki.bit_string()?;

        Ok(Self {
            tbs,
            issuer,
            subject,
            public_key,
            signature,
            not_before,
            not_after,
        })
    }
}

/// Parse a certificate far enough to confirm it is one, and name it.
///
/// Used when pinning an authority: a file that does not parse here would
/// silently never match anything at verification time, which is the worst
/// way to find out.
pub fn certificate_subject(der: &[u8]) -> Result<String, TimestampError> {
    let certificate = Certificate::parse(der)?;
    Ok(common_name(certificate.subject))
}

/// Pull the common name out of a DER-encoded X.509 `Name`, for messages.
///
/// A `Name` is a sequence of relative distinguished names, each a set of
/// type/value pairs. Only the common name is extracted: it is the part a
/// person recognises, and the rest would turn a one-line verdict into a
/// distinguished-name dump. Falls back to a fixed label rather than
/// guessing, because this string is shown to a human and never parsed.
fn common_name(der: &[u8]) -> String {
    const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];

    let Ok(mut name) = Der::new(der).sequence() else {
        return "unnamed authority".to_string();
    };
    while let Ok(mut rdn) = name.set() {
        while let Ok(mut pair) = rdn.sequence() {
            let Ok(oid) = pair.oid() else { break };
            // The value is a string of one of several ASN.1 flavours;
            // whichever it is, its contents are the text.
            let Some(tag) = pair.peek() else { break };
            let Ok(value) = pair.take(tag) else { break };
            if oid == OID_COMMON_NAME {
                if let Ok(text) = std::str::from_utf8(value) {
                    return text.to_string();
                }
            }
        }
    }
    "unnamed authority".to_string()
}
