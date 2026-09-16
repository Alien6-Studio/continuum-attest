//! Round trip against a real timestamp authority.
//!
//! Ignored by default: it needs the network, and a test suite that fails
//! because someone else's server is down teaches nothing. Run it on purpose
//! when the request encoding changes:
//!
//! ```console
//! $ cargo test --test timestamp_tsa -- --ignored --nocapture
//! ```

use std::time::Duration;

use attest::crypto::timestamp::{build_request, request_token, token_from_response};

const DIGICERT: &str = "http://timestamp.digicert.com";

#[test]
#[ignore = "requires network access to a timestamp authority"]
fn digicert_grants_a_token_for_our_hand_rolled_request() {
    // Stands in for the bytes of an Ed25519 receipt signature.
    let digest: [u8; 32] = *blake3::hash(b"attest signature bytes").as_bytes();

    let request = build_request(&digest);
    assert_eq!(request.len(), 59, "request encoding drifted");

    let token = request_token(DIGICERT, &digest, Duration::from_secs(30))
        .expect("the authority granted a token");

    // A token is a few kilobytes of CMS. Anything tiny means we parsed the
    // envelope but kept the wrong slice.
    assert!(
        token.len() > 1000,
        "token is implausibly small: {} bytes",
        token.len()
    );
    assert_eq!(token[0], 0x30, "token is not a DER SEQUENCE");

    // Re-parsing our own stored bytes must be a no-op, which is what makes
    // the token self-contained once it is in a receipt.
    let mut framed = vec![0x30, 0x00];
    let status = [0x30u8, 0x03, 0x02, 0x01, 0x00];
    let body_len = status.len() + token.len();
    framed = if body_len < 0x80 {
        let mut v = vec![0x30, body_len as u8];
        v.extend_from_slice(&status);
        v.extend_from_slice(&token);
        v
    } else {
        let mut v = vec![0x30, 0x82, (body_len >> 8) as u8, body_len as u8];
        v.extend_from_slice(&status);
        v.extend_from_slice(&token);
        framed.clear();
        v
    };
    assert_eq!(
        token_from_response(&framed).expect("re-parses"),
        token,
        "a token we stored does not round trip through our own parser"
    );

    println!("token: {} bytes from {}", token.len(), DIGICERT);
}
