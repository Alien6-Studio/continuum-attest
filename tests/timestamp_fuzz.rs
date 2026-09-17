//! Mutation fuzzing of the RFC 3161 token parser.
//!
//! The parser reads DER supplied by whoever answers a timestamp request, and
//! by whoever hands over a receipt to be verified. Neither is trusted. Two
//! properties have to hold for every byte string, well-formed or not:
//!
//!   1. it must not panic, because a panic here is a remote denial of
//!      service against `attest verify`;
//!   2. it must never report that a token covers an imprint it does not,
//!      because that is the whole claim the token makes.
//!
//! Ignored by default: this is a long-running harness, not a unit test. Run
//! it with `cargo test --test timestamp_fuzz -- --ignored --nocapture`.

use attest::crypto::timestamp::{parse_token, verify_token};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/timestamp/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn imprint() -> [u8; 32] {
    let hex = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/timestamp/fixture-imprint.txt"
    ))
    .expect("imprint fixture");
    hex::decode(hex.trim())
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

/// A deterministic generator, so a failure reported here can be reproduced
/// exactly from the seed printed alongside it.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Mutate `base` in one of the ways that actually break DER readers: flip a
/// bit, rewrite a byte, corrupt a length field, truncate, or splice.
fn mutate(base: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut out = base.to_vec();
    if out.is_empty() {
        return out;
    }
    match rng.below(6) {
        0 => {
            let i = rng.below(out.len());
            out[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(out.len());
            out[i] = rng.below(256) as u8;
        }
        2 => {
            // Lengths are where readers overflow, over-allocate, or run off
            // the end, so corrupt them deliberately rather than by chance.
            let i = rng.below(out.len());
            out[i] = [0x80, 0x81, 0x84, 0x88, 0xff, 0x7f][rng.below(6)];
        }
        3 => {
            let cut = rng.below(out.len());
            out.truncate(cut);
        }
        4 => {
            let i = rng.below(out.len());
            let j = rng.below(out.len());
            out.swap(i, j);
        }
        _ => {
            let at = rng.below(out.len());
            let run = 1 + rng.below(16);
            let byte = rng.below(256) as u8;
            for k in 0..run {
                if at + k < out.len() {
                    out[at + k] = byte;
                }
            }
        }
    }
    out
}

fn run(iterations: usize, seed: u64) {
    let token = fixture("digicert-token.der");
    let ca = fixture("digicert-tsa-ca.der");
    let pinned = vec![ca];
    let good = imprint();

    // The authentic answer, to compare every accepted mutation against.
    let authentic = verify_token(&token, &good, &pinned).expect("the fixture verifies");
    let authentic_time = authentic.info.gen_time;

    let mut rng = Rng(seed);
    let mut reached_signature = 0usize;
    let mut accepted = 0usize;

    std::panic::set_hook(Box::new(|_| {}));

    for i in 0..iterations {
        let case = mutate(&token, &mut rng);

        // The correct imprint, deliberately: with a wrong one `parse_token`
        // rejects at the imprint check and the certificate parsing, RSA
        // verification and issuer pinning below it never run at all.
        let case_for_verify = case.clone();
        let pinned_copy = pinned.clone();
        let outcome = std::panic::catch_unwind(move || {
            verify_token(&case_for_verify, &good, &pinned_copy)
                .map(|v| v.info.gen_time)
                .map_err(|e| e.to_string())
        });

        match outcome {
            Ok(Ok(time)) => {
                accepted += 1;
                if time != authentic_time {
                    let _ = std::panic::take_hook();
                    panic!(
                        "iteration {i} (seed {seed}): a mutated token verified but reported \
                         {time} instead of {authentic_time}; hex:\n{}",
                        hex::encode(&case)
                    );
                }
            }
            Ok(Err(msg)) => {
                // Anything past the imprint check means the certificate and
                // signature machinery actually ran on this input.
                if msg.contains("signature")
                    || msg.contains("authority")
                    || msg.contains("valid at")
                {
                    reached_signature += 1;
                }
            }
            Err(_) => {
                let _ = std::panic::take_hook();
                panic!(
                    "verify_token panicked at iteration {i} (seed {seed}); input hex:\n{}",
                    hex::encode(&case)
                );
            }
        }
    }

    let _ = std::panic::take_hook();
    println!(
        "{iterations} mutations, seed {seed}: {reached_signature} reached the signature path, \
         {accepted} verified (all reporting the authentic time)"
    );
    assert!(
        reached_signature > iterations / 20,
        "harness is not exercising the signature path: only {reached_signature} of {iterations}"
    );
}

#[test]
#[ignore = "fuzz harness; run explicitly"]
fn mutations_never_panic_and_never_assert_a_false_imprint() {
    for seed in [1u64, 0xdecafbad, 0x5eed, 12345] {
        run(40_000, seed);
    }
}

/// The fixture is one shape. Random input is another: it exercises the
/// earliest rejection paths, where a reader that trusts its first bytes
/// fails first.
#[test]
#[ignore = "fuzz harness; run explicitly"]
fn arbitrary_bytes_never_panic() {
    let good = imprint();
    let mut rng = Rng(0xa11ce);
    std::panic::set_hook(Box::new(|_| {}));
    for i in 0..200_000 {
        let len = rng.below(600);
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(rng.below(256) as u8);
        }
        let case = buf.clone();
        if std::panic::catch_unwind(move || parse_token(&case, &good).is_ok()).is_err() {
            let _ = std::panic::take_hook();
            panic!(
                "parse_token panicked on random input at {i}; hex:\n{}",
                hex::encode(&buf)
            );
        }
    }
    let _ = std::panic::take_hook();
    println!("200000 random inputs: no panic");
}
