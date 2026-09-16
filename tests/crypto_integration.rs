//! Integration tests for cryptographic functionality

use anyhow::Result;
use attest::crypto::sign::AttestKeypair;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_end_to_end_signing_workflow() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keys_dir = temp_dir.path().join("keys");

    // Generate initial keypair
    let keypair1 = AttestKeypair::load_or_generate(&keys_dir)?;
    let public_key1 = keypair1.public_key_hex();

    // Sign a message
    let message = b"ATTEST pipeline execution complete";
    let signature = keypair1.sign(message);

    // Verify signature works
    assert!(keypair1.verify(message, &signature)?);

    // Load same keypair from disk
    let keypair2 = AttestKeypair::load_or_generate(&keys_dir)?;
    let public_key2 = keypair2.public_key_hex();

    // Should be the same keypair
    assert_eq!(public_key1, public_key2);

    // Should be able to verify with loaded keypair
    assert!(keypair2.verify(message, &signature)?);

    // Different message should fail
    let different_message = b"Different message";
    assert!(!keypair2.verify(different_message, &signature)?);

    Ok(())
}

#[test]
fn test_key_persistence_and_security() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keys_dir = temp_dir.path().join("secure_keys");

    // Generate keypair
    let keypair = AttestKeypair::load_or_generate(&keys_dir)?;
    let original_public_key = keypair.public_key_hex();

    // Check key files exist and have correct format
    let private_key_path = keys_dir.join("private.key");
    let public_key_path = keys_dir.join("public.key");

    assert!(private_key_path.exists());
    assert!(public_key_path.exists());

    // Check key file sizes (Ed25519 keys are 32 bytes each)
    let private_key_content = fs::read(&private_key_path)?;
    let public_key_content = fs::read(&public_key_path)?;

    assert_eq!(private_key_content.len(), 32);
    assert_eq!(public_key_content.len(), 32);

    // Reload and verify consistency
    let reloaded_keypair = AttestKeypair::load_or_generate(&keys_dir)?;
    assert_eq!(reloaded_keypair.public_key_hex(), original_public_key);

    // Test signing consistency
    let test_message = b"consistency test";
    let signature1 = keypair.sign(test_message);
    let signature2 = reloaded_keypair.sign(test_message);

    // Both keypairs should verify both signatures
    assert!(keypair.verify(test_message, &signature1)?);
    assert!(keypair.verify(test_message, &signature2)?);
    assert!(reloaded_keypair.verify(test_message, &signature1)?);
    assert!(reloaded_keypair.verify(test_message, &signature2)?);

    Ok(())
}

#[test]
fn test_signature_integrity_and_tampering() -> Result<()> {
    let keypair = AttestKeypair::generate();
    let message = b"Critical security message";
    let signature = keypair.sign(message);

    // Valid signature should verify
    assert!(keypair.verify(message, &signature)?);

    // Test signature tampering resistance
    let mut tampered_signature = signature.clone();

    // Flip a bit in the signature
    let bytes = tampered_signature.as_bytes();
    if bytes[0] == b'a' {
        tampered_signature.replace_range(0..1, "b");
    } else {
        tampered_signature.replace_range(0..1, "a");
    }

    // Tampered signature should fail verification
    assert!(!keypair.verify(message, &tampered_signature)?);

    // Test message tampering
    let tampered_message = b"Critical security message!"; // Added exclamation
    assert!(!keypair.verify(tampered_message, &signature)?);

    // Test empty signature
    let empty_signature = "";
    let result = keypair.verify(message, empty_signature);
    assert!(result.is_err());

    // Test malformed signature
    let malformed_signature = "not_hex_at_all";
    let result = keypair.verify(message, malformed_signature);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_multiple_keypairs_isolation() -> Result<()> {
    let keypair1 = AttestKeypair::generate();
    let keypair2 = AttestKeypair::generate();
    let keypair3 = AttestKeypair::generate();

    let message = b"Multi-keypair test message";

    // Each keypair signs the same message
    let sig1 = keypair1.sign(message);
    let sig2 = keypair2.sign(message);
    let sig3 = keypair3.sign(message);

    // Signatures should be different
    assert_ne!(sig1, sig2);
    assert_ne!(sig2, sig3);
    assert_ne!(sig1, sig3);

    // Each keypair should only verify its own signature
    assert!(keypair1.verify(message, &sig1)?);
    assert!(!keypair1.verify(message, &sig2)?);
    assert!(!keypair1.verify(message, &sig3)?);

    assert!(!keypair2.verify(message, &sig1)?);
    assert!(keypair2.verify(message, &sig2)?);
    assert!(!keypair2.verify(message, &sig3)?);

    assert!(!keypair3.verify(message, &sig1)?);
    assert!(!keypair3.verify(message, &sig2)?);
    assert!(keypair3.verify(message, &sig3)?);

    // Public keys should be different
    let pub1 = keypair1.public_key_hex();
    let pub2 = keypair2.public_key_hex();
    let pub3 = keypair3.public_key_hex();

    assert_ne!(pub1, pub2);
    assert_ne!(pub2, pub3);
    assert_ne!(pub1, pub3);

    Ok(())
}

#[test]
fn test_large_message_signing() -> Result<()> {
    let keypair = AttestKeypair::generate();

    // Test with various message sizes
    let x_100 = "x".repeat(100);
    let y_1000 = "y".repeat(1000);
    let z_10000 = "z".repeat(10000);
    let w_100000 = "w".repeat(100000);

    let test_cases = vec![
        (0, ""),
        (1, "a"),
        (100, &x_100),
        (1000, &y_1000),
        (10000, &z_10000),
        (100000, &w_100000),
    ];

    for (size, message_str) in test_cases {
        let message = message_str.as_bytes();
        let signature = keypair.sign(message);

        // Signature length should be constant regardless of message size
        assert_eq!(signature.len(), 128, "Failed for message size {}", size);

        // Verification should work
        assert!(
            keypair.verify(message, &signature)?,
            "Failed verification for size {}",
            size
        );
    }

    Ok(())
}

#[test]
fn test_concurrent_signing_operations() -> Result<()> {
    let keypair = AttestKeypair::generate();

    // Simulate concurrent signing operations
    let signatures: Vec<String> = (0..100)
        .map(|i| {
            let msg = format!("Message #{}", i);
            keypair.sign(msg.as_bytes())
        })
        .collect();

    // All signatures should be valid for their respective messages
    for (i, signature) in signatures.iter().enumerate() {
        let msg = format!("Message #{}", i);
        assert!(
            keypair.verify(msg.as_bytes(), signature)?,
            "Failed for message {}",
            i
        );
    }

    // All signatures should be different (statistically very likely)
    for i in 0..signatures.len() {
        for j in (i + 1)..signatures.len() {
            assert_ne!(
                signatures[i], signatures[j],
                "Signatures {} and {} are identical",
                i, j
            );
        }
    }

    Ok(())
}

#[test]
fn test_key_generation_entropy() -> Result<()> {
    // Generate multiple keypairs and ensure they're all different
    let mut public_keys = Vec::new();
    let mut signatures = Vec::new();
    let test_message = b"entropy test";

    for _ in 0..50 {
        let keypair = AttestKeypair::generate();
        let public_key = keypair.public_key_hex();
        let signature = keypair.sign(test_message);

        // Each public key should be unique
        assert!(
            !public_keys.contains(&public_key),
            "Duplicate public key found"
        );
        public_keys.push(public_key);

        // Each signature should be unique (for the same message)
        assert!(
            !signatures.contains(&signature),
            "Duplicate signature found"
        );
        signatures.push(signature);
    }

    // Verify we have the expected number of unique keys and signatures
    assert_eq!(public_keys.len(), 50);
    assert_eq!(signatures.len(), 50);

    Ok(())
}

#[test]
fn test_key_file_corruption_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keys_dir = temp_dir.path().join("corrupted_keys");

    // Create corrupted key files
    fs::create_dir_all(&keys_dir)?;

    // Test with corrupted private key
    fs::write(keys_dir.join("private.key"), b"corrupted_private_key_data")?;
    fs::write(keys_dir.join("public.key"), &[0u8; 32])?; // Valid size but wrong key

    let result = AttestKeypair::load_or_generate(&keys_dir);
    assert!(result.is_err(), "Should fail with corrupted private key");

    // Clean up and test with corrupted public key
    fs::remove_file(keys_dir.join("private.key"))?;
    fs::remove_file(keys_dir.join("public.key"))?;

    fs::write(keys_dir.join("private.key"), &[1u8; 32])?; // Valid size
    fs::write(keys_dir.join("public.key"), b"corrupted_public_key_data")?;

    let result = AttestKeypair::load_or_generate(&keys_dir);
    assert!(result.is_err(), "Should fail with corrupted public key");

    // Test with completely invalid files
    fs::remove_file(keys_dir.join("private.key"))?;
    fs::remove_file(keys_dir.join("public.key"))?;

    fs::write(keys_dir.join("private.key"), b"")?; // Empty file
    fs::write(keys_dir.join("public.key"), b"")?; // Empty file

    let result = AttestKeypair::load_or_generate(&keys_dir);
    assert!(result.is_err(), "Should fail with empty key files");

    Ok(())
}

#[test]
fn test_signature_format_validation() -> Result<()> {
    let keypair = AttestKeypair::generate();
    let message = b"format validation test";
    let valid_signature = keypair.sign(message);

    // Valid signature should work
    assert!(keypair.verify(message, &valid_signature)?);

    // Test various invalid signature formats
    let invalid_z = "z".repeat(128);
    let invalid_short = "a".repeat(127);
    let invalid_long = "a".repeat(129);
    let invalid_mixed = "ABCDEF".repeat(21) + "AB";

    // Note: `AttestKeypair::verify` decodes the signature with `hex::decode`,
    // which is case-insensitive, so an all-uppercase encoding of a *valid*
    // signature (`valid_signature.to_uppercase()`) still decodes to the same
    // bytes and verifies successfully. That case is intentionally not
    // included here since it is not actually invalid.
    let invalid_signatures: Vec<&str> = vec![
        "",             // Empty
        "invalid",      // Too short
        &invalid_z,     // Invalid hex characters
        &invalid_short, // Too short by 1
        &invalid_long,  // Too long by 1
        &invalid_mixed, // Not the actual signature bytes
    ];

    for invalid_sig in invalid_signatures {
        let result = keypair.verify(message, &invalid_sig);
        assert!(
            result.is_err() || !result.unwrap(),
            "Invalid signature should not verify: '{}'",
            invalid_sig
        );
    }

    Ok(())
}
