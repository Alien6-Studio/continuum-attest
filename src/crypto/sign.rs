use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct AttestKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl AttestKeypair {
    pub fn generate() -> Self {
        let mut csprng = OsRng {};
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn load_or_generate(keys_dir: &Path) -> Result<Self> {
        let private_key_path = keys_dir.join("private.key");
        let public_key_path = keys_dir.join("public.key");

        for path in [&private_key_path, &public_key_path] {
            if path
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                anyhow::bail!("refusing symbolic link for key material");
            }
        }
        if private_key_path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))?;
            }
            let private_bytes =
                fs::read(&private_key_path).context("Failed to read private key")?;
            let key_array: [u8; 32] = private_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;
            let keypair = Self::from_signing_key(SigningKey::from_bytes(&key_array));
            if public_key_path.exists() {
                if fs::read(&public_key_path)? != keypair.verifying_key.to_bytes() {
                    anyhow::bail!("public key does not match the stored private key");
                }
            } else {
                fs::write(&public_key_path, keypair.verifying_key.to_bytes())?;
            }
            return Ok(keypair);
        }
        if public_key_path.exists() {
            anyhow::bail!(
                "private key is missing; refusing to replace the existing signing identity"
            );
        }
        fs::create_dir_all(keys_dir)?;
        let keypair = Self::generate();
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut private = options.open(&private_key_path)?;
        private.write_all(&keypair.signing_key.to_bytes())?;
        private.sync_all()?;
        fs::write(&public_key_path, keypair.verifying_key.to_bytes())?;
        eprintln!("Generated new Ed25519 keypair in {}", keys_dir.display());
        Ok(keypair)
    }

    pub fn sign(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        hex::encode(signature.to_bytes())
    }

    pub fn verify(&self, message: &[u8], signature_hex: &str) -> Result<bool> {
        let signature_bytes = hex::decode(signature_hex).context("Invalid signature hex")?;
        let sig_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
        let signature = Signature::from_bytes(&sig_array);

        Ok(self.verifying_key.verify(message, &signature).is_ok())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }
}

/// Verify an Ed25519 signature given only the hex-encoded public key,
/// without requiring the private half.
pub fn verify_with_public_key(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<bool> {
    let public_bytes = hex::decode(public_key_hex).context("Invalid public key hex")?;
    let key_array: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

    let signature_bytes = hex::decode(signature_hex).context("Invalid signature hex")?;
    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
    let signature = Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(message, &signature).is_ok())
}
