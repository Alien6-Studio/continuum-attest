//! Image signature verification for OCI containers
//!
//! This module provides cryptographic verification of container images
//! to ensure they are signed and trusted before execution in ATTEST pipelines.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use tracing::{debug, info, warn};

/// Configuration for image verification policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageVerificationConfig {
    /// Whether to enforce signature verification for all images
    pub require_signatures: bool,
    /// List of trusted public keys (in PEM format)
    pub trusted_keys: Vec<String>,
    /// List of trusted certificate authorities
    pub trusted_cas: Vec<String>,
    /// Sigstore transparency log verification
    pub verify_transparency_log: bool,
    /// OIDC issuer patterns for keyless verification
    pub trusted_oidc_issuers: Vec<String>,
    /// Subject patterns for keyless verification
    pub trusted_subjects: Vec<String>,
    /// Policy enforcement level
    pub enforcement_level: EnforcementLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnforcementLevel {
    /// Block execution if verification fails
    Strict,
    /// Warn but allow execution if verification fails
    Warn,
    /// Log verification results but don't enforce
    Audit,
}

impl Default for ImageVerificationConfig {
    fn default() -> Self {
        Self {
            require_signatures: true,
            trusted_keys: vec![],
            trusted_cas: vec![],
            verify_transparency_log: true,
            trusted_oidc_issuers: vec![
                "https://github.com/login/oauth".to_string(),
                "https://oauth2.sigstore.dev/auth".to_string(),
            ],
            trusted_subjects: vec![],
            enforcement_level: EnforcementLevel::Strict,
        }
    }
}

/// Result of image signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the image signature is valid
    pub is_valid: bool,
    /// The verified image digest
    pub image_digest: String,
    /// Details about the signature
    pub signature_info: Option<SignatureInfo>,
    /// Any verification errors or warnings
    pub messages: Vec<String>,
    /// Verification timestamp
    pub verified_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// The public key or certificate used for signing
    pub signer: String,
    /// OIDC issuer for keyless signatures
    pub oidc_issuer: Option<String>,
    /// Subject from the signing certificate
    pub subject: Option<String>,
    /// Transparency log entry information
    pub transparency_log_entry: Option<String>,
    /// Additional signature metadata
    pub metadata: HashMap<String, String>,
}

/// Image signature verifier
#[derive(Debug)]
pub struct ImageVerifier {
    config: ImageVerificationConfig,
    cosign_path: Option<String>,
}

impl ImageVerifier {
    /// Create a new image verifier with the given configuration
    pub fn new(config: ImageVerificationConfig) -> Result<Self> {
        let cosign_path = Self::find_cosign_binary()?;

        if config.require_signatures && cosign_path.is_none() {
            anyhow::bail!(
                "Image signature verification is required but cosign binary not found. \
                 Please install cosign: https://docs.sigstore.dev/cosign/installation/"
            );
        }

        Ok(Self {
            config,
            cosign_path,
        })
    }

    /// Verify the signature of a container image
    pub async fn verify_image_signature(&self, image: &str) -> Result<VerificationResult> {
        info!("Verifying signature for image: {}", image);

        let mut result = VerificationResult {
            is_valid: false,
            image_digest: String::new(),
            signature_info: None,
            messages: vec![],
            verified_at: chrono::Utc::now(),
        };

        // Skip verification if not required
        if !self.config.require_signatures {
            result
                .messages
                .push("Signature verification disabled".to_string());
            result.is_valid = true;
            return Ok(result);
        }

        // Check if cosign is available
        let cosign_path = match &self.cosign_path {
            Some(path) => path,
            None => {
                let msg = "Cosign binary not found - cannot verify image signatures".to_string();
                result.messages.push(msg.clone());

                match self.config.enforcement_level {
                    EnforcementLevel::Strict => {
                        anyhow::bail!("{}", msg);
                    }
                    EnforcementLevel::Warn => {
                        warn!("{}", msg);
                        result.is_valid = true;
                        return Ok(result);
                    }
                    EnforcementLevel::Audit => {
                        debug!("{}", msg);
                        result.is_valid = true;
                        return Ok(result);
                    }
                }
            }
        };

        // Get image digest first
        match self.get_image_digest(image).await {
            Ok(digest) => {
                result.image_digest = digest;
            }
            Err(e) => {
                let msg = format!("Failed to get image digest: {}", e);
                result.messages.push(msg);
            }
        }

        // Attempt signature verification
        match self.verify_with_cosign(cosign_path, image).await {
            Ok(sig_info) => {
                result.is_valid = true;
                result.signature_info = Some(sig_info);
                result
                    .messages
                    .push("Image signature verified successfully".to_string());
                info!("Image signature verified: {}", image);
            }
            Err(e) => {
                let msg = format!("Signature verification failed: {}", e);
                result.messages.push(msg.clone());

                match self.config.enforcement_level {
                    EnforcementLevel::Strict => {
                        return Err(anyhow::anyhow!(
                            "Image signature verification failed for {}: {}",
                            image,
                            e
                        ));
                    }
                    EnforcementLevel::Warn => {
                        warn!(
                            "warning:  Image signature verification failed for {}: {}",
                            image, e
                        );
                        result.is_valid = true; // Allow execution with warning
                    }
                    EnforcementLevel::Audit => {
                        debug!("Image signature verification failed for {}: {}", image, e);
                        result.is_valid = true; // Allow execution with audit log
                    }
                }
            }
        }

        Ok(result)
    }

    /// Find the cosign binary in the system PATH
    pub fn find_cosign_binary() -> Result<Option<String>> {
        match which::which("cosign") {
            Ok(path) => Ok(Some(path.to_string_lossy().to_string())),
            Err(_) => {
                // Check common installation paths
                let common_paths = [
                    "/usr/local/bin/cosign",
                    "/usr/bin/cosign",
                    "/opt/homebrew/bin/cosign",
                    "./cosign",
                ];

                for path in &common_paths {
                    if std::path::Path::new(path).exists() {
                        return Ok(Some(path.to_string()));
                    }
                }

                Ok(None)
            }
        }
    }

    /// Get the digest of a container image
    async fn get_image_digest(&self, image: &str) -> Result<String> {
        // Try to get digest using docker/podman
        for runtime in &["docker", "podman"] {
            if let Ok(output) = Command::new(runtime)
                .args(["inspect", "--format", "{{.RepoDigests}}", image])
                .output()
            {
                if output.status.success() {
                    let digest_output = String::from_utf8_lossy(&output.stdout);
                    if !digest_output.trim().is_empty() && digest_output != "[]" {
                        // Extract digest from format like [registry/image@sha256:abc123]
                        if let Some(digest_part) = digest_output.split('@').nth(1) {
                            if let Some(digest) = digest_part.split(']').next() {
                                return Ok(digest.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Fallback: use image tag as identifier
        warn!(
            "Could not get image digest, using image reference: {}",
            image
        );
        Ok(image.to_string())
    }

    /// Verify image signature using cosign
    async fn verify_with_cosign(&self, cosign_path: &str, image: &str) -> Result<SignatureInfo> {
        let mut cmd = Command::new(cosign_path);
        cmd.args(["verify", "--output", "json"]);

        // Add trusted keys if specified
        if !self.config.trusted_keys.is_empty() {
            for key in &self.config.trusted_keys {
                cmd.args(["--key", key]);
            }
        } else {
            // Use keyless verification
            cmd.arg("--certificate-identity-regexp")
                .arg(".*")
                .arg("--certificate-oidc-issuer-regexp")
                .arg(".*");
        }

        // Add transparency log verification
        if self.config.verify_transparency_log {
            cmd.arg("--rekor-url").arg("https://rekor.sigstore.dev");
        } else {
            cmd.arg("--insecure-ignore-tlog");
        }

        cmd.arg(image);

        debug!("Running cosign command: {:?}", cmd);

        let output = cmd.output().context("Failed to execute cosign command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Cosign verification failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_cosign_output(&stdout)
    }

    /// Parse cosign JSON output to extract signature information
    fn parse_cosign_output(&self, output: &str) -> Result<SignatureInfo> {
        let json_value: serde_json::Value =
            serde_json::from_str(output).context("Failed to parse cosign JSON output")?;

        let mut sig_info = SignatureInfo {
            signer: "unknown".to_string(),
            oidc_issuer: None,
            subject: None,
            transparency_log_entry: None,
            metadata: HashMap::new(),
        };

        // Parse the JSON structure (cosign output format)
        if let Some(signatures) = json_value.as_array() {
            if signatures.is_empty() {
                return Err(anyhow::anyhow!("No signatures found in cosign output"));
            }

            if let Some(first_sig) = signatures.first() {
                // Extract certificate information
                if let Some(cert_info) = first_sig.get("optional") {
                    if let Some(subject) = cert_info.get("Subject") {
                        sig_info.subject = Some(subject.as_str().unwrap_or("").to_string());
                        sig_info.signer = subject.as_str().unwrap_or("unknown").to_string();
                    }

                    if let Some(issuer) = cert_info.get("Issuer") {
                        sig_info.oidc_issuer = Some(issuer.as_str().unwrap_or("").to_string());
                    }
                }

                // Extract transparency log information
                if let Some(bundle) = first_sig.get("bundle") {
                    if let Some(payload) = bundle.get("Payload") {
                        sig_info.transparency_log_entry =
                            Some(payload.as_str().unwrap_or("").to_string());
                    }
                }

                // Store additional metadata
                sig_info.metadata.insert(
                    "verification_time".to_string(),
                    chrono::Utc::now().to_rfc3339(),
                );
            }
        }

        Ok(sig_info)
    }

    /// Verify multiple images in parallel
    pub async fn verify_images_batch(&self, images: &[String]) -> Result<Vec<VerificationResult>> {
        let mut results = Vec::new();

        for image in images {
            let result = self.verify_image_signature(image).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Get the current verification configuration
    pub fn get_config(&self) -> &ImageVerificationConfig {
        &self.config
    }

    /// Update the verification configuration
    pub fn update_config(&mut self, config: ImageVerificationConfig) -> Result<()> {
        // Validate the new configuration
        if config.require_signatures && self.cosign_path.is_none() {
            anyhow::bail!("Cannot enable signature verification without cosign binary");
        }

        self.config = config;
        Ok(())
    }
}

/// Convenience function to verify a single image with default configuration
pub async fn verify_container_signature(image: &str) -> Result<bool> {
    let config = ImageVerificationConfig::default();
    let verifier = ImageVerifier::new(config)?;
    let result = verifier.verify_image_signature(image).await?;
    Ok(result.is_valid)
}

/// Convenience function to verify an image with custom configuration
pub async fn verify_container_signature_with_config(
    image: &str,
    config: ImageVerificationConfig,
) -> Result<VerificationResult> {
    let verifier = ImageVerifier::new(config)?;
    verifier.verify_image_signature(image).await
}
