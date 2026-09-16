pub mod image_signing;
pub mod image_verification;
pub mod sign;
pub mod supply_chain;
pub mod timestamp;

pub use image_verification::ImageVerificationConfig;

/// Get the default crypto configuration for ATTEST
pub fn get_default_crypto_config() -> ImageVerificationConfig {
    ImageVerificationConfig::default()
}

/// Validate a signature configuration
pub fn validate_crypto_config(config: &ImageVerificationConfig) -> bool {
    !config.trusted_keys.is_empty() || !config.trusted_oidc_issuers.is_empty()
}
