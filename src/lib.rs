//! ATTEST Library
//!
//! Verifiable CI/CD platform with cryptographic attestation.

pub mod archive;
pub mod capsule;
pub mod core;
pub mod crypto;
pub mod executor;
pub mod hashing;
pub mod ignore;
pub mod interop;
pub mod keys;
pub mod pipeline;
pub mod provenance;
pub mod sandbox;
pub mod storage;
pub mod util;
pub mod verify;
pub mod wrap;

// Re-export common types
pub use core::AttestCore;
pub use crypto::sign::AttestKeypair;
pub use pipeline::{Pipeline, Step};
pub use storage::{Receipt, StepResult, Storage};
