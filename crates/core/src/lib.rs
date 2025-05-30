//! Core implementation of the Agent Commerce Kit Identity (ACK ID) protocol.
//!
//! This crate provides the fundamental types and traits for implementing
//! agent-based identity and trust in commerce applications.

use agentid_types::{AgentCapabilities, AgentId, AgentStatus, TrustLevel, TrustScore};

pub mod agent;
pub mod identity;
pub mod trust;
pub mod verification;

// Re-export our own types
pub use agent::Agent;
pub use identity::Identity;
// Do not re-export Rotation, Trust, Verification unless they exist as types

/// Errors that can occur in the core protocol implementation
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    // #[error("Identity error: {0}")]
    // Identity(#[from] crate::identity::IdentityError),
    // #[error("Crypto error: {0}")]
    // Crypto(#[from] crate::crypto::CryptoError),
    // #[error("Trust error: {0}")]
    // Trust(#[from] crate::trust::TrustError),
    // #[error("Verification error: {0}")]
    // Verification(#[from] crate::verification::VerificationError),
    // #[error("Rotation error: {0}")]
    // Rotation(#[from] crate::rotation::RotationError),
}

/// Errors that can occur in the core protocol implementation
#[derive(thiserror::Error, Debug)]
pub enum AgentIdError {
    #[error("Invalid agent identifier: {0}")]
    InvalidAgentId(String),
    #[error("Invalid identity data: {0}")]
    InvalidIdentityData(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Trust level error: {0}")]
    TrustLevelError(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for the core protocol
pub type Result<T> = std::result::Result<T, AgentIdError>;
