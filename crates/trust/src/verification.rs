//! Trust verification module
//!
//! This module provides types and traits for trust verification.
//! Currently, most verification logic is handled through the TrustOperations trait
//! and the rotation module. This module serves as a placeholder for future
//! trust-specific verification features such as:
//! - Custom trust verifiers
//! - Complex verification policies
//! - Trust-specific verification protocols
//! - Verification extensions and plugins

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of a trust verification operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the verification was successful
    pub successful: bool,
    /// The trust level required for verification
    pub required_level: crate::TrustLevel,
    /// The actual trust level achieved
    pub achieved_level: Option<crate::TrustLevel>,
    /// Verification timestamp
    pub verified_at: chrono::DateTime<chrono::Utc>,
    /// Additional verification metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Policy for trust verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationPolicy {
    /// Minimum trust level required
    pub required_level: crate::TrustLevel,
    /// Number of verifiers required
    pub required_verifiers: usize,
    /// Whether consensus is required among verifiers
    pub require_consensus: bool,
    /// Additional policy constraints
    #[serde(default)]
    pub constraints: HashMap<String, serde_json::Value>,
}

/// Trait for trust verifiers
///
/// TODO: This trait will be expanded to support custom trust verifiers
/// and verification protocols in the future.
#[async_trait::async_trait]
pub trait TrustVerifier: Send + Sync {
    /// Verify trust according to the given policy
    async fn verify_trust(
        &self,
        agent_id: &str,
        policy: &VerificationPolicy,
    ) -> crate::Result<VerificationResult>;
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            required_level: crate::TrustLevel::Medium,
            required_verifiers: 1,
            require_consensus: false,
            constraints: HashMap::new(),
        }
    }
}

impl VerificationResult {
    /// Create a new verification result
    pub fn new(
        successful: bool,
        required_level: crate::TrustLevel,
        achieved_level: Option<crate::TrustLevel>,
    ) -> Self {
        Self {
            successful,
            required_level,
            achieved_level,
            verified_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the verification result
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}
