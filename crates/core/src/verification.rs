//! Verification implementation for the ACK ID protocol.
//! 
//! This module provides the core verification types and their implementation,
//! which handle the verification of agent identities and trust relationships.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    Agent, AgentId, AgentIdError, Identity, Result, TrustLevel, TrustRelationship,
    VerificationLevel,
};

/// Represents the result of a verification attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the verification was successful
    success: bool,
    /// The level of verification achieved
    level: VerificationLevel,
    /// When this verification was performed
    verified_at: DateTime<Utc>,
    /// The agent that performed the verification
    verified_by: Option<AgentId>,
    /// Additional verification metadata
    #[serde(default)]
    metadata: serde_json::Value,
}

impl VerificationResult {
    /// Create a new verification result
    pub fn new(
        success: bool,
        level: VerificationLevel,
        verified_by: Option<AgentId>,
    ) -> Self {
        Self {
            success,
            level,
            verified_at: Utc::now(),
            verified_by,
            metadata: serde_json::json!({}),
        }
    }

    /// Get whether the verification was successful
    pub fn success(&self) -> bool {
        self.success
    }

    /// Get the level of verification achieved
    pub fn level(&self) -> VerificationLevel {
        self.level
    }

    /// Get when this verification was performed
    pub fn verified_at(&self) -> DateTime<Utc> {
        self.verified_at
    }

    /// Get the agent that performed the verification
    pub fn verified_by(&self) -> Option<&AgentId> {
        self.verified_by.as_ref()
    }

    /// Get the metadata for this verification
    pub fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }

    /// Update the metadata for this verification
    pub fn update_metadata(&mut self, metadata: serde_json::Value) {
        self.metadata = metadata;
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Verification {} (Level: {:?}, Verified: {})",
            if self.success { "Successful" } else { "Failed" },
            self.level,
            self.verified_at
        )
    }
}

/// A trait for verifying agent identities and trust relationships
#[async_trait]
pub trait Verifier {
    /// Verify an agent's identity
    async fn verify_identity(&self, identity: &Identity) -> Result<VerificationResult>;

    /// Verify a trust relationship
    async fn verify_trust(
        &self,
        relationship: &TrustRelationship,
        verifier: &Agent,
    ) -> Result<VerificationResult>;

    /// Verify multiple agents in a chain of trust
    async fn verify_trust_chain(
        &self,
        chain: &[TrustRelationship],
        verifier: &Agent,
    ) -> Result<VerificationResult>;
}

/// A trait for managing the verification process
#[async_trait]
pub trait VerificationManager {
    /// Request verification of an identity
    async fn request_verification(
        &mut self,
        identity: Identity,
        verifier: Agent,
    ) -> Result<VerificationResult>;

    /// Request verification of a trust relationship
    async fn request_trust_verification(
        &mut self,
        relationship: TrustRelationship,
        verifier: Agent,
    ) -> Result<VerificationResult>;

    /// Get the verification history for an identity
    async fn get_verification_history(
        &self,
        identity: &Identity,
    ) -> Result<Vec<VerificationResult>>;

    /// Get the verification history for a trust relationship
    async fn get_trust_verification_history(
        &self,
        relationship: &TrustRelationship,
    ) -> Result<Vec<VerificationResult>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result_creation() {
        let agent = AgentId::new("verifier");
        let result = VerificationResult::new(
            true,
            VerificationLevel::AgentVerified,
            Some(agent.clone()),
        );

        assert!(result.success());
        assert_eq!(result.level(), VerificationLevel::AgentVerified);
        assert_eq!(result.verified_by(), Some(&agent));
    }

    #[test]
    fn test_verification_result_metadata() {
        let mut result = VerificationResult::new(
            true,
            VerificationLevel::Basic,
            None,
        );

        let metadata = serde_json::json!({
            "reason": "Initial verification",
            "method": "Document check"
        });

        result.update_metadata(metadata.clone());
        assert_eq!(result.metadata(), &metadata);
    }
} 