//! Identity implementation for the ACK ID protocol.
//!
//! This module provides the core Identity type and its implementation,
//! which represents the identity and verification state of an agent.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{Agent, AgentId, AgentIdError, Result};

/// Represents the verification level of an identity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// The identity has not been verified
    Unverified,
    /// The identity has been self-verified
    SelfVerified,
    /// The identity has been verified by another agent
    AgentVerified,
    /// The identity has been verified by multiple agents
    MultiAgentVerified,
    /// The identity has been verified by a trusted authority
    AuthorityVerified,
}

impl Default for VerificationLevel {
    fn default() -> Self {
        Self::Unverified
    }
}

/// Represents the verification status of an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStatus {
    /// The current verification level
    level: VerificationLevel,
    /// When this identity was last verified
    verified_at: Option<DateTime<Utc>>,
    /// The agent that performed the last verification
    verified_by: Option<AgentId>,
    /// Additional verification metadata
    #[serde(default)]
    metadata: serde_json::Value,
}

impl Default for VerificationStatus {
    fn default() -> Self {
        Self {
            level: VerificationLevel::default(),
            verified_at: None,
            verified_by: None,
            metadata: serde_json::json!({}),
        }
    }
}

/// Represents an identity in the ACK ID system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// The agent this identity belongs to
    agent: Agent,
    /// The verification status of this identity
    verification: VerificationStatus,
    /// When this identity was created
    created_at: DateTime<Utc>,
    /// When this identity was last updated
    updated_at: DateTime<Utc>,
    /// Additional identity metadata
    #[serde(default)]
    metadata: serde_json::Value,
}

impl Identity {
    /// Create a new identity for an agent
    pub fn new(agent: Agent) -> Result<Self> {
        Ok(Self {
            verification: VerificationStatus::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::json!({}),
            agent,
        })
    }

    /// Get the agent this identity belongs to
    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    /// Get the verification status of this identity
    pub fn verification(&self) -> &VerificationStatus {
        &self.verification
    }

    /// Get when this identity was created
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Get when this identity was last updated
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// Get the metadata for this identity
    pub fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }

    /// Update the verification status of this identity
    pub fn update_verification(
        &mut self,
        level: VerificationLevel,
        verified_by: Option<AgentId>,
    ) -> Result<()> {
        self.verification.level = level;
        self.verification.verified_at = Some(Utc::now());
        self.verification.verified_by = verified_by;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Update the metadata for this identity
    pub fn update_metadata(&mut self, metadata: serde_json::Value) -> Result<()> {
        self.metadata = metadata;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Check if this identity is verified
    pub fn is_verified(&self) -> bool {
        self.verification.level != VerificationLevel::Unverified
    }

    /// Check if this identity is verified by an agent
    pub fn is_agent_verified(&self) -> bool {
        matches!(
            self.verification.level,
            VerificationLevel::AgentVerified | VerificationLevel::MultiAgentVerified
        )
    }

    /// Check if this identity is verified by an authority
    pub fn is_authority_verified(&self) -> bool {
        self.verification.level == VerificationLevel::AuthorityVerified
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Identity for {} (Verification: {:?}, Updated: {})",
            self.agent, self.verification.level, self.updated_at
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation() {
        let agent = Agent::new("test-agent").unwrap();
        let identity = Identity::new(agent).unwrap();
        assert!(!identity.is_verified());
        assert!(!identity.is_agent_verified());
        assert!(!identity.is_authority_verified());
    }

    #[test]
    fn test_identity_verification() {
        let agent = Agent::new("test-agent").unwrap();
        let mut identity = Identity::new(agent).unwrap();

        identity
            .update_verification(VerificationLevel::AgentVerified, Some(agent.id().clone()))
            .unwrap();

        assert!(identity.is_verified());
        assert!(identity.is_agent_verified());
        assert!(!identity.is_authority_verified());
    }

    #[test]
    fn test_identity_authority_verification() {
        let agent = Agent::new("test-agent").unwrap();
        let mut identity = Identity::new(agent).unwrap();

        identity
            .update_verification(VerificationLevel::AuthorityVerified, None)
            .unwrap();

        assert!(identity.is_verified());
        assert!(!identity.is_agent_verified());
        assert!(identity.is_authority_verified());
    }
}
