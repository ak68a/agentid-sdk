//! Core implementation of the Agent Commerce Kit Identity (ACK ID) protocol.
//! 
//! This crate provides the fundamental types and traits for implementing
//! agent-based identity and trust in commerce applications.

use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use validator::Validate;

pub mod agent;
pub mod identity;
pub mod trust;
pub mod verification;

pub use agent::Agent;
pub use identity::Identity;
pub use trust::TrustLevel;
pub use verification::Verification;

/// Errors that can occur in the core protocol implementation
#[derive(Error, Debug)]
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

/// Represents a unique identifier for an agent
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId {
    /// The unique identifier
    id: Uuid,
    /// The human-readable name of the agent
    name: String,
    /// When this agent was created
    created_at: DateTime<Utc>,
}

impl AgentId {
    /// Create a new agent identifier
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            created_at: Utc::now(),
        }
    }

    /// Get the UUID of this agent
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Get the name of this agent
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get when this agent was created
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.id)
    }
}

impl FromStr for AgentId {
    type Err = AgentIdError;

    fn from_str(s: &str) -> Result<Self> {
        // TODO: Implement proper parsing
        Err(AgentIdError::InvalidAgentId(s.to_string()))
    }
}

/// Represents the capabilities of an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapabilities {
    /// Whether the agent can perform commerce operations
    pub can_commerce: bool,
    /// Whether the agent can verify other agents
    pub can_verify: bool,
    /// Whether the agent can manage trust relationships
    pub can_manage_trust: bool,
}

impl Default for AgentCapabilities {
    fn default() -> Self {
        Self {
            can_commerce: true,
            can_verify: false,
            can_manage_trust: false,
        }
    }
}

/// Represents the status of an agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    /// The agent is active and can perform operations
    Active,
    /// The agent is suspended and cannot perform operations
    Suspended,
    /// The agent is revoked and can never perform operations again
    Revoked,
}

impl Default for AgentStatus {
    fn default() -> Self {
        Self::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_id_creation() {
        let agent_id = AgentId::new("test-agent");
        assert_eq!(agent_id.name(), "test-agent");
        assert!(agent_id.created_at() <= Utc::now());
    }

    #[test]
    fn test_agent_capabilities_default() {
        let capabilities = AgentCapabilities::default();
        assert!(capabilities.can_commerce);
        assert!(!capabilities.can_verify);
        assert!(!capabilities.can_manage_trust);
    }
} 