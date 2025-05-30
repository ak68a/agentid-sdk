//! Trust implementation for the ACK ID protocol.
//! 
//! This module provides the core trust types and their implementation,
//! which represent trust relationships between agents in the ACK ID system.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{Agent, AgentId, AgentIdError, Result};

/// Represents the level of trust between agents
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// No trust relationship
    None = 0,
    /// Basic trust (e.g., verified identity)
    Basic = 1,
    /// Established trust (e.g., successful transactions)
    Established = 2,
    /// High trust (e.g., long-term relationship)
    High = 3,
    /// Maximum trust (e.g., verified authority)
    Maximum = 4,
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::None
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Basic => write!(f, "Basic"),
            Self::Established => write!(f, "Established"),
            Self::High => write!(f, "High"),
            Self::Maximum => write!(f, "Maximum"),
        }
    }
}

/// Represents a trust relationship between two agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRelationship {
    /// The agent that established the trust
    from: AgentId,
    /// The agent that is trusted
    to: AgentId,
    /// The level of trust
    level: TrustLevel,
    /// When this trust relationship was established
    established_at: DateTime<Utc>,
    /// When this trust relationship was last updated
    updated_at: DateTime<Utc>,
    /// Additional trust metadata
    #[serde(default)]
    metadata: serde_json::Value,
}

impl TrustRelationship {
    /// Create a new trust relationship
    pub fn new(from: AgentId, to: AgentId, level: TrustLevel) -> Result<Self> {
        if from == to {
            return Err(AgentIdError::TrustLevelError(
                "Cannot establish trust with self".to_string(),
            ));
        }

        Ok(Self {
            from,
            to,
            level,
            established_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: serde_json::json!({}),
        })
    }

    /// Get the agent that established the trust
    pub fn from(&self) -> &AgentId {
        &self.from
    }

    /// Get the agent that is trusted
    pub fn to(&self) -> &AgentId {
        &self.to
    }

    /// Get the level of trust
    pub fn level(&self) -> TrustLevel {
        self.level
    }

    /// Get when this trust relationship was established
    pub fn established_at(&self) -> DateTime<Utc> {
        self.established_at
    }

    /// Get when this trust relationship was last updated
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// Get the metadata for this trust relationship
    pub fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }

    /// Update the level of trust
    pub fn update_level(&mut self, level: TrustLevel) -> Result<()> {
        self.level = level;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Update the metadata for this trust relationship
    pub fn update_metadata(&mut self, metadata: serde_json::Value) -> Result<()> {
        self.metadata = metadata;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Check if this trust relationship is active
    pub fn is_active(&self) -> bool {
        self.level != TrustLevel::None
    }

    /// Check if this trust relationship is at a specific level or higher
    pub fn is_at_least(&self, level: TrustLevel) -> bool {
        self.level >= level
    }
}

impl fmt::Display for TrustRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Trust from {} to {}: {} (Updated: {})",
            self.from,
            self.to,
            self.level,
            self.updated_at
        )
    }
}

/// A trait for managing trust relationships
#[async_trait]
pub trait TrustManager {
    /// Establish a trust relationship between two agents
    async fn establish_trust(
        &mut self,
        from: AgentId,
        to: AgentId,
        level: TrustLevel,
    ) -> Result<TrustRelationship>;

    /// Update the level of trust in a relationship
    async fn update_trust(
        &mut self,
        from: AgentId,
        to: AgentId,
        level: TrustLevel,
    ) -> Result<TrustRelationship>;

    /// Get the trust relationship between two agents
    async fn get_trust(&self, from: AgentId, to: AgentId) -> Result<Option<TrustRelationship>>;

    /// Remove a trust relationship
    async fn remove_trust(&mut self, from: AgentId, to: AgentId) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Maximum > TrustLevel::High);
        assert!(TrustLevel::High > TrustLevel::Established);
        assert!(TrustLevel::Established > TrustLevel::Basic);
        assert!(TrustLevel::Basic > TrustLevel::None);
    }

    #[test]
    fn test_trust_relationship_creation() {
        let agent1 = AgentId::new("agent1");
        let agent2 = AgentId::new("agent2");
        
        let trust = TrustRelationship::new(agent1.clone(), agent2.clone(), TrustLevel::Basic)
            .unwrap();
        
        assert_eq!(trust.from(), &agent1);
        assert_eq!(trust.to(), &agent2);
        assert_eq!(trust.level(), TrustLevel::Basic);
        assert!(trust.is_active());
    }

    #[test]
    fn test_trust_relationship_self_trust() {
        let agent = AgentId::new("agent");
        let result = TrustRelationship::new(agent.clone(), agent, TrustLevel::Basic);
        assert!(result.is_err());
    }

    #[test]
    fn test_trust_relationship_updates() {
        let agent1 = AgentId::new("agent1");
        let agent2 = AgentId::new("agent2");
        
        let mut trust = TrustRelationship::new(agent1, agent2, TrustLevel::Basic).unwrap();
        
        trust.update_level(TrustLevel::High).unwrap();
        assert_eq!(trust.level(), TrustLevel::High);
        assert!(trust.is_at_least(TrustLevel::Established));
        
        trust.update_level(TrustLevel::None).unwrap();
        assert!(!trust.is_active());
    }
} 