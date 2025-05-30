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

use crate::{Agent, AgentIdError, Result};
use agentid_trust::{TrustConfig, TrustOperations};
use agentid_types::{AgentId, TrustLevel, TrustRelationship as TypesTrustRelationship, TrustScore};

/// Core trust operations that extend the trust framework
#[async_trait]
pub trait CoreTrustOperations {
    /// Get the trust configuration
    async fn get_config(&self) -> Result<TrustConfig>;

    /// Get the trust score for an agent
    async fn get_trust_score(&self, agent: &Agent) -> Result<TrustScore>;

    /// Update trust attributes for an agent
    async fn update_trust_attributes(
        &self,
        agent: &Agent,
        attributes: &TrustAttributeSet,
    ) -> Result<TrustAttributeSet>;
}

/// Trust configuration for core operations
#[derive(Debug, Clone)]
pub struct CoreTrustConfig {
    /// Minimum trust score required for operations
    pub minimum_trust_score: f64,
    /// Trust score thresholds for different levels
    pub trust_level_thresholds: Vec<(TrustLevel, f64)>,
}

/// A set of trust attributes
#[derive(Debug, Clone)]
pub struct TrustAttributeSet {
    /// The agent ID these attributes belong to
    pub agent_id: AgentId,
    /// When the attributes were last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
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

/// Wrapper type for TrustRelationship that implements Display
#[derive(Debug, Clone)]
pub struct CoreTrustRelationship(pub TypesTrustRelationship);

impl fmt::Display for CoreTrustRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Trust from {} to {}: {} (Updated: {})",
            self.0.from(),
            self.0.to(),
            self.0.level(),
            self.0.updated_at()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentid_types::TrustLevel;

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::VeryHigh > TrustLevel::High);
        assert!(TrustLevel::High > TrustLevel::Medium);
        assert!(TrustLevel::Medium > TrustLevel::Low);
        assert!(TrustLevel::Low > TrustLevel::None);
    }

    #[test]
    fn test_trust_relationship_creation() {
        let agent1 = AgentId::new("agent1");
        let agent2 = AgentId::new("agent2");

        let trust =
            TrustRelationship::new(agent1.clone(), agent2.clone(), TrustLevel::Low).unwrap();

        assert_eq!(trust.from(), &agent1);
        assert_eq!(trust.to(), &agent2);
        assert_eq!(trust.level(), TrustLevel::Low);
        assert!(trust.is_active());
    }

    #[test]
    fn test_trust_relationship_self_trust() {
        let agent = AgentId::new("agent");
        let result = TrustRelationship::new(agent.clone(), agent, TrustLevel::Low);
        assert!(result.is_err());
    }

    #[test]
    fn test_trust_relationship_updates() {
        let agent1 = AgentId::new("agent1");
        let agent2 = AgentId::new("agent2");

        let mut trust = TrustRelationship::new(agent1, agent2, TrustLevel::Low).unwrap();

        trust.update_level(TrustLevel::High).unwrap();
        assert_eq!(trust.level(), TrustLevel::High);
        assert!(trust.is_at_least(TrustLevel::Medium));

        trust.update_level(TrustLevel::None).unwrap();
        assert!(!trust.is_active());
    }

    #[tokio::test]
    async fn test_trust_operations() {
        // TODO: Implement trust operation tests
    }
}
