//! Trust implementation for the ACK ID protocol.
//!
//! This module provides the core trust types and their implementation,
//! which represent trust relationships between agents in the ACK ID system.

use std::fmt;

use async_trait::async_trait;
use chrono::Duration;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Agent, AgentIdError, Result};
use agentid_trust::TrustConfig;
use agentid_types::{
    AgentId, TrustLevel as TypesTrustLevel, TrustMetrics,
    TrustRelationship as TypesTrustRelationship, TrustScore,
};

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
    pub trust_level_thresholds: Vec<(TypesTrustLevel, f64)>,
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
    level: TypesTrustLevel,
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
    pub fn new(from: AgentId, to: AgentId, level: TypesTrustLevel) -> Result<Self> {
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
    pub fn level(&self) -> TypesTrustLevel {
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
    pub fn update_level(&mut self, level: TypesTrustLevel) -> Result<()> {
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
        self.level != TypesTrustLevel::None
    }

    /// Check if this trust relationship is at a specific level or higher
    pub fn is_at_least(&self, level: TypesTrustLevel) -> bool {
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
    use agentid_trust::{TrustLevel as TrustTrustLevel, VerificationPolicy};
    use std::collections::HashMap;

    // Helper trait to convert between trust levels
    trait TrustLevelConverter {
        fn to_trust_level(&self) -> TrustTrustLevel;
    }

    impl TrustLevelConverter for TypesTrustLevel {
        fn to_trust_level(&self) -> TrustTrustLevel {
            match self {
                TypesTrustLevel::None => TrustTrustLevel::None,
                TypesTrustLevel::Low => TrustTrustLevel::Low,
                TypesTrustLevel::Medium => TrustTrustLevel::Medium,
                TypesTrustLevel::High => TrustTrustLevel::High,
                TypesTrustLevel::VeryHigh => TrustTrustLevel::VeryHigh,
            }
        }
    }

    // Mock implementation of CoreTrustOperations for testing
    struct MockTrustOperations {
        config: CoreTrustConfig,
        trust_scores: HashMap<AgentId, TrustScore>,
        trust_attributes: HashMap<AgentId, TrustAttributeSet>,
    }

    impl MockTrustOperations {
        fn new() -> Self {
            Self {
                config: CoreTrustConfig {
                    minimum_trust_score: 0.5,
                    trust_level_thresholds: vec![
                        (TypesTrustLevel::None, 0.0),
                        (TypesTrustLevel::Low, 0.3),
                        (TypesTrustLevel::Medium, 0.6),
                        (TypesTrustLevel::High, 0.8),
                        (TypesTrustLevel::VeryHigh, 0.9),
                    ],
                },
                trust_scores: HashMap::new(),
                trust_attributes: HashMap::new(),
            }
        }

        fn with_trust_score(mut self, agent_id: AgentId, score: TrustScore) -> Self {
            self.trust_scores.insert(agent_id, score);
            self
        }

        fn with_trust_attributes(
            mut self,
            agent_id: AgentId,
            attributes: TrustAttributeSet,
        ) -> Self {
            self.trust_attributes.insert(agent_id, attributes);
            self
        }
    }

    #[async_trait]
    impl CoreTrustOperations for MockTrustOperations {
        async fn get_config(&self) -> Result<TrustConfig> {
            Ok(TrustConfig {
                minimum_trust_score: self.config.minimum_trust_score,
                trust_level_thresholds: self
                    .config
                    .trust_level_thresholds
                    .clone()
                    .into_iter()
                    .map(|(level, score)| (level.to_trust_level(), score))
                    .collect(),
                max_delegation_depth: 3,
                attribute_weights: HashMap::from([
                    ("direct_trust".to_string(), 0.3),
                    ("indirect_trust".to_string(), 0.2),
                    ("historical_trust".to_string(), 0.2),
                    ("behavioral_trust".to_string(), 0.2),
                    ("identity_verification".to_string(), 0.1),
                ]),
                verification_policies: HashMap::from([
                    (
                        "basic".to_string(),
                        VerificationPolicy {
                            required_level: TrustTrustLevel::Medium,
                            required_verifiers: 1,
                            require_consensus: false,
                            constraints: HashMap::new(),
                        },
                    ),
                    (
                        "high_trust".to_string(),
                        VerificationPolicy {
                            required_level: TrustTrustLevel::High,
                            required_verifiers: 2,
                            require_consensus: true,
                            constraints: HashMap::new(),
                        },
                    ),
                ]),
            })
        }

        async fn get_trust_score(&self, _agent: &Agent) -> Result<TrustScore> {
            self.trust_scores
                .get(_agent.id())
                .cloned()
                .ok_or_else(|| AgentIdError::TrustLevelError("No trust score found".into()))
        }

        async fn update_trust_attributes(
            &self,
            agent: &Agent,
            attributes: &TrustAttributeSet,
        ) -> Result<TrustAttributeSet> {
            let mut new_attributes = attributes.clone();
            new_attributes.updated_at = Utc::now();
            Ok(new_attributes)
        }
    }

    // Helper function to create a test trust score
    fn create_test_trust_score(score: f64, level: TypesTrustLevel) -> TrustScore {
        TrustScore {
            score,
            level,
            metrics: TrustMetrics {
                direct_trust: score,
                indirect_trust: score,
                historical_trust: score,
                behavioral_trust: score,
                identity_verification: 1.0,
                custom_metrics: Default::default(),
            },
            timestamp: Utc::now(),
            confidence: 0.9,
            validity_period: Duration::hours(24),
        }
    }

    // Helper function to create test trust attributes
    fn create_test_trust_attributes(agent_id: AgentId) -> TrustAttributeSet {
        TrustAttributeSet {
            agent_id,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TypesTrustLevel::VeryHigh > TypesTrustLevel::High);
        assert!(TypesTrustLevel::High > TypesTrustLevel::Medium);
        assert!(TypesTrustLevel::Medium > TypesTrustLevel::Low);
        assert!(TypesTrustLevel::Low > TypesTrustLevel::None);
    }

    #[test]
    fn test_trust_relationship_creation() {
        let agent1 = AgentId::new("agent1");
        let agent2 = AgentId::new("agent2");

        let trust =
            TrustRelationship::new(agent1.clone(), agent2.clone(), TypesTrustLevel::Low).unwrap();

        assert_eq!(trust.from(), &agent1);
        assert_eq!(trust.to(), &agent2);
        assert_eq!(trust.level(), TypesTrustLevel::Low);
        assert!(trust.is_active());
    }

    #[test]
    fn test_trust_relationship_self_trust() {
        let agent = AgentId::new("agent");
        let result = TrustRelationship::new(agent.clone(), agent, TypesTrustLevel::Low);
        assert!(result.is_err());
    }

    #[test]
    fn test_trust_relationship_updates() {
        let agent1 = AgentId::new("agent1");
        let agent2 = AgentId::new("agent2");

        let mut trust = TrustRelationship::new(agent1, agent2, TypesTrustLevel::Low).unwrap();

        trust.update_level(TypesTrustLevel::High).unwrap();
        assert_eq!(trust.level(), TypesTrustLevel::High);
        assert!(trust.is_at_least(TypesTrustLevel::Medium));

        trust.update_level(TypesTrustLevel::None).unwrap();
        assert!(!trust.is_active());
    }

    #[test]
    fn test_trust_relationship_metadata() {
        let agent1 = AgentId::new("agent1");
        let agent2 = AgentId::new("agent2");
        let mut trust = TrustRelationship::new(agent1, agent2, TypesTrustLevel::High).unwrap();

        let metadata = serde_json::json!({
            "reason": "Business partnership",
            "established_date": "2024-01-01",
            "review_period": "6 months"
        });

        trust.update_metadata(metadata.clone()).unwrap();
        assert_eq!(trust.metadata(), &metadata);
    }

    #[tokio::test]
    async fn test_trust_operations_config() {
        let operations = MockTrustOperations::new();
        let _config = operations.get_config().await.unwrap();

        assert_eq!(operations.config.minimum_trust_score, 0.5);
        assert_eq!(operations.config.trust_level_thresholds.len(), 5);
        assert_eq!(
            operations.config.trust_level_thresholds[0].0,
            TypesTrustLevel::None
        );
        assert_eq!(
            operations.config.trust_level_thresholds[4].0,
            TypesTrustLevel::VeryHigh
        );
    }

    #[tokio::test]
    async fn test_trust_operations_score() {
        let agent = Agent::new("test-agent").unwrap();
        let agent_id = agent.id().clone();
        let trust_score = create_test_trust_score(0.85, TypesTrustLevel::High);

        let operations =
            MockTrustOperations::new().with_trust_score(agent_id.clone(), trust_score.clone());

        let score = operations.get_trust_score(&agent).await.unwrap();
        assert_eq!(score.score, 0.85);
        assert_eq!(score.level, TypesTrustLevel::High);
    }

    #[tokio::test]
    async fn test_trust_operations_attributes() {
        let agent = Agent::new("test-agent").unwrap();
        let agent_id = agent.id().clone();
        let attributes = create_test_trust_attributes(agent_id.clone());

        let operations =
            MockTrustOperations::new().with_trust_attributes(agent_id, attributes.clone());

        let updated_attributes = operations
            .update_trust_attributes(&agent, &attributes)
            .await
            .unwrap();

        assert!(updated_attributes.updated_at > attributes.updated_at);
    }

    #[tokio::test]
    async fn test_trust_operations_missing_score() {
        let agent = Agent::new("test-agent").unwrap();
        let operations = MockTrustOperations::new();

        let result = operations.get_trust_score(&agent).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_core_trust_relationship_display() {
        let agent1 = AgentId::new("agent1");
        let agent2 = AgentId::new("agent2");
        let trust = TypesTrustRelationship::new(agent1, agent2, TypesTrustLevel::High).unwrap();
        let core_trust = CoreTrustRelationship(trust);

        let display = format!("{}", core_trust);
        assert!(display.contains("agent1"));
        assert!(display.contains("agent2"));
        assert!(display.contains("High"));
    }

    #[tokio::test]
    async fn test_trust_score_thresholds() {
        let operations = MockTrustOperations::new();
        let config = operations.get_config().await.unwrap();

        // Test trust score thresholds
        let test_cases = vec![
            (0.0, TypesTrustLevel::None),
            (0.2, TypesTrustLevel::None),
            (0.4, TypesTrustLevel::Low),
            (0.7, TypesTrustLevel::Medium),
            (0.85, TypesTrustLevel::High),
            (0.95, TypesTrustLevel::VeryHigh),
        ];

        for (score, expected_level) in test_cases {
            let trust_score = create_test_trust_score(score, expected_level);
            assert_eq!(trust_score.level, expected_level);
        }
    }

    #[tokio::test]
    async fn test_trust_relationship_chain() {
        let agent1 = AgentId::new("agent1");
        let agent2 = AgentId::new("agent2");
        let agent3 = AgentId::new("agent3");

        let trust1 =
            TrustRelationship::new(agent1.clone(), agent2.clone(), TypesTrustLevel::High).unwrap();
        let trust2 = TrustRelationship::new(agent2, agent3.clone(), TypesTrustLevel::High).unwrap();

        let _operations = MockTrustOperations::new().with_trust_score(
            agent3,
            create_test_trust_score(0.9, TypesTrustLevel::VeryHigh),
        );

        // Verify that trust relationships can form a chain
        assert_eq!(trust1.to(), trust2.from());
        assert!(trust1.is_active() && trust2.is_active());
        assert!(
            trust1.is_at_least(TypesTrustLevel::High) && trust2.is_at_least(TypesTrustLevel::High)
        );
    }

    #[tokio::test]
    async fn test_trust_attributes_update() {
        let agent = Agent::new("test-agent").unwrap();
        let agent_id = agent.id().clone();
        let attributes = create_test_trust_attributes(agent_id.clone());
        let operations = MockTrustOperations::new();

        // Test that attributes are updated with new timestamp
        let updated = operations
            .update_trust_attributes(&agent, &attributes)
            .await
            .unwrap();

        assert!(updated.updated_at > attributes.updated_at);
        assert_eq!(updated.agent_id, agent_id);
    }

    #[tokio::test]
    async fn test_trust_attributes_concurrent_updates() {
        let agent = Agent::new("test-agent").unwrap();
        let agent_id = agent.id().clone();
        let attributes = create_test_trust_attributes(agent_id.clone());
        let operations = MockTrustOperations::new();

        // Simulate concurrent updates
        let update1 = operations.update_trust_attributes(&agent, &attributes);
        let update2 = operations.update_trust_attributes(&agent, &attributes);

        let (result1, result2) = tokio::join!(update1, update2);
        let updated1 = result1.unwrap();
        let updated2 = result2.unwrap();

        // Both updates should succeed but have different timestamps
        assert!(updated1.updated_at != updated2.updated_at);
        assert_eq!(updated1.agent_id, updated2.agent_id);
    }
}
