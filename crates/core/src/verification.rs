//! Verification implementation for the ACK ID protocol.
//!
//! This module provides the core verification types and their implementation,
//! which handle the verification of agent identities and trust relationships.

use crate::AgentIdError;
use crate::{Agent, Identity};
use agentid_types::VerificationPolicy;
use agentid_types::{
    AgentId, TrustLevel, TrustMetrics, TrustRelationship, TrustScore, VerificationRequest,
    VerificationResult, VerificationStatus,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::HashMap;

type Result<T> = std::result::Result<T, AgentIdError>;

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

    // Mock implementation of Verifier for testing
    struct MockVerifier {
        verification_results: HashMap<AgentId, VerificationResult>,
        trust_scores: HashMap<AgentId, TrustScore>,
    }

    impl MockVerifier {
        fn new() -> Self {
            Self {
                verification_results: HashMap::new(),
                trust_scores: HashMap::new(),
            }
        }

        fn with_verification_result(
            mut self,
            agent_id: AgentId,
            result: VerificationResult,
        ) -> Self {
            self.verification_results.insert(agent_id, result);
            self
        }

        fn with_trust_score(mut self, agent_id: AgentId, score: TrustScore) -> Self {
            self.trust_scores.insert(agent_id, score);
            self
        }
    }

    #[async_trait]
    impl Verifier for MockVerifier {
        async fn verify_identity(&self, identity: &Identity) -> Result<VerificationResult> {
            if let Some(result) = self.verification_results.get(identity.agent().id()) {
                Ok(result.clone())
            } else {
                Err(AgentIdError::VerificationError(
                    "No verification result found".into(),
                ))
            }
        }

        async fn verify_trust(
            &self,
            relationship: &TrustRelationship,
            _verifier: &Agent,
        ) -> Result<VerificationResult> {
            if let Some(result) = self.verification_results.get(relationship.to()) {
                Ok(result.clone())
            } else {
                Err(AgentIdError::VerificationError(
                    "No verification result found".into(),
                ))
            }
        }

        async fn verify_trust_chain(
            &self,
            chain: &[TrustRelationship],
            _verifier: &Agent,
        ) -> Result<VerificationResult> {
            if chain.is_empty() {
                return Err(AgentIdError::VerificationError("Empty trust chain".into()));
            }

            // Verify each relationship in the chain
            for relationship in chain {
                if self.verification_results.get(relationship.to()).is_none() {
                    return Err(AgentIdError::VerificationError(
                        "Invalid trust chain".into(),
                    ));
                }
            }

            // Create a successful verification result for the chain
            Ok(VerificationResult {
                request: VerificationRequest {
                    id: "chain-verification".to_string(),
                    requester_id: chain[0].from().clone(),
                    target_id: chain.last().unwrap().to().clone(),
                    policy: VerificationPolicy {
                        name: "chain-verification".to_string(),
                        description: "Verify trust chain".to_string(),
                        required_level: TrustLevel::High,
                        min_verifiers: 1,
                        require_consensus: true,
                        verification_period: Duration::hours(1),
                        metadata: Default::default(),
                    },
                    created_at: Utc::now(),
                    expires_at: Utc::now() + Duration::hours(1),
                    metadata: Default::default(),
                },
                status: VerificationStatus::Verified,
                verified_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                trust_score: Some(TrustScore {
                    score: 0.9,
                    level: TrustLevel::High,
                    metrics: TrustMetrics {
                        direct_trust: 0.9,
                        indirect_trust: 0.9,
                        historical_trust: 0.9,
                        behavioral_trust: 0.9,
                        identity_verification: 1.0,
                        custom_metrics: Default::default(),
                    },
                    timestamp: Utc::now(),
                    confidence: 0.95,
                    validity_period: Duration::hours(24),
                }),
                evidence: Default::default(),
                failure_reasons: Default::default(),
            })
        }
    }

    // Mock implementation of VerificationManager for testing
    struct MockVerificationManager {
        verifier: MockVerifier,
        verification_history: HashMap<AgentId, Vec<VerificationResult>>,
        trust_verification_history: HashMap<(AgentId, AgentId), Vec<VerificationResult>>,
    }

    impl MockVerificationManager {
        fn new(verifier: MockVerifier) -> Self {
            Self {
                verifier,
                verification_history: HashMap::new(),
                trust_verification_history: HashMap::new(),
            }
        }
    }

    #[async_trait]
    impl VerificationManager for MockVerificationManager {
        async fn request_verification(
            &mut self,
            identity: Identity,
            verifier: Agent,
        ) -> Result<VerificationResult> {
            let result = self.verifier.verify_identity(&identity).await?;

            // Store in history
            self.verification_history
                .entry(identity.agent().id().clone())
                .or_default()
                .push(result.clone());

            Ok(result)
        }

        async fn request_trust_verification(
            &mut self,
            relationship: TrustRelationship,
            verifier: Agent,
        ) -> Result<VerificationResult> {
            let result = self.verifier.verify_trust(&relationship, &verifier).await?;

            // Store in history
            let key = (relationship.from().clone(), relationship.to().clone());
            self.trust_verification_history
                .entry(key)
                .or_default()
                .push(result.clone());

            Ok(result)
        }

        async fn get_verification_history(
            &self,
            identity: &Identity,
        ) -> Result<Vec<VerificationResult>> {
            Ok(self
                .verification_history
                .get(identity.agent().id())
                .cloned()
                .unwrap_or_default())
        }

        async fn get_trust_verification_history(
            &self,
            relationship: &TrustRelationship,
        ) -> Result<Vec<VerificationResult>> {
            let key = (relationship.from().clone(), relationship.to().clone());
            Ok(self
                .trust_verification_history
                .get(&key)
                .cloned()
                .unwrap_or_default())
        }
    }

    // Helper function to create a test verification result
    fn create_test_verification_result(
        requester_id: AgentId,
        target_id: AgentId,
        status: VerificationStatus,
        trust_score: Option<TrustScore>,
    ) -> VerificationResult {
        VerificationResult {
            request: VerificationRequest {
                id: "test-verification".to_string(),
                requester_id,
                target_id,
                policy: VerificationPolicy {
                    name: "test-policy".to_string(),
                    description: "Test verification policy".to_string(),
                    required_level: TrustLevel::High,
                    min_verifiers: 1,
                    require_consensus: true,
                    verification_period: Duration::hours(1),
                    metadata: Default::default(),
                },
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                metadata: Default::default(),
            },
            status,
            verified_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            trust_score,
            evidence: Default::default(),
            failure_reasons: Default::default(),
        }
    }

    // Helper function to create a test trust score
    fn create_test_trust_score(score: f64, level: TrustLevel) -> TrustScore {
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

    #[test]
    fn test_verification_result_creation() {
        let agent = AgentId::new("verifier");
        let request = VerificationRequest {
            id: "test".to_string(),
            requester_id: agent.clone(),
            target_id: agent.clone(),
            policy: VerificationPolicy {
                name: "test".to_string(),
                description: "test".to_string(),
                required_level: TrustLevel::High,
                min_verifiers: 1,
                require_consensus: true,
                verification_period: Duration::hours(1),
                metadata: Default::default(),
            },
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            metadata: Default::default(),
        };

        let metrics = TrustMetrics {
            direct_trust: 0.8,
            indirect_trust: 0.7,
            historical_trust: 0.9,
            behavioral_trust: 0.85,
            identity_verification: 1.0,
            custom_metrics: Default::default(),
        };

        let result = VerificationResult {
            request,
            status: VerificationStatus::Verified,
            verified_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            trust_score: Some(TrustScore {
                score: 0.85,
                level: TrustLevel::High,
                metrics,
                timestamp: Utc::now(),
                confidence: 0.9,
                validity_period: Duration::hours(24),
            }),
            evidence: Default::default(),
            failure_reasons: Default::default(),
        };

        assert_eq!(result.status, VerificationStatus::Verified);
        assert!(result.trust_score.is_some());
        assert_eq!(result.trust_score.as_ref().unwrap().level, TrustLevel::High);
    }

    #[tokio::test]
    async fn test_verifier_identity_verification() {
        let agent = Agent::new("test-agent").unwrap();
        let agent_id = agent.id().clone();
        let verifier_id = AgentId::new("verifier");

        let trust_score = create_test_trust_score(0.85, TrustLevel::High);
        let verification_result = create_test_verification_result(
            verifier_id.clone(),
            agent_id.clone(),
            VerificationStatus::Verified,
            Some(trust_score),
        );

        let verifier = MockVerifier::new()
            .with_verification_result(agent_id.clone(), verification_result.clone());

        let identity = Identity::new(agent).unwrap();

        let result = verifier.verify_identity(&identity).await.unwrap();
        assert_eq!(result.status, VerificationStatus::Verified);
        assert!(result.trust_score.is_some());
        assert_eq!(result.trust_score.unwrap().level, TrustLevel::High);
    }

    #[tokio::test]
    async fn test_verifier_trust_verification() {
        let agent1_id = AgentId::new("agent1");
        let agent2_id = AgentId::new("agent2");
        let verifier_id = AgentId::new("verifier");

        let trust_score = create_test_trust_score(0.9, TrustLevel::VeryHigh);
        let verification_result = create_test_verification_result(
            verifier_id.clone(),
            agent2_id.clone(),
            VerificationStatus::Verified,
            Some(trust_score),
        );

        let verifier = MockVerifier::new()
            .with_verification_result(agent2_id.clone(), verification_result.clone());

        let relationship = TrustRelationship::new(agent1_id, agent2_id, TrustLevel::High).unwrap();
        let verifier_agent = Agent::new("verifier").unwrap();

        let result = verifier
            .verify_trust(&relationship, &verifier_agent)
            .await
            .unwrap();
        assert_eq!(result.status, VerificationStatus::Verified);
        assert!(result.trust_score.is_some());
        assert_eq!(result.trust_score.unwrap().level, TrustLevel::VeryHigh);
    }

    #[tokio::test]
    async fn test_verifier_trust_chain() {
        let agent1_id = AgentId::new("agent1");
        let agent2_id = AgentId::new("agent2");
        let agent3_id = AgentId::new("agent3");
        let verifier_id = AgentId::new("verifier");

        // Create verification results for both agent2 and agent3
        let trust_score2 = create_test_trust_score(0.9, TrustLevel::High);
        let verification_result2 = create_test_verification_result(
            verifier_id.clone(),
            agent2_id.clone(),
            VerificationStatus::Verified,
            Some(trust_score2),
        );

        let trust_score3 = create_test_trust_score(0.95, TrustLevel::VeryHigh);
        let verification_result3 = create_test_verification_result(
            verifier_id.clone(),
            agent3_id.clone(),
            VerificationStatus::Verified,
            Some(trust_score3),
        );

        let verifier = MockVerifier::new()
            .with_verification_result(agent2_id.clone(), verification_result2)
            .with_verification_result(agent3_id.clone(), verification_result3);

        let relationship1 =
            TrustRelationship::new(agent1_id.clone(), agent2_id.clone(), TrustLevel::High).unwrap();
        let relationship2 = TrustRelationship::new(agent2_id, agent3_id, TrustLevel::High).unwrap();
        let verifier_agent = Agent::new("verifier").unwrap();

        let chain = vec![relationship1, relationship2];
        let result = verifier
            .verify_trust_chain(&chain, &verifier_agent)
            .await
            .unwrap();
        assert_eq!(result.status, VerificationStatus::Verified);
        assert!(result.trust_score.is_some());
        assert_eq!(result.trust_score.unwrap().level, TrustLevel::High);
    }

    #[tokio::test]
    async fn test_verification_manager() {
        let agent = Agent::new("test-agent").unwrap();
        let agent_id = agent.id().clone();
        let verifier_agent = Agent::new("verifier").unwrap();
        let verifier_id = verifier_agent.id().clone();

        let trust_score = create_test_trust_score(0.85, TrustLevel::High);
        let verification_result = create_test_verification_result(
            verifier_id.clone(),
            agent_id.clone(),
            VerificationStatus::Verified,
            Some(trust_score),
        );

        let verifier = MockVerifier::new()
            .with_verification_result(agent_id.clone(), verification_result.clone());

        let mut manager = MockVerificationManager::new(verifier);

        let identity = Identity::new(agent).unwrap();

        // Test identity verification
        let result = manager
            .request_verification(identity.clone(), verifier_agent.clone())
            .await
            .unwrap();
        assert_eq!(result.status, VerificationStatus::Verified);

        // Test verification history
        let history = manager.get_verification_history(&identity).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, VerificationStatus::Verified);

        // Test trust verification
        let relationship = TrustRelationship::new(verifier_id, agent_id, TrustLevel::High).unwrap();
        let result = manager
            .request_trust_verification(relationship.clone(), verifier_agent)
            .await
            .unwrap();
        assert_eq!(result.status, VerificationStatus::Verified);

        // Test trust verification history
        let history = manager
            .get_trust_verification_history(&relationship)
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, VerificationStatus::Verified);
    }

    #[tokio::test]
    async fn test_verification_failures() {
        let agent_id = AgentId::new("test-agent");
        let verifier = MockVerifier::new(); // No verification results set up

        let agent = Agent::new("test-agent").unwrap();
        let identity = Identity::new(agent).unwrap();

        // Test identity verification failure
        let result = verifier.verify_identity(&identity).await;
        assert!(result.is_err());

        // Test trust verification failure
        let relationship =
            TrustRelationship::new(AgentId::new("agent1"), agent_id, TrustLevel::High).unwrap();
        let verifier_agent = Agent::new("verifier").unwrap();
        let result = verifier.verify_trust(&relationship, &verifier_agent).await;
        assert!(result.is_err());

        // Test empty trust chain
        let result = verifier.verify_trust_chain(&[], &verifier_agent).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verification_expiration() {
        let agent = Agent::new("test-agent").unwrap();
        let agent_id = agent.id().clone();
        let verifier_agent = Agent::new("verifier").unwrap();
        let verifier_id = verifier_agent.id().clone();

        // Create a verification result that's already expired
        let mut verification_result = create_test_verification_result(
            verifier_id.clone(),
            agent_id.clone(),
            VerificationStatus::Verified,
            Some(create_test_trust_score(0.85, TrustLevel::High)),
        );
        verification_result.expires_at = Utc::now() - Duration::hours(1);

        let verifier = MockVerifier::new()
            .with_verification_result(agent_id.clone(), verification_result.clone());

        let mut manager = MockVerificationManager::new(verifier);

        let identity = Identity::new(agent).unwrap();

        // The verification should still succeed (expiration is handled by the caller)
        let result = manager
            .request_verification(identity, verifier_agent)
            .await
            .unwrap();
        assert_eq!(result.status, VerificationStatus::Verified);
        assert!(result.expires_at < Utc::now());
    }
}
