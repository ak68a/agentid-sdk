//! Verification implementation for the ACK ID protocol.
//!
//! This module provides the core verification types and their implementation,
//! which handle the verification of agent identities and trust relationships.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{Agent, AgentIdError, Identity, Result};
use agentid_types::{
    AgentId, TrustLevel, TrustMetrics, TrustRelationship, TrustScore, VerificationLevel,
    VerificationPolicy, VerificationRequest, VerificationResult, VerificationStatus,
};

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
}
