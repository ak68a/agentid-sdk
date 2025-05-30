use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

use agentid_core::{
    Agent,
    AgentId,
    Result as CoreResult,
    rotation::{
        RotationConfig,
        RotationRecord,
        RotationStatus,
        RotationOperations,
        RotationError,
    },
};
use crate::{
    VerificationPolicy,
    VerificationRequest,
    VerificationResult,
    VerificationService,
    VerificationStatus,
};

/// Verification operations for key rotation
pub struct RotationVerifier {
    verification_service: VerificationService,
    config: RotationConfig,
    status: RotationStatus,
}

impl RotationVerifier {
    pub fn new(verification_service: VerificationService, config: RotationConfig) -> Self {
        Self {
            verification_service,
            config,
            status: RotationStatus::Stable,
        }
    }

    /// Create a verification policy for key rotation
    fn create_rotation_policy(&self, agent: &Agent, required_level: TrustLevel) -> VerificationPolicy {
        VerificationPolicy {
            name: "key_rotation".to_string(),
            description: "Verify key rotation for agent".to_string(),
            required_level,
            min_verifiers: match required_level {
                TrustLevel::High => 3,
                TrustLevel::Medium => 2,
                TrustLevel::Low => 1,
            },
            require_consensus: required_level == TrustLevel::High,
            verification_period: self.config.overlap_period,
            metadata: HashMap::from([
                ("rotation_type".to_string(), json!("key_rotation")),
                ("agent_id".to_string(), json!(agent.id().to_string())),
            ]),
        }
    }

    /// Create a verification request for key rotation
    async fn create_rotation_request(
        &self,
        agent: &Agent,
        new_key: &PublicKey,
        policy: &VerificationPolicy,
    ) -> CoreResult<VerificationRequest> {
        let request = VerificationRequest {
            id: Uuid::new_v4(),
            agent_id: agent.id().clone(),
            policy: policy.clone(),
            status: VerificationStatus::Pending,
            created_at: Utc::now(),
            expires_at: Utc::now() + policy.verification_period,
            metadata: HashMap::from([
                ("new_key".to_string(), json!(new_key.to_string())),
                ("rotation_type".to_string(), json!("key_rotation")),
            ]),
        };

        // Store request in verification service
        self.verification_service.store_request(&request).await
            .map_err(|e| RotationError::Internal(e.to_string()))?;

        Ok(request)
    }

    /// Verify a key rotation request
    async fn verify_rotation(
        &self,
        request: &VerificationRequest,
        verifier: &Agent,
        proof: &[u8],
    ) -> CoreResult<VerificationResult> {
        // Verify the proof
        let is_valid = self.verification_service.verify_proof(
            request,
            verifier.id(),
            proof,
        ).await.map_err(|e| RotationError::Internal(e.to_string()))?;

        // Create verification result
        let result = VerificationResult {
            request_id: request.id,
            verifier_id: verifier.id().clone(),
            verified_at: Utc::now(),
            successful: is_valid,
            level: request.policy.required_level,
            metadata: HashMap::from([
                ("verification_type".to_string(), json!("key_rotation")),
                ("proof_valid".to_string(), json!(is_valid)),
            ]),
        };

        // Store result
        self.verification_service.store_result(&result).await
            .map_err(|e| RotationError::Internal(e.to_string()))?;

        Ok(result)
    }

    /// Get verification results for a rotation
    async fn get_rotation_verifications(
        &self,
        request: &VerificationRequest,
    ) -> CoreResult<Vec<VerificationResult>> {
        self.verification_service.get_results(request.id).await
            .map_err(|e| RotationError::Internal(e.to_string()))
    }

    /// Check if verification requirements are met
    async fn check_verification_requirements(
        &self,
        request: &VerificationRequest,
        results: &[VerificationResult],
    ) -> CoreResult<bool> {
        // Check minimum verifiers
        if results.len() < request.policy.min_verifiers {
            return Ok(false);
        }

        // Check consensus if required
        if request.policy.require_consensus {
            let all_verified = results.iter().all(|r| r.successful);
            if !all_verified {
                return Ok(false);
            }
        }

        // Check verification level
        let all_meet_level = results.iter()
            .all(|r| r.level >= request.policy.required_level);
        if !all_meet_level {
            return Ok(false);
        }

        Ok(true)
    }
}

#[async_trait]
impl RotationOperations for RotationVerifier {
    async fn get_config(&self) -> CoreResult<RotationConfig> {
        Ok(self.config.clone())
    }

    async fn get_status(&self) -> CoreResult<RotationStatus> {
        Ok(self.status.clone())
    }

    async fn get_history(&self, limit: Option<usize>) -> CoreResult<Vec<RotationRecord>> {
        // Get rotation history from verification service
        let history = self.verification_service.get_agent_metadata(
            self.verification_service.current_agent().id()
        ).await
            .map_err(|e| RotationError::Internal(e.to_string()))?
            .get("key_rotation_history")
            .and_then(|h| serde_json::from_value::<Vec<RotationRecord>>(h.clone()).ok())
            .unwrap_or_default();

        let mut history = history;
        if let Some(limit) = limit {
            history.truncate(limit);
        }
        Ok(history)
    }

    async fn check_rotation_needed(&self) -> CoreResult<bool> {
        match &self.status {
            RotationStatus::Stable => {
                // Check verification history
                if let Some(last_rotation) = self.get_history(Some(1)).await?.first() {
                    let key_age = Utc::now() - last_rotation.rotated_at;
                    if key_age > self.config.max_key_age {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    async fn schedule_rotation(&mut self, reason: String) -> CoreResult<()> {
        match &self.status {
            RotationStatus::Stable => {
                let scheduled_at = Utc::now() + self.config.rotation_period;
                self.status = RotationStatus::Scheduled { scheduled_at };
                Ok(())
            }
            _ => Err(RotationError::InvalidState(
                "Cannot schedule rotation in current state".into()
            )),
        }
    }

    async fn begin_rotation(&mut self) -> CoreResult<()> {
        match &self.status {
            RotationStatus::Scheduled { .. } | RotationStatus::Stable => {
                let agent = self.verification_service.current_agent();
                let new_key = agent.public_key().clone();

                // Create verification policy
                let policy = self.create_rotation_policy(&agent, TrustLevel::High);

                // Create verification request
                let request = self.create_rotation_request(&agent, &new_key, &policy).await?;

                // Update status
                self.status = RotationStatus::Rotating {
                    new_key,
                    verifications: Vec::new(),
                };

                Ok(())
            }
            _ => Err(RotationError::InvalidState(
                "Cannot begin rotation in current state".into()
            )),
        }
    }

    async fn complete_rotation(&mut self) -> CoreResult<RotationRecord> {
        match &self.status {
            RotationStatus::Rotating { new_key, verifications } => {
                // Get verification request
                let request = self.verification_service.get_active_request(
                    self.verification_service.current_agent().id()
                ).await
                    .map_err(|e| RotationError::Internal(e.to_string()))?
                    .ok_or_else(|| RotationError::VerificationFailed(
                        "No active verification request".into()
                    ))?;

                // Get verification results
                let results = self.get_rotation_verifications(&request).await?;

                // Check if requirements are met
                if !self.check_verification_requirements(&request, &results).await? {
                    return Err(RotationError::VerificationFailed(
                        "Verification requirements not met".into()
                    ));
                }

                // Create rotation record
                let record = RotationRecord {
                    old_key: self.verification_service.current_agent().public_key().clone(),
                    new_key: new_key.clone(),
                    rotated_at: Utc::now(),
                    reason: "Verified rotation".to_string(),
                    verified: true,
                    verified_by: results.first().map(|r| r.verifier_id.clone()),
                    metadata: HashMap::from([
                        ("verification_count".to_string(), json!(results.len())),
                        ("verification_level".to_string(), json!(request.policy.required_level)),
                    ]),
                };

                // Update status
                self.status = RotationStatus::Complete { record: record.clone() };

                Ok(record)
            }
            _ => Err(RotationError::InvalidState(
                "Cannot complete rotation in current state".into()
            )),
        }
    }

    async fn cancel_rotation(&mut self) -> CoreResult<()> {
        match &self.status {
            RotationStatus::Scheduled { .. } |
            RotationStatus::Distributing { .. } |
            RotationStatus::Rotating { .. } => {
                // Cancel any active verification requests
                if let Ok(Some(request)) = self.verification_service.get_active_request(
                    self.verification_service.current_agent().id()
                ).await {
                    self.verification_service.cancel_request(request.id).await
                        .map_err(|e| RotationError::Internal(e.to_string()))?;
                }

                self.status = RotationStatus::Failed {
                    reason: "Rotation cancelled".into(),
                    error: None,
                };
                Ok(())
            }
            _ => Err(RotationError::InvalidState(
                "Cannot cancel rotation in current state".into()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VerificationService;

    #[tokio::test]
    async fn test_rotation_verifier_basic() {
        let verification_service = VerificationService::new();
        let config = RotationConfig {
            rotation_period: chrono::Duration::days(90),
            overlap_period: chrono::Duration::days(7),
            max_key_age: chrono::Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };

        let mut verifier = RotationVerifier::new(verification_service, config);

        // Test scheduling
        assert!(verifier.schedule_rotation("Test rotation".into()).await.is_ok());
        assert!(matches!(verifier.get_status().await.unwrap(), RotationStatus::Scheduled { .. }));

        // Test beginning rotation
        assert!(verifier.begin_rotation().await.is_ok());
        assert!(matches!(verifier.get_status().await.unwrap(), RotationStatus::Rotating { .. }));

        // Test cancellation
        assert!(verifier.cancel_rotation().await.is_ok());
        assert!(matches!(verifier.get_status().await.unwrap(), RotationStatus::Failed { .. }));
    }

    #[tokio::test]
    async fn test_rotation_verification() {
        let verification_service = VerificationService::new();
        let config = RotationConfig {
            rotation_period: chrono::Duration::days(90),
            overlap_period: chrono::Duration::days(7),
            max_key_age: chrono::Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };

        let verifier = RotationVerifier::new(verification_service, config);

        // Test policy creation
        let agent = Agent::new("test-agent");
        let policy = verifier.create_rotation_policy(&agent, TrustLevel::High);
        assert_eq!(policy.min_verifiers, 3);
        assert!(policy.require_consensus);

        // Test verification request
        let new_key = KeyPair::generate().public_key();
        let request = verifier.create_rotation_request(&agent, &new_key, &policy).await.unwrap();
        assert_eq!(request.status, VerificationStatus::Pending);

        // Test verification
        let verifier_agent = Agent::new("verifier");
        let proof = b"test proof";
        let result = verifier.verify_rotation(&request, &verifier_agent, proof).await.unwrap();
        assert!(!result.successful); // Should fail with invalid proof
    }
} 