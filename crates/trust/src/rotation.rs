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
    TrustLevel,
    TrustScore,
    TrustService,
    TrustRequirements,
    TrustScoreUpdate,
};

/// Trust operations for key rotation
pub struct RotationTrust {
    trust_service: TrustService,
    config: RotationConfig,
    status: RotationStatus,
}

impl RotationTrust {
    pub fn new(trust_service: TrustService, config: RotationConfig) -> Self {
        Self {
            trust_service,
            config,
            status: RotationStatus::Stable,
        }
    }

    /// Get trust requirements for rotation
    async fn get_trust_requirements(&self, agent: &Agent) -> CoreResult<TrustRequirements> {
        let trust_score = self.trust_service.get_trust_score(agent.id()).await
            .map_err(|e| RotationError::Internal(e.to_string()))?;
        
        // Determine required trust level based on history
        let required_level = if trust_score.rotation_history.is_empty() {
            TrustLevel::High // Require high trust for first rotation
        } else {
            match trust_score.level {
                TrustLevel::High => TrustLevel::Medium,
                TrustLevel::Medium => TrustLevel::Medium,
                TrustLevel::Low => TrustLevel::High,
            }
        };

        Ok(TrustRequirements {
            required_level,
            min_verifiers: match required_level {
                TrustLevel::High => 3,
                TrustLevel::Medium => 2,
                TrustLevel::Low => 1,
            },
            require_consensus: required_level == TrustLevel::High,
        })
    }

    /// Update trust based on rotation
    async fn update_trust(&mut self, agent: &Agent, rotation: &RotationRecord) -> CoreResult<()> {
        let mut trust_update = TrustScoreUpdate::new();
        
        if rotation.verified {
            trust_update = trust_update
                .with_key_rotation_success()
                .with_trust_impact(0.1); // Positive impact for successful rotation
        } else {
            trust_update = trust_update
                .with_key_rotation_failure()
                .with_trust_impact(-0.1); // Negative impact for failed rotation
        }

        // Update trust score
        self.trust_service.update_trust_score(
            agent.id(),
            trust_update,
        ).await.map_err(|e| RotationError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Get trusted agents for verification
    async fn get_trusted_verifiers(
        &self,
        agent: &Agent,
        required_level: TrustLevel,
        count: usize,
    ) -> CoreResult<Vec<Agent>> {
        // Get potential verifiers
        let potential_verifiers = self.trust_service.get_trusted_agents(
            agent.id(),
            required_level,
            Some(count * 2), // Get more than needed for filtering
        ).await.map_err(|e| RotationError::Internal(e.to_string()))?;

        // Score and sort verifiers
        let mut scored_verifiers: Vec<(Agent, f64)> = Vec::new();
        for verifier in potential_verifiers {
            let score = self.calculate_verifier_score(agent, &verifier).await?;
            scored_verifiers.push((verifier, score));
        }

        // Sort by score and take top N
        scored_verifiers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        Ok(scored_verifiers.into_iter()
            .take(count)
            .map(|(agent, _)| agent)
            .collect())
    }

    /// Calculate a verifier's suitability score
    async fn calculate_verifier_score(
        &self,
        agent: &Agent,
        verifier: &Agent,
    ) -> CoreResult<f64> {
        let mut score = 0.0;

        // Base score from trust level
        let trust_level = self.trust_service.get_trust_level(verifier.id()).await
            .map_err(|e| RotationError::Internal(e.to_string()))?;
        score += match trust_level {
            TrustLevel::High => 1.0,
            TrustLevel::Medium => 0.7,
            TrustLevel::Low => 0.4,
        };

        // Previous verification history
        let verification_history = self.trust_service.get_verification_history(
            agent.id(),
            verifier.id(),
        ).await.map_err(|e| RotationError::Internal(e.to_string()))?;
        
        let successful_verifications = verification_history.iter()
            .filter(|v| v.successful)
            .count();
        
        score += (successful_verifications as f64) * 0.1;

        // Trust stability bonus
        let trust_stability = self.trust_service.get_trust_stability(verifier.id()).await
            .map_err(|e| RotationError::Internal(e.to_string()))?;
        if trust_stability.is_stable() {
            score += 0.2;
        }

        // Recent activity bonus
        let recent_activity = self.trust_service.get_recent_activity(verifier.id()).await
            .map_err(|e| RotationError::Internal(e.to_string()))?;
        if recent_activity.is_active() {
            score += 0.1;
        }

        Ok(score)
    }
}

#[async_trait]
impl RotationOperations for RotationTrust {
    async fn get_config(&self) -> CoreResult<RotationConfig> {
        Ok(self.config.clone())
    }

    async fn get_status(&self) -> CoreResult<RotationStatus> {
        Ok(self.status.clone())
    }

    async fn get_history(&self, limit: Option<usize>) -> CoreResult<Vec<RotationRecord>> {
        // Get rotation history from trust service
        let history = self.trust_service.get_agent_metadata(self.trust_service.current_agent().id())
            .await
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
                // Get trust score
                let trust_score = self.trust_service.get_trust_score(
                    self.trust_service.current_agent().id()
                ).await.map_err(|e| RotationError::Internal(e.to_string()))?;

                // Check if trust level requires rotation
                if trust_score.level == TrustLevel::Low {
                    return Ok(true);
                }

                // Check rotation history
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
                // Check trust requirements
                let requirements = self.get_trust_requirements(
                    &self.trust_service.current_agent()
                ).await?;

                if requirements.required_level == TrustLevel::High {
                    return Err(RotationError::NotAllowed(
                        "Insufficient trust level for rotation".into()
                    ));
                }

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
                // Get trust requirements
                let requirements = self.get_trust_requirements(
                    &self.trust_service.current_agent()
                ).await?;

                // Get trusted verifiers
                let verifiers = self.get_trusted_verifiers(
                    &self.trust_service.current_agent(),
                    requirements.required_level,
                    requirements.min_verifiers,
                ).await?;

                if verifiers.is_empty() {
                    return Err(RotationError::NotAllowed(
                        "No trusted verifiers available".into()
                    ));
                }

                // Update status to indicate verification is needed
                self.status = RotationStatus::Rotating {
                    new_key: self.trust_service.current_agent().public_key().clone(),
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
                // Get trust requirements
                let requirements = self.get_trust_requirements(
                    &self.trust_service.current_agent()
                ).await?;

                // Verify we have enough verifications
                if verifications.len() < requirements.min_verifiers {
                    return Err(RotationError::VerificationFailed(
                        "Insufficient verifications".into()
                    ));
                }

                // Check consensus if required
                if requirements.require_consensus {
                    let all_verified = verifications.iter().all(|v| v.is_verified());
                    if !all_verified {
                        return Err(RotationError::VerificationFailed(
                            "No consensus among verifiers".into()
                        ));
                    }
                }

                // Create rotation record
                let record = RotationRecord {
                    old_key: self.trust_service.current_agent().public_key().clone(),
                    new_key: new_key.clone(),
                    rotated_at: Utc::now(),
                    reason: "Trust-based rotation".to_string(),
                    verified: true,
                    verified_by: verifications.first().map(|v| v.verifier_id().clone()),
                    metadata: HashMap::from([
                        ("trust_level".to_string(), json!(requirements.required_level)),
                        ("verification_count".to_string(), json!(verifications.len())),
                    ]),
                };

                // Update trust
                self.update_trust(&self.trust_service.current_agent(), &record).await?;

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
                // Update trust to reflect cancellation
                let trust_update = TrustScoreUpdate::new()
                    .with_key_rotation_failure()
                    .with_trust_impact(-0.05); // Small negative impact for cancellation

                self.trust_service.update_trust_score(
                    self.trust_service.current_agent().id(),
                    trust_update,
                ).await.map_err(|e| RotationError::Internal(e.to_string()))?;

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
    use crate::TrustService;

    #[tokio::test]
    async fn test_rotation_trust_basic() {
        let trust_service = TrustService::new();
        let config = RotationConfig {
            rotation_period: chrono::Duration::days(90),
            overlap_period: chrono::Duration::days(7),
            max_key_age: chrono::Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };

        let mut rotation = RotationTrust::new(trust_service, config);

        // Test trust requirements
        let agent = Agent::new("test-agent");
        let requirements = rotation.get_trust_requirements(&agent).await.unwrap();
        assert_eq!(requirements.required_level, TrustLevel::High); // First rotation

        // Test scheduling with insufficient trust
        assert!(rotation.schedule_rotation("Test rotation".into()).await.is_err());

        // Test cancellation
        assert!(rotation.cancel_rotation().await.is_ok());
        assert!(matches!(rotation.get_status().await.unwrap(), RotationStatus::Failed { .. }));
    }

    #[tokio::test]
    async fn test_rotation_trust_verifiers() {
        let trust_service = TrustService::new();
        let config = RotationConfig {
            rotation_period: chrono::Duration::days(90),
            overlap_period: chrono::Duration::days(7),
            max_key_age: chrono::Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };

        let rotation = RotationTrust::new(trust_service, config);

        // Test verifier selection
        let agent = Agent::new("test-agent");
        let verifiers = rotation.get_trusted_verifiers(
            &agent,
            TrustLevel::High,
            3,
        ).await.unwrap();

        assert!(verifiers.len() <= 3);
        // Additional assertions about verifier trust levels and scores
    }
} 