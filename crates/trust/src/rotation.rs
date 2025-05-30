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

    // New tests for trust requirements
    #[test]
    fn test_trust_requirements() {
        let trust = RotationTrust::new();
        let agent_id = AgentId::new("test");

        // Test trust requirements for different trust levels
        let low_trust = TrustLevel::Low;
        let requirements = trust.get_trust_requirements(&agent_id, low_trust).unwrap();
        assert_eq!(requirements.required_verifiers, 1);
        assert_eq!(requirements.min_trust_level, TrustLevel::Low);

        let high_trust = TrustLevel::High;
        let requirements = trust.get_trust_requirements(&agent_id, high_trust).unwrap();
        assert_eq!(requirements.required_verifiers, 3);
        assert_eq!(requirements.min_trust_level, TrustLevel::Medium);

        // Test trust requirements for new agent
        let new_agent = AgentId::new("new");
        let requirements = trust.get_trust_requirements(&new_agent, TrustLevel::Medium).unwrap();
        assert_eq!(requirements.required_verifiers, 2);
        assert_eq!(requirements.min_trust_level, TrustLevel::Medium);
    }

    #[test]
    fn test_trust_score_updates() {
        let mut trust = RotationTrust::new();
        let agent_id = AgentId::new("test");
        let verifier_id = AgentId::new("verifier");

        // Test successful rotation trust update
        assert!(trust.update_trust(&agent_id, &verifier_id, true).is_ok());
        let score = trust.get_trust_score(&agent_id).unwrap();
        assert!(score > 0.0);

        // Test failed rotation trust update
        assert!(trust.update_trust(&agent_id, &verifier_id, false).is_ok());
        let new_score = trust.get_trust_score(&agent_id).unwrap();
        assert!(new_score < score);

        // Test trust update for new agent
        let new_agent = AgentId::new("new");
        assert!(trust.update_trust(&new_agent, &verifier_id, true).is_ok());
        let score = trust.get_trust_score(&new_agent).unwrap();
        assert!(score > 0.0);
    }

    #[test]
    fn test_verifier_scoring() {
        let trust = RotationTrust::new();
        let agent_id = AgentId::new("test");
        let verifier_id = AgentId::new("verifier");

        // Test verifier scoring
        let score = trust.calculate_verifier_score(&verifier_id, &agent_id).unwrap();
        assert!(score >= 0.0);
        assert!(score <= 1.0);

        // Test scoring with different trust levels
        let high_trust_verifier = AgentId::new("high_trust");
        trust.update_trust(&high_trust_verifier, &agent_id, true).unwrap();
        let high_score = trust.calculate_verifier_score(&high_trust_verifier, &agent_id).unwrap();
        assert!(high_score > score);

        // Test scoring with verification history
        for _ in 0..5 {
            trust.update_trust(&verifier_id, &agent_id, true).unwrap();
        }
        let history_score = trust.calculate_verifier_score(&verifier_id, &agent_id).unwrap();
        assert!(history_score > score);
    }

    #[tokio::test]
    async fn test_rotation_operations() {
        let mut trust = RotationTrust::new();
        let agent_id = AgentId::new("test");
        let now = Utc::now();

        // Test initial state
        let status = trust.get_status().await.unwrap();
        assert!(matches!(status, RotationStatus::Stable));

        // Test scheduling with insufficient trust
        assert!(trust.schedule_rotation("Test rotation".into()).await.is_err());

        // Build up trust
        for _ in 0..5 {
            trust.update_trust(&agent_id, &AgentId::new("verifier"), true).unwrap();
        }

        // Test scheduling with sufficient trust
        assert!(trust.schedule_rotation("Test rotation".into()).await.is_ok());
        let status = trust.get_status().await.unwrap();
        assert!(matches!(status, RotationStatus::Scheduled { .. }));

        // Test beginning rotation
        assert!(trust.begin_rotation().await.is_ok());
        let status = trust.get_status().await.unwrap();
        assert!(matches!(status, RotationStatus::Rotating { .. }));

        // Test completing rotation
        let record = trust.complete_rotation().await.unwrap();
        assert!(record.verified);
        assert_eq!(record.reason, "Test rotation");

        // Test cancellation
        assert!(trust.schedule_rotation("Another rotation".into()).await.is_ok());
        assert!(trust.cancel_rotation().await.is_ok());
        let status = trust.get_status().await.unwrap();
        assert!(matches!(status, RotationStatus::Stable));
    }

    #[test]
    fn test_trust_history() {
        let mut trust = RotationTrust::new();
        let agent_id = AgentId::new("test");
        let verifier_id = AgentId::new("verifier");
        let now = Utc::now();

        // Create trust history
        for i in 0..5 {
            let timestamp = now - chrono::Duration::days(i * 30);
            let success = i % 2 == 0;
            assert!(trust.update_trust_with_timestamp(&agent_id, &verifier_id, success, timestamp).is_ok());
        }

        // Test history retrieval
        let history = trust.get_trust_history(&agent_id).unwrap();
        assert_eq!(history.len(), 5);

        // Test history ordering
        for i in 0..4 {
            assert!(history[i].timestamp > history[i + 1].timestamp);
        }

        // Test history filtering
        let recent_history = trust.get_trust_history_since(&agent_id, now - chrono::Duration::days(60)).unwrap();
        assert_eq!(recent_history.len(), 2);

        // Test success rate calculation
        let success_rate = trust.calculate_success_rate(&agent_id).unwrap();
        assert_eq!(success_rate, 0.6); // 3 successes out of 5 attempts
    }

    #[test]
    fn test_trust_level_transitions() {
        let mut trust = RotationTrust::new();
        let agent_id = AgentId::new("test");
        let verifier_id = AgentId::new("verifier");

        // Test initial trust level
        let initial_level = trust.get_trust_level(&agent_id).unwrap();
        assert_eq!(initial_level, TrustLevel::Low);

        // Test trust level increase
        for _ in 0..10 {
            trust.update_trust(&agent_id, &verifier_id, true).unwrap();
        }
        let increased_level = trust.get_trust_level(&agent_id).unwrap();
        assert!(increased_level > initial_level);

        // Test trust level decrease
        for _ in 0..5 {
            trust.update_trust(&agent_id, &verifier_id, false).unwrap();
        }
        let decreased_level = trust.get_trust_level(&agent_id).unwrap();
        assert!(decreased_level < increased_level);

        // Test trust level stability
        let stable_level = trust.get_trust_level(&agent_id).unwrap();
        for _ in 0..3 {
            trust.update_trust(&agent_id, &verifier_id, true).unwrap();
            trust.update_trust(&agent_id, &verifier_id, false).unwrap();
        }
        let new_level = trust.get_trust_level(&agent_id).unwrap();
        assert_eq!(new_level, stable_level);
    }

    #[test]
    fn test_verifier_selection() {
        let mut trust = RotationTrust::new();
        let agent_id = AgentId::new("test");
        let now = Utc::now();

        // Create pool of verifiers with different trust levels
        let verifiers = vec![
            AgentId::new("verifier1"),
            AgentId::new("verifier2"),
            AgentId::new("verifier3"),
            AgentId::new("verifier4"),
            AgentId::new("verifier5"),
        ];

        // Build up trust for verifiers
        for (i, verifier) in verifiers.iter().enumerate() {
            for _ in 0..(i + 1) {
                trust.update_trust(verifier, &agent_id, true).unwrap();
            }
        }

        // Test verifier selection for different requirements
        let low_requirements = TrustRequirements {
            required_verifiers: 1,
            min_trust_level: TrustLevel::Low,
        };
        let low_verifiers = trust.get_trusted_verifiers(&agent_id, &low_requirements).unwrap();
        assert_eq!(low_verifiers.len(), 1);
        assert!(trust.get_trust_level(&low_verifiers[0]).unwrap() >= TrustLevel::Low);

        let high_requirements = TrustRequirements {
            required_verifiers: 3,
            min_trust_level: TrustLevel::High,
        };
        let high_verifiers = trust.get_trusted_verifiers(&agent_id, &high_requirements).unwrap();
        assert_eq!(high_verifiers.len(), 3);
        for verifier in &high_verifiers {
            assert!(trust.get_trust_level(verifier).unwrap() >= TrustLevel::High);
        }

        // Test verifier selection with insufficient trust
        let impossible_requirements = TrustRequirements {
            required_verifiers: 5,
            min_trust_level: TrustLevel::High,
        };
        assert!(trust.get_trusted_verifiers(&agent_id, &impossible_requirements).is_err());
    }
} 