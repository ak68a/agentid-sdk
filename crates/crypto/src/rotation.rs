use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

use agentid_core::{
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
    KeyPair,
    PublicKey,
    KeyManager,
    CryptoError,
};

/// Cryptographic operations for key rotation
pub struct RotationCrypto {
    key_manager: KeyManager,
    config: RotationConfig,
    status: RotationStatus,
    history: Vec<RotationRecord>,
}

impl RotationCrypto {
    pub fn new(key_manager: KeyManager, config: RotationConfig) -> Self {
        Self {
            key_manager,
            config,
            status: RotationStatus::Stable,
            history: Vec::new(),
        }
    }

    /// Generate a new key pair for rotation
    async fn generate_rotation_key(&self) -> CoreResult<KeyPair> {
        // Generate new key pair with appropriate parameters
        let new_key = self.key_manager.generate_key_pair().await
            .map_err(|e| RotationError::Internal(e.to_string()))?;
        
        // Validate the new key
        self.validate_rotation_key(&new_key).await?;
        
        Ok(new_key)
    }

    /// Validate a key for rotation
    async fn validate_rotation_key(&self, key: &KeyPair) -> CoreResult<()> {
        // Check key strength
        if !self.key_manager.validate_key_strength(key).await
            .map_err(|e| RotationError::Internal(e.to_string()))? {
            return Err(RotationError::NotAllowed(
                "Key does not meet strength requirements".into()
            ));
        }

        // Check if key is different from current key
        if key.public_key() == self.key_manager.current_public_key().await
            .map_err(|e| RotationError::Internal(e.to_string()))? {
            return Err(RotationError::NotAllowed(
                "New key must be different from current key".into()
            ));
        }

        Ok(())
    }

    /// Generate proof of key ownership
    async fn generate_ownership_proof(&self, key: &KeyPair) -> CoreResult<Vec<u8>> {
        // Create a challenge
        let challenge = self.key_manager.generate_challenge().await
            .map_err(|e| RotationError::Internal(e.to_string()))?;
        
        // Sign the challenge with the key
        let signature = self.key_manager.sign(&challenge, key).await
            .map_err(|e| RotationError::Internal(e.to_string()))?;
        
        // Combine challenge and signature
        Ok([challenge.as_ref(), signature.as_ref()].concat())
    }

    /// Verify key ownership
    async fn verify_ownership(&self, key: &PublicKey, proof: &[u8]) -> CoreResult<bool> {
        // Split proof into challenge and signature
        let (challenge, signature) = proof.split_at(32);
        
        // Verify signature
        self.key_manager.verify(challenge, signature, key).await
            .map_err(|e| RotationError::Internal(e.to_string()))
    }
}

#[async_trait]
impl RotationOperations for RotationCrypto {
    async fn get_config(&self) -> CoreResult<RotationConfig> {
        Ok(self.config.clone())
    }

    async fn get_status(&self) -> CoreResult<RotationStatus> {
        Ok(self.status.clone())
    }

    async fn get_history(&self, limit: Option<usize>) -> CoreResult<Vec<RotationRecord>> {
        let mut history = self.history.clone();
        if let Some(limit) = limit {
            history.truncate(limit);
        }
        Ok(history)
    }

    async fn check_rotation_needed(&self) -> CoreResult<bool> {
        match &self.status {
            RotationStatus::Stable => {
                // Check if current key is too old
                if let Some(last_rotation) = self.history.last() {
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
                // Generate new key
                let new_key = self.generate_rotation_key().await?;
                
                // Update status
                self.status = RotationStatus::Distributing {
                    new_key: new_key.public_key().clone(),
                    distributed_to: Vec::new(),
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
                // Verify all required verifications are present
                if self.config.require_verification && verifications.is_empty() {
                    return Err(RotationError::VerificationFailed(
                        "Verification required but none provided".into()
                    ));
                }

                // Create rotation record
                let record = RotationRecord {
                    old_key: self.key_manager.current_public_key().await
                        .map_err(|e| RotationError::Internal(e.to_string()))?,
                    new_key: new_key.clone(),
                    rotated_at: Utc::now(),
                    reason: "Scheduled rotation".to_string(),
                    verified: !verifications.is_empty(),
                    verified_by: verifications.first().map(|v| v.verifier_id().clone()),
                    metadata: HashMap::new(),
                };

                // Update key manager
                self.key_manager.rotate_key(new_key.clone()).await
                    .map_err(|e| RotationError::Internal(e.to_string()))?;

                // Update history and status
                self.history.push(record.clone());
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
    use crate::KeyManager;

    #[tokio::test]
    async fn test_rotation_crypto_basic() {
        let key_manager = KeyManager::new();
        let config = RotationConfig {
            rotation_period: chrono::Duration::days(90),
            overlap_period: chrono::Duration::days(7),
            max_key_age: chrono::Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };

        let mut rotation = RotationCrypto::new(key_manager, config);

        // Test scheduling
        assert!(rotation.schedule_rotation("Test rotation".into()).await.is_ok());
        assert!(matches!(rotation.get_status().await.unwrap(), RotationStatus::Scheduled { .. }));

        // Test beginning rotation
        assert!(rotation.begin_rotation().await.is_ok());
        assert!(matches!(rotation.get_status().await.unwrap(), RotationStatus::Distributing { .. }));

        // Test cancellation
        assert!(rotation.cancel_rotation().await.is_ok());
        assert!(matches!(rotation.get_status().await.unwrap(), RotationStatus::Failed { .. }));
    }

    #[tokio::test]
    async fn test_rotation_crypto_validation() {
        let key_manager = KeyManager::new();
        let config = RotationConfig {
            rotation_period: chrono::Duration::days(90),
            overlap_period: chrono::Duration::days(7),
            max_key_age: chrono::Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };

        let rotation = RotationCrypto::new(key_manager, config);

        // Test key generation
        let new_key = rotation.generate_rotation_key().await.unwrap();
        assert!(rotation.validate_rotation_key(&new_key).await.is_ok());

        // Test ownership proof
        let proof = rotation.generate_ownership_proof(&new_key).await.unwrap();
        assert!(rotation.verify_ownership(new_key.public_key(), &proof).await.unwrap());
    }

    #[test]
    fn test_key_generation_and_validation() {
        let crypto = RotationCrypto::new();
        let agent_id = AgentId::new("test");

        // Test key generation
        let (new_key, proof) = crypto.generate_rotation_key().unwrap();
        assert!(new_key.is_valid());
        assert!(!proof.is_empty());

        // Test key validation
        assert!(crypto.validate_rotation_key(&new_key).is_ok());

        // Test invalid key validation
        let invalid_key = KeyPair::generate().public_key();
        assert!(crypto.validate_rotation_key(&invalid_key).is_err());

        // Test key strength validation
        let weak_key = KeyPair::generate_weak().public_key();
        assert!(crypto.validate_rotation_key(&weak_key).is_err());
    }

    #[test]
    fn test_ownership_proof() {
        let crypto = RotationCrypto::new();
        let agent_id = AgentId::new("test");
        let key_pair = KeyPair::generate();

        // Test proof generation
        let proof = crypto.generate_ownership_proof(&key_pair).unwrap();
        assert!(!proof.is_empty());

        // Test proof verification
        assert!(crypto.verify_ownership(key_pair.public_key(), &proof).is_ok());

        // Test invalid proof
        let invalid_proof = vec![0u8; 32];
        assert!(crypto.verify_ownership(key_pair.public_key(), &invalid_proof).is_err());

        // Test proof with wrong agent
        let wrong_agent = AgentId::new("wrong");
        assert!(crypto.verify_ownership(key_pair.public_key(), &proof).is_err());
    }

    #[test]
    fn test_key_distribution() {
        let crypto = RotationCrypto::new();
        let agent_id = AgentId::new("test");
        let verifier_id = AgentId::new("verifier");
        let key_pair = KeyPair::generate();

        // Test key distribution
        let distributed = crypto.distribute_key(&key_pair.public_key(), &agent_id, &verifier_id).unwrap();
        assert!(distributed.contains(&verifier_id));

        // Test duplicate distribution
        assert!(crypto.distribute_key(&key_pair.public_key(), &agent_id, &verifier_id).is_err());

        // Test distribution to self
        assert!(crypto.distribute_key(&key_pair.public_key(), &agent_id, &agent_id).is_err());
    }

    #[tokio::test]
    async fn test_rotation_operations() {
        let mut crypto = RotationCrypto::new();
        let agent_id = AgentId::new("test");
        let now = Utc::now();

        // Test initial state
        let status = crypto.get_status().await.unwrap();
        assert!(matches!(status, RotationStatus::Stable));

        // Test scheduling rotation
        assert!(crypto.schedule_rotation("Test rotation".into()).await.is_ok());
        let status = crypto.get_status().await.unwrap();
        assert!(matches!(status, RotationStatus::Scheduled { .. }));

        // Test beginning rotation
        assert!(crypto.begin_rotation().await.is_ok());
        let status = crypto.get_status().await.unwrap();
        assert!(matches!(status, RotationStatus::Distributing { .. }));

        // Test completing rotation
        let record = crypto.complete_rotation().await.unwrap();
        assert!(record.verified);
        assert_eq!(record.reason, "Test rotation");

        // Test cancellation
        assert!(crypto.schedule_rotation("Another rotation".into()).await.is_ok());
        assert!(crypto.cancel_rotation().await.is_ok());
        let status = crypto.get_status().await.unwrap();
        assert!(matches!(status, RotationStatus::Stable));
    }

    #[test]
    fn test_rotation_history() {
        let crypto = RotationCrypto::new();
        let agent_id = AgentId::new("test");
        let now = Utc::now();

        // Create some rotation records
        let record1 = RotationRecord {
            old_key: KeyPair::generate().public_key(),
            new_key: KeyPair::generate().public_key(),
            rotated_at: now - chrono::Duration::days(90),
            reason: "First rotation".to_string(),
            verified: true,
            verified_by: Some(AgentId::new("verifier1")),
            metadata: HashMap::new(),
        };

        let record2 = RotationRecord {
            old_key: KeyPair::generate().public_key(),
            new_key: KeyPair::generate().public_key(),
            rotated_at: now - chrono::Duration::days(30),
            reason: "Second rotation".to_string(),
            verified: true,
            verified_by: Some(AgentId::new("verifier2")),
            metadata: HashMap::new(),
        };

        // Test history management
        assert!(crypto.add_rotation_record(record1.clone()).is_ok());
        assert!(crypto.add_rotation_record(record2.clone()).is_ok());

        // Test history retrieval
        let history = crypto.get_rotation_history().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].reason, "Second rotation");
        assert_eq!(history[1].reason, "First rotation");

        // Test history limit
        let limited_history = crypto.get_rotation_history_with_limit(1).unwrap();
        assert_eq!(limited_history.len(), 1);
        assert_eq!(limited_history[0].reason, "Second rotation");
    }

    #[test]
    fn test_rotation_config_management() {
        let mut crypto = RotationCrypto::new();
        let config = RotationConfig {
            rotation_period: chrono::Duration::days(90),
            overlap_period: chrono::Duration::days(7),
            max_key_age: chrono::Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };

        // Test config setting
        assert!(crypto.set_rotation_config(config.clone()).is_ok());

        // Test config retrieval
        let retrieved_config = crypto.get_rotation_config().unwrap();
        assert_eq!(retrieved_config.rotation_period, config.rotation_period);
        assert_eq!(retrieved_config.overlap_period, config.overlap_period);
        assert_eq!(retrieved_config.max_key_age, config.max_key_age);
        assert_eq!(retrieved_config.require_verification, config.require_verification);

        // Test invalid config
        let invalid_config = RotationConfig {
            rotation_period: chrono::Duration::days(7),
            overlap_period: chrono::Duration::days(90),
            max_key_age: chrono::Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };
        assert!(crypto.set_rotation_config(invalid_config).is_err());
    }

    #[test]
    fn test_rotation_verification() {
        let crypto = RotationCrypto::new();
        let agent_id = AgentId::new("test");
        let verifier_id = AgentId::new("verifier");
        let key_pair = KeyPair::generate();

        // Test verification process
        let proof = crypto.generate_ownership_proof(&key_pair).unwrap();
        assert!(crypto.verify_rotation(&key_pair.public_key(), &proof, &agent_id, &verifier_id).is_ok());

        // Test invalid verification
        let invalid_proof = vec![0u8; 32];
        assert!(crypto.verify_rotation(&key_pair.public_key(), &invalid_proof, &agent_id, &verifier_id).is_err());

        // Test self-verification
        assert!(crypto.verify_rotation(&key_pair.public_key(), &proof, &agent_id, &agent_id).is_err());

        // Test verification with wrong agent
        let wrong_agent = AgentId::new("wrong");
        assert!(crypto.verify_rotation(&key_pair.public_key(), &proof, &wrong_agent, &verifier_id).is_err());
    }
} 