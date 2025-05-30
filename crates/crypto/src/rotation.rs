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
} 