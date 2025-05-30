use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::AgentId;
use crate::crypto::PublicKey;

#[derive(Debug, Error)]
pub enum RotationError {
    #[error("Invalid rotation state: {0}")]
    InvalidState(String),
    #[error("Rotation not allowed: {0}")]
    NotAllowed(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Distribution failed: {0}")]
    DistributionFailed(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, RotationError>;

/// Core configuration for key rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// How often keys should be rotated
    pub rotation_period: Duration,
    /// How long the old key should remain valid after rotation
    pub overlap_period: Duration,
    /// Maximum age a key can be before forced rotation
    pub max_key_age: Duration,
    /// Whether verification is required after rotation
    pub require_verification: bool,
    /// Additional configuration
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Current state of key rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationStatus {
    /// No rotation in progress
    Stable,
    /// Rotation has been scheduled
    Scheduled {
        scheduled_at: DateTime<Utc>,
    },
    /// New key is being distributed
    Distributing {
        new_key: PublicKey,
        distributed_to: Vec<AgentId>,
    },
    /// Rotation is in progress
    Rotating {
        new_key: PublicKey,
        verifications: Vec<VerificationResult>,
    },
    /// Rotation is complete
    Complete {
        record: RotationRecord,
    },
    /// Rotation failed
    Failed {
        reason: String,
        error: Option<String>,
    },
}

/// Record of a key rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecord {
    /// The old key that was rotated out
    pub old_key: PublicKey,
    /// The new key that was rotated in
    pub new_key: PublicKey,
    /// When the rotation occurred
    pub rotated_at: DateTime<Utc>,
    /// Why the rotation occurred
    pub reason: String,
    /// Whether the rotation was verified
    pub verified: bool,
    /// Who verified the rotation (if applicable)
    pub verified_by: Option<AgentId>,
    /// Additional rotation metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Core operations for key rotation
#[async_trait::async_trait]
pub trait RotationOperations {
    /// Get the current rotation configuration
    async fn get_config(&self) -> Result<RotationConfig>;
    
    /// Get the current rotation status
    async fn get_status(&self) -> Result<RotationStatus>;
    
    /// Get rotation history
    async fn get_history(&self, limit: Option<usize>) -> Result<Vec<RotationRecord>>;
    
    /// Check if rotation is needed
    async fn check_rotation_needed(&self) -> Result<bool>;
    
    /// Schedule a rotation
    async fn schedule_rotation(&mut self, reason: String) -> Result<()>;
    
    /// Begin the rotation process
    async fn begin_rotation(&mut self) -> Result<()>;
    
    /// Complete the rotation process
    async fn complete_rotation(&mut self) -> Result<RotationRecord>;
    
    /// Cancel an in-progress rotation
    async fn cancel_rotation(&mut self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use chrono::{Duration, Utc};

    #[test]
    fn test_rotation_config_serialization() {
        let config = RotationConfig {
            rotation_period: Duration::days(90),
            overlap_period: Duration::days(7),
            max_key_age: Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: RotationConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config.rotation_period, deserialized.rotation_period);
        assert_eq!(config.overlap_period, deserialized.overlap_period);
        assert_eq!(config.max_key_age, deserialized.max_key_age);
        assert_eq!(config.require_verification, deserialized.require_verification);
    }

    #[test]
    fn test_rotation_record_creation() {
        let old_key = KeyPair::generate().public_key();
        let new_key = KeyPair::generate().public_key();
        let now = Utc::now();

        let record = RotationRecord {
            old_key: old_key.clone(),
            new_key: new_key.clone(),
            rotated_at: now,
            reason: "Test rotation".to_string(),
            verified: true,
            verified_by: Some(AgentId::new()),
            metadata: HashMap::new(),
        };

        assert_eq!(record.old_key, old_key);
        assert_eq!(record.new_key, new_key);
        assert!(record.verified);
        assert!(record.verified_by.is_some());
    }

    #[test]
    fn test_rotation_status_transitions() {
        let now = Utc::now();
        
        // Test Stable -> Scheduled
        let scheduled = RotationStatus::Scheduled { scheduled_at: now };
        assert!(matches!(scheduled, RotationStatus::Scheduled { .. }));

        // Test Scheduled -> Distributing
        let distributing = RotationStatus::Distributing {
            new_key: KeyPair::generate().public_key(),
            distributed_to: Vec::new(),
        };
        assert!(matches!(distributing, RotationStatus::Distributing { .. }));

        // Test Distributing -> Rotating
        let rotating = RotationStatus::Rotating {
            new_key: KeyPair::generate().public_key(),
            verifications: Vec::new(),
        };
        assert!(matches!(rotating, RotationStatus::Rotating { .. }));

        // Test Rotating -> Complete
        let record = RotationRecord {
            old_key: KeyPair::generate().public_key(),
            new_key: KeyPair::generate().public_key(),
            rotated_at: now,
            reason: "Test".to_string(),
            verified: true,
            verified_by: Some(AgentId::new("test")),
            metadata: HashMap::new(),
        };
        let complete = RotationStatus::Complete { record };
        assert!(matches!(complete, RotationStatus::Complete { .. }));

        // Test -> Failed
        let failed = RotationStatus::Failed {
            reason: "Test failure".to_string(),
            error: Some("Test error".to_string()),
        };
        assert!(matches!(failed, RotationStatus::Failed { .. }));
    }

    #[test]
    fn test_rotation_error_variants() {
        let invalid_state = RotationError::InvalidState("test".to_string());
        assert!(matches!(invalid_state, RotationError::InvalidState(_)));

        let not_allowed = RotationError::NotAllowed("test".to_string());
        assert!(matches!(not_allowed, RotationError::NotAllowed(_)));

        let verification_failed = RotationError::VerificationFailed("test".to_string());
        assert!(matches!(verification_failed, RotationError::VerificationFailed(_)));

        let distribution_failed = RotationError::DistributionFailed("test".to_string());
        assert!(matches!(distribution_failed, RotationError::DistributionFailed(_)));

        let internal = RotationError::Internal("test".to_string());
        assert!(matches!(internal, RotationError::Internal(_)));
    }

    #[test]
    fn test_rotation_config_validation() {
        // Test valid config
        let valid_config = RotationConfig {
            rotation_period: Duration::days(90),
            overlap_period: Duration::days(7),
            max_key_age: Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };
        assert!(valid_config.rotation_period > valid_config.overlap_period);
        assert!(valid_config.max_key_age > valid_config.rotation_period);

        // Test invalid config (overlap > rotation period)
        let invalid_config = RotationConfig {
            rotation_period: Duration::days(7),
            overlap_period: Duration::days(90),
            max_key_age: Duration::days(365),
            require_verification: true,
            metadata: HashMap::new(),
        };
        assert!(invalid_config.overlap_period > invalid_config.rotation_period);
    }

    #[test]
    fn test_rotation_record_validation() {
        let old_key = KeyPair::generate().public_key();
        let new_key = KeyPair::generate().public_key();
        let now = Utc::now();

        // Test valid record
        let valid_record = RotationRecord {
            old_key: old_key.clone(),
            new_key: new_key.clone(),
            rotated_at: now,
            reason: "Test rotation".to_string(),
            verified: true,
            verified_by: Some(AgentId::new("test")),
            metadata: HashMap::new(),
        };
        assert!(valid_record.verified);
        assert!(valid_record.verified_by.is_some());

        // Test unverified record
        let unverified_record = RotationRecord {
            old_key: old_key.clone(),
            new_key: new_key.clone(),
            rotated_at: now,
            reason: "Test rotation".to_string(),
            verified: false,
            verified_by: None,
            metadata: HashMap::new(),
        };
        assert!(!unverified_record.verified);
        assert!(unverified_record.verified_by.is_none());

        // Test record with metadata
        let mut metadata = HashMap::new();
        metadata.insert("test_key".to_string(), json!("test_value"));
        let record_with_metadata = RotationRecord {
            old_key,
            new_key,
            rotated_at: now,
            reason: "Test rotation".to_string(),
            verified: true,
            verified_by: Some(AgentId::new("test")),
            metadata,
        };
        assert!(record_with_metadata.metadata.contains_key("test_key"));
    }

    #[tokio::test]
    async fn test_rotation_operations() {
        struct MockRotation;
        
        #[async_trait]
        impl RotationOperations for MockRotation {
            async fn get_config(&self) -> Result<RotationConfig> {
                Ok(RotationConfig {
                    rotation_period: Duration::days(90),
                    overlap_period: Duration::days(7),
                    max_key_age: Duration::days(365),
                    require_verification: true,
                    metadata: HashMap::new(),
                })
            }

            async fn get_status(&self) -> Result<RotationStatus> {
                Ok(RotationStatus::Stable)
            }

            async fn get_history(&self, limit: Option<usize>) -> Result<Vec<RotationRecord>> {
                Ok(Vec::new())
            }

            async fn check_rotation_needed(&self) -> Result<bool> {
                Ok(false)
            }

            async fn schedule_rotation(&mut self, _reason: String) -> Result<()> {
                Ok(())
            }

            async fn begin_rotation(&mut self) -> Result<()> {
                Ok(())
            }

            async fn complete_rotation(&mut self) -> Result<RotationRecord> {
                Ok(RotationRecord {
                    old_key: KeyPair::generate().public_key(),
                    new_key: KeyPair::generate().public_key(),
                    rotated_at: Utc::now(),
                    reason: "Test".to_string(),
                    verified: true,
                    verified_by: Some(AgentId::new("test")),
                    metadata: HashMap::new(),
                })
            }

            async fn cancel_rotation(&mut self) -> Result<()> {
                Ok(())
            }
        }

        let mut mock = MockRotation;

        // Test get_config
        let config = mock.get_config().await.unwrap();
        assert_eq!(config.rotation_period, Duration::days(90));

        // Test get_status
        let status = mock.get_status().await.unwrap();
        assert!(matches!(status, RotationStatus::Stable));

        // Test get_history
        let history = mock.get_history(Some(10)).await.unwrap();
        assert!(history.is_empty());

        // Test check_rotation_needed
        let needed = mock.check_rotation_needed().await.unwrap();
        assert!(!needed);

        // Test schedule_rotation
        assert!(mock.schedule_rotation("test".into()).await.is_ok());

        // Test begin_rotation
        assert!(mock.begin_rotation().await.is_ok());

        // Test complete_rotation
        let record = mock.complete_rotation().await.unwrap();
        assert!(record.verified);

        // Test cancel_rotation
        assert!(mock.cancel_rotation().await.is_ok());
    }
} 