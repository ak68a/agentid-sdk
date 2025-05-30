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
} 