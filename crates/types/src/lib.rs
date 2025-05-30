//! Shared types and traits for AgentID SDK

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

// AgentId and related types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

impl AgentId {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            created_at: Utc::now(),
        }
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCapabilities {
    pub can_commerce: bool,
    pub can_verify: bool,
    pub can_manage_trust: bool,
}

impl Default for AgentCapabilities {
    fn default() -> Self {
        Self {
            can_commerce: true,
            can_verify: false,
            can_manage_trust: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Active,
    Suspended,
    Revoked,
}

impl Default for AgentStatus {
    fn default() -> Self {
        Self::Active
    }
}

// Remove rotation types
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("Invalid agent ID: {0}")]
    InvalidId(String),
    #[error("Invalid agent name: {0}")]
    InvalidName(String),
    #[error("Invalid agent capabilities: {0}")]
    InvalidCapabilities(String),
    #[error("Invalid agent metadata: {0}")]
    InvalidMetadata(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<&str> for AgentError {
    fn from(s: &str) -> Self {
        AgentError::Internal(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AgentError>;

// Verification types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// The identity has not been verified
    Unverified,
    /// The identity has been self-verified
    SelfVerified,
    /// The identity has been verified by another agent
    AgentVerified,
    /// The identity has been verified by multiple agents
    MultiAgentVerified,
    /// The identity has been verified by a trusted authority
    AuthorityVerified,
}

impl Default for VerificationLevel {
    fn default() -> Self {
        Self::Unverified
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// No trust established
    None,
    /// Basic trust level
    Low,
    /// Moderate trust level
    Medium,
    /// High trust level
    High,
    /// Very high trust level
    VeryHigh,
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::None
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::VeryHigh => write!(f, "Very High"),
        }
    }
}

/// Trust metrics used in score calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustMetrics {
    /// Direct trust score (0.0 to 1.0)
    pub direct_trust: f64,
    /// Indirect trust score (0.0 to 1.0)
    pub indirect_trust: f64,
    /// Historical trust score (0.0 to 1.0)
    pub historical_trust: f64,
    /// Behavioral trust score (0.0 to 1.0)
    pub behavioral_trust: f64,
    /// Identity verification score (0.0 to 1.0)
    pub identity_verification: f64,
    /// Additional custom metrics
    #[serde(default)]
    pub custom_metrics: HashMap<String, f64>,
}

impl Default for TrustMetrics {
    fn default() -> Self {
        Self {
            direct_trust: 0.0,
            indirect_trust: 0.0,
            historical_trust: 0.0,
            behavioral_trust: 0.0,
            identity_verification: 0.0,
            custom_metrics: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// The calculated trust score (0.0 to 1.0)
    pub score: f64,
    /// The trust level based on the score
    pub level: TrustLevel,
    /// The individual trust metrics
    pub metrics: TrustMetrics,
    /// Timestamp when the score was calculated
    pub timestamp: DateTime<Utc>,
    /// Score confidence (0.0 to 1.0)
    pub confidence: f64,
    /// Score validity period
    pub validity_period: Duration,
}

impl TrustScore {
    /// Create a new trust score
    pub fn new(
        score: f64,
        level: TrustLevel,
        metrics: TrustMetrics,
        confidence: f64,
        validity_period: Duration,
    ) -> Result<Self> {
        if !(0.0..=1.0).contains(&score) {
            return Err("Score must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&confidence) {
            return Err("Confidence must be between 0.0 and 1.0".into());
        }

        Ok(Self {
            score,
            level,
            metrics,
            timestamp: Utc::now(),
            confidence,
            validity_period,
        })
    }

    /// Check if the trust score is still valid
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now - self.timestamp < self.validity_period
    }

    /// Calculate the weighted trust score from metrics
    pub fn calculate_weighted_score(metrics: &TrustMetrics, weights: &HashMap<String, f64>) -> f64 {
        let default_weights: HashMap<&str, f64> = [
            ("direct_trust", 0.3),
            ("indirect_trust", 0.2),
            ("historical_trust", 0.2),
            ("behavioral_trust", 0.2),
            ("identity_verification", 0.1),
        ]
        .into_iter()
        .collect();

        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        // Calculate weighted sum for standard metrics
        weighted_sum += metrics.direct_trust
            * weights
                .get("direct_trust")
                .unwrap_or(&default_weights["direct_trust"]);
        weighted_sum += metrics.indirect_trust
            * weights
                .get("indirect_trust")
                .unwrap_or(&default_weights["indirect_trust"]);
        weighted_sum += metrics.historical_trust
            * weights
                .get("historical_trust")
                .unwrap_or(&default_weights["historical_trust"]);
        weighted_sum += metrics.behavioral_trust
            * weights
                .get("behavioral_trust")
                .unwrap_or(&default_weights["behavioral_trust"]);
        weighted_sum += metrics.identity_verification
            * weights
                .get("identity_verification")
                .unwrap_or(&default_weights["identity_verification"]);

        total_weight += weights
            .get("direct_trust")
            .unwrap_or(&default_weights["direct_trust"]);
        total_weight += weights
            .get("indirect_trust")
            .unwrap_or(&default_weights["indirect_trust"]);
        total_weight += weights
            .get("historical_trust")
            .unwrap_or(&default_weights["historical_trust"]);
        total_weight += weights
            .get("behavioral_trust")
            .unwrap_or(&default_weights["behavioral_trust"]);
        total_weight += weights
            .get("identity_verification")
            .unwrap_or(&default_weights["identity_verification"]);

        // Add custom metrics
        for (key, value) in &metrics.custom_metrics {
            if let Some(weight) = weights.get(key) {
                weighted_sum += value * weight;
                total_weight += weight;
            }
        }

        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
    }

    /// Determine trust level from a score
    pub fn determine_trust_level(score: f64, thresholds: &[(TrustLevel, f64)]) -> TrustLevel {
        let mut level = TrustLevel::None;
        for (trust_level, threshold) in thresholds {
            if score >= *threshold {
                level = *trust_level;
            } else {
                break;
            }
        }
        level
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationPolicy {
    /// Name of the verification policy
    pub name: String,
    /// Description of the policy
    pub description: String,
    /// Minimum required trust level
    pub required_level: TrustLevel,
    /// Minimum number of verifiers required
    pub min_verifiers: u32,
    /// Whether consensus is required among verifiers
    pub require_consensus: bool,
    /// How long the verification is valid for
    pub verification_period: Duration,
    /// Additional policy metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// Unique identifier for the request
    pub id: String,
    /// The agent requesting verification
    pub requester_id: AgentId,
    /// The agent being verified
    pub target_id: AgentId,
    /// The verification policy to apply
    pub policy: VerificationPolicy,
    /// When the request was created
    pub created_at: DateTime<Utc>,
    /// When the request expires
    pub expires_at: DateTime<Utc>,
    /// Additional request metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Verification passed all requirements
    Verified,
    /// Verification failed to meet requirements
    Failed,
    /// Verification is pending additional checks
    Pending,
    /// Verification was rejected
    Rejected,
    /// Verification expired
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// The verification request
    pub request: VerificationRequest,
    /// The verification status
    pub status: VerificationStatus,
    /// When the verification was performed
    pub verified_at: DateTime<Utc>,
    /// When the verification result expires
    pub expires_at: DateTime<Utc>,
    /// The trust score at verification time
    pub trust_score: Option<TrustScore>,
    /// Verification details and evidence
    #[serde(default)]
    pub evidence: HashMap<String, serde_json::Value>,
    /// Verification failure reasons (if any)
    #[serde(default)]
    pub failure_reasons: Vec<String>,
}

/// Represents a trust relationship between two agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRelationship {
    /// The agent that established the trust
    pub from: AgentId,
    /// The agent that is trusted
    pub to: AgentId,
    /// The level of trust
    pub level: TrustLevel,
    /// When this trust relationship was established
    pub established_at: DateTime<Utc>,
    /// When this trust relationship was last updated
    pub updated_at: DateTime<Utc>,
    /// Additional trust metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl TrustRelationship {
    /// Create a new trust relationship
    pub fn new(from: AgentId, to: AgentId, level: TrustLevel) -> Result<Self> {
        if from == to {
            return Err("Cannot establish trust with self".into());
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
    pub fn level(&self) -> TrustLevel {
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
    pub fn update_level(&mut self, level: TrustLevel) -> Result<()> {
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
        self.level != TrustLevel::None
    }

    /// Check if this trust relationship is at a specific level or higher
    pub fn is_at_least(&self, level: TrustLevel) -> bool {
        self.level >= level
    }
}

impl fmt::Display for TrustRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Trust from {} to {}: {} (Updated: {})",
            self.from, self.to, self.level, self.updated_at
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_id_creation() {
        let agent_id = AgentId::new("test-agent");
        assert_eq!(agent_id.name(), "test-agent");
        assert!(agent_id.created_at() <= Utc::now());
    }

    #[test]
    fn test_agent_capabilities_default() {
        let capabilities = AgentCapabilities::default();
        assert!(capabilities.can_commerce);
        assert!(!capabilities.can_verify);
        assert!(!capabilities.can_manage_trust);
    }
}
