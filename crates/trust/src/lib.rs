//! Trust framework for Agent Commerce Kit Identity (ACK ID)
//!
//! This crate implements the trust framework components for ACK ID, including:
//! - Trust scoring and assessment
//! - Trust attributes and metrics
//! - Trust relationships and delegation
//! - Trust lifecycle management
//! - Trust verification and validation
//!
//! TODO: Implement trust delegation features:
//! - Chain of trust validation
//! - Delegation depth limits
//! - Delegation revocation
//! - Delegation history tracking
//!
//! TODO: Implement advanced verification workflows:
//! - Multi-agent verification
//! - Consensus-based verification
//! - Verification evidence collection
//! - Verification history and audit trails

mod attributes;
mod error;
mod lifecycle;
mod relationships;
mod score;
mod verification;

pub use attributes::{AttributeSource, TrustAttribute, TrustAttributeSet};
pub use error::TrustError;
pub use lifecycle::{StateTransition, TrustLifecycle, TrustState};
pub use relationships::{RelationshipType, TrustDelegation, TrustRelationship};
pub use score::{TrustLevel, TrustMetrics, TrustScore};
pub use verification::{TrustVerifier, VerificationPolicy, VerificationResult};

/// Result type for trust operations
pub type Result<T> = std::result::Result<T, TrustError>;

/// Trust framework operations trait
#[async_trait::async_trait]
pub trait TrustOperations {
    /// Calculate a trust score based on available attributes and metrics
    async fn calculate_trust_score(&self, attributes: &TrustAttributeSet) -> Result<TrustScore>;

    /// Assess trust level based on current trust score and policy
    async fn assess_trust_level(&self, score: &TrustScore) -> Result<TrustLevel>;

    /// Establish a trust relationship between two agents
    async fn establish_relationship(
        &self,
        relationship_type: RelationshipType,
        attributes: &TrustAttributeSet,
    ) -> Result<TrustRelationship>;

    /// Delegate trust to another agent
    async fn delegate_trust(
        &self,
        delegation: TrustDelegation,
        attributes: &TrustAttributeSet,
    ) -> Result<TrustRelationship>;

    /// Update trust attributes for an agent
    async fn update_attributes(
        &self,
        agent_id: &str,
        attributes: &TrustAttributeSet,
    ) -> Result<TrustAttributeSet>;

    /// Verify trust status of an agent
    async fn verify_trust(
        &self,
        agent_id: &str,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult>;

    /// Manage trust lifecycle state transitions
    async fn transition_state(
        &self,
        agent_id: &str,
        transition: StateTransition,
    ) -> Result<TrustState>;
}

/// Trust framework configuration
#[derive(Debug, Clone)]
pub struct TrustConfig {
    /// Minimum trust score required for basic operations
    pub minimum_trust_score: f64,
    /// Trust score thresholds for different trust levels
    pub trust_level_thresholds: Vec<(TrustLevel, f64)>,
    /// Maximum delegation depth
    pub max_delegation_depth: u32,
    /// Trust attribute weights for score calculation
    pub attribute_weights: std::collections::HashMap<String, f64>,
    /// Trust verification policies
    pub verification_policies: std::collections::HashMap<String, VerificationPolicy>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            minimum_trust_score: 0.5,
            trust_level_thresholds: vec![
                (TrustLevel::Low, 0.3),
                (TrustLevel::Medium, 0.6),
                (TrustLevel::High, 0.8),
                (TrustLevel::VeryHigh, 0.9),
            ],
            max_delegation_depth: 3,
            attribute_weights: std::collections::HashMap::new(),
            verification_policies: std::collections::HashMap::new(),
        }
    }
}
