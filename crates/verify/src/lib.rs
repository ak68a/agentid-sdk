use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use agentid_core::{AgentId, RelationshipType, TrustLevel, TrustScore};
use thiserror::Error;

/// Errors that can occur during verification
#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Policy error: {0}")]
    PolicyError(String),

    #[error("Request error: {0}")]
    RequestError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for verification operations
pub type Result<T> = std::result::Result<T, VerifyError>;

/// Verification policy requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationPolicy {
    /// Minimum required trust level
    pub minimum_trust_level: TrustLevel,
    /// Required attributes
    pub required_attributes: HashSet<String>,
    /// Required relationship types
    pub required_relationship_types: HashSet<RelationshipType>,
    /// Maximum delegation depth
    pub max_delegation_depth: u32,
    /// Verification validity period
    pub validity_period: Duration,
    /// Additional policy constraints
    #[serde(default)]
    pub constraints: HashMap<String, serde_json::Value>,
}

impl VerificationPolicy {
    /// Create a new verification policy
    pub fn new(minimum_trust_level: TrustLevel) -> Self {
        Self {
            minimum_trust_level,
            required_attributes: HashSet::new(),
            required_relationship_types: HashSet::new(),
            max_delegation_depth: 1,
            validity_period: Duration::hours(24),
            constraints: HashMap::new(),
        }
    }

    /// Add a required attribute
    pub fn with_required_attribute(mut self, attribute: impl Into<String>) -> Self {
        self.required_attributes.insert(attribute.into());
        self
    }

    /// Add a required relationship type
    pub fn with_required_relationship_type(mut self, relationship_type: RelationshipType) -> Self {
        self.required_relationship_types.insert(relationship_type);
        self
    }

    /// Set the maximum delegation depth
    pub fn with_max_delegation_depth(mut self, depth: u32) -> Self {
        self.max_delegation_depth = depth;
        self
    }

    /// Set the validity period
    pub fn with_validity_period(mut self, period: Duration) -> Self {
        self.validity_period = period;
        self
    }

    /// Add a policy constraint
    pub fn with_constraint(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.constraints.insert(key.into(), value);
        self
    }
}

/// Verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// The requesting agent's ID
    pub requester_id: AgentId,
    /// The target agent's ID to verify
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

impl VerificationRequest {
    /// Create a new verification request
    pub fn new(requester_id: AgentId, target_id: AgentId, policy: VerificationPolicy) -> Self {
        let created_at = Utc::now();
        Self {
            requester_id,
            target_id,
            policy,
            created_at,
            expires_at: created_at + Duration::hours(1),
            metadata: HashMap::new(),
        }
    }

    /// Set a custom expiration time
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Add request metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Check if the request is still valid
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

/// Verification result status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// Verification result
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

impl VerificationResult {
    /// Create a new verification result
    pub fn new(request: VerificationRequest, status: VerificationStatus) -> Self {
        let verified_at = Utc::now();
        Self {
            expires_at: verified_at + request.policy.validity_period,
            request,
            status,
            verified_at,
            trust_score: None,
            evidence: HashMap::new(),
            failure_reasons: Vec::new(),
        }
    }

    /// Add verification evidence
    pub fn with_evidence(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.evidence.insert(key.into(), value);
        self
    }

    /// Add a failure reason
    pub fn with_failure_reason(mut self, reason: impl Into<String>) -> Self {
        self.failure_reasons.push(reason.into());
        self
    }

    /// Set the trust score
    pub fn with_trust_score(mut self, score: TrustScore) -> Self {
        self.trust_score = Some(score);
        self
    }

    /// Check if the verification result is still valid
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    /// Check if the verification passed
    pub fn is_verified(&self) -> bool {
        self.status == VerificationStatus::Verified
    }
}

/// Verification service
#[derive(Debug, Clone)]
pub struct VerificationService {
    /// Active verification requests
    requests: HashMap<String, VerificationRequest>,
    /// Verification results
    results: HashMap<String, VerificationResult>,
}

impl VerificationService {
    /// Create a new verification service
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
            results: HashMap::new(),
        }
    }

    /// Submit a verification request
    pub fn submit_request(&mut self, request: VerificationRequest) -> Result<String> {
        if !request.is_valid() {
            return Err(VerifyError::RequestError(
                "Verification request has expired".into(),
            ));
        }

        let request_id = format!(
            "verify_{}_{}_{}",
            request.requester_id.id(),
            request.target_id.id(),
            request.created_at.timestamp()
        );

        self.requests.insert(request_id.clone(), request);
        Ok(request_id)
    }

    /// Get a verification request by ID
    pub fn get_request(&self, request_id: &str) -> Option<&VerificationRequest> {
        self.requests.get(request_id)
    }

    /// Store a verification result
    pub fn store_result(&mut self, result: VerificationResult) -> Result<String> {
        let result_id = format!(
            "result_{}_{}_{}",
            result.request.requester_id.id(),
            result.request.target_id.id(),
            result.verified_at.timestamp()
        );

        // Remove the corresponding request
        self.requests.remove(&format!(
            "verify_{}_{}_{}",
            result.request.requester_id.id(),
            result.request.target_id.id(),
            result.request.created_at.timestamp()
        ));

        self.results.insert(result_id.clone(), result);
        Ok(result_id)
    }

    /// Get a verification result by ID
    pub fn get_result(&self, result_id: &str) -> Option<&VerificationResult> {
        self.results.get(result_id)
    }

    /// Get all valid verification results for a target agent
    pub fn get_valid_results_for_target(
        &self,
        target_id: &AgentId,
    ) -> impl Iterator<Item = &VerificationResult> {
        self.results
            .values()
            .filter(move |result| &result.request.target_id == target_id && result.is_valid())
    }

    /// Clean up expired requests and results
    pub fn cleanup_expired(&mut self) {
        self.requests.retain(|_, request| request.is_valid());
        self.results.retain(|_, result| result.is_valid());
    }
}

impl Default for VerificationService {
    fn default() -> Self {
        Self::new()
    }
}

pub mod rotation;
pub use rotation::RotationVerifier;
