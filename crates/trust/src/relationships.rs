use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of trust relationship between agents
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    /// Direct trust relationship
    Direct,
    /// Indirect trust through delegation
    Delegated,
    /// Trust through a trusted third party
    ThirdParty,
    /// Trust through a consortium or group
    Consortium,
    /// Trust through a hierarchical relationship
    Hierarchical,
}

/// Trust delegation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDelegation {
    /// The delegating agent's ID
    pub delegator_id: String,
    /// The delegate agent's ID
    pub delegate_id: String,
    /// The type of delegation
    pub relationship_type: RelationshipType,
    /// The scope of delegated trust
    pub scope: Vec<String>,
    /// Maximum delegation depth
    pub max_depth: u32,
    /// When the delegation expires
    pub expires_at: Option<DateTime<Utc>>,
    /// Additional delegation constraints
    #[serde(default)]
    pub constraints: HashMap<String, serde_json::Value>,
}

impl TrustDelegation {
    /// Create a new trust delegation
    pub fn new(
        delegator_id: impl Into<String>,
        delegate_id: impl Into<String>,
        relationship_type: RelationshipType,
        scope: Vec<String>,
    ) -> Self {
        Self {
            delegator_id: delegator_id.into(),
            delegate_id: delegate_id.into(),
            relationship_type,
            scope,
            max_depth: 1,
            expires_at: None,
            constraints: HashMap::new(),
        }
    }

    /// Set the maximum delegation depth
    pub fn with_max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Set the expiration time
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add a delegation constraint
    pub fn with_constraint(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.constraints.insert(key.into(), value);
        self
    }

    /// Check if the delegation is still valid
    pub fn is_valid(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() < expires_at
        } else {
            true
        }
    }
}

/// A trust relationship between agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRelationship {
    /// The source agent's ID
    pub source_id: String,
    /// The target agent's ID
    pub target_id: String,
    /// The type of relationship
    pub relationship_type: RelationshipType,
    /// When the relationship was established
    pub established_at: DateTime<Utc>,
    /// When the relationship expires (if applicable)
    pub expires_at: Option<DateTime<Utc>>,
    /// The current trust score for this relationship
    pub trust_score: Option<crate::TrustScore>,
    /// The scope of the relationship
    pub scope: Vec<String>,
    /// The delegation chain (if applicable)
    pub delegation_chain: Vec<String>,
    /// Relationship metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TrustRelationship {
    /// Create a new trust relationship
    pub fn new(
        source_id: impl Into<String>,
        target_id: impl Into<String>,
        relationship_type: RelationshipType,
        scope: Vec<String>,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            target_id: target_id.into(),
            relationship_type,
            established_at: Utc::now(),
            expires_at: None,
            trust_score: None,
            scope,
            delegation_chain: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Create a delegated trust relationship
    pub fn from_delegation(
        delegation: &TrustDelegation,
        delegation_chain: Vec<String>,
    ) -> crate::Result<Self> {
        if !delegation.is_valid() {
            return Err(crate::TrustError::DelegationError(
                "Delegation is no longer valid".into(),
            ));
        }

        if delegation_chain.len() > delegation.max_depth as usize {
            return Err(crate::TrustError::DelegationError(
                "Delegation chain exceeds maximum depth".into(),
            ));
        }

        Ok(Self {
            source_id: delegation.delegator_id.clone(),
            target_id: delegation.delegate_id.clone(),
            relationship_type: delegation.relationship_type,
            established_at: Utc::now(),
            expires_at: delegation.expires_at,
            trust_score: None,
            scope: delegation.scope.clone(),
            delegation_chain,
            metadata: delegation.constraints.clone(),
        })
    }

    /// Check if the relationship is still valid
    pub fn is_valid(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() < expires_at
        } else {
            true
        }
    }

    /// Update the trust score for this relationship
    pub fn update_trust_score(&mut self, score: crate::TrustScore) {
        self.trust_score = Some(score);
    }

    /// Set the expiration time
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add relationship metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Check if the relationship has a specific scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.contains(&scope.to_string())
    }

    /// Get the current trust level (if available)
    pub fn trust_level(&self) -> Option<crate::TrustLevel> {
        self.trust_score.as_ref().map(|score| score.level)
    }

    /// Check if the relationship meets minimum trust requirements
    pub fn meets_trust_requirements(&self, minimum_level: crate::TrustLevel) -> bool {
        self.trust_level()
            .map(|level| level >= minimum_level)
            .unwrap_or(false)
    }
}

/// A collection of trust relationships for an agent
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustRelationshipSet {
    /// The agent ID these relationships belong to
    pub agent_id: String,
    /// The relationships
    pub relationships: HashMap<String, TrustRelationship>,
    /// When the relationship set was last updated
    pub updated_at: DateTime<Utc>,
}

impl TrustRelationshipSet {
    /// Create a new empty relationship set
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            relationships: HashMap::new(),
            updated_at: Utc::now(),
        }
    }

    /// Add a relationship to the set
    pub fn add_relationship(&mut self, relationship: TrustRelationship) {
        self.relationships
            .insert(relationship.target_id.clone(), relationship);
        self.updated_at = Utc::now();
    }

    /// Get a relationship by target agent ID
    pub fn get_relationship(&self, target_id: &str) -> Option<&TrustRelationship> {
        self.relationships.get(target_id)
    }

    /// Remove a relationship by target agent ID
    pub fn remove_relationship(&mut self, target_id: &str) -> Option<TrustRelationship> {
        let removed = self.relationships.remove(target_id);
        if removed.is_some() {
            self.updated_at = Utc::now();
        }
        removed
    }

    /// Get all valid relationships
    pub fn valid_relationships(&self) -> impl Iterator<Item = &TrustRelationship> {
        self.relationships.values().filter(|rel| rel.is_valid())
    }

    /// Get relationships by type
    pub fn relationships_by_type(
        &self,
        relationship_type: RelationshipType,
    ) -> impl Iterator<Item = &TrustRelationship> {
        self.relationships
            .values()
            .filter(move |rel| rel.relationship_type == relationship_type)
    }

    /// Get relationships that meet minimum trust requirements
    pub fn trusted_relationships(
        &self,
        minimum_level: crate::TrustLevel,
    ) -> impl Iterator<Item = &TrustRelationship> {
        self.relationships
            .values()
            .filter(move |rel| rel.meets_trust_requirements(minimum_level))
    }
}
