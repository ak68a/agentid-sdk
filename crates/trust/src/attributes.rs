use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Source of a trust attribute
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeSource {
    /// Self-reported by the agent
    SelfReported,
    /// Verified by a trusted third party
    Verified,
    /// Derived from behavior or history
    Derived,
    /// Delegated from another trusted agent
    Delegated,
    /// System-generated
    System,
}

/// A trust attribute with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAttribute {
    /// The attribute name
    pub name: String,
    /// The attribute value
    pub value: serde_json::Value,
    /// The source of the attribute
    pub source: AttributeSource,
    /// When the attribute was created
    pub created_at: DateTime<Utc>,
    /// When the attribute expires (if applicable)
    pub expires_at: Option<DateTime<Utc>>,
    /// Confidence in the attribute (0.0 to 1.0)
    pub confidence: f64,
    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TrustAttribute {
    /// Create a new trust attribute
    pub fn new(
        name: impl Into<String>,
        value: serde_json::Value,
        source: AttributeSource,
        confidence: f64,
    ) -> crate::Result<Self> {
        if !(0.0..=1.0).contains(&confidence) {
            return Err(crate::TrustError::InvalidAttributes(
                "Confidence must be between 0.0 and 1.0".into(),
            ));
        }

        Ok(Self {
            name: name.into(),
            value,
            source,
            created_at: Utc::now(),
            expires_at: None,
            confidence,
            metadata: HashMap::new(),
        })
    }

    /// Check if the attribute is still valid
    pub fn is_valid(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() < expires_at
        } else {
            true
        }
    }

    /// Set the expiration time
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// A set of trust attributes for an agent
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustAttributeSet {
    /// The agent ID these attributes belong to
    pub agent_id: String,
    /// The attributes
    pub attributes: HashMap<String, TrustAttribute>,
    /// When the attribute set was last updated
    pub updated_at: DateTime<Utc>,
}

impl TrustAttributeSet {
    /// Create a new empty attribute set
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            attributes: HashMap::new(),
            updated_at: Utc::now(),
        }
    }

    /// Add an attribute to the set
    pub fn add_attribute(&mut self, attribute: TrustAttribute) {
        self.attributes.insert(attribute.name.clone(), attribute);
        self.updated_at = Utc::now();
    }

    /// Get an attribute by name
    pub fn get_attribute(&self, name: &str) -> Option<&TrustAttribute> {
        self.attributes.get(name)
    }

    /// Remove an attribute by name
    pub fn remove_attribute(&mut self, name: &str) -> Option<TrustAttribute> {
        let removed = self.attributes.remove(name);
        if removed.is_some() {
            self.updated_at = Utc::now();
        }
        removed
    }

    /// Get all valid attributes
    pub fn valid_attributes(&self) -> impl Iterator<Item = &TrustAttribute> {
        self.attributes.values().filter(|attr| attr.is_valid())
    }

    /// Get attributes by source
    pub fn attributes_by_source(
        &self,
        source: AttributeSource,
    ) -> impl Iterator<Item = &TrustAttribute> {
        self.attributes
            .values()
            .filter(move |attr| attr.source == source)
    }

    /// Merge another attribute set into this one
    pub fn merge(&mut self, other: TrustAttributeSet) {
        for (name, attribute) in other.attributes {
            // Only update if the new attribute is more recent or has higher confidence
            if let Some(existing) = self.attributes.get(&name) {
                if attribute.created_at > existing.created_at
                    || attribute.confidence > existing.confidence
                {
                    self.attributes.insert(name, attribute);
                }
            } else {
                self.attributes.insert(name, attribute);
            }
        }
        self.updated_at = Utc::now();
    }
}
