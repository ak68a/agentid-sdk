//! Agent implementation for the ACK ID protocol.
//!
//! This module provides the core Agent type and its implementation,
//! which represents an autonomous entity in the ACK ID system.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Result;
use agentid_types::{AgentCapabilities, AgentId, AgentStatus};

/// Represents an agent in the ACK ID system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    /// The unique identifier for this agent
    id: AgentId,
    /// The capabilities of this agent
    capabilities: AgentCapabilities,
    /// The current status of this agent
    status: AgentStatus,
    /// When this agent was last updated
    updated_at: DateTime<Utc>,
    /// Additional metadata for this agent
    #[serde(default)]
    metadata: serde_json::Value,
}

impl Agent {
    /// Create a new agent with the given name
    pub fn new(name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            id: AgentId::new(name),
            capabilities: AgentCapabilities::default(),
            status: AgentStatus::default(),
            updated_at: Utc::now(),
            metadata: serde_json::json!({}),
        })
    }

    /// Create a new agent with custom capabilities
    pub fn with_capabilities(
        name: impl Into<String>,
        capabilities: AgentCapabilities,
    ) -> Result<Self> {
        Ok(Self {
            id: AgentId::new(name),
            capabilities,
            status: AgentStatus::default(),
            updated_at: Utc::now(),
            metadata: serde_json::json!({}),
        })
    }

    /// Get the ID of this agent
    pub fn id(&self) -> &AgentId {
        &self.id
    }

    /// Get the capabilities of this agent
    pub fn capabilities(&self) -> &AgentCapabilities {
        &self.capabilities
    }

    /// Get the status of this agent
    pub fn status(&self) -> AgentStatus {
        self.status
    }

    /// Get when this agent was last updated
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// Get the metadata for this agent
    pub fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }

    /// Update the capabilities of this agent
    pub fn update_capabilities(&mut self, capabilities: AgentCapabilities) -> Result<()> {
        self.capabilities = capabilities;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Update the status of this agent
    pub fn update_status(&mut self, status: AgentStatus) -> Result<()> {
        self.status = status;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Update the metadata for this agent
    pub fn update_metadata(&mut self, metadata: serde_json::Value) -> Result<()> {
        self.metadata = metadata;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Check if this agent can perform commerce operations
    pub fn can_commerce(&self) -> bool {
        self.capabilities.can_commerce && self.status == AgentStatus::Active
    }

    /// Check if this agent can verify other agents
    pub fn can_verify(&self) -> bool {
        self.capabilities.can_verify && self.status == AgentStatus::Active
    }

    /// Check if this agent can manage trust relationships
    pub fn can_manage_trust(&self) -> bool {
        self.capabilities.can_manage_trust && self.status == AgentStatus::Active
    }
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Agent {} (Status: {:?}, Updated: {})",
            self.id, self.status, self.updated_at
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_creation() {
        let agent = Agent::new("test-agent").unwrap();
        assert_eq!(agent.id().name(), "test-agent");
        assert!(agent.can_commerce());
        assert!(!agent.can_verify());
        assert!(!agent.can_manage_trust());
    }

    #[test]
    fn test_agent_capabilities() {
        let capabilities = AgentCapabilities {
            can_commerce: true,
            can_verify: true,
            can_manage_trust: true,
        };
        let agent = Agent::with_capabilities("test-agent", capabilities).unwrap();
        assert!(agent.can_commerce());
        assert!(agent.can_verify());
        assert!(agent.can_manage_trust());
    }

    #[test]
    fn test_agent_status() {
        let mut agent = Agent::new("test-agent").unwrap();
        assert!(agent.can_commerce());

        agent.update_status(AgentStatus::Suspended).unwrap();
        assert!(!agent.can_commerce());

        agent.update_status(AgentStatus::Active).unwrap();
        assert!(agent.can_commerce());

        agent.update_status(AgentStatus::Revoked).unwrap();
        assert!(!agent.can_commerce());
    }

    #[test]
    fn test_agent_with_capabilities() {
        let capabilities = AgentCapabilities {
            can_commerce: false,
            can_verify: true,
            can_manage_trust: false,
        };
        let agent = Agent::with_capabilities("test-agent", capabilities.clone()).unwrap();
        assert_eq!(agent.capabilities(), &capabilities);
        assert!(!agent.can_commerce());
        assert!(agent.can_verify());
        assert!(!agent.can_manage_trust());
    }

    #[test]
    fn test_agent_update_capabilities() {
        let mut agent = Agent::new("test-agent").unwrap();
        let initial_capabilities = agent.capabilities().clone();

        let new_capabilities = AgentCapabilities {
            can_commerce: false,
            can_verify: true,
            can_manage_trust: true,
        };

        agent.update_capabilities(new_capabilities.clone()).unwrap();
        assert_eq!(agent.capabilities(), &new_capabilities);
        assert_ne!(agent.capabilities(), &initial_capabilities);
        assert!(!agent.can_commerce());
        assert!(agent.can_verify());
        assert!(agent.can_manage_trust());
    }

    #[test]
    fn test_agent_metadata() {
        let mut agent = Agent::new("test-agent").unwrap();
        assert_eq!(agent.metadata(), &serde_json::json!({}));

        let metadata = serde_json::json!({
            "name": "Test Agent",
            "version": "1.0",
            "tags": ["test", "agent"]
        });

        agent.update_metadata(metadata.clone()).unwrap();
        assert_eq!(agent.metadata(), &metadata);
    }

    #[test]
    fn test_agent_updated_at() {
        let mut agent = Agent::new("test-agent").unwrap();
        let initial_updated_at = agent.updated_at();

        // Wait a small amount of time to ensure timestamp difference
        std::thread::sleep(std::time::Duration::from_millis(1));

        agent.update_status(AgentStatus::Suspended).unwrap();
        assert!(agent.updated_at() > initial_updated_at);

        let second_updated_at = agent.updated_at();
        std::thread::sleep(std::time::Duration::from_millis(1));

        agent
            .update_capabilities(AgentCapabilities::default())
            .unwrap();
        assert!(agent.updated_at() > second_updated_at);
    }

    #[test]
    fn test_agent_display() {
        let agent = Agent::new("test-agent").unwrap();
        let display = format!("{}", agent);
        assert!(display.contains("test-agent"));
        assert!(display.contains("Active"));
        assert!(display.contains("Updated:"));
    }
}
