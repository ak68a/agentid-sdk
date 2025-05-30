//! Basic trust flow tests for the core crate.
//! These tests verify simple operations within the trust module.

use agentid_core::trust::TrustRelationship;
use agentid_types::{AgentId, TrustLevel};

#[test]
fn test_trust_relationship_creation() {
    // Create two agents for testing
    let agent1 = AgentId::new("agent1");
    let agent2 = AgentId::new("agent2");

    // Test basic trust relationship creation
    let trust = TrustRelationship::new(agent1.clone(), agent2.clone(), TrustLevel::Low).unwrap();

    // Verify initial state
    assert_eq!(trust.from(), &agent1);
    assert_eq!(trust.to(), &agent2);
    assert_eq!(trust.level(), TrustLevel::Low);
    assert!(trust.is_active());
    assert!(trust.metadata().as_object().unwrap().is_empty());
}

#[test]
fn test_trust_relationship_self_trust() {
    // Attempt to create a self-trust relationship (should fail)
    let agent = AgentId::new("agent");
    let result = TrustRelationship::new(agent.clone(), agent, TrustLevel::Low);
    assert!(result.is_err());
}

#[test]
fn test_trust_level_management() {
    let agent1 = AgentId::new("agent1");
    let agent2 = AgentId::new("agent2");
    let mut trust = TrustRelationship::new(agent1, agent2, TrustLevel::Low).unwrap();

    // Test trust level ordering
    assert!(TrustLevel::VeryHigh > TrustLevel::High);
    assert!(TrustLevel::High > TrustLevel::Medium);
    assert!(TrustLevel::Medium > TrustLevel::Low);
    assert!(TrustLevel::Low > TrustLevel::None);

    // Test trust level updates
    trust.update_level(TrustLevel::High).unwrap();
    assert_eq!(trust.level(), TrustLevel::High);
    assert!(trust.is_active());
    assert!(trust.is_at_least(TrustLevel::Medium));
    assert!(!trust.is_at_least(TrustLevel::VeryHigh));

    // Test deactivation
    trust.update_level(TrustLevel::None).unwrap();
    assert!(!trust.is_active());
    assert!(!trust.is_at_least(TrustLevel::Low));
}

#[test]
fn test_trust_metadata_management() {
    let agent1 = AgentId::new("agent1");
    let agent2 = AgentId::new("agent2");
    let mut trust = TrustRelationship::new(agent1, agent2, TrustLevel::Low).unwrap();

    // Test initial metadata state
    assert!(trust.metadata().as_object().unwrap().is_empty());

    // Update metadata
    let metadata = serde_json::json!({
        "reason": "Business partnership",
        "scope": "Financial transactions",
        "expires_at": "2024-12-31"
    });

    let original_updated_at = trust.updated_at();
    trust.update_metadata(metadata.clone()).unwrap();

    // Verify metadata update
    assert_eq!(trust.metadata(), &metadata);
    assert!(trust.updated_at() > original_updated_at);

    // Update metadata again
    let new_metadata = serde_json::json!({
        "reason": "Updated partnership",
        "scope": "Extended operations",
        "expires_at": "2025-12-31"
    });

    trust.update_metadata(new_metadata.clone()).unwrap();
    assert_eq!(trust.metadata(), &new_metadata);
}

#[test]
fn test_trust_relationship_validation() {
    let agent1 = AgentId::new("agent1");
    let agent2 = AgentId::new("agent2");
    let mut trust = TrustRelationship::new(agent1, agent2, TrustLevel::Low).unwrap();

    // Test active state
    assert!(trust.is_active());
    assert!(trust.is_at_least(TrustLevel::Low));

    // Test level changes
    trust.update_level(TrustLevel::High).unwrap();
    assert!(trust.is_active());
    assert!(trust.is_at_least(TrustLevel::High));
    assert!(!trust.is_at_least(TrustLevel::VeryHigh));

    // Test deactivation
    trust.update_level(TrustLevel::None).unwrap();
    assert!(!trust.is_active());
    assert!(!trust.is_at_least(TrustLevel::Low));

    // Test reactivation
    trust.update_level(TrustLevel::Medium).unwrap();
    assert!(trust.is_active());
    assert!(trust.is_at_least(TrustLevel::Medium));
    assert!(!trust.is_at_least(TrustLevel::High));
}
