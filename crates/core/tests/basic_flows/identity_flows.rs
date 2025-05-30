//! Basic flow tests for the core crate.
//! These tests verify simple operations within the core crate.

use agentid_core::{identity::VerificationLevel, trust::TrustRelationship, Agent, Identity};
use agentid_types::AgentId;
use chrono::Utc;

#[test]
fn test_identity_creation_and_initial_state() {
    // Create an agent and verify its initial state
    let agent = Agent::new("test-agent").unwrap();
    let identity = Identity::new(agent.clone()).unwrap();

    // Verify initial state
    assert_eq!(identity.agent().id(), agent.id());
    assert!(!identity.is_verified());
    assert!(!identity.is_agent_verified());
    assert!(!identity.is_authority_verified());
    assert!(identity.metadata().as_object().unwrap().is_empty());
}

#[test]
fn test_identity_verification_progression() {
    let agent = Agent::new("test-agent").unwrap();
    let verifier_id = AgentId::new("verifier-agent");
    let mut identity = Identity::new(agent).unwrap();

    // Test progression through verification levels
    // Start with self verification
    identity
        .update_verification(VerificationLevel::SelfVerified, None)
        .unwrap();
    assert!(identity.is_verified());
    assert!(!identity.is_agent_verified());
    assert!(!identity.is_authority_verified());

    // Move to agent verification
    identity
        .update_verification(VerificationLevel::AgentVerified, Some(verifier_id.clone()))
        .unwrap();
    assert!(identity.is_verified());
    assert!(identity.is_agent_verified());
    assert!(!identity.is_authority_verified());

    // Move to multi-agent verification
    identity
        .update_verification(
            VerificationLevel::MultiAgentVerified,
            Some(verifier_id.clone()),
        )
        .unwrap();
    assert!(identity.is_verified());
    assert!(identity.is_agent_verified());
    assert!(!identity.is_authority_verified());

    // Finally, authority verification
    identity
        .update_verification(VerificationLevel::AuthorityVerified, None)
        .unwrap();
    assert!(identity.is_verified());
    assert!(!identity.is_agent_verified());
    assert!(identity.is_authority_verified());
}

#[test]
fn test_identity_metadata_updates() {
    let agent = Agent::new("test-agent").unwrap();
    let mut identity = Identity::new(agent).unwrap();

    // Test initial metadata state
    assert!(identity.metadata().as_object().unwrap().is_empty());

    // Update metadata
    let metadata = serde_json::json!({
        "name": "Test Agent",
        "type": "individual",
        "location": "US"
    });

    let original_updated_at = identity.updated_at();
    identity.update_metadata(metadata.clone()).unwrap();

    // Verify metadata update
    assert_eq!(identity.metadata(), &metadata);
    assert!(identity.updated_at() > original_updated_at);

    // Update metadata again
    let new_metadata = serde_json::json!({
        "name": "Updated Test Agent",
        "type": "individual",
        "location": "EU"
    });

    identity.update_metadata(new_metadata.clone()).unwrap();
    assert_eq!(identity.metadata(), &new_metadata);
}

#[test]
fn test_identity_verification_checks() {
    let agent = Agent::new("test-agent").unwrap();
    let mut identity = Identity::new(agent).unwrap();

    // Test unverified state
    assert!(!identity.is_verified());
    assert!(!identity.is_agent_verified());
    assert!(!identity.is_authority_verified());

    // Test self-verified state
    identity
        .update_verification(VerificationLevel::SelfVerified, None)
        .unwrap();
    assert!(identity.is_verified());
    assert!(!identity.is_agent_verified());
    assert!(!identity.is_authority_verified());

    // Test agent-verified state
    identity
        .update_verification(
            VerificationLevel::AgentVerified,
            Some(AgentId::new("verifier")),
        )
        .unwrap();
    assert!(identity.is_verified());
    assert!(identity.is_agent_verified());
    assert!(!identity.is_authority_verified());

    // Test authority-verified state
    identity
        .update_verification(VerificationLevel::AuthorityVerified, None)
        .unwrap();
    assert!(identity.is_verified());
    assert!(!identity.is_agent_verified());
    assert!(identity.is_authority_verified());
}

#[test]
fn test_basic_trust_flow() {
    // TODO: Implement basic trust flow test
    // This will test trust relationship creation and updates within core
}
