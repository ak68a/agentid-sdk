use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use agentid_core::{Agent, Identity};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .pretty()
        .init();

    info!("Starting AgentID SDK demo...");

    // 1. Create a basic agent
    let agent = Agent::new("demo-agent")?;
    info!("Created agent with ID: {}", agent.id());

    // 2. Create an identity for the agent
    let mut identity = Identity::new(agent.clone())?;
    
    // Print identity using Display implementation
    info!("Identity: {}", identity);

    // Print identity using Debug implementation
    //  info!("Identity: {:?}", identity);
    
    // Print verification status using public methods
    info!("Verification status:");
    info!("  Is verified: {}", identity.is_verified());
    info!("  Is agent verified: {}", identity.is_agent_verified());
    info!("  Is authority verified: {}", identity.is_authority_verified());

    info!("Demo completed successfully!");
    Ok(())
}
