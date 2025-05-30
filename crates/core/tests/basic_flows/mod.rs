//! Basic flow tests for the core crate.
//! These tests verify simple operations within each module.

mod identity_flows;
mod trust_flows;

// Re-export test modules for easier access
pub use identity_flows::*;
pub use trust_flows::*;
