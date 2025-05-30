use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trust lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    /// Initial state, no trust established
    Initial,
    /// Trust is being established
    Establishing,
    /// Trust is active and valid
    Active,
    /// Trust is suspended temporarily
    Suspended,
    /// Trust is being reviewed
    Reviewing,
    /// Trust is revoked
    Revoked,
    /// Trust has expired
    Expired,
    /// Trust is in a grace period
    GracePeriod,
}

/// Trust state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// The target state to transition to
    pub target_state: TrustState,
    /// The reason for the transition
    pub reason: String,
    /// When the transition should occur
    pub transition_at: DateTime<Utc>,
    /// Additional transition metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl StateTransition {
    /// Create a new state transition
    pub fn new(target_state: TrustState, reason: impl Into<String>) -> Self {
        Self {
            target_state,
            reason: reason.into(),
            transition_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Set a future transition time
    pub fn with_future_transition(mut self, duration: Duration) -> Self {
        self.transition_at = Utc::now() + duration;
        self
    }

    /// Add transition metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Trust lifecycle management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustLifecycle {
    /// The current state
    pub current_state: TrustState,
    /// When the current state was entered
    pub state_entered_at: DateTime<Utc>,
    /// The next scheduled transition (if any)
    pub next_transition: Option<StateTransition>,
    /// State history
    pub state_history: Vec<StateHistoryEntry>,
    /// State-specific metadata
    #[serde(default)]
    pub state_metadata: HashMap<TrustState, HashMap<String, serde_json::Value>>,
}

/// Entry in the state history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateHistoryEntry {
    /// The state that was entered
    pub state: TrustState,
    /// When the state was entered
    pub entered_at: DateTime<Utc>,
    /// The reason for entering the state
    pub reason: String,
    /// Additional metadata for this state entry
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TrustLifecycle {
    /// Create a new trust lifecycle starting in the initial state
    pub fn new() -> Self {
        Self {
            current_state: TrustState::Initial,
            state_entered_at: Utc::now(),
            next_transition: None,
            state_history: vec![StateHistoryEntry {
                state: TrustState::Initial,
                entered_at: Utc::now(),
                reason: "Initial state".into(),
                metadata: HashMap::new(),
            }],
            state_metadata: HashMap::new(),
        }
    }

    /// Check if a state transition is valid
    pub fn is_valid_transition(&self, transition: &StateTransition) -> bool {
        match (self.current_state, transition.target_state) {
            // Initial state can transition to Establishing
            (TrustState::Initial, TrustState::Establishing) => true,

            // Establishing can transition to Active or Revoked
            (TrustState::Establishing, TrustState::Active) => true,
            (TrustState::Establishing, TrustState::Revoked) => true,

            // Active can transition to Suspended, Reviewing, Revoked, or Expired
            (TrustState::Active, TrustState::Suspended) => true,
            (TrustState::Active, TrustState::Reviewing) => true,
            (TrustState::Active, TrustState::Revoked) => true,
            (TrustState::Active, TrustState::Expired) => true,

            // Suspended can transition to Active, Reviewing, or Revoked
            (TrustState::Suspended, TrustState::Active) => true,
            (TrustState::Suspended, TrustState::Reviewing) => true,
            (TrustState::Suspended, TrustState::Revoked) => true,

            // Reviewing can transition to Active, Suspended, or Revoked
            (TrustState::Reviewing, TrustState::Active) => true,
            (TrustState::Reviewing, TrustState::Suspended) => true,
            (TrustState::Reviewing, TrustState::Revoked) => true,

            // GracePeriod can transition to Active or Expired
            (TrustState::GracePeriod, TrustState::Active) => true,
            (TrustState::GracePeriod, TrustState::Expired) => true,

            // Any state can transition to GracePeriod
            (_, TrustState::GracePeriod) => true,

            // No other transitions are allowed
            _ => false,
        }
    }

    /// Apply a state transition
    pub fn apply_transition(&mut self, transition: StateTransition) -> crate::Result<()> {
        if !self.is_valid_transition(&transition) {
            return Err(crate::TrustError::InvalidStateTransition(format!(
                "Invalid transition from {:?} to {:?}",
                self.current_state, transition.target_state
            )));
        }

        // Record the current state in history
        self.state_history.push(StateHistoryEntry {
            state: self.current_state,
            entered_at: self.state_entered_at,
            reason: transition.reason.clone(),
            metadata: transition.metadata.clone(),
        });

        // Update the current state
        self.current_state = transition.target_state;
        self.state_entered_at = transition.transition_at;
        self.next_transition = None;

        Ok(())
    }

    /// Schedule a future state transition
    pub fn schedule_transition(&mut self, transition: StateTransition) -> crate::Result<()> {
        if !self.is_valid_transition(&transition) {
            return Err(crate::TrustError::InvalidStateTransition(format!(
                "Invalid transition from {:?} to {:?}",
                self.current_state, transition.target_state
            )));
        }

        if transition.transition_at <= Utc::now() {
            return Err(crate::TrustError::InvalidStateTransition(
                "Transition time must be in the future".into(),
            ));
        }

        self.next_transition = Some(transition);
        Ok(())
    }

    /// Check if there are any pending transitions that should be applied
    pub fn check_pending_transitions(&mut self) -> crate::Result<Option<TrustState>> {
        if let Some(transition) = &self.next_transition {
            if transition.transition_at <= Utc::now() {
                let target_state = transition.target_state;
                self.apply_transition(transition.clone())?;
                return Ok(Some(target_state));
            }
        }
        Ok(None)
    }

    /// Get the duration spent in the current state
    pub fn current_state_duration(&self) -> Duration {
        Utc::now() - self.state_entered_at
    }

    /// Get the state history
    pub fn state_history(&self) -> &[StateHistoryEntry] {
        &self.state_history
    }

    /// Add metadata for the current state
    pub fn add_state_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.state_metadata
            .entry(self.current_state)
            .or_insert_with(HashMap::new)
            .insert(key.into(), value);
    }

    /// Get metadata for a specific state
    pub fn get_state_metadata(
        &self,
        state: TrustState,
    ) -> Option<&HashMap<String, serde_json::Value>> {
        self.state_metadata.get(&state)
    }

    /// Check if the current state is active
    pub fn is_active(&self) -> bool {
        matches!(self.current_state, TrustState::Active)
    }

    /// Check if the current state is valid for trust operations
    pub fn is_valid_for_trust(&self) -> bool {
        matches!(
            self.current_state,
            TrustState::Active | TrustState::GracePeriod
        )
    }
}

impl Default for TrustLifecycle {
    fn default() -> Self {
        Self::new()
    }
}
