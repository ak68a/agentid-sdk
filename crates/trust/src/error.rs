use thiserror::Error;

/// Errors that can occur during trust operations
#[derive(Error, Debug)]
pub enum TrustError {
    #[error("Invalid trust score: {0}")]
    InvalidTrustScore(String),

    #[error("Invalid trust level: {0}")]
    InvalidTrustLevel(String),

    #[error("Invalid trust attributes: {0}")]
    InvalidAttributes(String),

    #[error("Invalid trust relationship: {0}")]
    InvalidRelationship(String),

    #[error("Trust delegation failed: {0}")]
    DelegationError(String),

    #[error("Trust verification failed: {0}")]
    VerificationError(String),

    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("Trust lifecycle error: {0}")]
    LifecycleError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<std::io::Error> for TrustError {
    fn from(err: std::io::Error) -> Self {
        TrustError::InternalError(err.to_string())
    }
}

impl From<serde_json::Error> for TrustError {
    fn from(err: serde_json::Error) -> Self {
        TrustError::InternalError(err.to_string())
    }
}

impl From<agentid_crypto::CryptoError> for TrustError {
    fn from(err: agentid_crypto::CryptoError) -> Self {
        TrustError::InternalError(err.to_string())
    }
}
