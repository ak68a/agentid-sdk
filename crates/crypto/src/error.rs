use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<ring::error::Unspecified> for CryptoError {
    fn from(err: ring::error::Unspecified) -> Self {
        CryptoError::InternalError(err.to_string())
    }
}

impl From<ed25519_dalek::ed25519::Error> for CryptoError {
    fn from(err: ed25519_dalek::ed25519::Error) -> Self {
        CryptoError::InvalidSignature(err.to_string())
    }
}
