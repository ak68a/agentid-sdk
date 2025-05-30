//! Cryptographic operations for Agent Commerce Kit Identity (ACK ID)
//! 
//! This crate provides cryptographic primitives and operations needed for:
//! - Key generation and management
//! - Digital signatures
//! - Encryption/decryption
//! - Hash functions
//! - Secure random number generation

mod error;
mod keys;
mod signatures;
mod encryption;
pub mod rotation;

pub use error::CryptoError;
pub use keys::{KeyPair, PublicKey, PrivateKey, KeyManager};
pub use signatures::Signature;
pub use encryption::{EncryptedData, EncryptionKey};
pub use rotation::RotationCrypto;

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Cryptographic operations trait
#[async_trait::async_trait]
pub trait CryptoOperations {
    /// Generate a new key pair
    async fn generate_key_pair() -> Result<KeyPair>;
    
    /// Sign a message with a private key
    async fn sign(&self, message: &[u8], private_key: &PrivateKey) -> Result<Signature>;
    
    /// Verify a signature with a public key
    async fn verify(&self, message: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<bool>;
    
    /// Encrypt data with a public key
    async fn encrypt(&self, data: &[u8], public_key: &PublicKey) -> Result<EncryptedData>;
    
    /// Decrypt data with a private key
    async fn decrypt(&self, encrypted_data: &EncryptedData, private_key: &PrivateKey) -> Result<Vec<u8>>;
} 