//! Cryptographic operations for Agent Commerce Kit Identity (ACK ID)
//!
//! This crate provides cryptographic primitives and operations needed for:
//! - Key generation and management
//! - Digital signatures
//! - Encryption/decryption
//! - Hash functions
//! - Secure random number generation

use async_trait::async_trait;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

mod encryption;
mod error;
mod keys;
mod signatures;

pub use encryption::{EncryptedData, EncryptionKey};
pub use error::CryptoError;
pub use keys::KeyManager;
pub use signatures::Signature;

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// A key pair consisting of a public and private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// The public key component
    pub public_key: PublicKey,
    /// The private key component
    #[serde(skip_serializing, skip_deserializing, default)]
    pub private_key: PrivateKey,
}

/// A public key used for verification and encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// The raw public key bytes
    pub key_bytes: Vec<u8>,
    /// The verifying key for signatures
    #[serde(skip)]
    pub verifying_key: Option<VerifyingKey>,
}

/// A private key used for signing and decryption
#[derive(Debug, Clone, Serialize)]
pub struct PrivateKey {
    /// The raw private key bytes
    pub key_bytes: Vec<u8>,
    /// The signing key for signatures
    #[serde(skip_serializing, skip_deserializing)]
    pub signing_key: SigningKey,
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            #[serde(rename = "key_bytes")]
            KeyBytes,
        }

        struct PrivateKeyVisitor;

        impl<'de> de::Visitor<'de> for PrivateKeyVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct PrivateKey")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<PrivateKey, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut key_bytes: Option<Vec<u8>> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::KeyBytes => {
                            if key_bytes.is_some() {
                                return Err(de::Error::duplicate_field("key_bytes"));
                            }
                            key_bytes = Some(map.next_value()?);
                        }
                    }
                }
                let key_bytes = key_bytes.ok_or_else(|| de::Error::missing_field("key_bytes"))?;
                let key_bytes_clone = key_bytes.clone();
                let signing_key = SigningKey::from_bytes(
                    &key_bytes_clone
                        .try_into()
                        .map_err(|_| de::Error::custom("Invalid key length"))?,
                );
                Ok(PrivateKey {
                    key_bytes,
                    signing_key,
                })
            }
        }

        deserializer.deserialize_struct("PrivateKey", &["key_bytes"], PrivateKeyVisitor)
    }
}

impl Default for PrivateKey {
    fn default() -> Self {
        panic!("Default not implemented for PrivateKey");
    }
}

impl KeyPair {
    /// Create a new key pair from existing keys
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Generate a new key pair
    pub fn generate() -> Result<Self> {
        let mut rng = OsRng;
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self::new(
            PublicKey::from_bytes(&verifying_key.to_bytes())?,
            PrivateKey::from_bytes(&secret_key_bytes)?,
        ))
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the private key
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Check if the key pair is valid
    pub fn is_valid(&self) -> bool {
        self.public_key.verifying_key.is_some() && !self.private_key.key_bytes.is_empty()
    }
}

impl PublicKey {
    /// Create a new public key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

        Ok(Self {
            key_bytes: bytes.to_vec(),
            verifying_key: Some(verifying_key),
        })
    }

    /// Get the raw key bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_bytes == other.key_bytes
    }
}

impl Eq for PublicKey {}

impl PrivateKey {
    /// Create a new private key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes);

        Ok(Self {
            key_bytes: bytes.to_vec(),
            signing_key,
        })
    }

    /// Get the raw key bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

/// Cryptographic operations trait
#[async_trait]
pub trait CryptoOperations {
    /// Generate a new key pair
    async fn generate_key_pair() -> Result<KeyPair>;

    /// Sign a message with a private key
    async fn sign(&self, message: &[u8], private_key: &PrivateKey) -> Result<Signature>;

    /// Verify a signature with a public key
    async fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool>;

    /// Encrypt data with a public key
    async fn encrypt(&self, data: &[u8], public_key: &PublicKey) -> Result<EncryptedData>;

    /// Decrypt data with a private key
    async fn decrypt(
        &self,
        encrypted_data: &EncryptedData,
        private_key: &PrivateKey,
    ) -> Result<Vec<u8>>;
}
