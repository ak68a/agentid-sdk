use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A key pair consisting of a public and private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// The public key component
    pub public_key: PublicKey,
    /// The private key component
    #[serde(skip_serializing)]
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
#[derive(Debug, Clone)]
pub struct PrivateKey {
    /// The raw private key bytes
    pub key_bytes: Vec<u8>,
    /// The signing key for signatures
    pub signing_key: SigningKey,
}

impl KeyPair {
    /// Create a new key pair from existing keys
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the private key
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

impl PublicKey {
    /// Create a new public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| crate::CryptoError::InvalidKeyFormat(e.to_string()))?;

        Ok(Self {
            key_bytes: bytes.to_vec(),
            verifying_key: Some(verifying_key),
        })
    }

    /// Get the raw key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

impl PrivateKey {
    /// Create a new private key from bytes
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes)
            .map_err(|e| crate::CryptoError::InvalidKeyFormat(e.to_string()))?;

        Ok(Self {
            key_bytes: bytes.to_vec(),
            signing_key,
        })
    }

    /// Get the raw key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}
