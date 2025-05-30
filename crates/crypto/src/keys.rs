use async_trait::async_trait;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{CryptoError, KeyPair, PrivateKey, PublicKey, Result};

/// Manages cryptographic keys and operations
#[derive(Clone)]
pub struct KeyManager {
    current_key: Arc<RwLock<KeyPair>>,
    min_key_strength: u32, // Minimum bits of security
}

impl KeyManager {
    /// Create a new KeyManager with the given initial key pair
    pub fn new(initial_key: KeyPair, min_key_strength: u32) -> Self {
        Self {
            current_key: Arc::new(RwLock::new(initial_key)),
            min_key_strength,
        }
    }

    /// Generate a new key pair
    pub async fn generate_key_pair(&self) -> Result<KeyPair> {
        let mut rng = OsRng;
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(KeyPair::new(
            PublicKey::from_bytes(&verifying_key.to_bytes())?,
            PrivateKey::from_bytes(&secret_key_bytes)?,
        ))
    }

    /// Validate if a key meets the minimum strength requirements
    pub async fn validate_key_strength(&self, key: &KeyPair) -> Result<bool> {
        // For Ed25519, we consider it secure if it's a valid key
        // In a real implementation, you might want to add more checks
        Ok(key.public_key().verifying_key.is_some())
    }

    /// Get the current public key
    pub async fn current_public_key(&self) -> Result<PublicKey> {
        Ok(self.current_key.read().await.public_key().clone())
    }

    /// Generate a random challenge for key ownership proof
    pub async fn generate_challenge(&self) -> Result<Vec<u8>> {
        let mut challenge = vec![0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        Ok(challenge)
    }

    /// Sign data with the given key
    pub async fn sign(&self, data: &[u8], key: &KeyPair) -> Result<Vec<u8>> {
        let signature = key.private_key().signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify a signature
    pub async fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool> {
        let verifying_key = public_key
            .verifying_key
            .as_ref()
            .ok_or_else(|| CryptoError::InvalidKeyFormat("Public key not initialized".into()))?;

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature("Invalid signature length".into()))?;
        let sig = Ed25519Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(data, &sig).is_ok())
    }

    /// Rotate to a new key
    pub async fn rotate_key(&self, new_public_key: PublicKey) -> Result<()> {
        // In a real implementation, you might want to:
        // 1. Verify the new key is different from current
        // 2. Validate the new key
        // 3. Store the old key for a grace period
        // 4. Update any key metadata

        let mut current = self.current_key.write().await;
        *current = KeyPair::new(new_public_key, current.private_key().clone());
        Ok(())
    }
}
