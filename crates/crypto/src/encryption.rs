use ring::aead::{self, Aad};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

/// Encrypted data with associated metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encrypted data bytes
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption
    pub nonce: Vec<u8>,
    /// Additional authenticated data (if any)
    pub aad: Option<Vec<u8>>,
}

/// An encryption key for symmetric encryption
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    /// The raw key bytes
    key_bytes: Vec<u8>,
    /// The AEAD key
    #[doc(hidden)]
    aead_key: aead::LessSafeKey,
}

impl EncryptionKey {
    /// Create a new encryption key from bytes
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let aead_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
                .map_err(|e| crate::CryptoError::InvalidKeyFormat(e.to_string()))?,
        );

        Ok(Self {
            key_bytes: bytes.to_vec(),
            aead_key,
        })
    }

    /// Generate a new random encryption key
    pub fn generate() -> crate::Result<Self> {
        let mut key_bytes = vec![0u8; 32]; // 256 bits for ChaCha20-Poly1305
        ring::rand::SystemRandom::new()
            .fill(&mut key_bytes)
            .map_err(|e| crate::CryptoError::KeyGenerationError(e.to_string()))?;

        Self::from_bytes(&key_bytes)
    }

    /// Get the raw key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Encrypt data with this key
    pub fn encrypt(&self, data: &[u8], aad: Option<&[u8]>) -> crate::Result<EncryptedData> {
        let mut nonce_bytes = [0u8; 12];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|e| crate::CryptoError::EncryptionError(e.to_string()))?;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = data.to_vec();

        let aad_bytes = aad.unwrap_or(&[]);
        let aad = Aad::from(aad_bytes);
        self.aead_key
            .seal_in_place_separate_tag(nonce, aad, &mut in_out)
            .map_err(|e| crate::CryptoError::EncryptionError(e.to_string()))?;

        Ok(EncryptedData {
            ciphertext: in_out,
            nonce: nonce_bytes.to_vec(),
            aad: Some(aad_bytes.to_vec()),
        })
    }

    /// Decrypt data with this key
    pub fn decrypt(&self, encrypted: &EncryptedData) -> crate::Result<Vec<u8>> {
        let nonce = aead::Nonce::try_assume_unique_for_key(&encrypted.nonce)
            .map_err(|e| crate::CryptoError::DecryptionError(e.to_string()))?;

        let mut ciphertext = encrypted.ciphertext.clone();
        let aad = Aad::from(encrypted.aad.as_deref().unwrap_or(&[]));

        self.aead_key
            .open_in_place(nonce, aad, &mut ciphertext)
            .map_err(|e| crate::CryptoError::DecryptionError(e.to_string()))?;

        Ok(ciphertext)
    }
}
