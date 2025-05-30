use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

/// A digital signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// The raw signature bytes
    pub signature_bytes: Vec<u8>,
    /// The Ed25519 signature
    #[serde(skip)]
    pub ed25519_signature: Option<Ed25519Signature>,
}

impl Signature {
    /// Create a new signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|_| crate::CryptoError::InvalidSignature("Invalid signature length".into()))?;
        let ed25519_signature = Ed25519Signature::from_bytes(&bytes);

        Ok(Self {
            signature_bytes: bytes.to_vec(),
            ed25519_signature: Some(ed25519_signature),
        })
    }

    /// Get the raw signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature_bytes
    }

    /// Verify this signature against a message and public key
    pub fn verify(&self, message: &[u8], public_key: &crate::PublicKey) -> crate::Result<bool> {
        let signature = self.ed25519_signature.as_ref().ok_or_else(|| {
            crate::CryptoError::InvalidSignature("Signature not initialized".into())
        })?;

        let verifying_key = public_key.verifying_key.as_ref().ok_or_else(|| {
            crate::CryptoError::InvalidKeyFormat("Public key not initialized".into())
        })?;

        verifying_key
            .verify(message, signature)
            .map(|_| true)
            .map_err(|e| crate::CryptoError::InvalidSignature(e.to_string()))
    }
}

impl From<Ed25519Signature> for Signature {
    fn from(sig: Ed25519Signature) -> Self {
        Self {
            signature_bytes: sig.to_bytes().to_vec(),
            ed25519_signature: Some(sig),
        }
    }
}
