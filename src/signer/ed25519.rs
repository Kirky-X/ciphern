// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::provider::Signer;
use crate::types::Algorithm;
use ring::signature::{Ed25519KeyPair, KeyPair, ED25519};

/// Ed25519 签名提供者
pub struct Ed25519Provider {
    algorithm: Algorithm,
}

impl Ed25519Provider {
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }
}

impl Signer for Ed25519Provider {
    fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let secret = key.secret_bytes()?;

        let key_pair = Ed25519KeyPair::from_pkcs8(secret.as_bytes())
            .map_err(|e| CryptoError::KeyError(format!("Invalid Ed25519 PKCS#8 key: {}", e)))?;

        let signature = key_pair.sign(message);

        Ok(signature.as_ref().to_vec())
    }

    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let secret = key.secret_bytes()?;

        let key_pair = Ed25519KeyPair::from_pkcs8(secret.as_bytes())
            .map_err(|e| CryptoError::KeyError(format!("Invalid Ed25519 PKCS#8 key: {}", e)))?;

        let public_key_bytes = key_pair.public_key().as_ref();

        use ring::signature::UnparsedPublicKey;

        let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);

        match public_key.verify(message, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
