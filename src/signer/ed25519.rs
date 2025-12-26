// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::provider::Signer;
use crate::error::{CryptoError, Result};
use crate::hardware;
use crate::key::Key;
use crate::types::Algorithm;

/// Ed25519 签名提供者 - 使用硬件加速
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

        let private_key = key.secret_bytes()?;
        hardware::accelerated_ed25519_sign(private_key.as_bytes(), message)
    }

    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let public_key_bytes = if let Ok(private_key) = key.secret_bytes() {
            use ring::signature::{Ed25519KeyPair, KeyPair};
            let key_pair = Ed25519KeyPair::from_pkcs8(private_key.as_bytes())
                .map_err(|e| CryptoError::KeyError(format!("Invalid Ed25519 PKCS#8 key: {}", e)))?;
            key_pair.public_key().as_ref().to_vec()
        } else {
            key.public_bytes()?
        };

        hardware::accelerated_ed25519_verify(&public_key_bytes, message, signature)
    }
}
