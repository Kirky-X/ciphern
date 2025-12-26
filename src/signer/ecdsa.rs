// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::provider::Signer;
use crate::error::{CryptoError, Result};
use crate::hardware;
use crate::key::Key;
use crate::types::Algorithm;

/// ECDSA 签名提供者 - 使用硬件加速
pub struct EcdsaProvider {
    algorithm: Algorithm,
}

impl EcdsaProvider {
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    fn to_hardware_algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

impl Signer for EcdsaProvider {
    fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let private_key = key.secret_bytes()?;
        let algo = self.to_hardware_algorithm();
        hardware::accelerated_ecdsa_sign(private_key.as_bytes(), message, algo)
    }

    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let private_key = key.secret_bytes()?;

        use ring::signature::{EcdsaKeyPair, KeyPair};
        let secret = private_key.as_bytes();
        let alg = match self.algorithm {
            Algorithm::ECDSAP256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            Algorithm::ECDSAP384 => &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm(
                    "Key algorithm mismatch".into(),
                ))
            }
        };

        let rng = ring::rand::SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(alg, secret, &rng)
            .map_err(|e| CryptoError::KeyError(format!("Invalid ECDSA PKCS#8 key: {}", e)))?;

        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        let algo = self.to_hardware_algorithm();
        hardware::accelerated_ecdsa_verify(&public_key_bytes, message, signature, algo)
    }
}
