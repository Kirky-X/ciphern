// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::provider::Signer;
use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::types::Algorithm;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
};

/// ECDSA 签名提供者
pub struct EcdsaProvider {
    algorithm: Algorithm,
}

impl EcdsaProvider {
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    fn get_signing_alg(&self) -> Result<&'static ring::signature::EcdsaSigningAlgorithm> {
        match self.algorithm {
            Algorithm::ECDSAP256 => Ok(&ECDSA_P256_SHA256_FIXED_SIGNING),
            Algorithm::ECDSAP384 => Ok(&ECDSA_P384_SHA384_FIXED_SIGNING),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "{:?}",
                self.algorithm
            ))),
        }
    }

    fn get_verification_alg(&self) -> Result<&'static ring::signature::EcdsaVerificationAlgorithm> {
        match self.algorithm {
            Algorithm::ECDSAP256 => Ok(&ring::signature::ECDSA_P256_SHA256_FIXED),
            Algorithm::ECDSAP384 => Ok(&ring::signature::ECDSA_P384_SHA384_FIXED),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "{:?}",
                self.algorithm
            ))),
        }
    }
}

impl Signer for EcdsaProvider {
    fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let secret = key.secret_bytes()?;
        let alg = self.get_signing_alg()?;

        let rng = ring::rand::SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(alg, secret.as_bytes(), &rng)
            .map_err(|e| CryptoError::KeyError(format!("Invalid ECDSA PKCS#8 key: {}", e)))?;

        let signature = key_pair
            .sign(&rng, message)
            .map_err(|_| CryptoError::SigningFailed("ECDSA signing failed".into()))?;

        Ok(signature.as_ref().to_vec())
    }

    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let secret = key.secret_bytes()?;
        let alg = self.get_signing_alg()?;

        let rng = ring::rand::SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(alg, secret.as_bytes(), &rng)
            .map_err(|e| CryptoError::KeyError(format!("Invalid ECDSA PKCS#8 key: {}", e)))?;

        let public_key_bytes = key_pair.public_key().as_ref();
        let verification_alg = self.get_verification_alg()?;

        let public_key = UnparsedPublicKey::new(verification_alg, public_key_bytes);

        match public_key.verify(message, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
