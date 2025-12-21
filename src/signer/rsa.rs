// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::provider::Signer;
use crate::types::Algorithm;
use ring::signature::{KeyPair, RsaKeyPair};

/// RSA 签名提供者
pub struct RsaProvider {
    algorithm: Algorithm,
}

impl RsaProvider {
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    fn get_signing_alg(&self) -> Result<&'static dyn ring::signature::RsaEncoding> {
        match self.algorithm {
            Algorithm::RSA2048 | Algorithm::RSA3072 | Algorithm::RSA4096 => {
                Ok(&ring::signature::RSA_PKCS1_SHA256)
            }
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "{:?}",
                self.algorithm
            ))),
        }
    }
}

impl Signer for RsaProvider {
    fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let secret = key.secret_bytes()?;

        let key_pair = RsaKeyPair::from_pkcs8(secret.as_bytes())
            .map_err(|e| CryptoError::KeyError(format!("Invalid RSA PKCS#8 key: {}", e)))?;

        let mut signature = vec![0u8; key_pair.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();

        key_pair
            .sign(self.get_signing_alg()?, &rng, message, &mut signature)
            .map_err(|_| CryptoError::SigningFailed("RSA signing failed".into()))?;

        Ok(signature)
    }

    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let secret = key.secret_bytes()?;

        let key_pair = RsaKeyPair::from_pkcs8(secret.as_bytes())
            .map_err(|e| CryptoError::KeyError(format!("Invalid RSA PKCS#8 key: {}", e)))?;

        let public_key_bytes = key_pair.public_key().as_ref();

        let verification_alg = match self.algorithm {
            Algorithm::RSA2048 | Algorithm::RSA3072 | Algorithm::RSA4096 => {
                &ring::signature::RSA_PKCS1_2048_8192_SHA256
            }
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm(format!(
                    "{:?}",
                    self.algorithm
                )))
            }
        };

        let public_key =
            ring::signature::UnparsedPublicKey::new(verification_alg, public_key_bytes);

        match public_key.verify(message, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
