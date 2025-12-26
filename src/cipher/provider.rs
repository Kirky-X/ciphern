// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::types::Algorithm;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::cipher::aes::AesGcmProvider;
use crate::cipher::sm4::Sm4GcmProvider;
use crate::signer::ecdsa::EcdsaProvider;
use crate::signer::ed25519::Ed25519Provider;
use crate::signer::rsa::RsaProvider;
use crate::signer::sm2::Sm2Provider;

/// Symmetric Cipher Trait
pub trait SymmetricCipher: Send + Sync {
    fn encrypt(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
    fn decrypt(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
    #[allow(dead_code)]
    fn algorithm(&self) -> Algorithm;

    /// Specific for CAVP/KAT tests where IV must be provided
    #[allow(dead_code)]
    fn encrypt_with_nonce(
        &self,
        key: &Key,
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}

/// 签名算法 Trait
pub trait Signer: Send + Sync {
    fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool>;
}

/// 提供者注册表
pub struct ProviderRegistry {
    symmetric: RwLock<HashMap<Algorithm, Arc<dyn SymmetricCipher>>>,
    signers: RwLock<HashMap<Algorithm, Arc<dyn Signer>>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        let registry = Self {
            symmetric: RwLock::new(HashMap::new()),
            signers: RwLock::new(HashMap::new()),
        };
        registry.register_defaults();
        registry
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    fn register_defaults(&self) {
        {
            let mut map = self.symmetric.write().unwrap();
            map.insert(Algorithm::AES128GCM, Arc::new(AesGcmProvider::aes128()));
            map.insert(Algorithm::AES192GCM, Arc::new(AesGcmProvider::aes192()));
            map.insert(Algorithm::AES256GCM, Arc::new(AesGcmProvider::aes256()));
            map.insert(Algorithm::SM4GCM, Arc::new(Sm4GcmProvider::default()));
        }

        {
            let mut map = self.signers.write().unwrap();
            map.insert(
                Algorithm::ECDSAP256,
                Arc::new(EcdsaProvider::new(Algorithm::ECDSAP256)),
            );
            map.insert(
                Algorithm::ECDSAP384,
                Arc::new(EcdsaProvider::new(Algorithm::ECDSAP384)),
            );
            map.insert(
                Algorithm::RSA2048,
                Arc::new(RsaProvider::new(Algorithm::RSA2048)),
            );
            map.insert(
                Algorithm::RSA3072,
                Arc::new(RsaProvider::new(Algorithm::RSA3072)),
            );
            map.insert(
                Algorithm::RSA4096,
                Arc::new(RsaProvider::new(Algorithm::RSA4096)),
            );
            map.insert(
                Algorithm::Ed25519,
                Arc::new(Ed25519Provider::new(Algorithm::Ed25519)),
            );
            map.insert(Algorithm::SM2, Arc::new(Sm2Provider::new(Algorithm::SM2)));
        }
    }

    pub fn get_symmetric(&self, algo: Algorithm) -> Result<Arc<dyn SymmetricCipher>> {
        // FIPS 检查
        crate::fips::validate_algorithm_fips(&algo)?;

        let map = self
            .symmetric
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Registry Lock".into()))?;
        map.get(&algo)
            .cloned()
            .ok_or_else(|| CryptoError::UnsupportedAlgorithm(format!("{:?}", algo)))
    }

    pub fn get_signer(&self, algo: Algorithm) -> Result<Arc<dyn Signer>> {
        // FIPS 检查
        crate::fips::validate_algorithm_fips(&algo)?;

        let map = self
            .signers
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Registry Lock".into()))?;
        map.get(&algo)
            .cloned()
            .ok_or_else(|| CryptoError::UnsupportedAlgorithm(format!("{:?}", algo)))
    }
}

lazy_static! {
    pub static ref REGISTRY: ProviderRegistry = ProviderRegistry::new();
}
