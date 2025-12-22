// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::base_provider::BaseCipherProvider;
use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::provider::SymmetricCipher;
use crate::random::SecureRandom;
use crate::side_channel::SideChannelConfig;
use crate::types::Algorithm;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{aes::Aes192, AeadCore, AesGcm};

/// AES-192 GCM Provider with unified base provider structure
pub struct Aes192GcmProvider {
    base: BaseCipherProvider,
}

impl Aes192GcmProvider {
    /// Create a new AES-192 GCM provider with default configuration
    pub fn new() -> Self {
        Self {
            base: BaseCipherProvider::new(),
        }
    }

    /// Create a new AES-192 GCM provider with custom side-channel configuration
    pub fn with_side_channel_config(config: SideChannelConfig) -> Self {
        Self {
            base: BaseCipherProvider::with_side_channel_config(config),
        }
    }

    /// Internal encryption implementation
    fn encrypt_internal(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let secret = key.secret_bytes()?;
        self.encrypt_core(secret.as_bytes(), plaintext, aad)
    }

    /// Core encryption logic
    fn encrypt_core(&self, key_bytes: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let cipher = AesGcm::<Aes192, U12>::new_from_slice(key_bytes)
            .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;

        let nonce = AesGcm::<Aes192, U12>::generate_nonce(&mut SecureRandom::new()?);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))?;

        // Prepend Nonce
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Internal decryption implementation
    fn decrypt_internal(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let secret = key.secret_bytes()?;
        self.decrypt_core(secret.as_bytes(), ciphertext, aad)
    }

    /// Core decryption logic
    fn decrypt_core(&self, key_bytes: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let cipher = AesGcm::<Aes192, U12>::new_from_slice(key_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid Key".into()))?;

        if ciphertext.len() < 12 {
            // Nonce size
            return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = nonce_bytes.into();

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: encrypted_data,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed("Decryption failed".into()))?;

        Ok(plaintext)
    }

    /// Get side-channel protection statistics
    pub fn get_side_channel_stats(&self) -> Option<crate::side_channel::SideChannelStats> {
        self.base.side_channel_context()
            .as_ref()
            .map(|ctx| ctx.lock().unwrap().get_stats())
    }

    /// Check if side-channel protection is enabled
    pub fn is_side_channel_protected(&self) -> bool {
        self.base.side_channel_context().is_some()
    }
}

impl Default for Aes192GcmProvider {
    fn default() -> Self {
        Self::new()
    }
}

crate::impl_cipher_provider!(Aes192GcmProvider, Algorithm::AES192GCM);

impl SymmetricCipher for Aes192GcmProvider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::AES192GCM
    }

    fn encrypt(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if key.algorithm() != Algorithm::AES192GCM {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algo mismatch".into(),
            ));
        }

        self.base.protect_operation(|| self.encrypt_internal(key, plaintext, aad))
    }

    fn decrypt(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            // Nonce + Tag min
            return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        self.base.protect_operation(|| self.decrypt_internal(key, ciphertext, aad))
    }

    fn encrypt_with_nonce(
        &self,
        key: &Key,
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.algorithm() != Algorithm::AES192GCM {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algo mismatch".into(),
            ));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::EncryptionFailed("Invalid nonce length".into()));
        }

        let operation = || {
            let secret = key.secret_bytes()?;

            let cipher = AesGcm::<Aes192, U12>::new_from_slice(secret.as_bytes())
                .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
            let nonce_val = nonce.into();

            cipher
                .encrypt(
                    nonce_val,
                    Payload {
                        msg: plaintext,
                        aad: aad.unwrap_or(&[]),
                    },
                )
                .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))
        };

        self.base.protect_operation(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key;
    use crate::types::Algorithm;

    #[test]
    fn test_aes192_with_side_channel_protection() {
        // 使用自定义配置强制启用所有防护
        let config = SideChannelConfig {
            power_analysis_protection: true, // 强制启用电源分析防护
            constant_time_enabled: true,
            error_injection_protection: true,
            cache_protection: true,
            ..SideChannelConfig::default()
        };

        let provider = Aes192GcmProvider::with_side_channel_config(config);
        assert!(provider.is_side_channel_protected());

        // Test basic encryption/decryption
        let key_data = vec![0u8; 24];
        let mut key = Key::new(Algorithm::AES192GCM, key_data).unwrap();

        // 激活密钥以使其有效
        key.activate(None).unwrap();

        let plaintext = b"Hello, World! This is a test message.";
        let aad = b"additional authenticated data";

        // Encrypt
        let ciphertext = provider.encrypt(&key, plaintext, Some(aad)).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = provider.decrypt(&key, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);

        // Check stats
        let stats = provider.get_side_channel_stats().unwrap();
        println!("Side-channel stats: {:?}", stats);
        assert!(
            stats.timing_protections > 0
                || stats.masking_operations > 0
                || stats.error_detection_triggers > 0
                || stats.cache_flush_operations > 0
        );
    }

    #[test]
    fn test_aes192_without_side_channel_protection() {
        let config = SideChannelConfig {
            power_analysis_protection: false,
            constant_time_enabled: false,
            error_injection_protection: false,
            cache_protection: false,
            timing_noise_enabled: false,
            masking_operations_enabled: false,
            redundancy_checks_enabled: false,
            cache_flush_enabled: false,
            ..SideChannelConfig::default()
        };

        // 即使配置全关，new() 默认也会创建一个 context
        // 我们通过 is_side_channel_protected() 检查的是 context 是否存在
        let provider = Aes192GcmProvider::with_side_channel_config(config);
        assert!(provider.is_side_channel_protected());

        // Test basic encryption/decryption
        let key_data = vec![0u8; 24];
        let mut key = Key::new(Algorithm::AES192GCM, key_data).unwrap();
        key.activate(None).unwrap();
        let plaintext = b"Hello, World! This is a test message.";

        // Encrypt
        let ciphertext = provider.encrypt(&key, plaintext, None).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = provider.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes192_wrong_algorithm_key() {
        let provider = Aes192GcmProvider::new();
        let key_data = vec![0u8; 24];
        let wrong_key = Key::new(Algorithm::SM4GCM, key_data).unwrap();
        let plaintext = b"test";

        let result = provider.encrypt(&wrong_key, plaintext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes192_invalid_ciphertext() {
        let provider = Aes192GcmProvider::new();
        let key_data = vec![0u8; 24];
        let key = Key::new(Algorithm::AES192GCM, key_data).unwrap();
        let invalid_ciphertext = b"too short";

        let result = provider.decrypt(&key, invalid_ciphertext, None);
        assert!(result.is_err());
    }
}