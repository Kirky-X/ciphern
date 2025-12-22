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
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

/// AES-128 GCM Provider with unified base provider structure
pub struct Aes128GcmProvider {
    base: BaseCipherProvider,
}

impl Aes128GcmProvider {
    /// Create a new AES-128 GCM provider with default configuration
    pub fn new() -> Self {
        Self {
            base: BaseCipherProvider::new(),
        }
    }

    /// Create a new AES-128 GCM provider with custom side-channel configuration
    pub fn with_side_channel_config(config: SideChannelConfig) -> Self {
        Self {
            base: BaseCipherProvider::with_side_channel_config(config),
        }
    }

    /// Internal encryption implementation
    fn encrypt_internal(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let key_bytes = key.secret_bytes()?;
        self.encrypt_core(key_bytes.as_bytes(), plaintext, aad)
    }

    /// Core encryption logic
    fn encrypt_core(&self, key_bytes: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_128_GCM, key_bytes)
            .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; 12];
        SecureRandom::new()?.fill(&mut nonce_bytes)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        less_safe_key
            .seal_in_place_append_tag(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

        // Prepend Nonce
        let mut result = nonce_bytes.to_vec();
        result.append(&mut in_out);
        Ok(result)
    }

    /// Internal decryption implementation
    fn decrypt_internal(
        &self,
        key: &Key,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key_bytes = key.secret_bytes()?;
        self.decrypt_core(key_bytes.as_bytes(), ciphertext, aad)
    }

    /// Core decryption logic
    fn decrypt_core(&self, key_bytes: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_128_GCM, key_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid Key".into()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionFailed(
                "Invalid ciphertext length".into(),
            ));
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce_array: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed("Invalid nonce length".into()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_array);

        let mut in_out = encrypted_data.to_vec();
        let plaintext = less_safe_key
            .open_in_place(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed("Open failed".into()))?;

        Ok(plaintext.to_vec())
    }

    /// Get side-channel protection statistics
    pub fn get_side_channel_stats(&self) -> Option<crate::side_channel::SideChannelStats> {
        self.base.side_channel_context()
            .as_ref()
            .map(|ctx| ctx.lock().unwrap().get_stats())
    }

    /// Check if side-channel protection is enabled
    pub fn is_side_channel_protected(&self) -> bool {
        self.base.side_channel_context().is_some() && self.base.rotating_sbox().is_some()
    }
}

impl Default for Aes128GcmProvider {
    fn default() -> Self {
        Self::new()
    }
}

crate::impl_cipher_provider!(Aes128GcmProvider, Algorithm::AES128GCM);

impl SymmetricCipher for Aes128GcmProvider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::AES128GCM
    }

    fn encrypt(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if key.algorithm() != Algorithm::AES128GCM {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algo mismatch".into(),
            ));
        }

        self.base.protect_operation(|| self.encrypt_internal(key, plaintext, aad))
    }

    fn decrypt(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 + 16 {
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
        if key.algorithm() != Algorithm::AES128GCM {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algo mismatch".into(),
            ));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::EncryptionFailed("Invalid nonce length".into()));
        }

        let operation = || {
            let key_bytes = key.secret_bytes()?;

            let unbound_key = UnboundKey::new(&AES_128_GCM, key_bytes.as_bytes())
                .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
            let less_safe_key = LessSafeKey::new(unbound_key);
            let nonce_val = Nonce::assume_unique_for_key(
                nonce
                    .try_into()
                    .map_err(|_| CryptoError::EncryptionFailed("Invalid nonce".into()))?,
            );

            let mut in_out = plaintext.to_vec();
            less_safe_key
                .seal_in_place_append_tag(nonce_val, Aad::from(aad.unwrap_or(&[])), &mut in_out)
                .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

            Ok(in_out)
        };

        self.base.protect_operation(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key;

    #[test]
    fn test_aes128_with_side_channel_protection() {
        // 使用自定义配置强制启用所有防护
        let config = SideChannelConfig {
            power_analysis_protection: true, // 强制启用电源分析防护
            constant_time_enabled: true,
            error_injection_protection: true,
            cache_protection: true,
            timing_noise_enabled: true,
            masking_operations_enabled: true,
            redundancy_checks_enabled: true,
            cache_flush_enabled: true,
            ..SideChannelConfig::default()
        };

        let provider = Aes128GcmProvider::with_side_channel_config(config);
        assert!(provider.is_side_channel_protected());

        // Test basic encryption/decryption
        let key_data = vec![0u8; 16];
        let mut key = Key::new(Algorithm::AES128GCM, key_data).unwrap();

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
    fn test_aes128_without_side_channel_protection() {
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

        let provider = Aes128GcmProvider::with_side_channel_config(config);
        assert!(!provider.is_side_channel_protected());

        // Test basic encryption/decryption
        let key_data = vec![0u8; 16];
        let key = Key::new_active(Algorithm::AES128GCM, key_data).unwrap();
        let plaintext = b"Hello, World! This is a test message.";

        // Encrypt
        let ciphertext = provider.encrypt(&key, plaintext, None).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = provider.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_wrong_algorithm_key() {
        let provider = Aes128GcmProvider::new();
        let key_data = vec![0u8; 16];
        let wrong_key = Key::new(Algorithm::SM4GCM, key_data).unwrap();
        let plaintext = b"test";

        let result = provider.encrypt(&wrong_key, plaintext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes128_invalid_ciphertext() {
        let provider = Aes128GcmProvider::new();
        let key_data = vec![0u8; 16];
        let key = Key::new(Algorithm::AES128GCM, key_data).unwrap();
        let invalid_ciphertext = b"too short";

        let result = provider.decrypt(&key, invalid_ciphertext, None);
        assert!(result.is_err());
    }
}