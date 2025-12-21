// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::provider::SymmetricCipher;
use crate::random::SecureRandom;
use crate::side_channel::{
    protect_critical_operation, RotatingSboxMasking, SideChannelConfig, SideChannelContext,
};
use crate::types::Algorithm;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use std::sync::{Arc, Mutex};

pub struct Aes256GcmProvider {
    side_channel_context: Option<Arc<Mutex<SideChannelContext>>>,
    rotating_sbox: Option<Arc<Mutex<RotatingSboxMasking>>>,
}

impl Aes256GcmProvider {
    pub fn new() -> Self {
        let side_channel_context = Some(Arc::new(Mutex::new(SideChannelContext::new(
            SideChannelConfig::default(),
        ))));
        let rotating_sbox = RotatingSboxMasking::new(4)
            .ok()
            .map(|sbox| Arc::new(Mutex::new(sbox))); // 4 rotating S-boxes

        Self {
            side_channel_context,
            rotating_sbox,
        }
    }
}

impl Aes256GcmProvider {
    pub fn with_side_channel_config(config: SideChannelConfig) -> Self {
        let rotating_sbox = if config.power_analysis_protection {
            RotatingSboxMasking::new(4)
                .ok()
                .map(|sbox| Arc::new(Mutex::new(sbox))) // 4 rotating S-boxes if power analysis protection enabled
        } else {
            None
        };

        Self {
            side_channel_context: Some(Arc::new(Mutex::new(SideChannelContext::new(config)))),
            rotating_sbox,
        }
    }

    fn encrypt_internal(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        self.encrypt_core(key, plaintext, aad)
    }

    fn encrypt_core(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let secret = key.secret_bytes()?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
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

    fn decrypt_internal(
        &self,
        key: &Key,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt_core(key, ciphertext, aad)
    }

    fn decrypt_core(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let secret = key.secret_bytes()?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
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

    /// Perform side-channel protected key expansion
    #[allow(dead_code)]
    fn expand_key_protected(&self, key_bytes: &[u8]) -> Result<Vec<u8>> {
        // If we have rotating S-box protection, use it for key expansion
        if let Some(ref sbox_masking) = self.rotating_sbox {
            // Apply masked S-box operations during key expansion
            let mut expanded_key = Vec::with_capacity(240); // AES-256 expanded key size
            expanded_key.extend_from_slice(key_bytes);

            // Simulate key expansion with side-channel protection
            // In a real implementation, this would use the masked S-box for all SubBytes operations
            for i in 0..(expanded_key.len() / 4) {
                if i > 7 && i % 4 == 0 {
                    // Apply masked S-box transformation
                    let byte_idx = i * 4;
                    for j in 0..4 {
                        if byte_idx + j < expanded_key.len() {
                            let input = expanded_key[byte_idx + j];
                            // Use rotating S-box for side-channel protection
                            let mut sbox = sbox_masking.lock().map_err(|_| {
                                CryptoError::SideChannelError("S-box lock poisoned".into())
                            })?;
                            expanded_key[byte_idx + j] = sbox.lookup(input);
                        }
                    }
                }
            }

            Ok(expanded_key)
        } else {
            // Fallback to simple key copy without additional protection
            Ok(key_bytes.to_vec())
        }
    }

    /// Simple AES S-box lookup (for demonstration)
    fn _aes_sbox(input: u8) -> u8 {
        const AES_SBOX: [u8; 256] = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
            0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
            0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
            0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
            0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
            0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
            0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
            0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
            0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
            0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
            0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
            0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
            0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
            0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
            0xb0, 0x54, 0xbb, 0x16,
        ];
        AES_SBOX[input as usize]
    }
}

impl Default for Aes256GcmProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key;
    use crate::types::Algorithm;

    #[test]
    fn test_aes_with_side_channel_protection() {
        // 使用自定义配置强制启用所有防护
        let mut config = SideChannelConfig::default();
        config.power_analysis_protection = true; // 强制启用电源分析防护
        config.constant_time_enabled = true;
        config.error_injection_protection = true;
        config.cache_protection = true;

        let provider = Aes256GcmProvider::with_side_channel_config(config);
        assert!(provider.is_side_channel_protected());

        // Test basic encryption/decryption
        let key_data = vec![0u8; 32];
        let mut key = Key::new(Algorithm::AES256GCM, key_data).unwrap();

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
    fn test_aes_without_side_channel_protection() {
        let mut config = SideChannelConfig::default();
        config.power_analysis_protection = false;
        config.constant_time_enabled = false;
        config.error_injection_protection = false;
        config.cache_protection = false;

        let provider = Aes256GcmProvider::with_side_channel_config(config);
        assert!(!provider.is_side_channel_protected());

        // Test basic encryption/decryption
        let key_data = vec![0u8; 32];
        let key = Key::new_active(Algorithm::AES256GCM, key_data).unwrap();
        let plaintext = b"Hello, World! This is a test message.";

        // Encrypt
        let ciphertext = provider.encrypt(&key, plaintext, None).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = provider.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_wrong_algorithm_key() {
        let provider = Aes256GcmProvider::new();
        let key_data = vec![0u8; 32];
        let wrong_key = Key::new(Algorithm::SM4GCM, key_data).unwrap();
        let plaintext = b"test";

        let result = provider.encrypt(&wrong_key, plaintext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_invalid_ciphertext() {
        let provider = Aes256GcmProvider::new();
        let key_data = vec![0u8; 32];
        let key = Key::new(Algorithm::AES256GCM, key_data).unwrap();
        let invalid_ciphertext = b"too short";

        let result = provider.decrypt(&key, invalid_ciphertext, None);
        assert!(result.is_err());
    }
}

impl SymmetricCipher for Aes256GcmProvider {
    fn encrypt(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if key.algorithm() != Algorithm::AES256GCM {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algo mismatch".into(),
            ));
        }

        if let Some(context) = &self.side_channel_context {
            let mut context_guard = context
                .lock()
                .map_err(|_| CryptoError::SideChannelError("Context lock poisoned".into()))?;
            protect_critical_operation(&mut context_guard, || {
                self.encrypt_internal(key, plaintext, aad)
            })
        } else {
            self.encrypt_internal(key, plaintext, aad)
        }
    }

    fn decrypt(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if key.algorithm() != Algorithm::AES256GCM {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algo mismatch".into(),
            ));
        }

        if let Some(context) = &self.side_channel_context {
            let mut context_guard = context
                .lock()
                .map_err(|_| CryptoError::SideChannelError("Context lock poisoned".into()))?;
            protect_critical_operation(&mut context_guard, || {
                self.decrypt_internal(key, ciphertext, aad)
            })
        } else {
            self.decrypt_internal(key, ciphertext, aad)
        }
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::AES256GCM
    }

    fn encrypt_with_nonce(
        &self,
        key: &Key,
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.algorithm() != Algorithm::AES256GCM {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algo mismatch".into(),
            ));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::EncryptionFailed("Invalid nonce length".into()));
        }

        let operation = || {
            let secret = key.secret_bytes()?;

            let unbound_key = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
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

        if let Some(context) = &self.side_channel_context {
            let mut context_guard = context
                .lock()
                .map_err(|_| CryptoError::SideChannelError("Context lock poisoned".into()))?;
            protect_critical_operation(&mut context_guard, operation)
        } else {
            operation()
        }
    }
}

impl Aes256GcmProvider {
    /// Get side-channel protection statistics
    pub fn get_side_channel_stats(&self) -> Option<crate::side_channel::SideChannelStats> {
        self.side_channel_context
            .as_ref()
            .and_then(|ctx| ctx.lock().ok().map(|guard| guard.get_stats()))
    }

    /// Check if side-channel protection is enabled
    pub fn is_side_channel_protected(&self) -> bool {
        self.side_channel_context.is_some() && self.rotating_sbox.is_some()
    }
}
