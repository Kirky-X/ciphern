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
use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::{aes::Aes192, AesGcm};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

/// AES key length enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeyLength {
    Aes128,
    Aes192,
    Aes256,
}

/// Unified AES-GCM Provider supporting AES-128, AES-192, and AES-256
pub struct AesGcmProvider {
    base: BaseCipherProvider,
    key_length: AesKeyLength,
}

/// Type alias for backward compatibility
pub type Aes256GcmProvider = AesGcmProvider;

impl SymmetricCipher for AesGcmProvider {
    fn encrypt(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let expected_algorithm = match self.key_length {
            AesKeyLength::Aes128 => Algorithm::AES128GCM,
            AesKeyLength::Aes192 => Algorithm::AES192GCM,
            AesKeyLength::Aes256 => Algorithm::AES256GCM,
        };
        if key.algorithm() != expected_algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }
        self.base.protect_operation(|| self.encrypt_internal(key, plaintext, aad))
    }

    fn decrypt(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let expected_algorithm = match self.key_length {
            AesKeyLength::Aes128 => Algorithm::AES128GCM,
            AesKeyLength::Aes192 => Algorithm::AES192GCM,
            AesKeyLength::Aes256 => Algorithm::AES256GCM,
        };
        if key.algorithm() != expected_algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }
        self.base.protect_operation(|| self.decrypt_internal(key, ciphertext, aad))
    }

    fn algorithm(&self) -> Algorithm {
        match self.key_length {
            AesKeyLength::Aes128 => Algorithm::AES128GCM,
            AesKeyLength::Aes192 => Algorithm::AES192GCM,
            AesKeyLength::Aes256 => Algorithm::AES256GCM,
        }
    }

    fn encrypt_with_nonce(
        &self,
        key: &Key,
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let expected_algorithm = match self.key_length {
            AesKeyLength::Aes128 => Algorithm::AES128GCM,
            AesKeyLength::Aes192 => Algorithm::AES192GCM,
            AesKeyLength::Aes256 => Algorithm::AES256GCM,
        };
        if key.algorithm() != expected_algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::EncryptionFailed("Invalid nonce length".into()));
        }

        let operation = || {
            let secret = key.secret_bytes()?;

            match self.key_length {
                AesKeyLength::Aes128 => {
                    let cipher = AesGcm::<aes_gcm::aes::Aes128, U12>::new_from_slice(secret.as_bytes())
                        .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                    let nonce_val = nonce.into();
                    
                    cipher.encrypt(
                        nonce_val,
                        Payload {
                            msg: plaintext,
                            aad: aad.unwrap_or(&[]),
                        },
                    ).map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))
                },
                AesKeyLength::Aes192 => {
                    let cipher = AesGcm::<Aes192, U12>::new_from_slice(secret.as_bytes())
                        .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                    let nonce_val = nonce.into();
                    
                    cipher.encrypt(
                        nonce_val,
                        Payload {
                            msg: plaintext,
                            aad: aad.unwrap_or(&[]),
                        },
                    ).map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))
                },
                AesKeyLength::Aes256 => {
                    let unbound_key = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
                        .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                    let less_safe_key = LessSafeKey::new(unbound_key);
                    let nonce_val = Nonce::assume_unique_for_key(nonce.try_into().unwrap());

                    let mut in_out = plaintext.to_vec();
                    less_safe_key
                        .seal_in_place_append_tag(nonce_val, Aad::from(aad.unwrap_or(&[])), &mut in_out)
                        .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

                    Ok(in_out)
                }
            }
        };

        self.base.protect_operation(operation)
    }
}

impl AesGcmProvider {
    /// Create a new AES-256 GCM provider with default configuration (backward compatibility)
    pub fn new() -> Self {
        Self::with_key_length(AesKeyLength::Aes256)
    }

    /// Create a new AES-GCM provider with specified key length
    pub fn with_key_length(key_length: AesKeyLength) -> Self {
        Self {
            base: BaseCipherProvider::new(),
            key_length,
        }
    }

    /// Create a new AES-GCM provider with custom side-channel configuration
    pub fn with_side_channel_config(config: SideChannelConfig) -> Self {
        Self::with_key_length_and_config(AesKeyLength::Aes256, config)
    }

    /// Create a new AES-GCM provider with specified key length and side-channel configuration
    pub fn with_key_length_and_config(key_length: AesKeyLength, config: SideChannelConfig) -> Self {
        Self {
            base: BaseCipherProvider::with_side_channel_config(config),
            key_length,
        }
    }

    fn encrypt_internal(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let secret_bytes = key.secret_bytes()?;
        self.encrypt_core(secret_bytes.as_bytes(), plaintext, aad)
    }

    /// Core encryption logic supporting all AES key lengths
    fn encrypt_core(&self, key_bytes: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        match self.key_length {
            AesKeyLength::Aes128 => self.encrypt_with_aes128(key_bytes, plaintext, aad),
            AesKeyLength::Aes192 => self.encrypt_with_aes192(key_bytes, plaintext, aad),
            AesKeyLength::Aes256 => self.encrypt_with_aes256(key_bytes, plaintext, aad),
        }
    }

    /// AES-128 encryption using aes-gcm crate
    fn encrypt_with_aes128(&self, key_bytes: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let cipher = AesGcm::<aes_gcm::aes::Aes128, U12>::new_from_slice(key_bytes)
            .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;

        let nonce = AesGcm::<aes_gcm::aes::Aes128, U12>::generate_nonce(&mut SecureRandom::new()?);

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

    /// AES-192 encryption using aes-gcm crate
    fn encrypt_with_aes192(&self, key_bytes: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
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

    /// AES-256 encryption using ring crate
    fn encrypt_with_aes256(&self, key_bytes: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; 12];
        SecureRandom::new()?.fill(&mut nonce_bytes)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        less_safe_key
            .seal_in_place_append_tag(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

        // 组合 Nonce 和加密结果
        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        
        Ok(result)
    }

    fn decrypt_internal(
        &self,
        key: &Key,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let secret = key.secret_bytes()?;
        self.decrypt_core(secret.as_bytes(), ciphertext, aad)
    }

    /// Core decryption logic supporting all AES key lengths
    fn decrypt_core(&self, key_bytes: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        match self.key_length {
            AesKeyLength::Aes128 => self.decrypt_with_aes128(key_bytes, ciphertext, aad),
            AesKeyLength::Aes192 => self.decrypt_with_aes192(key_bytes, ciphertext, aad),
            AesKeyLength::Aes256 => self.decrypt_with_aes256(key_bytes, ciphertext, aad),
        }
    }

    /// AES-128 decryption using aes-gcm crate
    fn decrypt_with_aes128(&self, key_bytes: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let cipher = AesGcm::<aes_gcm::aes::Aes128, U12>::new_from_slice(key_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid Key".into()))?;

        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = nonce_bytes.into();

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: encrypted_data,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed("Decryption failed".into()))
    }

    /// AES-192 decryption using aes-gcm crate
    fn decrypt_with_aes192(&self, key_bytes: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let cipher = AesGcm::<Aes192, U12>::new_from_slice(key_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid Key".into()))?;

        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = nonce_bytes.into();

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: encrypted_data,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed("Decryption failed".into()))
    }

    /// AES-256 decryption using ring crate
    fn decrypt_with_aes256(&self, key_bytes: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid Key".into()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid nonce".into()))?;

        let mut in_out = encrypted_data.to_vec();
        less_safe_key
            .open_in_place(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed("Open failed".into()))?;

        // Remove the authentication tag from the end
        let plaintext_len = in_out.len().saturating_sub(16); // AES-GCM tag size is 16 bytes
        in_out.truncate(plaintext_len);
        Ok(in_out)
    }

    /// Perform side-channel protected key expansion
    #[allow(dead_code)]
    fn expand_key_protected(&self, key_bytes: &[u8]) -> Result<Vec<u8>> {
        self.base.expand_key_protected(key_bytes)
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

impl Default for AesGcmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Aes256GcmProvider {
    /// Get side-channel protection statistics
    pub fn get_side_channel_stats(&self) -> Option<crate::side_channel::SideChannelStats> {
        self.base.get_side_channel_stats()
    }

    /// Check if side-channel protection is enabled
    pub fn is_side_channel_protected(&self) -> bool {
        self.base.is_side_channel_protected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key;
    use crate::types::Algorithm;

    #[test]
    fn test_aes128_encryption_decryption() {
        let provider = AesGcmProvider::aes128();
        assert_eq!(provider.key_length(), AesKeyLength::Aes128);

        let key_data = vec![0u8; 16]; // AES-128 uses 16-byte keys
        let key = Key::new_active(Algorithm::AES128GCM, key_data).unwrap();

        let plaintext = b"Hello, World! This is a test message.";
        let aad = b"additional authenticated data";

        // Encrypt
        let ciphertext = provider.encrypt(&key, plaintext, Some(aad)).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = provider.decrypt(&key, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes192_encryption_decryption() {
        let provider = AesGcmProvider::aes192();
        assert_eq!(provider.key_length(), AesKeyLength::Aes192);

        let key_data = vec![0u8; 24]; // AES-192 uses 24-byte keys
        let key = Key::new_active(Algorithm::AES192GCM, key_data).unwrap();

        let plaintext = b"Hello, World! This is a test message.";
        let aad = b"additional authenticated data";

        // Encrypt
        let ciphertext = provider.encrypt(&key, plaintext, Some(aad)).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = provider.decrypt(&key, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_encryption_decryption() {
        let provider = AesGcmProvider::aes256();
        assert_eq!(provider.key_length(), AesKeyLength::Aes256);

        let key_data = vec![0u8; 32]; // AES-256 uses 32-byte keys
        let key = Key::new_active(Algorithm::AES256GCM, key_data).unwrap();

        let plaintext = b"Hello, World! This is a test message.";
        let aad = b"additional authenticated data";

        // Encrypt
        let ciphertext = provider.encrypt(&key, plaintext, Some(aad)).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = provider.decrypt(&key, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_backward_compatibility() {
        // Test that Aes256GcmProvider still works as a type alias
        let provider: Aes256GcmProvider = Aes256GcmProvider::new();
        assert_eq!(provider.key_length(), AesKeyLength::Aes256);

        let key_data = vec![0u8; 32];
        let key = Key::new_active(Algorithm::AES256GCM, key_data).unwrap();

        let plaintext = b"Backward compatibility test";
        let ciphertext = provider.encrypt(&key, plaintext, None).unwrap();
        let decrypted = provider.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_with_side_channel_protection() {
        // 使用自定义配置强制启用所有防护
        let config = SideChannelConfig {
            power_analysis_protection: true, // 强制启用电源分析防护
            constant_time_enabled: true,
            error_injection_protection: true,
            cache_protection: true,
            ..SideChannelConfig::default()
        };

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

// Convenience constructors for different key lengths
impl AesGcmProvider {
    /// Create a new AES-128 GCM provider
    pub fn aes128() -> Self {
        Self::with_key_length(AesKeyLength::Aes128)
    }

    /// Create a new AES-192 GCM provider
    pub fn aes192() -> Self {
        Self::with_key_length(AesKeyLength::Aes192)
    }

    /// Create a new AES-256 GCM provider
    pub fn aes256() -> Self {
        Self::with_key_length(AesKeyLength::Aes256)
    }

    /// Create a new AES-128 GCM provider with custom side-channel configuration
    pub fn aes128_with_config(config: SideChannelConfig) -> Self {
        Self::with_key_length_and_config(AesKeyLength::Aes128, config)
    }

    /// Create a new AES-192 GCM provider with custom side-channel configuration
    pub fn aes192_with_config(config: SideChannelConfig) -> Self {
        Self::with_key_length_and_config(AesKeyLength::Aes192, config)
    }

    /// Create a new AES-256 GCM provider with custom side-channel configuration
    pub fn aes256_with_config(config: SideChannelConfig) -> Self {
        Self::with_key_length_and_config(AesKeyLength::Aes256, config)
    }

    /// Get the key length this provider is configured for
    pub fn key_length(&self) -> AesKeyLength {
        self.key_length
    }
}

crate::impl_cipher_provider!(AesGcmProvider, Algorithm::AES256GCM);
