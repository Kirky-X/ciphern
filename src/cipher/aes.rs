// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::base_provider::BaseCipherProvider;
use crate::error::{CryptoError, Result};
use crate::i18n::translate_with_args;
use crate::key::Key;
use crate::provider::SymmetricCipher;
use crate::random::SecureRandom;
use crate::side_channel::SideChannelConfig;
use crate::types::Algorithm;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::aes::Aes192;
use aes_gcm::{Aes128Gcm, AesGcm};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

/// 统一的 AES-GCM 提供者，支持 AES-128、AES-192 和 AES-256
pub struct AesGcmProvider {
    base: BaseCipherProvider,
    algorithm: Algorithm,
}

/// 类型别名，用于向后兼容
pub type Aes256GcmProvider = AesGcmProvider;

impl SymmetricCipher for AesGcmProvider {
    fn encrypt(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }
        self.base
            .protect_operation(|| self.encrypt_internal(key, plaintext, aad))
    }

    fn decrypt(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }
        self.base
            .protect_operation(|| self.decrypt_internal(key, ciphertext, aad))
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn encrypt_with_nonce(
        &self,
        key: &Key,
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::EncryptionFailed("Invalid nonce length".into()));
        }

        let operation = || {
            let secret = key.secret_bytes()?;

            match self.algorithm {
                Algorithm::AES128GCM => {
                    let cipher =
                        AesGcm::<aes_gcm::aes::Aes128, U12>::new_from_slice(secret.as_bytes())
                            .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                    let nonce_val = aes_gcm::Nonce::from_slice(nonce);

                    cipher
                        .encrypt(
                            nonce_val,
                            Payload {
                                msg: plaintext,
                                aad: aad.unwrap_or(&[]),
                            },
                        )
                        .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))
                }
                Algorithm::AES192GCM => {
                    let cipher = AesGcm::<Aes192, U12>::new_from_slice(secret.as_bytes())
                        .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                    let nonce_val = aes_gcm::Nonce::from_slice(nonce);

                    cipher
                        .encrypt(
                            nonce_val,
                            Payload {
                                msg: plaintext,
                                aad: aad.unwrap_or(&[]),
                            },
                        )
                        .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))
                }
                Algorithm::AES256GCM => {
                    let unbound_key = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
                        .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                    let less_safe_key = LessSafeKey::new(unbound_key);
                    let nonce_val = Nonce::assume_unique_for_key(nonce.try_into().unwrap());

                    let mut in_out = plaintext.to_vec();
                    less_safe_key
                        .seal_in_place_append_tag(
                            nonce_val,
                            Aad::from(aad.unwrap_or(&[])),
                            &mut in_out,
                        )
                        .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

                    Ok(in_out)
                }
                _ => Err(CryptoError::UnsupportedAlgorithm(
                    "Unsupported AES algorithm".into(),
                )),
            }
        };

        self.base.protect_operation(operation)
    }
}

impl AesGcmProvider {
    /// 创建一个新的 AES-256 GCM 提供者，使用默认配置（向后兼容）
    #[inline]
    pub fn new() -> Result<Self> {
        Ok(Self {
            base: BaseCipherProvider::new()?,
            algorithm: Algorithm::AES256GCM,
        })
    }

    /// 创建一个新的 AES-GCM 提供者，使用指定算法
    #[inline]
    pub fn with_algorithm(algorithm: Algorithm) -> Result<Self> {
        match algorithm {
            Algorithm::AES128GCM | Algorithm::AES192GCM | Algorithm::AES256GCM => Ok(Self {
                base: BaseCipherProvider::new()?,
                algorithm,
            }),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "AesGcmProvider 不支持的算法: {:?}",
                algorithm
            ))),
        }
    }

    /// 创建一个新的 AES-GCM 提供者，使用自定义侧信道配置
    #[inline]
    #[allow(dead_code)]
    pub fn with_side_channel_config(config: SideChannelConfig) -> Result<Self> {
        Ok(Self {
            base: BaseCipherProvider::with_side_channel_config(config)?,
            algorithm: Algorithm::AES256GCM,
        })
    }

    /// 创建一个新的 AES-GCM 提供者，使用指定算法和侧信道配置
    #[inline]
    pub fn with_algorithm_and_config(
        algorithm: Algorithm,
        config: SideChannelConfig,
    ) -> Result<Self> {
        match algorithm {
            Algorithm::AES128GCM | Algorithm::AES192GCM | Algorithm::AES256GCM => Ok(Self {
                base: BaseCipherProvider::with_side_channel_config(config)?,
                algorithm,
            }),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!(
                "AesGcmProvider 不支持的算法: {:?}",
                algorithm
            ))),
        }
    }

    fn encrypt_internal(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let secret_bytes = key.secret_bytes()?;
        self.encrypt_core(secret_bytes.as_bytes(), plaintext, aad)
    }

    #[inline]
    fn encrypt_core(
        &self,
        key_bytes: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.algorithm {
            Algorithm::AES128GCM => self.encrypt_aes128(key_bytes, plaintext, aad),
            Algorithm::AES192GCM => self.encrypt_aes192(key_bytes, plaintext, aad),
            Algorithm::AES256GCM => self.encrypt_with_aes256(key_bytes, plaintext, aad),
            _ => Err(CryptoError::UnsupportedAlgorithm(
                "Unsupported AES algorithm".into(),
            )),
        }
    }

    #[inline]
    fn encrypt_aes128(
        &self,
        key_bytes: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let cipher = Aes128Gcm::new_from_slice(key_bytes)
            .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;

        let nonce = Aes128Gcm::generate_nonce(&mut SecureRandom::new()?);
        let aad_ref = aad.unwrap_or(&[]);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: aad_ref,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    #[inline]
    fn encrypt_aes192(
        &self,
        key_bytes: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let cipher = AesGcm::<Aes192, U12>::new_from_slice(key_bytes)
            .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;

        let nonce = AesGcm::<Aes192, U12>::generate_nonce(&mut SecureRandom::new()?);
        let aad_ref = aad.unwrap_or(&[]);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: aad_ref,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    #[inline]
    fn encrypt_with_aes256(
        &self,
        key_bytes: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; 12];
        SecureRandom::new()?.fill(&mut nonce_bytes)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let capacity = 12 + plaintext.len() + 16;
        let mut in_out = Vec::with_capacity(capacity);
        in_out.extend_from_slice(plaintext);
        less_safe_key
            .seal_in_place_append_tag(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

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

    #[inline]
    fn decrypt_core(
        &self,
        key_bytes: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.algorithm {
            Algorithm::AES128GCM => self.decrypt_aes128(key_bytes, ciphertext, aad),
            Algorithm::AES192GCM => self.decrypt_aes192(key_bytes, ciphertext, aad),
            Algorithm::AES256GCM => self.decrypt_with_aes256(key_bytes, ciphertext, aad),
            _ => Err(CryptoError::UnsupportedAlgorithm(
                "Unsupported AES algorithm".into(),
            )),
        }
    }

    #[inline]
    fn decrypt_aes128(
        &self,
        key_bytes: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let cipher = Aes128Gcm::new_from_slice(key_bytes)
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

    #[inline]
    fn decrypt_aes192(
        &self,
        key_bytes: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
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

    #[inline]
    fn decrypt_with_aes256(
        &self,
        key_bytes: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid Key".into()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid nonce".into()))?;

        let plaintext_len = ciphertext.len().saturating_sub(28);
        let mut in_out = Vec::with_capacity(plaintext_len);
        in_out.extend_from_slice(encrypted_data);
        less_safe_key
            .open_in_place(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed("Open failed".into()))?;

        in_out.truncate(plaintext_len);
        Ok(in_out)
    }

    #[inline]
    #[allow(dead_code)]
    fn expand_key_protected(&self, key_bytes: &[u8]) -> Result<Vec<u8>> {
        self.base.expand_key_protected(key_bytes)
    }
}

impl Default for AesGcmProvider {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            log::error!(
                "{}",
                translate_with_args(
                    "metrics.create_provider_failed",
                    &[("provider", "AesGcmProvider"), ("error", &e.to_string())]
                )
            );
            panic!(
                "{}",
                translate_with_args(
                    "metrics.init_security_component_failed",
                    &[("error", &e.to_string())]
                )
            )
        })
    }
}

impl Aes256GcmProvider {
    /// 获取侧信道防护统计信息
    #[allow(dead_code)]
    pub fn get_side_channel_stats(&self) -> Option<crate::side_channel::SideChannelStats> {
        self.base.get_side_channel_stats()
    }

    /// 检查是否启用了侧信道防护
    #[allow(dead_code)]
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
        assert_eq!(provider.algorithm(), Algorithm::AES128GCM);

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
        assert_eq!(provider.algorithm(), Algorithm::AES192GCM);

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
        assert_eq!(provider.algorithm(), Algorithm::AES256GCM);

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
        let provider: Aes256GcmProvider = Aes256GcmProvider::new().unwrap();
        assert_eq!(provider.algorithm(), Algorithm::AES256GCM);

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

        let provider = Aes256GcmProvider::with_side_channel_config(config).unwrap();
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

        let provider = Aes256GcmProvider::with_side_channel_config(config).unwrap();
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
        let provider = Aes256GcmProvider::new().unwrap();
        let key_data = vec![0u8; 32];
        let wrong_key = Key::new(Algorithm::SM4GCM, key_data).unwrap();
        let plaintext = b"test";

        let result = provider.encrypt(&wrong_key, plaintext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_invalid_ciphertext() {
        let provider = Aes256GcmProvider::new().unwrap();
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
        Self::with_algorithm(Algorithm::AES128GCM)
            .expect("Failed to create AES-128 GCM provider - algorithm should be valid")
    }

    /// Create a new AES-192 GCM provider
    pub fn aes192() -> Self {
        Self::with_algorithm(Algorithm::AES192GCM)
            .expect("Failed to create AES-192 GCM provider - algorithm should be valid")
    }

    /// Create a new AES-256 GCM provider
    pub fn aes256() -> Self {
        Self::with_algorithm(Algorithm::AES256GCM)
            .expect("Failed to create AES-256 GCM provider - algorithm should be valid")
    }

    /// Create a new AES-128 GCM provider with custom side-channel configuration
    #[allow(dead_code)]
    pub fn aes128_with_config(config: SideChannelConfig) -> Self {
        Self::with_algorithm_and_config(Algorithm::AES128GCM, config)
            .expect("Failed to create AES-128 GCM provider - algorithm should be valid")
    }

    /// Create a new AES-192 GCM provider with custom side-channel configuration
    #[allow(dead_code)]
    pub fn aes192_with_config(config: SideChannelConfig) -> Self {
        Self::with_algorithm_and_config(Algorithm::AES192GCM, config)
            .expect("Failed to create AES-192 GCM provider - algorithm should be valid")
    }

    /// Create a new AES-256 GCM provider with custom side-channel configuration
    #[allow(dead_code)]
    pub fn aes256_with_config(config: SideChannelConfig) -> Self {
        Self::with_algorithm_and_config(Algorithm::AES256GCM, config)
            .expect("Failed to create AES-256 GCM provider - algorithm should be valid")
    }

    /// Get the algorithm this provider is configured for
    #[allow(dead_code)]
    pub fn algorithm_type(&self) -> Algorithm {
        self.algorithm
    }
}

crate::impl_cipher_provider!(AesGcmProvider, Algorithm::AES256GCM);
