// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::base_provider::BaseCipherProvider;
use crate::cipher::provider::SymmetricCipher;
use crate::error::{CryptoError, Result};
use crate::key::Key as CiphernKey;
use crate::random::SecureRandom;
use crate::side_channel::SideChannelConfig;
use crate::types::Algorithm;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::KeyInit;

/// ChaCha20-Poly1305 AEAD 加密提供者
#[allow(dead_code)]
pub struct ChaCha20Poly1305Provider {
    #[allow(dead_code)]
    base: BaseCipherProvider,
    algorithm: Algorithm,
}

impl ChaCha20Poly1305Provider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            base: BaseCipherProvider::new()?,
            algorithm: Algorithm::ChaCha20Poly1305,
        })
    }

    #[allow(dead_code)]
    pub fn with_algorithm(algorithm: Algorithm) -> Result<Self> {
        if algorithm != Algorithm::ChaCha20Poly1305 {
            return Err(CryptoError::UnsupportedAlgorithm(format!(
                "ChaCha20Poly1305Provider 不支持的算法: {:?}",
                algorithm
            )));
        }
        Ok(Self {
            base: BaseCipherProvider::new()?,
            algorithm,
        })
    }

    #[allow(dead_code)]
    pub fn with_side_channel_config(config: SideChannelConfig) -> Result<Self> {
        Ok(Self {
            base: BaseCipherProvider::with_side_channel_config(config)?,
            algorithm: Algorithm::ChaCha20Poly1305,
        })
    }

    fn encrypt_internal(
        &self,
        key: &CiphernKey,
        plaintext: &[u8],
        nonce: [u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let secret = key.secret_bytes()?;
        let key_bytes: [u8; 32] = secret.as_bytes().try_into().map_err(|_| {
            CryptoError::KeyError("Invalid ChaCha20 key length, must be 256 bits".into())
        })?;

        let cipher =
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|_| {
                CryptoError::EncryptionFailed("Invalid key for ChaCha20-Poly1305".into())
            })?;

        let payload = Payload {
            msg: plaintext,
            aad: aad.unwrap_or(&[]),
        };

        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(&nonce);

        cipher
            .encrypt(&nonce_array.into(), payload)
            .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))
    }

    fn decrypt_internal(
        &self,
        key: &CiphernKey,
        ciphertext: &[u8],
        nonce: [u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::DecryptionFailed(
                "Ciphertext too short for ChaCha20-Poly1305".into(),
            ));
        }

        let secret = key.secret_bytes()?;
        let key_bytes: [u8; 32] = secret.as_bytes().try_into().map_err(|_| {
            CryptoError::KeyError("Invalid ChaCha20 key length, must be 256 bits".into())
        })?;

        let cipher =
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|_| {
                CryptoError::DecryptionFailed("Invalid key for ChaCha20-Poly1305".into())
            })?;

        let payload = Payload {
            msg: ciphertext,
            aad: aad.unwrap_or(&[]),
        };

        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(&nonce);

        cipher
            .decrypt(&nonce_array.into(), payload)
            .map_err(|_| CryptoError::DecryptionFailed("Decryption or verification failed".into()))
    }
}

impl SymmetricCipher for ChaCha20Poly1305Provider {
    fn encrypt(&self, key: &CiphernKey, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        // 生成随机 nonce
        let mut nonce = [0u8; 12];
        SecureRandom::new()?.fill(&mut nonce)?;

        let mut result = nonce.to_vec();
        let ciphertext = self.encrypt_internal(key, plaintext, nonce, aad)?;
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, key: &CiphernKey, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        if ciphertext.len() < 12 + 16 {
            return Err(CryptoError::DecryptionFailed(
                "Ciphertext too short for ChaCha20-Poly1305".into(),
            ));
        }

        let (nonce, ciphertext) = ciphertext.split_at(12);
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce);

        self.decrypt_internal(key, ciphertext, nonce_array, aad)
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn encrypt_with_nonce(
        &self,
        key: &CiphernKey,
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
            return Err(CryptoError::EncryptionFailed(
                "Invalid nonce length for ChaCha20-Poly1305, must be 12 bytes".into(),
            ));
        }

        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce);

        self.encrypt_internal(key, plaintext, nonce_array, aad)
    }
}

impl Default for ChaCha20Poly1305Provider {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| panic!("Failed to create ChaCha20Poly1305Provider: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20poly1305_basic() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0u8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = provider.encrypt(&key, plaintext, None).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(ciphertext.len() >= 12 + 16);

        let decrypted = provider.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_with_aad() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0x42u8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let plaintext = b"Test message";
        let aad = b"additional data";

        let ciphertext = provider.encrypt(&key, plaintext, Some(aad)).unwrap();
        let decrypted = provider.decrypt(&key, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_with_nonce() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0xABu8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let plaintext = b"Test with fixed nonce";
        let nonce = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78,
        ];

        let ciphertext = provider
            .encrypt_with_nonce(&key, plaintext, &nonce, None)
            .unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        // 使用相同 nonce 解密
        let decrypted = provider
            .decrypt_internal(&key, &ciphertext, nonce, None)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_empty_plaintext() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0xFFu8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let plaintext = b"";
        let ciphertext = provider.encrypt(&key, plaintext, None).unwrap();
        assert_eq!(ciphertext.len(), 12 + 16); // nonce + tag

        let decrypted = provider.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_large_data() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0x55u8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        // 1MB 数据
        let plaintext = vec![0xAAu8; 1024 * 1024];
        let ciphertext = provider.encrypt(&key, &plaintext, None).unwrap();

        let decrypted = provider.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_with_wrong_key_fails() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key1_data = vec![0x11u8; 32];
        let key1 = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key1_data).unwrap();
        let key2_data = vec![0x22u8; 32];
        let key2 = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key2_data).unwrap();

        let plaintext = b"Secret message";

        let ciphertext = provider.encrypt(&key1, plaintext, None).unwrap();

        // 使用不同的密钥解密应该失败
        let result = provider.decrypt(&key2, &ciphertext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20poly1305_too_short_ciphertext() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0x33u8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let short_ciphertext = vec![0x01u8; 20]; // 少于 12 + 16 = 28 字节

        let result = provider.decrypt(&key, &short_ciphertext, None);
        assert!(result.is_err());
        match result {
            Err(CryptoError::DecryptionFailed(msg)) => {
                assert!(msg.contains("too short"));
            }
            _ => panic!("Expected DecryptionFailed error"),
        }
    }

    #[test]
    fn test_chacha20poly1305_wrong_algorithm_key() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0x44u8; 32];
        let key = CiphernKey::new_active(Algorithm::AES256GCM, key_data).unwrap();

        let plaintext = b"Test message";

        let result = provider.encrypt(&key, plaintext, None);
        assert!(result.is_err());
        match result {
            Err(CryptoError::UnsupportedAlgorithm(msg)) => {
                assert!(msg.contains("mismatch"));
            }
            _ => panic!("Expected UnsupportedAlgorithm error"),
        }
    }

    #[test]
    fn test_chacha20poly1305_with_algorithm_validation() {
        let result = ChaCha20Poly1305Provider::with_algorithm(Algorithm::ChaCha20Poly1305);
        assert!(result.is_ok());

        let result = ChaCha20Poly1305Provider::with_algorithm(Algorithm::AES256GCM);
        assert!(result.is_err());
        match result {
            Err(CryptoError::UnsupportedAlgorithm(msg)) => {
                assert!(msg.contains("不支持"));
            }
            _ => panic!("Expected UnsupportedAlgorithm error"),
        }
    }

    #[test]
    fn test_chacha20poly1305_aad_mismatch_fails() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0x66u8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let plaintext = b"Test message";
        let aad1 = b"original aad";
        let aad2 = b"modified aad";

        let ciphertext = provider.encrypt(&key, plaintext, Some(aad1)).unwrap();

        // 使用不同的 AAD 解密应该失败
        let result = provider.decrypt(&key, &ciphertext, Some(aad2));
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20poly1305_encrypt_with_nonce_wrong_length() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0x77u8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let plaintext = b"Test";
        let wrong_nonce = [0x01u8; 16]; // 错误的 nonce 长度

        let result = provider.encrypt_with_nonce(&key, plaintext, &wrong_nonce, None);
        assert!(result.is_err());
        match result {
            Err(CryptoError::EncryptionFailed(msg)) => {
                assert!(msg.contains("Invalid nonce"));
            }
            _ => panic!("Expected EncryptionFailed error"),
        }
    }

    #[test]
    fn test_chacha20poly1305_reuse_nonce_different_ciphertext() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        let key_data = vec![0x88u8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let nonce = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
        ];
        let plaintext1 = b"First message";
        let plaintext2 = b"Second message";

        let ciphertext1 = provider
            .encrypt_with_nonce(&key, plaintext1, &nonce, None)
            .unwrap();
        let ciphertext2 = provider
            .encrypt_with_nonce(&key, plaintext2, &nonce, None)
            .unwrap();

        // 密文应该不同
        assert_ne!(ciphertext1, ciphertext2);

        // 分别解密
        let decrypted1 = provider
            .decrypt_internal(&key, &ciphertext1, nonce, None)
            .unwrap();
        let decrypted2 = provider
            .decrypt_internal(&key, &ciphertext2, nonce, None)
            .unwrap();

        assert_eq!(decrypted1, plaintext1);
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_chacha20poly1305_with_side_channel_config() {
        let config = SideChannelConfig::default();
        let provider = ChaCha20Poly1305Provider::with_side_channel_config(config).unwrap();
        let key_data = vec![0x99u8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let plaintext = b"Test with side channel protection";
        let ciphertext = provider.encrypt(&key, plaintext, None).unwrap();

        let decrypted = provider.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_default() {
        let provider = ChaCha20Poly1305Provider::default();
        let key_data = vec![0xAAu8; 32];
        let key = CiphernKey::new_active(Algorithm::ChaCha20Poly1305, key_data).unwrap();

        let plaintext = b"Test default provider";
        let ciphertext = provider.encrypt(&key, plaintext, None).unwrap();

        let decrypted = provider.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_algorithm_method() {
        let provider = ChaCha20Poly1305Provider::new().unwrap();
        assert_eq!(provider.algorithm(), Algorithm::ChaCha20Poly1305);
    }
}
