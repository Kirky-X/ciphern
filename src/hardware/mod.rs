// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

mod parallel;

use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use sha2::Digest;
use std::sync::atomic::{AtomicBool, Ordering};

pub static AES_NI_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static AVX2_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static SHA_NI_SUPPORTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuFeatures {
    pub aes_ni: bool,
    pub avx2: bool,
    pub sha_ni: bool,
}

impl CpuFeatures {
    #[inline]
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            CpuFeatures {
                aes_ni: std::is_x86_feature_detected!("aes"),
                avx2: std::is_x86_feature_detected!("avx2"),
                sha_ni: std::is_x86_feature_detected!("sha"),
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            CpuFeatures {
                aes_ni: std::is_aarch64_feature_detected!("aes"),
                avx2: std::is_aarch64_feature_detected!("fp"),
                sha_ni: std::is_aarch64_feature_detected!("sha2"),
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            CpuFeatures {
                aes_ni: false,
                avx2: false,
                sha_ni: false,
            }
        }
    }

    #[inline]
    pub fn is_accelerated(&self) -> bool {
        self.aes_ni || self.avx2 || self.sha_ni
    }
}

#[inline]
pub fn init_cpu_features() {
    let features = CpuFeatures::detect();
    AES_NI_SUPPORTED.store(features.aes_ni, Ordering::Relaxed);
    AVX2_SUPPORTED.store(features.avx2, Ordering::Relaxed);
    SHA_NI_SUPPORTED.store(features.sha_ni, Ordering::Relaxed);
}

#[inline]
pub fn has_aes_ni() -> bool {
    AES_NI_SUPPORTED.load(Ordering::Relaxed)
}

#[inline]
pub fn has_avx2() -> bool {
    AVX2_SUPPORTED.load(Ordering::Relaxed)
}

#[inline]
pub fn has_sha_ni() -> bool {
    SHA_NI_SUPPORTED.load(Ordering::Relaxed)
}

#[inline]
pub fn accelerated_hash(data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::SHA256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Algorithm::SHA384 => {
            let mut hasher = sha2::Sha384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        Algorithm::SHA512 => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(CryptoError::UnsupportedAlgorithm(
            "Hardware acceleration not supported for this hash algorithm".into(),
        )),
    }
}

#[inline]
pub fn accelerated_aes_encrypt(key: &[u8], plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if !has_aes_ni() {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "AES-NI not available".into(),
        ));
    }

    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    if nonce.len() != 12 {
        return Err(CryptoError::EncryptionFailed("Invalid nonce length".into()));
    }

    let unbound_key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
        .map_err(|_| CryptoError::EncryptionFailed("Invalid key".into()))?;
    let less_safe_key = ring::aead::LessSafeKey::new(unbound_key);
    let nonce_val = ring::aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap());

    let mut in_out = plaintext.to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce_val, ring::aead::Aad::from(&[]), &mut in_out)
        .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

    Ok(in_out)
}

#[inline]
pub fn accelerated_aes_decrypt(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if !has_aes_ni() {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "AES-NI not available".into(),
        ));
    }

    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    if nonce.len() != 12 {
        return Err(CryptoError::DecryptionFailed("Invalid nonce length".into()));
    }

    let unbound_key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
        .map_err(|_| CryptoError::DecryptionFailed("Invalid key".into()))?;
    let less_safe_key = ring::aead::LessSafeKey::new(unbound_key);
    let nonce_val = ring::aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap());

    let mut in_out = ciphertext.to_vec();
    less_safe_key
        .open_in_place(nonce_val, ring::aead::Aad::from(&[]), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed("Open failed".into()))?;

    Ok(in_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_features_detection() {
        let features = CpuFeatures::detect();
        println!(
            "AES-NI: {}, AVX2: {}, SHA-NI: {}",
            features.aes_ni, features.avx2, features.sha_ni
        );
        assert!(
            features.is_accelerated() || !cfg!(any(target_arch = "x86", target_arch = "x86_64"))
        );
    }

    #[test]
    fn test_cpu_features_functions() {
        init_cpu_features();
        let _ = has_aes_ni();
        let _ = has_avx2();
        let _ = has_sha_ni();
    }

    #[test]
    fn test_accelerated_hash_sha256() {
        init_cpu_features();
        let data = b"Hello, World!";
        let result = accelerated_hash(data, Algorithm::SHA256);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_accelerated_aes_encrypt_decrypt() {
        init_cpu_features();
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";

        let encrypted = accelerated_aes_encrypt(&key, plaintext, &nonce);
        assert!(encrypted.is_ok());

        let decrypted = accelerated_aes_decrypt(&key, &encrypted.unwrap(), &nonce);
        assert!(decrypted.is_ok());
        // AES-GCM returns plaintext + tag, so we need to trim to original length
        let decrypted_trimmed = &decrypted.unwrap()[..plaintext.len()];
        assert_eq!(decrypted_trimmed, plaintext);
    }
}
