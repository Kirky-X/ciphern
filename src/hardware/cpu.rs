// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::provider;
use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::types::Algorithm;
use libsm::sm3::hash::Sm3Hash;
use rayon::prelude::*;
use sha2::Digest;

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_aes_ni_hw() -> bool {
    std::is_x86_feature_detected!("aes")
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_sha_ni_hw() -> bool {
    std::is_x86_feature_detected!("sha")
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_avx2_hw() -> bool {
    std::is_x86_feature_detected!("avx2")
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn has_aes_ni_hw() -> bool {
    false
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn has_sha_ni_hw() -> bool {
    false
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn has_avx2_hw() -> bool {
    false
}

pub fn is_hardware_acceleration_available() -> bool {
    has_aes_ni_hw() || has_sha_ni_hw() || has_avx2_hw()
}

pub fn get_cpu_capabilities() -> CpuCapabilities {
    CpuCapabilities {
        aes_ni: has_aes_ni_hw(),
        sha_ni: has_sha_ni_hw(),
        avx2: has_avx2_hw(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuCapabilities {
    pub aes_ni: bool,
    pub sha_ni: bool,
    pub avx2: bool,
}

#[inline]
pub fn accelerated_batch_hash_cpu(
    data_chunks: Vec<&[u8]>,
    algorithm: Algorithm,
) -> Result<Vec<Vec<u8>>> {
    if data_chunks.is_empty() {
        return Ok(Vec::new());
    }

    match algorithm {
        Algorithm::SHA256 | Algorithm::SHA384 | Algorithm::SHA512 | Algorithm::SM3 => {
            let results: Result<Vec<Vec<u8>>> = data_chunks
                .par_iter()
                .map(|chunk| accelerated_hash_cpu(chunk, algorithm))
                .collect();
            results
        }
        _ => Err(CryptoError::UnsupportedAlgorithm(
            "Hardware acceleration not supported for this hash algorithm".into(),
        )),
    }
}

#[inline]
pub fn accelerated_hash_cpu(data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
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
        Algorithm::SM3 => {
            let mut hasher = Sm3Hash::new(data);
            Ok(hasher.get_hash().to_vec())
        }
        _ => Err(CryptoError::UnsupportedAlgorithm(
            "Hardware acceleration not supported for this hash algorithm".into(),
        )),
    }
}

#[inline]
pub fn accelerated_batch_aes_encrypt_cpu(
    key: &[u8],
    plaintexts: Vec<&[u8]>,
    nonces: Vec<&[u8]>,
) -> Result<Vec<Vec<u8>>> {
    if plaintexts.len() != nonces.len() {
        return Err(CryptoError::EncryptionFailed(
            "Plaintexts and nonces must have same length".into(),
        ));
    }

    if plaintexts.is_empty() {
        return Ok(Vec::new());
    }

    let results: Result<Vec<Vec<u8>>> = plaintexts
        .par_iter()
        .zip(nonces.par_iter())
        .map(|(pt, nonce)| accelerated_aes_encrypt_cpu(key, pt, nonce))
        .collect();
    results
}

#[inline]
pub fn accelerated_aes_encrypt_cpu(key: &[u8], plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
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
pub fn accelerated_batch_aes_decrypt_cpu(
    key: &[u8],
    ciphertexts: Vec<Vec<u8>>,
    nonces: Vec<&[u8]>,
) -> Result<Vec<Vec<u8>>> {
    if ciphertexts.len() != nonces.len() {
        return Err(CryptoError::DecryptionFailed(
            "Ciphertexts and nonces must have same length".into(),
        ));
    }

    if ciphertexts.is_empty() {
        return Ok(Vec::new());
    }

    let ciphertext_refs: Vec<&[u8]> = ciphertexts.iter().map(|v| v.as_slice()).collect();
    let results: Result<Vec<Vec<u8>>> = ciphertext_refs
        .par_iter()
        .zip(nonces.par_iter())
        .map(|(ct, nonce)| accelerated_aes_decrypt_cpu(key, ct, nonce))
        .collect();
    results
}

#[inline]
pub fn accelerated_aes_decrypt_cpu(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
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
    let plaintext_len = ciphertext.len() - 16;
    less_safe_key
        .open_in_place(nonce_val, ring::aead::Aad::from(&[]), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed("Open failed".into()))?;

    Ok(in_out[..plaintext_len].to_vec())
}

#[inline]
pub fn accelerated_batch_sm4_cpu(
    key: &[u8],
    data_chunks: Vec<Vec<u8>>,
    encrypt: bool,
) -> Result<Vec<Vec<u8>>> {
    if data_chunks.is_empty() {
        return Ok(Vec::new());
    }

    let data_refs: Vec<&[u8]> = data_chunks.iter().map(|v| v.as_slice()).collect();
    let results: Result<Vec<Vec<u8>>> = data_refs
        .par_iter()
        .map(|data| {
            if encrypt {
                accelerated_sm4_encrypt_cpu(key, data)
            } else {
                accelerated_sm4_decrypt_cpu(key, data)
            }
        })
        .collect();
    results
}

#[inline]
pub fn accelerated_sm4_encrypt_cpu(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    let cipher = provider::REGISTRY.get_symmetric(Algorithm::SM4GCM)?;
    let key_obj = Key::new_active(Algorithm::SM4GCM, key.to_vec())?;
    cipher.encrypt(&key_obj, plaintext, None)
}

#[inline]
pub fn accelerated_sm4_decrypt_cpu(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    let cipher = provider::REGISTRY.get_symmetric(Algorithm::SM4GCM)?;
    let key_obj = Key::new_active(Algorithm::SM4GCM, key.to_vec())?;
    cipher.decrypt(&key_obj, ciphertext, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_capabilities() {
        let caps = get_cpu_capabilities();
        println!(
            "AES-NI: {}, SHA-NI: {}, AVX2: {}",
            caps.aes_ni, caps.sha_ni, caps.avx2
        );
    }

    #[test]
    fn test_accelerated_hash_cpu_sha256() {
        let data = b"Hello, World!";
        let result = accelerated_hash_cpu(data, Algorithm::SHA256);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_accelerated_hash_cpu_sha512() {
        let data = b"Hello, World!";
        let result = accelerated_hash_cpu(data, Algorithm::SHA512);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_accelerated_hash_cpu_sm3() {
        let data = b"Hello, World!";
        let result = accelerated_hash_cpu(data, Algorithm::SM3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_accelerated_batch_hash_cpu() {
        let data = vec![b"Hello".as_slice(), b"World".as_slice(), b"Test".as_slice()];
        let results = accelerated_batch_hash_cpu(data, Algorithm::SHA256);
        assert!(results.is_ok());
        let hashes = results.unwrap();
        assert_eq!(hashes.len(), 3);
        for hash in &hashes {
            assert_eq!(hash.len(), 32);
        }
    }

    #[test]
    fn test_accelerated_aes_encrypt_decrypt_cpu() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";

        let encrypted = accelerated_aes_encrypt_cpu(&key, plaintext, &nonce);
        assert!(encrypted.is_ok());

        let decrypted = accelerated_aes_decrypt_cpu(&key, &encrypted.unwrap(), &nonce);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_accelerated_batch_aes_cpu() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        let plaintexts: Vec<&[u8]> = vec![b"Hello", b"World", b"Test", b"Data"];
        let nonces: Vec<&[u8]> = vec![&nonce; 4];

        let encrypted = accelerated_batch_aes_encrypt_cpu(&key, plaintexts.clone(), nonces.clone());
        assert!(encrypted.is_ok());
        let encrypted_inner = encrypted.unwrap();
        assert_eq!(encrypted_inner.len(), 4);

        let decrypted = accelerated_batch_aes_decrypt_cpu(&key, encrypted_inner, nonces);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintexts);
    }

    #[test]
    fn test_accelerated_sm4_encrypt_decrypt_cpu() {
        let _ = crate::fips::FipsContext::disable();

        let key = [0u8; 16];
        let plaintext = b"Hello, World!";

        let encrypted = accelerated_sm4_encrypt_cpu(&key, plaintext);
        assert!(encrypted.is_ok(), "SM4 encryption failed: {:?}", encrypted);

        let decrypted = accelerated_sm4_decrypt_cpu(&key, &encrypted.unwrap());
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_accelerated_batch_sm4_cpu() {
        let _ = crate::fips::FipsContext::disable();

        let key = [0u8; 16];

        let plaintexts: Vec<Vec<u8>> = vec![
            b"Hello".to_vec(),
            b"World".to_vec(),
            b"Test".to_vec(),
            b"Data".to_vec(),
        ];

        let encrypted = accelerated_batch_sm4_cpu(&key, plaintexts.clone(), true);
        assert!(encrypted.is_ok());
        let encrypted_inner = encrypted.unwrap();
        assert_eq!(encrypted_inner.len(), 4);

        let decrypted = accelerated_batch_sm4_cpu(&key, encrypted_inner, false);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintexts);
    }
}
