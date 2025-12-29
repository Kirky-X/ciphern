// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SIMD acceleration module for cryptographic operations.
//! This module provides portable SIMD implementations using the `std::simd` module.
//!
//! ## Features
//! - Batch processing for multiple messages
//! - Vectorized operations for better performance
//! - Hardware instruction set detection (AES-NI, SHA-NI, AVX2)

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

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_avx512_hw() -> bool {
    std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512bw")
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn has_avx2_hw() -> bool {
    false
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn has_avx512_hw() -> bool {
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimdCapabilities {
    pub aes_ni: bool,
    pub sha_ni: bool,
    pub avx2: bool,
    pub avx512: bool,
    pub std_simd: bool,
}

#[cfg(feature = "simd")]
pub fn get_simd_capabilities() -> SimdCapabilities {
    SimdCapabilities {
        aes_ni: has_aes_ni_hw(),
        sha_ni: has_sha_ni_hw(),
        avx2: has_avx2_hw(),
        avx512: has_avx512_hw(),
        std_simd: true,
    }
}

#[cfg(not(feature = "simd"))]
pub fn get_simd_capabilities() -> SimdCapabilities {
    SimdCapabilities {
        aes_ni: has_aes_ni_hw(),
        sha_ni: has_sha_ni_hw(),
        avx2: has_avx2_hw(),
        avx512: has_avx512_hw(),
        std_simd: false,
    }
}

#[cfg(feature = "simd")]
pub fn is_hardware_accelerated() -> bool {
    has_aes_ni_hw() || has_sha_ni_hw() || has_avx2_hw()
}

#[cfg(feature = "simd")]
pub mod hash;

#[cfg(feature = "simd")]
pub mod sm4;

#[cfg(feature = "simd")]
pub mod sm3;

#[cfg(feature = "simd")]
pub use hash::{simd_combine_hashes, simd_process_blocks_sha256, simd_sha256_finalize};

#[cfg(feature = "simd")]
pub use sm4::{
    avx512_process_sm4_blocks, batch_sm4_decrypt, batch_sm4_encrypt, has_avx512,
    simd_process_sm4_blocks, simd_sm4_decrypt, simd_sm4_encrypt, sm4_key_schedule,
};

#[cfg(feature = "simd")]
pub use sm3::{simd_combine_sm3_hashes, simd_process_blocks_sm3, simd_sm3_finalize};

#[inline]
pub fn is_simd_available() -> bool {
    cfg!(feature = "simd")
}

#[cfg(feature = "simd")]
pub fn batch_process_sha256(data_chunks: Vec<&[u8]>) -> Vec<Vec<u8>> {
    use rayon::prelude::*;
    data_chunks
        .par_iter()
        .map(|chunk| simd_process_blocks_sha256(chunk))
        .collect()
}

#[cfg(feature = "simd")]
pub fn batch_process_sm3(data_chunks: Vec<&[u8]>) -> Vec<Vec<u8>> {
    use rayon::prelude::*;
    data_chunks
        .par_iter()
        .map(|chunk| simd_process_blocks_sm3(chunk))
        .collect()
}

#[cfg(feature = "simd")]
pub fn batch_process_sm4(data_chunks: Vec<&[u8]>, key: &[u8; 16], encrypt: bool) -> Vec<Vec<u8>> {
    use rayon::prelude::*;
    let key_copy = *key;
    data_chunks
        .par_iter()
        .map(|chunk| {
            if encrypt {
                simd_sm4_encrypt(&key_copy, chunk)
            } else {
                simd_sm4_decrypt(&key_copy, chunk)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_availability() {
        let caps = get_simd_capabilities();
        println!("SIMD capabilities: {:?}", caps);
        if is_simd_available() {
            println!("SIMD feature is enabled");
        } else {
            println!("SIMD feature not enabled");
        }
    }

    #[cfg(feature = "simd")]
    #[test]
    fn test_simd_capabilities() {
        let caps = get_simd_capabilities();
        assert!(!caps.aes_ni || std::is_x86_feature_detected!("aes"));
        assert!(!caps.sha_ni || std::is_x86_feature_detected!("sha"));
        assert!(!caps.avx2 || std::is_x86_feature_detected!("avx2"));
        assert!(caps.std_simd);
    }

    #[cfg(feature = "simd")]
    #[test]
    fn test_hardware_accelerated() {
        let is_accel = is_hardware_accelerated();
        println!("Hardware acceleration available: {}", is_accel);
    }

    #[cfg(feature = "simd")]
    #[test]
    fn test_batch_sha256() {
        let data = vec![b"hello".as_slice(), b"world".as_slice(), b"test".as_slice()];
        let results = batch_process_sha256(data);
        assert_eq!(results.len(), 3);
        for hash in &results {
            assert_eq!(hash.len(), 32);
        }
    }

    #[cfg(feature = "simd")]
    #[test]
    fn test_batch_sm3() {
        let data = vec![b"hello".as_slice(), b"world".as_slice(), b"test".as_slice()];
        let results = batch_process_sm3(data);
        assert_eq!(results.len(), 3);
        for hash in &results {
            assert_eq!(hash.len(), 32);
        }
    }

    #[cfg(feature = "simd")]
    #[test]
    fn test_batch_sm4() {
        let key = [0u8; 16];
        let plaintexts = vec![b"hello".as_slice(), b"world".as_slice(), b"test".as_slice()];

        let padded: Vec<Vec<u8>> = plaintexts
            .iter()
            .map(|pt| {
                let mut padded_data = pt.to_vec();
                padded_data.resize(16, 0);
                padded_data
            })
            .collect();

        let padded_refs: Vec<&[u8]> = padded.iter().map(|v| v.as_slice()).collect();

        let encrypted: Vec<Vec<u8>> = batch_process_sm4(padded_refs, &key, true);
        assert_eq!(encrypted.len(), 3);

        let encrypted_refs: Vec<&[u8]> = encrypted.iter().map(|v| v.as_slice()).collect();
        let decrypted = batch_process_sm4(encrypted_refs, &key, false);
        assert_eq!(decrypted.len(), 3);

        for (i, (pt, dec)) in plaintexts.iter().zip(decrypted.iter()).enumerate() {
            assert_eq!(*pt, &dec[..pt.len()], "Mismatch at index {}", i);
        }
    }
}
