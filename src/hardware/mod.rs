// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

mod parallel;

#[cfg(target_arch = "aarch64")]
#[allow(unused)]
#[allow(clippy::single_component_path_imports)]
use cpufeatures;

pub mod cpu;

use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use sha2::Digest;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "gpu")]
pub mod gpu;

#[cfg(feature = "gpu")]
#[allow(unused)]
pub use gpu::{
    accelerated_aes_gpu, accelerated_ecdsa_sign_gpu, accelerated_ecdsa_verify_batch_gpu,
    accelerated_ecdsa_verify_gpu, accelerated_ed25519_sign_gpu, accelerated_ed25519_verify_gpu,
    accelerated_hash_gpu, get_gpu_config, init_gpu, is_gpu_enabled, is_gpu_initialized,
    set_gpu_config, shutdown_gpu, GpuThresholdConfig, GPU_CONFIG, GPU_ENABLED, GPU_INITIALIZED,
};

#[cfg(not(feature = "gpu"))]
#[allow(dead_code)]
pub fn init_gpu() -> Result<()> {
    Err(CryptoError::HardwareAccelerationUnavailable(
        "GPU support not enabled".into(),
    ))
}

#[cfg(not(feature = "gpu"))]
#[allow(dead_code)]
pub fn is_gpu_enabled() -> bool {
    false
}

#[cfg(not(feature = "gpu"))]
#[allow(dead_code)]
pub fn is_gpu_initialized() -> bool {
    false
}

pub use cpu::{
    accelerated_aes_decrypt_cpu, accelerated_aes_encrypt_cpu, accelerated_batch_aes_decrypt_cpu,
    accelerated_batch_aes_encrypt_cpu, accelerated_batch_hash_cpu, accelerated_batch_sm4_cpu,
    accelerated_hash_cpu, accelerated_sm4_decrypt_cpu, accelerated_sm4_encrypt_cpu,
    get_cpu_capabilities, is_hardware_acceleration_available,
};

pub static AES_NI_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static AVX2_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static AVX512_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static SHA_NI_SUPPORTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuFeatures {
    pub aes_ni: bool,
    pub avx2: bool,
    pub avx512: bool,
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
                avx512: std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512bw"),
                sha_ni: std::is_x86_feature_detected!("sha"),
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            CpuFeatures {
                #[cfg(feature = "cpu-aesni")]
                aes_ni: cpufeatures::is_aarch64_feature_detected!("aes"),
                #[cfg(not(feature = "cpu-aesni"))]
                aes_ni: false,
                #[cfg(feature = "cpu-aesni")]
                avx2: cpufeatures::is_aarch64_feature_detected!("fp"),
                #[cfg(not(feature = "cpu-aesni"))]
                avx2: false,
                avx512: false, // ARM equivalent is sve but not directly mapped
                #[cfg(feature = "cpu-aesni")]
                sha_ni: cpufeatures::is_aarch64_feature_detected!("sha2"),
                #[cfg(not(feature = "cpu-aesni"))]
                sha_ni: false,
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            CpuFeatures {
                aes_ni: false,
                avx2: false,
                avx512: false,
                sha_ni: false,
            }
        }
    }

    #[inline]
    pub fn is_accelerated(&self) -> bool {
        self.aes_ni || self.avx2 || self.sha_ni
    }

    #[inline]
    pub fn has_avx512(&self) -> bool {
        self.avx512
    }
}

#[inline]
pub fn init_cpu_features() {
    let features = CpuFeatures::detect();
    AES_NI_SUPPORTED.store(features.aes_ni, Ordering::Relaxed);
    AVX2_SUPPORTED.store(features.avx2, Ordering::Relaxed);
    AVX512_SUPPORTED.store(features.avx512, Ordering::Relaxed);
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
pub fn has_avx512() -> bool {
    AVX512_SUPPORTED.load(Ordering::Relaxed)
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

#[inline]
pub fn accelerated_ecdsa_sign(
    private_key: &[u8],
    data: &[u8],
    algorithm: Algorithm,
) -> Result<Vec<u8>> {
    #[cfg(feature = "gpu")]
    {
        if is_gpu_enabled() {
            let config = get_gpu_config();
            if config.should_use_gpu(data.len(), 1) {
                if let Ok(sig) = accelerated_ecdsa_sign_gpu(private_key, data, algorithm) {
                    return Ok(sig);
                }
            }
        }
    }

    let _start = std::time::Instant::now();
    let result = match algorithm {
        Algorithm::ECDSAP256 => {
            use ring::signature::EcdsaKeyPair;

            let rng = ring::rand::SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                private_key,
                &rng,
            )
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

            let signature = key_pair
                .sign(&rng, data)
                .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
            Ok(signature.as_ref().to_vec())
        }
        Algorithm::ECDSAP384 => {
            use ring::signature::EcdsaKeyPair;

            let rng = ring::rand::SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                private_key,
                &rng,
            )
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

            let signature = key_pair
                .sign(&rng, data)
                .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
            Ok(signature.as_ref().to_vec())
        }
        Algorithm::ECDSAP521 => {
            return Err(CryptoError::UnsupportedAlgorithm(
                "ECDSA P-521 signing requires pkcs8 format key".into(),
            ));
        }
        _ => Err(CryptoError::UnsupportedAlgorithm(
            "ECDSA signing not supported for this algorithm".into(),
        )),
    };

    result
}

#[inline]
pub fn accelerated_ecdsa_verify(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
    algorithm: Algorithm,
) -> Result<bool> {
    #[cfg(feature = "gpu")]
    {
        if is_gpu_enabled() {
            let config = get_gpu_config();
            if config.should_use_gpu(data.len(), 1) {
                if let Ok(result) =
                    accelerated_ecdsa_verify_gpu(public_key, data, signature, algorithm)
                {
                    return Ok(result);
                }
            }
        }
    }

    match algorithm {
        Algorithm::ECDSAP256 => {
            use ring::signature::UnparsedPublicKey;

            if public_key.len() != 65 {
                return Err(CryptoError::InvalidParameter(
                    "Invalid public key length".into(),
                ));
            }

            let key = UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, public_key);
            match key.verify(data, signature) {
                Ok(()) => Ok(true),
                Err(e) => Err(CryptoError::VerificationFailed(e.to_string())),
            }
        }
        Algorithm::ECDSAP384 => {
            use ring::signature::UnparsedPublicKey;

            if public_key.len() != 97 {
                return Err(CryptoError::InvalidParameter(
                    "Invalid public key length".into(),
                ));
            }

            let key = UnparsedPublicKey::new(&ring::signature::ECDSA_P384_SHA384_FIXED, public_key);
            match key.verify(data, signature) {
                Ok(()) => Ok(true),
                Err(e) => Err(CryptoError::VerificationFailed(e.to_string())),
            }
        }
        Algorithm::ECDSAP521 => Err(CryptoError::UnsupportedAlgorithm(
            "ECDSA P-521 verification requires ring with proper format".into(),
        )),
        _ => Err(CryptoError::UnsupportedAlgorithm(
            "ECDSA verification not supported for this algorithm".into(),
        )),
    }
}

/// CPU-accelerated ECDSA batch verification using Rayon parallel processing
///
/// This function provides SIMD-like parallelization for ECDSA verification by processing
/// multiple signatures concurrently using Rayon's work-stealing thread pool.
///
/// # Arguments
///
/// * `public_key` - The ECDSA public key
/// * `messages` - Slice of message slices to verify
/// * `signatures` - Slice of signature slices corresponding to messages
/// * `algorithm` - The ECDSA algorithm variant (P-256 or P-384)
///
/// # Returns
///
/// Returns a vector of boolean results, each indicating whether the corresponding
/// signature verified successfully.
///
/// # Performance Notes
///
/// - Uses Rayon for parallel processing, automatically scaling to available cores
/// - Most effective for batch sizes > 10 signatures
/// - Falls back to sequential processing if parallel feature is disabled
#[cfg(feature = "parallel")]
#[inline]
pub fn accelerated_ecdsa_verify_batch_cpu(
    public_key: &[u8],
    messages: &[&[u8]],
    signatures: &[&[u8]],
    algorithm: Algorithm,
) -> Result<Vec<bool>> {
    use rayon::prelude::*;

    if messages.len() != signatures.len() {
        return Err(CryptoError::InvalidParameter(
            "Messages and signatures must have the same length".into(),
        ));
    }

    if messages.is_empty() {
        return Ok(Vec::new());
    }

    let results: Vec<bool> = messages
        .par_iter()
        .zip(signatures.par_iter())
        .map(|(&msg, &sig)| {
            match accelerated_ecdsa_verify(public_key, msg, sig, algorithm) {
                Ok(valid) => valid,
                Err(_) => false,
            }
        })
        .collect();

    Ok(results)
}

/// Sequential CPU ECDSA batch verification (fallback when parallel feature is disabled)
#[cfg(not(feature = "parallel"))]
#[inline]
pub fn accelerated_ecdsa_verify_batch_cpu(
    public_key: &[u8],
    messages: &[&[u8]],
    signatures: &[&[u8]],
    algorithm: Algorithm,
) -> Result<Vec<bool>> {
    if messages.len() != signatures.len() {
        return Err(CryptoError::InvalidParameter(
            "Messages and signatures must have the same length".into(),
        ));
    }

    if messages.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = Vec::with_capacity(messages.len());
    for (&msg, &sig) in messages.iter().zip(signatures.iter()) {
        match accelerated_ecdsa_verify(public_key, msg, sig, algorithm) {
            Ok(valid) => results.push(valid),
            Err(_) => results.push(false),
        }
    }

    Ok(results)
}

#[inline]
pub fn accelerated_ed25519_sign(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "gpu")]
    {
        if is_gpu_enabled() {
            let config = get_gpu_config();
            if config.should_use_gpu(data.len(), 1) {
                if let Ok(sig) = accelerated_ed25519_sign_gpu(private_key, data) {
                    return Ok(sig);
                }
            }
        }
    }

    use ring::signature::Ed25519KeyPair;

    let key_pair = Ed25519KeyPair::from_pkcs8(private_key)
        .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

    let signature = key_pair.sign(data);
    Ok(signature.as_ref().to_vec())
}

#[inline]
pub fn accelerated_ed25519_verify(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    #[cfg(feature = "gpu")]
    {
        if is_gpu_enabled() {
            let config = get_gpu_config();
            if config.should_use_gpu(data.len(), 1) {
                if let Ok(result) = accelerated_ed25519_verify_gpu(public_key, data, signature) {
                    return Ok(result);
                }
            }
        }
    }

    use ring::signature::{UnparsedPublicKey, ED25519};

    if public_key.len() != 32 {
        return Err(CryptoError::InvalidParameter(
            "Invalid Ed25519 public key length".into(),
        ));
    }

    if signature.len() != 64 {
        return Err(CryptoError::InvalidParameter(
            "Invalid Ed25519 signature length".into(),
        ));
    }

    let key = UnparsedPublicKey::new(&ED25519, public_key);
    match key.verify(data, signature) {
        Ok(()) => Ok(true),
        Err(e) => Err(CryptoError::VerificationFailed(e.to_string())),
    }
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
        if !has_aes_ni() {
            return;
        }
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";

        let encrypted = accelerated_aes_encrypt(&key, plaintext, &nonce);
        assert!(encrypted.is_ok());

        let decrypted = accelerated_aes_decrypt(&key, &encrypted.unwrap(), &nonce);
        assert!(decrypted.is_ok());
        let decrypted_trimmed = &decrypted.unwrap()[..plaintext.len()];
        assert_eq!(decrypted_trimmed, plaintext);
    }
}
