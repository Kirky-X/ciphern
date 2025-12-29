#![feature(portable_simd)]
// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Ciphern 加密库
//!
//! 企业级、安全优先的 Rust 加密库。

#[cfg(feature = "hash")]
use hmac::Mac;

pub(crate) mod audit;
#[cfg(feature = "encrypt")]
pub(crate) mod cipher;
pub(crate) mod error;
pub(crate) mod fips;
#[cfg(feature = "encrypt")]
pub mod hardware;
#[cfg(feature = "encrypt")]
pub(crate) mod hash;
#[cfg(feature = "encrypt")]
pub(crate) mod key;
pub(crate) mod memory;

#[cfg(feature = "simd")]
pub mod simd;

pub(crate) mod random;

pub(crate) mod ffi;
#[cfg(feature = "plugin")]
pub mod plugin;
#[cfg(feature = "encrypt")]
pub(crate) mod side_channel;
#[cfg(feature = "encrypt")]
pub(crate) mod signer;
pub(crate) mod types;

#[cfg(feature = "i18n")]
pub(crate) mod i18n;
#[cfg(feature = "i18n")]
pub(crate) mod service;
#[cfg(feature = "i18n")]
pub(crate) mod ui;

// 重新导出 FIPS 相关类型
pub use fips::{get_fips_approved_algorithms, is_fips_enabled, FipsContext, FipsError, FipsMode};

pub use error::CryptoError;
pub use error::Result;
#[cfg(feature = "kdf")]
pub use key::derivation::{Argon2id, Hkdf, Pbkdf2, Sm3Kdf};
#[cfg(feature = "encrypt")]
pub use key::manager::KeyManager;
#[cfg(feature = "encrypt")]
pub use key::{Key, KeyState};
pub use random::{EntropySource, SecureRandom};
pub use types::Algorithm;

#[cfg(feature = "simd")]
pub use simd::{
    is_simd_available, simd_combine_hashes, simd_process_blocks_sha256, simd_sha256_finalize,
    simd_sm4_decrypt, simd_sm4_encrypt,
};

#[cfg(feature = "i18n")]
pub use error::{get_localized_error, get_localized_message, get_localized_title, LocalizedError};
#[cfg(feature = "i18n")]
pub use i18n::{
    get_locale, get_supported_locales, is_locale_supported, reset_for_testing, set_locale,
    translate, translate_safe, translate_with_args, I18nError,
};
#[cfg(feature = "i18n")]
pub use service::TranslationService;
#[cfg(feature = "i18n")]
pub use ui::{Button, FormField, Label, LocalizedMessage, MenuItem, Notification, UIElement};

#[cfg(feature = "plugin")]
pub use plugin::manager::PluginManager;
#[cfg(feature = "plugin")]
pub use plugin::{CipherPlugin, Plugin, PluginLoadError, PluginMetadata};

/// Initialize the library (e.g., FIPS self-tests)
///
/// # Errors
/// Returns `CryptoError` if FIPS self-tests fail or initialization fails
pub fn init() -> Result<()> {
    #[cfg(feature = "fips")]
    {
        fips::FipsContext::enable()?;
        fips::init_fips_context()?;
    }

    // 初始化审计日志
    audit::AuditLogger::init();

    // 初始化 RNG 监控系统
    let _rng_monitor_manager = random::get_rng_monitor_manager();

    // 初始化 CPU 硬件加速特性
    #[cfg(feature = "encrypt")]
    {
        hardware::init_cpu_features();
    }

    Ok(())
}

/// High-level Cipher API
#[cfg(feature = "encrypt")]
pub struct Cipher {
    provider: std::sync::Arc<dyn cipher::provider::SymmetricCipher>,
    algorithm: Algorithm,
}

#[cfg(feature = "encrypt")]
impl Cipher {
    /// Create a new cipher instance
    ///
    /// This method first checks for plugin-provided implementations,
    /// then falls back to built-in providers.
    ///
    /// # Errors
    /// Returns `CryptoError` if the algorithm is not supported or FIPS validation fails
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        fips::validate_algorithm_fips(&algorithm)?;

        let provider: std::sync::Arc<dyn cipher::provider::SymmetricCipher> = {
            #[cfg(feature = "plugin")]
            {
                if let Some(plugin_provider) = plugin::PLUGIN_MANAGER.get_cipher_provider(algorithm)
                {
                    plugin_provider
                } else {
                    cipher::provider::REGISTRY.get_symmetric(algorithm)?
                }
            }
            #[cfg(not(feature = "plugin"))]
            {
                cipher::provider::REGISTRY.get_symmetric(algorithm)?
            }
        };

        Ok(Self {
            provider,
            algorithm,
        })
    }

    /// Get the internal implementation provider
    #[cfg(test)]
    pub(crate) fn get_implementation(
        &self,
    ) -> std::sync::Arc<dyn cipher::provider::SymmetricCipher> {
        self.provider.clone()
    }

    /// Encrypt data using the specified key
    ///
    /// # Errors
    /// Returns `CryptoError` if encryption fails, key is not found, or FIPS validation fails
    pub fn encrypt(
        &self,
        key_manager: &KeyManager,
        key_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();

        // FIPS 条件自检
        #[cfg(feature = "fips")]
        {
            if let Some(fips_context) = fips::get_fips_context() {
                fips_context.run_conditional_self_test(self.algorithm)?;
            }
        }

        let result =
            key_manager.with_key(key_id, |key| self.provider.encrypt(key, plaintext, None));

        // 将密钥相关的错误转换为通用错误，防止信息泄露
        let result = result.map_err(|e| match e {
            CryptoError::KeyNotFound(_) => CryptoError::EncryptionFailed("Operation failed".into()),
            _ => e,
        });

        // Audit Log
        let _duration = start.elapsed();

        audit::AuditLogger::log(
            "ENCRYPT",
            Some(self.algorithm),
            Some(key_id),
            if result.is_ok() {
                Ok(())
            } else {
                Err(CryptoError::EncryptionFailed(
                    "Encryption operation failed".into(),
                ))
            },
        );

        result
    }

    /// Decrypt data using the specified key
    ///
    /// # Errors
    /// Returns `CryptoError` if decryption fails, key is not found, or FIPS validation fails
    pub fn decrypt(
        &self,
        key_manager: &KeyManager,
        key_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();

        // FIPS 条件自检
        #[cfg(feature = "fips")]
        {
            if let Some(fips_context) = fips::get_fips_context() {
                fips_context.run_conditional_self_test(self.algorithm)?;
            }
        }

        let result =
            key_manager.with_key(key_id, |key| self.provider.decrypt(key, ciphertext, None));

        // 将密钥相关的错误转换为通用错误，防止信息泄露
        let result = result.map_err(|e| match e {
            CryptoError::KeyNotFound(_) => CryptoError::DecryptionFailed("Operation failed".into()),
            _ => e,
        });

        // Audit Log
        let _duration = start.elapsed();

        audit::AuditLogger::log(
            "DECRYPT",
            Some(self.algorithm),
            Some(key_id),
            if result.is_ok() {
                Ok(())
            } else {
                Err(CryptoError::DecryptionFailed(
                    "Decryption operation failed".into(),
                ))
            },
        );

        result
    }

    /// Encrypt data with additional authenticated data (AAD)
    ///
    /// # Errors
    /// Returns `CryptoError` if encryption fails
    pub fn encrypt_aad(
        &self,
        key_manager: &KeyManager,
        key_id: &str,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        key_manager.with_key(key_id, |key| {
            self.provider.encrypt(key, plaintext, Some(aad))
        })
    }

    /// Decrypt data with additional authenticated data (AAD)
    ///
    /// # Errors
    /// Returns `CryptoError` if decryption fails or authentication fails
    pub fn decrypt_aad(
        &self,
        key_manager: &KeyManager,
        key_id: &str,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        key_manager.with_key(key_id, |key| {
            self.provider.decrypt(key, ciphertext, Some(aad))
        })
    }
}

#[cfg(feature = "encrypt")]
impl Drop for Cipher {
    fn drop(&mut self) {
        audit::AuditLogger::log("CIPHER_DROP", Some(self.algorithm), None, Ok(()));
    }
}

/// High-level Hashing API
#[cfg(feature = "hash")]
pub struct Hasher {
    hash: hash::MultiHash,
}

#[cfg(feature = "hash")]
impl Hasher {
    pub fn new(algorithm: types::Algorithm) -> Result<Self> {
        let algo_type = match algorithm {
            types::Algorithm::SHA256 => hash::AlgorithmType::Sha256,
            types::Algorithm::SHA384 => hash::AlgorithmType::Sha384,
            types::Algorithm::SHA512 => hash::AlgorithmType::Sha512,
            types::Algorithm::SM3 => hash::AlgorithmType::Sm3,
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm(
                    "Unsupported hash algorithm".into(),
                ))
            }
        };
        Ok(Self {
            hash: hash::MultiHash::new(algo_type)?,
        })
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = self.hash.clone();
        hasher.update(data);
        hasher.finalize()
    }

    #[cfg(feature = "encrypt")]
    pub fn hash_large(&self, data: &[u8]) -> Result<Vec<u8>> {
        if hardware::has_sha_ni() || hardware::has_avx2() {
            let algorithm = match self.hash.algorithm() {
                hash::AlgorithmType::Sha256 => Algorithm::SHA256,
                hash::AlgorithmType::Sha384 => Algorithm::SHA384,
                hash::AlgorithmType::Sha512 => Algorithm::SHA512,
                hash::AlgorithmType::Sm3 => Algorithm::SM3,
            };
            hardware::accelerated_hash(data, algorithm)
        } else {
            Ok(self.hash(data))
        }
    }
}

/// High-level MAC API
#[cfg(feature = "hash")]
pub struct Hmac {
    algorithm: types::Algorithm,
}

#[cfg(feature = "hash")]
impl Hmac {
    pub fn new(algorithm: types::Algorithm) -> Result<Self> {
        Ok(Self { algorithm })
    }

    pub fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            types::Algorithm::SHA256 => {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
                    .map_err(|_| CryptoError::KeyError("Invalid HMAC key".into()))?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            types::Algorithm::SHA384 => {
                let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(key)
                    .map_err(|_| CryptoError::KeyError("Invalid HMAC key".into()))?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            types::Algorithm::SHA512 => {
                let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
                    .map_err(|_| CryptoError::KeyError("Invalid HMAC key".into()))?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            _ => Err(CryptoError::UnsupportedAlgorithm(
                "Unsupported MAC algorithm".into(),
            )),
        }
    }

    pub fn verify(&self, key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        match self.algorithm {
            types::Algorithm::SHA256 => {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
                    .map_err(|_| CryptoError::KeyError("Invalid HMAC key".into()))?;
                mac.update(data);
                Ok(mac.verify_slice(signature).is_ok())
            }
            types::Algorithm::SHA384 => {
                let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(key)
                    .map_err(|_| CryptoError::KeyError("Invalid HMAC key".into()))?;
                mac.update(data);
                Ok(mac.verify_slice(signature).is_ok())
            }
            types::Algorithm::SHA512 => {
                let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
                    .map_err(|_| CryptoError::KeyError("Invalid HMAC key".into()))?;
                mac.update(data);
                Ok(mac.verify_slice(signature).is_ok())
            }
            _ => Err(CryptoError::UnsupportedAlgorithm(
                "Unsupported MAC algorithm".into(),
            )),
        }
    }
}

/// High-level Digital Signature API
#[cfg(feature = "encrypt")]
pub struct Signer {
    algorithm: types::Algorithm,
}

#[cfg(feature = "encrypt")]
impl Signer {
    pub fn new(algorithm: types::Algorithm) -> Result<Self> {
        Ok(Self { algorithm })
    }

    pub fn sign(&self, key_manager: &KeyManager, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let signer = cipher::provider::REGISTRY.get_signer(self.algorithm)?;
        key_manager.with_key(key_id, |key| signer.sign(key, data))
    }

    pub fn verify(
        &self,
        key_manager: &KeyManager,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let signer = cipher::provider::REGISTRY.get_signer(self.algorithm)?;
        key_manager.with_key(key_id, |key| signer.verify(key, data, signature))
    }
}

/// Get the hardware acceleration status
#[cfg(feature = "encrypt")]
pub fn get_hardware_info() -> hardware::CpuFeatures {
    hardware::CpuFeatures::detect()
}

/// Check if AES-NI is available
#[cfg(feature = "encrypt")]
pub fn has_aes_ni() -> bool {
    hardware::has_aes_ni()
}

/// Check if AVX2 is available
#[cfg(feature = "encrypt")]
pub fn has_avx2() -> bool {
    hardware::has_avx2()
}

/// Check if SHA-NI is available
#[cfg(feature = "encrypt")]
pub fn has_sha_ni() -> bool {
    hardware::has_sha_ni()
}

#[cfg(feature = "encrypt")]
pub fn is_hardware_acceleration_available() -> bool {
    hardware::is_hardware_acceleration_available()
}

#[cfg(feature = "encrypt")]
pub fn get_cpu_capabilities() -> hardware::cpu::CpuCapabilities {
    hardware::get_cpu_capabilities()
}

#[cfg(feature = "encrypt")]
pub fn accelerated_hash_cpu(data: &[u8], algorithm: types::Algorithm) -> error::Result<Vec<u8>> {
    hardware::accelerated_hash_cpu(data, algorithm)
}

#[cfg(feature = "encrypt")]
pub fn accelerated_batch_hash_cpu(
    data_chunks: Vec<&[u8]>,
    algorithm: types::Algorithm,
) -> error::Result<Vec<Vec<u8>>> {
    hardware::accelerated_batch_hash_cpu(data_chunks, algorithm)
}

#[cfg(feature = "encrypt")]
pub fn accelerated_aes_encrypt_cpu(
    key: &[u8],
    plaintext: &[u8],
    nonce: &[u8],
) -> error::Result<Vec<u8>> {
    hardware::accelerated_aes_encrypt_cpu(key, plaintext, nonce)
}

#[cfg(feature = "encrypt")]
pub fn accelerated_aes_decrypt_cpu(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
) -> error::Result<Vec<u8>> {
    hardware::accelerated_aes_decrypt_cpu(key, ciphertext, nonce)
}

#[cfg(feature = "encrypt")]
pub fn accelerated_batch_aes_encrypt_cpu(
    key: &[u8],
    plaintexts: Vec<&[u8]>,
    nonces: Vec<&[u8]>,
) -> error::Result<Vec<Vec<u8>>> {
    hardware::accelerated_batch_aes_encrypt_cpu(key, plaintexts, nonces)
}

#[cfg(feature = "encrypt")]
pub fn accelerated_batch_aes_decrypt_cpu(
    key: &[u8],
    ciphertexts: Vec<Vec<u8>>,
    nonces: Vec<&[u8]>,
) -> error::Result<Vec<Vec<u8>>> {
    hardware::accelerated_batch_aes_decrypt_cpu(key, ciphertexts, nonces)
}

#[cfg(feature = "encrypt")]
pub fn accelerated_sm4_encrypt_cpu(key: &[u8], plaintext: &[u8]) -> error::Result<Vec<u8>> {
    hardware::accelerated_sm4_encrypt_cpu(key, plaintext)
}

#[cfg(feature = "encrypt")]
pub fn accelerated_sm4_decrypt_cpu(key: &[u8], ciphertext: &[u8]) -> error::Result<Vec<u8>> {
    hardware::accelerated_sm4_decrypt_cpu(key, ciphertext)
}

#[cfg(feature = "encrypt")]
pub fn accelerated_batch_sm4_cpu(
    key: &[u8],
    data_chunks: Vec<Vec<u8>>,
    encrypt: bool,
) -> error::Result<Vec<Vec<u8>>> {
    hardware::accelerated_batch_sm4_cpu(key, data_chunks, encrypt)
}
