// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Ciphern Crypto Library
//!
//! Enterprise-grade, security-first Rust cryptographic library.

pub(crate) mod audit;
#[cfg(feature = "encrypt")]
pub(crate) mod cipher;
pub(crate) mod error;
pub(crate) mod fips;
#[cfg(feature = "encrypt")]
pub(crate) mod hash;
#[cfg(feature = "encrypt")]
pub(crate) use cipher::provider;
#[cfg(feature = "encrypt")]
pub(crate) mod key;
pub(crate) mod memory;

pub(crate) mod random;

pub(crate) mod ffi;
#[cfg(feature = "plugin")]
pub(crate) mod plugin;
#[cfg(feature = "encrypt")]
pub(crate) mod side_channel;
#[cfg(feature = "encrypt")]
pub(crate) mod signer;
pub(crate) mod types;

// 重新导出 FIPS 相关类型
pub use fips::{get_fips_approved_algorithms, is_fips_enabled, FipsContext, FipsError, FipsMode};

pub use error::CryptoError;
pub use error::Result;
#[cfg(feature = "encrypt")]
pub use key::manager::KeyManager;
#[cfg(feature = "encrypt")]
pub use key::{Key, KeyState};
pub use types::Algorithm;

/// Initialize the library (e.g., FIPS self-tests)
///
/// # Errors
/// Returns `CryptoError` if FIPS self-tests fail or initialization fails
pub fn init() -> Result<()> {
    #[cfg(feature = "fips")]
    {
        fips::FipsContext::enable()?;
    }

    // 初始化审计日志
    audit::AuditLogger::init();

    // 初始化 RNG 监控系统
    let _rng_monitor_manager = random::get_rng_monitor_manager();

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
            if let Some(fips_context) = get_fips_context() {
                fips_context.run_conditional_self_test(self.algorithm)?;
            }
        }

        let result =
            key_manager.with_key(key_id, |key| self.provider.encrypt(key, plaintext, None));

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
            if let Some(fips_context) = get_fips_context() {
                fips_context.run_conditional_self_test(self.algorithm)?;
            }
        }

        let result =
            key_manager.with_key(key_id, |key| self.provider.decrypt(key, ciphertext, None));

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
}

/// High-level Signer API
#[cfg(feature = "encrypt")]
pub struct Signer {
    provider: std::sync::Arc<dyn cipher::provider::Signer>,
    algorithm: Algorithm,
}

#[cfg(feature = "encrypt")]
impl Signer {
    /// Create a new signer instance
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        fips::validate_algorithm_fips(&algorithm)?;
        let provider = cipher::provider::REGISTRY.get_signer(algorithm)?;
        Ok(Self {
            provider,
            algorithm,
        })
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Sign a message using the specified key
    pub fn sign(&self, key_manager: &KeyManager, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let result = key_manager.with_key(key_id, |key| self.provider.sign(key, message));

        // Record metrics
        audit::CRYPTO_OPERATIONS_TOTAL.inc();
        audit::CRYPTO_OPERATION_LATENCY.observe(start.elapsed().as_secs_f64());

        // Audit log
        audit::AuditLogger::log(
            "SIGN",
            Some(self.algorithm),
            Some(key_id),
            if result.is_ok() {
                Ok(())
            } else {
                Err(CryptoError::SigningFailed(
                    "Signing operation failed".into(),
                ))
            },
        );

        result
    }

    /// Verify a signature
    pub fn verify(
        &self,
        key_manager: &KeyManager,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let start = std::time::Instant::now();
        let result =
            key_manager.with_key(key_id, |key| self.provider.verify(key, message, signature));

        // Record metrics
        audit::CRYPTO_OPERATIONS_TOTAL.inc();
        audit::CRYPTO_OPERATION_LATENCY.observe(start.elapsed().as_secs_f64());

        // Audit log
        audit::AuditLogger::log(
            "VERIFY",
            Some(self.algorithm),
            Some(key_id),
            if result.is_ok() {
                Ok(())
            } else {
                Err(CryptoError::SigningFailed(
                    "Verification operation failed".into(),
                ))
            },
        );

        result
    }
}

/// High-level Hash API
#[cfg(feature = "hash")]
pub struct Hash;

#[cfg(feature = "hash")]
impl Hash {
    /// Calculate SHA-256 hash
    pub fn sha256(data: &[u8]) -> Result<Vec<u8>> {
        use hash::{AlgorithmType, MultiHash};
        let mut hasher = MultiHash::new(AlgorithmType::Sha256)?;
        hasher.update(data);
        Ok(hasher.finalize())
    }

    /// Calculate SHA-384 hash
    pub fn sha384(data: &[u8]) -> Result<Vec<u8>> {
        use hash::{AlgorithmType, MultiHash};
        let mut hasher = MultiHash::new(AlgorithmType::Sha384)?;
        hasher.update(data);
        Ok(hasher.finalize())
    }

    /// Calculate SHA-512 hash
    pub fn sha512(data: &[u8]) -> Result<Vec<u8>> {
        use hash::{AlgorithmType, MultiHash};
        let mut hasher = MultiHash::new(AlgorithmType::Sha512)?;
        hasher.update(data);
        Ok(hasher.finalize())
    }

    /// Calculate SM3 hash
    pub fn sm3(data: &[u8]) -> Result<Vec<u8>> {
        use hash::{AlgorithmType, MultiHash};
        let mut hasher = MultiHash::new(AlgorithmType::Sm3)?;
        hasher.update(data);
        Ok(hasher.finalize())
    }
}

use std::sync::{Arc, Mutex, OnceLock};

/// 全局 FIPS 上下文实例
static GLOBAL_FIPS_CONTEXT: OnceLock<Arc<Mutex<Option<FipsContext>>>> = OnceLock::new();

/// 获取全局 FIPS 上下文
///
/// 返回一个线程安全的全局 FIPS 上下文引用。如果启用了 FIPS 模式且上下文尚未初始化，
/// 将会尝试初始化一个新的上下文。
#[cfg(feature = "fips")]
#[allow(dead_code)]
fn get_fips_context() -> Option<FipsContext> {
    if !fips::is_fips_enabled() {
        return None;
    }

    let context_lock = GLOBAL_FIPS_CONTEXT.get_or_init(|| Arc::new(Mutex::new(None)));

    let mut context_guard = context_lock.lock().ok()?;

    if context_guard.is_none() {
        if let Ok(new_context) = FipsContext::new(fips::FipsMode::Enabled) {
            *context_guard = Some(new_context);
        }
    }

    context_guard.clone()
}
