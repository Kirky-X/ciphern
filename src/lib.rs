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
    /// # Errors
    /// Returns `CryptoError` if the algorithm is not supported or FIPS validation fails
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        // FIPS 模式验证
        fips::validate_algorithm_fips(&algorithm)?;

        let provider = cipher::provider::REGISTRY.get_symmetric(algorithm)?;
        Ok(Self {
            provider,
            algorithm,
        })
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
                Err("Failed")
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
                Err("Failed")
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
            if result.is_ok() { Ok(()) } else { Err("Failed") },
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
        let result = key_manager.with_key(key_id, |key| self.provider.verify(key, message, signature));

        // Record metrics
        audit::CRYPTO_OPERATIONS_TOTAL.inc();
        audit::CRYPTO_OPERATION_LATENCY.observe(start.elapsed().as_secs_f64());

        // Audit log
        audit::AuditLogger::log(
            "VERIFY",
            Some(self.algorithm),
            Some(key_id),
            if result.is_ok() { Ok(()) } else { Err("Failed") },
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
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    /// Calculate SHA-384 hash
    pub fn sha384(data: &[u8]) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    /// Calculate SHA-512 hash
    pub fn sha512(data: &[u8]) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    /// Calculate SM3 hash
    pub fn sm3(data: &[u8]) -> Result<Vec<u8>> {
        use libsm::sm3::hash::Sm3Hash;
        let mut hash = Sm3Hash::new(data);
        Ok(hash.get_hash().to_vec())
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
