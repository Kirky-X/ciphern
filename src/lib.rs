// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Ciphern Crypto Library
//!
//! Enterprise-grade, security-first Rust cryptographic library.

pub mod audit;
pub mod cipher;
pub mod error;
pub mod fips;
pub mod key;
pub mod memory;
pub mod provider;
pub mod random;
pub mod side_channel;
pub mod signer;
pub mod types;

// 重新导出 FIPS 相关类型
pub use fips::{get_fips_approved_algorithms, is_fips_enabled, FipsContext, FipsError, FipsMode};

pub use error::{CryptoError, Result};
pub use key::manager::KeyManager;
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
pub struct Cipher {
    provider: std::sync::Arc<dyn provider::SymmetricCipher>,
    algorithm: Algorithm,
}

impl Cipher {
    /// Create a new cipher instance
    ///
    /// # Errors
    /// Returns `CryptoError` if the algorithm is not supported or FIPS validation fails
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        // FIPS 模式验证
        fips::validate_algorithm_fips(&algorithm)?;

        let provider = provider::registry::REGISTRY.get_symmetric(algorithm)?;
        Ok(Self {
            provider,
            algorithm,
        })
    }

    /// Access internal provider for specialized tests (CAVP/KAT)
    #[must_use]
    pub fn get_implementation(&self) -> std::sync::Arc<dyn provider::SymmetricCipher> {
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
            if result.is_ok() { Ok(()) } else { Err("Failed") },
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
            if result.is_ok() { Ok(()) } else { Err("Failed") },
        );

        result
    }
}

/// 获取全局 FIPS 上下文 (简化实现)
#[cfg(feature = "fips")]
fn get_fips_context() -> Option<FipsContext> {
    if fips::is_fips_enabled() {
        FipsContext::new(fips::FipsMode::Enabled).ok()
    } else {
        None
    }
}
