// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Ciphern Crypto Library
//! 
//! Enterprise-grade, security-first Rust cryptographic library.

pub mod error;
pub mod types;
pub mod memory;
pub mod random;
pub mod fips;
pub mod audit;
pub mod key;
pub mod provider;
pub mod cipher;
pub mod side_channel;
pub mod signer;

// 重新导出 FIPS 相关类型
pub use fips::{FipsContext, FipsMode, FipsError, is_fips_enabled, get_fips_approved_algorithms};

pub use error::{CryptoError, Result};
pub use types::Algorithm;
pub use key::manager::KeyManager;

/// Initialize the library (e.g., FIPS self-tests)
pub fn init() -> Result<()> {
    #[cfg(feature = "fips")]
    {
        fips::FipsContext::enable()?;
    }
    
    // 初始化审计日志
    audit::AuditLogger::init();
    
    Ok(())
}

/// High-level Cipher API
pub struct Cipher {
    provider: std::sync::Arc<dyn provider::SymmetricCipher>,
    algorithm: Algorithm,
}

impl Cipher {
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        // FIPS 模式验证
        fips::validate_algorithm_fips(&algorithm)?;
        
        let provider = provider::registry::REGISTRY.get_symmetric(algorithm)?;
        Ok(Self { provider, algorithm })
    }

    pub fn encrypt(&self, key_manager: &KeyManager, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        
        // FIPS 条件自检
        #[cfg(feature = "fips")]
        {
            if let Some(fips_context) = get_fips_context() {
                fips_context.run_conditional_self_test(self.algorithm)?;
            }
        }
        
        let result = key_manager.with_key(key_id, |key| {
            self.provider.encrypt(key, plaintext, None)
        });

        // Audit Log
        let _duration = start.elapsed();
        
        audit::AuditLogger::log(
            "ENCRYPT", 
            Some(self.algorithm), 
            Some(key_id), 
            match result.is_ok() { true => Ok(()), false => Err("Failed") }
        );

        result
    }

    pub fn decrypt(&self, key_manager: &KeyManager, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        
        // FIPS 条件自检
        #[cfg(feature = "fips")]
        {
            if let Some(fips_context) = get_fips_context() {
                fips_context.run_conditional_self_test(self.algorithm)?;
            }
        }
        
        let result = key_manager.with_key(key_id, |key| {
            self.provider.decrypt(key, ciphertext, None)
        });

        // Audit Log
        let _duration = start.elapsed();
        audit::AuditLogger::log(
            "DECRYPT", 
            Some(self.algorithm), 
            Some(key_id), 
            match result.is_ok() { true => Ok(()), false => Err("Failed") }
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