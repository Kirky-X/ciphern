#![feature(portable_simd)]
// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Ciphern 加密库
//!
//! 企业级、安全优先的 Rust 加密库，提供：
//!
//! - **对称加密**: AES-GCM, ChaCha20-Poly1305, SM4-GCM
//! - **非对称加密**: RSA, ECDSA, Ed25519, SM2
//! - **密钥派生**: PBKDF2, HKDF, Argon2id, SM3-KDF
//! - **密钥交换**: X25519 (ECDH)
//! - **哈希函数**: SHA-256, SHA-384, SHA-512, SM3
//! - **FIPS 140-3 合规**: 支持联邦信息处理标准
//! - **硬件加速**: SIMD, AES-NI, RDSEED
//! - **多语言绑定**: C FFI, Java JNI, Python PyO3
//! - **国际化**: 支持中英文界面
//!
//! # 快速开始
//!
//! ```rust
//! use ciphern::{Algorithm, Cipher, KeyManager};
//!
//! // 初始化库
//! ciphern::init()?;
//!
//! // 创建密钥管理器
//! let key_manager = KeyManager::new()?;
//!
//! // 生成密钥
//! let key_id = key_manager.generate_key(Algorithm::AES256GCM)?;
//!
//! // 创建加密器
//! let cipher = Cipher::new(Algorithm::AES256GCM)?;
//!
//! // 加密数据
//! let plaintext = b"Hello, World!";
//! let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
//!
//! // 解密数据
//! let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
//!
//! # Ok::<(), ciphern::CryptoError>(())
//! ```
//!
//! # 特性
//!
//! ## 安全特性
//! - **零化内存**: 敏感数据使用 `zeroize` 自动清除
//! - **恒定时间操作**: 防止计时攻击
//! - **侧信道保护**: 缓存攻击、功耗分析防护
//! - **密钥生命周期管理**: 生成、轮换、销毁
//! - **审计日志**: 完整的操作记录
//!
//! ## 性能特性
//! - **SIMD 加速**: AVX2, AVX-512 支持
//! - **硬件随机数生成器**: Intel RDSEED
//! - **批量加密**: 流式处理大文件
//! - **并行处理**: 多线程支持
//!
//! ## 合规特性
//! - **FIPS 140-3**: 符合联邦标准
//! - **NIST SP 800-22**: 随机数测试套件
//! - **GB/T 32907**: SM4 国密标准
//! - **GM/T 0009**: SM2 国密标准
//!
//! # Cargo Features
//!
//! - `encrypt`: 启用加密功能（默认）
//! - `hash`: 启用哈希功能（默认）
//! - `kdf`: 启用密钥派生功能
//! - `fips`: 启用 FIPS 合规模式
//! - `simd`: 启用 SIMD 加速
//! - `i18n`: 启用国际化支持
//! - `plugin`: 启用插件系统
//!
//! # 错误处理
//!
//! 所有操作返回 `Result<T, CryptoError>`，其中 `CryptoError` 包含详细的错误信息。
//!
//! # 线程安全
//!
//! 大多数类型实现了 `Send` 和 `Sync`，可以安全地在多线程环境中使用。
//!
//! # 内存安全
//!
//! 所有敏感数据都使用 `ProtectedKey` 和 `SecretBytes` 保护，自动零化内存。

#[macro_use]
extern crate arrayref;

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

pub mod random;

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
pub use key::{Key, X25519KeyManager, X25519Session};
#[cfg(feature = "encrypt")]
pub use random::{
    detect_hardware_rng, hardware_fill_bytes, is_rdseed_available, rdseed_fill_bytes,
    BulkHardwareRng, SeedGenerator,
};
pub use random::{is_hardware_rng_available, EntropySource, HardwareRng, SecureRandom};
pub use types::Algorithm;
pub use types::KeyState;

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

/// 初始化 Ciphern 库
///
/// 此函数执行以下初始化操作：
/// - 运行 FIPS 自检（如果启用了 FIPS 特性）
/// - 初始化审计日志系统
/// - 初始化 RNG 监控系统
/// - 检测 CPU 硬件加速特性
/// - 检测硬件随机数生成器
///
/// # 示例
///
/// ```rust
/// # use ciphern::init;
/// # use ciphern::CryptoError;
/// fn main() -> Result<(), CryptoError> {
///     init()?;
///     // 库已初始化，可以安全使用
///     Ok(())
/// }
/// ```
///
/// # 错误
///
/// 返回 `CryptoError` 如果：
/// - FIPS 自检失败
/// - 审计日志初始化失败
/// - 硬件特性检测失败
///
/// # 注意
///
/// 此函数应该在程序启动时调用一次，之后才能使用库的其他功能。
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

    // Initialize CPU hardware acceleration features
    #[cfg(feature = "encrypt")]
    {
        hardware::init_cpu_features();
        random::detect_hardware_rng();
    }

    Ok(())
}

/// 高级对称加密 API
///
/// 此结构体提供统一的加密接口，支持多种对称加密算法：
/// - AES-GCM (128/256位）
/// - ChaCha20-Poly1305
/// - SM4-GCM（国密）
///
/// # 线程安全
///
/// `Cipher` 实现了 `Send` 和 `Sync`，可以安全地在多线程环境中共享。
///
/// # 示例
///
/// ```rust
/// # use ciphern::{Algorithm, Cipher, KeyManager};
/// # use ciphern::CryptoError;
/// # fn main() -> Result<(), CryptoError> {
/// let key_manager = KeyManager::new()?;
/// let key_id = key_manager.generate_key(Algorithm::AES256GCM)?;
/// let cipher = Cipher::new(Algorithm::AES256GCM)?;
///
/// let plaintext = b"secret message";
/// let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
/// let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
/// assert_eq!(plaintext, &decrypted[..]);
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "encrypt")]
pub struct Cipher {
    provider: std::sync::Arc<dyn cipher::provider::SymmetricCipher>,
    algorithm: Algorithm,
}

#[cfg(feature = "encrypt")]
impl Cipher {
    /// 创建新的加密器实例
    ///
    /// 此方法按照以下优先级选择加密提供者：
    /// 1. 插件提供的实现（如果启用了 plugin 特性）
    /// 2. 内置实现
    ///
    /// # 参数
    ///
    /// * `algorithm` - 要使用的加密算法
    ///
    /// # 示例
    ///
    /// ```rust
    /// # use ciphern::{Algorithm, Cipher};
    /// # use ciphern::CryptoError;
    /// # fn main() -> Result<(), CryptoError> {
    /// let cipher = Cipher::new(Algorithm::AES256GCM)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # 错误
    ///
    /// 返回 `CryptoError` 如果：
    /// - 算法不被支持
    /// - FIPS 验证失败（如果启用了 FIPS 模式）
    /// - 插件加载失败
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

    /// 使用指定密钥加密数据
    ///
    /// 此方法执行以下操作：
    /// - 运行 FIPS 条件自检（如果启用了 FIPS 特性）
    /// - 使用密钥管理器获取密钥
    /// - 使用加密提供者执行加密
    /// - 记录审计日志
    ///
    /// # 参数
    ///
    /// * `key_manager` - 密钥管理器实例
    /// * `key_id` - 密钥 ID 或别名
    /// * `plaintext` - 要加密的明文数据
    ///
    /// # 返回
    ///
    /// 返回加密后的密文，包含 nonce 和 authentication tag。
    ///
    /// # 示例
    ///
    /// ```rust
    /// # use ciphern::{Algorithm, Cipher, KeyManager};
    /// # use ciphern::CryptoError;
    /// # fn main() -> Result<(), CryptoError> {
    /// let key_manager = KeyManager::new()?;
    /// let key_id = key_manager.generate_key(Algorithm::AES256GCM)?;
    /// let cipher = Cipher::new(Algorithm::AES256GCM)?;
    ///
    /// let plaintext = b"secret message";
    /// let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # 错误
    ///
    /// 返回 `CryptoError` 如果：
    /// - 加密失败
    /// - 密钥未找到
    /// - FIPS 验证失败
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

        // Audit Log - 使用哈希化的密钥ID防止信息泄露
        let _duration = start.elapsed();
        let hashed_key_id = crate::error::hash_key_id(key_id);

        audit::AuditLogger::log(
            "ENCRYPT",
            Some(self.algorithm),
            Some(&hashed_key_id),
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

    /// 使用指定密钥解密数据
    ///
    /// 此方法执行以下操作：
    /// - 运行 FIPS 条件自检（如果启用了 FIPS 特性）
    /// - 使用密钥管理器获取密钥
    /// - 使用加密提供者执行解密
    /// - 验证 authentication tag
    /// - 记录审计日志
    ///
    /// # 参数
    ///
    /// * `key_manager` - 密钥管理器实例
    /// * `key_id` - 密钥 ID 或别名
    /// * `ciphertext` - 要解密的密文数据（包含 nonce 和 tag）
    ///
    /// # 返回
    ///
    /// 返回解密后的明文数据。
    ///
    /// # 示例
    ///
    /// ```rust
    /// # use ciphern::{Algorithm, Cipher, KeyManager};
    /// # use ciphern::CryptoError;
    /// # fn main() -> Result<(), CryptoError> {
    /// let key_manager = KeyManager::new()?;
    /// let key_id = key_manager.generate_key(Algorithm::AES256GCM)?;
    /// let cipher = Cipher::new(Algorithm::AES256GCM)?;
    ///
    /// let plaintext = b"secret message";
    /// let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
    /// let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
    /// assert_eq!(plaintext, &decrypted[..]);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # 错误
    ///
    /// 返回 `CryptoError` 如果：
    /// - 解密失败
    /// - 密钥未找到
    /// - Authentication tag 验证失败
    /// - FIPS 验证失败
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

        // Audit Log - 使用哈希化的密钥ID防止信息泄露
        let _duration = start.elapsed();
        let hashed_key_id = crate::error::hash_key_id(key_id);

        audit::AuditLogger::log(
            "DECRYPT",
            Some(self.algorithm),
            Some(&hashed_key_id),
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
