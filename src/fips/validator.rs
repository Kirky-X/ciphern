// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::types::Algorithm;

/// FIPS 140-3 算法验证器
#[derive(Clone)]
pub struct FipsAlgorithmValidator;

impl FipsAlgorithmValidator {
    /// FIPS 批准的算法列表
    const APPROVED_ALGORITHMS: &'static [Algorithm] = &[
        // 对称加密算法
        Algorithm::AES128GCM,
        Algorithm::AES192GCM,
        Algorithm::AES256GCM,
        // 非对称加密/签名算法
        Algorithm::ECDSAP256,
        Algorithm::ECDSAP384,
        Algorithm::ECDSAP521,
        Algorithm::RSA2048,
        Algorithm::RSA3072,
        Algorithm::RSA4096,
        // 哈希算法
        Algorithm::SHA256,
        Algorithm::SHA384,
        Algorithm::SHA512,
        Algorithm::SHA3_256,
        Algorithm::SHA3_384,
        Algorithm::SHA3_512,
        // 密钥派生函数
        Algorithm::HKDF,
        Algorithm::PBKDF2,
    ];

    /// 非 FIPS 批准的算法列表 (国密和现代算法)
    #[allow(dead_code)]
    const NON_APPROVED_ALGORITHMS: &'static [Algorithm] = &[
        // 国密算法
        Algorithm::SM2,
        Algorithm::SM3,
        Algorithm::SM4GCM,
        Algorithm::Sm3Kdf,
        // 现代算法
        Algorithm::Ed25519,
        Algorithm::X25519,           // 密钥交换算法，非 FIPS 批准
        Algorithm::ChaCha20Poly1305, // AEAD 加密，非 FIPS 批准
        Algorithm::Argon2id,
    ];

    /// 检查算法是否在 FIPS 批准列表中
    pub fn is_algorithm_approved(algorithm: &Algorithm) -> bool {
        Self::APPROVED_ALGORITHMS.contains(algorithm)
    }

    /// 检查算法是否在非 FIPS 批准列表中
    #[allow(dead_code)]
    pub fn is_algorithm_non_approved(algorithm: &Algorithm) -> bool {
        Self::NON_APPROVED_ALGORITHMS.contains(algorithm)
    }

    /// 验证算法是否符合 FIPS 140-3 要求
    pub fn validate_fips_compliance(algorithm: &Algorithm) -> Result<()> {
        if !Self::is_algorithm_approved(algorithm) {
            return Err(CryptoError::FipsError(format!(
                "算法 {:?} 不符合 FIPS 140-3 要求。批准的算法: {:?}",
                algorithm,
                Self::get_approved_algorithms()
            )));
        }
        Ok(())
    }

    /// 获取所有 FIPS 批准的算法
    pub fn get_approved_algorithms() -> Vec<Algorithm> {
        Self::APPROVED_ALGORITHMS.to_vec()
    }

    /// 获取所有非 FIPS 批准的算法
    #[allow(dead_code)]
    pub fn get_non_approved_algorithms() -> Vec<Algorithm> {
        Self::NON_APPROVED_ALGORITHMS.to_vec()
    }

    /// 获取所有支持的算法 (包括 FIPS 和非 FIPS)
    #[allow(dead_code)]
    pub fn get_all_supported_algorithms() -> Vec<Algorithm> {
        let mut all_algorithms = Self::APPROVED_ALGORITHMS.to_vec();
        all_algorithms.extend(Self::NON_APPROVED_ALGORITHMS);
        all_algorithms
    }

    /// 验证密钥大小是否符合 FIPS 要求
    pub fn validate_key_size(algorithm: &Algorithm, key_size: usize) -> Result<()> {
        match algorithm {
            // AES 密钥大小要求
            Algorithm::AES128GCM if key_size != 16 => {
                return Err(CryptoError::FipsError(format!(
                    "AES-128 requires 16 byte key, got {}",
                    key_size
                )));
            }
            Algorithm::AES192GCM if key_size != 24 => {
                return Err(CryptoError::FipsError(format!(
                    "AES-192 requires 24 byte key, got {}",
                    key_size
                )));
            }
            Algorithm::AES256GCM if key_size != 32 => {
                return Err(CryptoError::FipsError(format!(
                    "AES-256 requires 32 byte key, got {}",
                    key_size
                )));
            }

            // RSA 密钥大小要求 (FIPS 140-3 要求最小 2048 位)
            Algorithm::RSA2048 if key_size < 256 => {
                // 2048 bits = 256 bytes
                return Err(CryptoError::FipsError(format!(
                    "RSA-2048 requires at least 256 byte key, got {}",
                    key_size
                )));
            }
            Algorithm::RSA3072 if key_size < 384 => {
                // 3072 bits = 384 bytes
                return Err(CryptoError::FipsError(format!(
                    "RSA-3072 requires at least 384 byte key, got {}",
                    key_size
                )));
            }
            Algorithm::RSA4096 if key_size < 512 => {
                // 4096 bits = 512 bytes
                return Err(CryptoError::FipsError(format!(
                    "RSA-4096 requires at least 512 byte key, got {}",
                    key_size
                )));
            }

            // ECDSA 曲线密钥大小要求
            Algorithm::ECDSAP256 if key_size < 32 => {
                return Err(CryptoError::FipsError(format!(
                    "ECDSA P-256 requires at least 32 byte key, got {}",
                    key_size
                )));
            }
            Algorithm::ECDSAP384 if key_size < 48 => {
                return Err(CryptoError::FipsError(format!(
                    "ECDSA P-384 requires at least 48 byte key, got {}",
                    key_size
                )));
            }
            Algorithm::ECDSAP521 if key_size < 66 => {
                return Err(CryptoError::FipsError(format!(
                    "ECDSA P-521 requires at least 66 byte key, got {}",
                    key_size
                )));
            }

            _ => {} // 其他算法不做密钥大小检查
        }

        Ok(())
    }

    /// 获取算法的 FIPS 状态描述
    #[allow(dead_code)]
    pub fn get_algorithm_fips_status(algorithm: &Algorithm) -> &'static str {
        if Self::is_algorithm_approved(algorithm) {
            "FIPS 140-3 Approved"
        } else if Self::is_algorithm_non_approved(algorithm) {
            "Non-FIPS Approved"
        } else {
            "Unknown"
        }
    }

    /// 验证算法列表是否全部符合 FIPS 要求
    #[allow(dead_code)]
    pub fn validate_algorithms_fips_compliance(algorithms: &[Algorithm]) -> Result<()> {
        let mut non_approved = Vec::with_capacity(algorithms.len());

        for algorithm in algorithms {
            if !Self::is_algorithm_approved(algorithm) {
                non_approved.push(*algorithm);
            }
        }

        if !non_approved.is_empty() {
            return Err(CryptoError::FipsError(format!(
                "The following algorithms are not FIPS 140-3 approved: {:?}",
                non_approved
            )));
        }

        Ok(())
    }
}
