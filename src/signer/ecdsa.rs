// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::audit::AuditLogger;
use crate::cipher::provider::Signer;
use crate::error::{CryptoError, Result};
use crate::hardware;
use crate::key::Key;
use crate::types::Algorithm;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// ECDSA 签名提供者 - 使用硬件加速
pub struct EcdsaProvider {
    algorithm: Algorithm,
}

impl EcdsaProvider {
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    fn to_hardware_algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

impl Signer for EcdsaProvider {
    fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let private_key = key.secret_bytes()?;
        let algo = self.to_hardware_algorithm();

        // Log signing operation start
        AuditLogger::log("ECDSA_SIGN_START", Some(self.algorithm), None, Ok(()));

        let result = hardware::accelerated_ecdsa_sign(private_key.as_bytes(), message, algo);

        // Log signing operation complete
        AuditLogger::log(
            "ECDSA_SIGN_COMPLETE",
            Some(self.algorithm),
            None,
            result.as_ref().map_err(|e| (*e).clone()).map(|_| ()),
        );

        result
    }

    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let private_key = key.secret_bytes()?;

        use ring::signature::{EcdsaKeyPair, KeyPair};
        let secret = private_key.as_bytes();
        let alg = match self.algorithm {
            Algorithm::ECDSAP256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            Algorithm::ECDSAP384 => &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm(
                    "Key algorithm mismatch".into(),
                ))
            }
        };

        let rng = ring::rand::SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(alg, secret, &rng)
            .map_err(|e| CryptoError::KeyError(format!("Invalid ECDSA PKCS#8 key: {}", e)))?;

        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        let algo = self.to_hardware_algorithm();

        // Log verification operation
        let result =
            hardware::accelerated_ecdsa_verify(&public_key_bytes, message, signature, algo);

        AuditLogger::log(
            "ECDSA_VERIFY",
            Some(self.algorithm),
            None,
            result.as_ref().map_err(|e| (*e).clone()).map(|_| ()),
        );

        result
    }
}

/// ECDSA 批量签名验证提供者 - 支持并行处理多个签名验证
#[cfg(feature = "parallel")]
#[derive(Clone)]
#[allow(dead_code)]
pub struct EcdsaBatchProvider {
    algorithm: Algorithm,
}

#[cfg(feature = "parallel")]
#[allow(dead_code)]
impl EcdsaBatchProvider {
    /// 创建新的批量签名验证提供者
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    /// 批量验证多个签名（并行执行）
    ///
    /// 使用Rayon进行并行处理，显著提升批量验证性能。
    ///
    /// # 参数
    ///
    /// * `key` - 用于验证的密钥
    /// * `messages` - 消息列表
    /// * `signatures` - 签名列表
    ///
    /// # 返回
    ///
    /// 返回验证结果列表
    #[cfg(feature = "parallel")]
    pub fn verify_batch(
        &self,
        key: &Key,
        messages: &[&[u8]],
        signatures: &[&[u8]],
    ) -> Result<Vec<bool>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        if messages.len() != signatures.len() {
            return Err(CryptoError::InvalidParameter(
                "Messages and signatures must have the same length".into(),
            ));
        }

        AuditLogger::log(
            "ECDSA_BATCH_VERIFY_START",
            Some(self.algorithm),
            None,
            Ok(()),
        );

        let public_key_bytes = if let Ok(private_key) = key.secret_bytes() {
            use ring::signature::{EcdsaKeyPair, KeyPair};
            let alg = match self.algorithm {
                Algorithm::ECDSAP256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                Algorithm::ECDSAP384 => &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                _ => {
                    return Err(CryptoError::UnsupportedAlgorithm(
                        "Key algorithm mismatch".into(),
                    ))
                }
            };
            let rng = ring::rand::SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(alg, private_key.as_bytes(), &rng)
                .map_err(|e| CryptoError::KeyError(format!("Invalid ECDSA PKCS#8 key: {}", e)))?;
            key_pair.public_key().as_ref().to_vec()
        } else {
            key.public_bytes()?
        };

        let algo = self.to_hardware_algorithm();

        // 并行验证
        let results: Vec<bool> = messages
            .par_iter()
            .zip(signatures.par_iter())
            .map(|(&msg, &sig)| {
                hardware::accelerated_ecdsa_verify(&public_key_bytes, msg, sig, algo)
                    .unwrap_or(false)
            })
            .collect();

        AuditLogger::log(
            "ECDSA_BATCH_VERIFY_COMPLETE",
            Some(self.algorithm),
            None,
            Ok(()),
        );

        Ok(results)
    }

    /// 批量验证多个签名（顺序执行，无并行）
    pub fn verify_batch_sequential(
        &self,
        key: &Key,
        messages: &[&[u8]],
        signatures: &[&[u8]],
    ) -> Result<Vec<bool>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        if messages.len() != signatures.len() {
            return Err(CryptoError::InvalidParameter(
                "Messages and signatures must have the same length".into(),
            ));
        }

        let public_key_bytes = if let Ok(private_key) = key.secret_bytes() {
            use ring::signature::{EcdsaKeyPair, KeyPair};
            let alg = match self.algorithm {
                Algorithm::ECDSAP256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                Algorithm::ECDSAP384 => &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                _ => {
                    return Err(CryptoError::UnsupportedAlgorithm(
                        "Key algorithm mismatch".into(),
                    ))
                }
            };
            let rng = ring::rand::SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(alg, private_key.as_bytes(), &rng)
                .map_err(|e| CryptoError::KeyError(format!("Invalid ECDSA PKCS#8 key: {}", e)))?;
            key_pair.public_key().as_ref().to_vec()
        } else {
            key.public_bytes()?
        };

        let algo = self.to_hardware_algorithm();

        let mut results = Vec::with_capacity(messages.len());
        for (&msg, &sig) in messages.iter().zip(signatures.iter()) {
            let result = hardware::accelerated_ecdsa_verify(&public_key_bytes, msg, sig, algo)
                .unwrap_or(false);
            results.push(result);
        }

        Ok(results)
    }

    fn to_hardware_algorithm(&self) -> Algorithm {
        self.algorithm
    }
}
