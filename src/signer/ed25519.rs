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

/// Ed25519 签名提供者 - 使用硬件加速
pub struct Ed25519Provider {
    algorithm: Algorithm,
}

impl Ed25519Provider {
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    /// 检查SHA-512硬件加速是否可用
    #[inline]
    fn is_sha512_accelerated() -> bool {
        hardware::has_sha_ni()
    }
}

impl Signer for Ed25519Provider {
    fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        // Log signing operation start
        let sha_accelerated = Self::is_sha512_accelerated();
        AuditLogger::log(
            "ED25519_SIGN_START",
            Some(self.algorithm),
            None,
            if sha_accelerated {
                Ok(())
            } else {
                Err(CryptoError::HardwareAccelerationUnavailable(
                    "SHA-512 acceleration not available".into(),
                ))
            },
        );

        let private_key = key.secret_bytes()?;
        let result = hardware::accelerated_ed25519_sign(private_key.as_bytes(), message);

        // Log signing operation complete
        AuditLogger::log("ED25519_SIGN_COMPLETE", Some(self.algorithm), None, {
            let r = result.as_ref();
            match r {
                Ok(_) => Ok(()),
                Err(e) => Err((*e).clone()),
            }
        });

        result
    }

    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let public_key_bytes = if let Ok(private_key) = key.secret_bytes() {
            use ring::signature::{Ed25519KeyPair, KeyPair};
            let key_pair = Ed25519KeyPair::from_pkcs8(private_key.as_bytes())
                .map_err(|e| CryptoError::KeyError(format!("Invalid Ed25519 PKCS#8 key: {}", e)))?;
            key_pair.public_key().as_ref().to_vec()
        } else {
            key.public_bytes()?
        };

        let result = hardware::accelerated_ed25519_verify(&public_key_bytes, message, signature);

        // Log verification result
        AuditLogger::log("ED25519_VERIFY", Some(self.algorithm), None, {
            let r = result.as_ref();
            match r {
                Ok(_) => Ok(()),
                Err(e) => Err((*e).clone()),
            }
        });

        result
    }
}

/// Ed25519 批量签名提供者 - 支持并行处理多个签名
#[derive(Clone)]
#[allow(dead_code)]
pub struct Ed25519BatchProvider {
    algorithm: Algorithm,
}

impl Ed25519BatchProvider {
    #[allow(dead_code)]
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    /// 批量签名多个消息
    ///
    /// 使用Rayon进行并行处理，显著提升批量签名性能。
    ///
    /// # 参数
    ///
    /// * `key` - 用于签名的私钥
    /// * `messages` - 要签名的消息列表
    ///
    /// # 返回
    ///
    /// 返回签名列表
    #[cfg(feature = "parallel")]
    pub fn sign_batch(&self, key: &Key, messages: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        AuditLogger::log(
            "ED25519_BATCH_SIGN_START",
            Some(self.algorithm),
            None,
            Ok(()),
        );

        let private_key = key.secret_bytes()?;

        // 并行签名
        let signatures: Result<Vec<Vec<u8>>> = messages
            .par_iter()
            .map(|&msg| hardware::accelerated_ed25519_sign(private_key.as_bytes(), msg))
            .collect();

        AuditLogger::log(
            "ED25519_BATCH_SIGN_COMPLETE",
            Some(self.algorithm),
            None,
            signatures.as_ref().map_err(|e| (*e).clone()).map(|_| ()),
        );

        signatures
    }

    /// 批量签名多个消息（顺序执行，无并行）
    pub fn sign_batch_sequential(&self, key: &Key, messages: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        let private_key = key.secret_bytes()?;

        let mut signatures = Vec::with_capacity(messages.len());
        for &msg in messages {
            let sig = hardware::accelerated_ed25519_sign(private_key.as_bytes(), msg)?;
            signatures.push(sig);
        }

        Ok(signatures)
    }

    /// 批量验证多个签名
    ///
    /// 使用Rayon进行并行处理，显著提升批量验证性能。
    ///
    /// # 参数
    ///
    /// * `key` - 用于验证的公钥或私钥
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
            "ED25519_BATCH_VERIFY_START",
            Some(self.algorithm),
            None,
            Ok(()),
        );

        let public_key_bytes = if let Ok(private_key) = key.secret_bytes() {
            use ring::signature::{Ed25519KeyPair, KeyPair};
            let key_pair = Ed25519KeyPair::from_pkcs8(private_key.as_bytes())
                .map_err(|e| CryptoError::KeyError(format!("Invalid Ed25519 PKCS#8 key: {}", e)))?;
            key_pair.public_key().as_ref().to_vec()
        } else {
            key.public_bytes()?
        };

        // 并行验证
        let results: Vec<bool> = messages
            .par_iter()
            .zip(signatures.par_iter())
            .map(|(&msg, &sig)| {
                hardware::accelerated_ed25519_verify(&public_key_bytes, msg, sig).unwrap_or(false)
            })
            .collect();

        AuditLogger::log(
            "ED25519_BATCH_VERIFY_COMPLETE",
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
            use ring::signature::{Ed25519KeyPair, KeyPair};
            let key_pair = Ed25519KeyPair::from_pkcs8(private_key.as_bytes())
                .map_err(|e| CryptoError::KeyError(format!("Invalid Ed25519 PKCS#8 key: {}", e)))?;
            key_pair.public_key().as_ref().to_vec()
        } else {
            key.public_bytes()?
        };

        let mut results = Vec::with_capacity(messages.len());
        for (&msg, &sig) in messages.iter().zip(signatures.iter()) {
            let result =
                hardware::accelerated_ed25519_verify(&public_key_bytes, msg, sig).unwrap_or(false);
            results.push(result);
        }

        Ok(results)
    }
}
