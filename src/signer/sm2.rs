// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::audit::AuditLogger;
use crate::cipher::provider::Signer;
use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::types::Algorithm;
use libsm::sm2::signature::{SigCtx, Signature as Sm2Signature};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// SM2 签名提供者
pub struct Sm2Provider {
    algorithm: Algorithm,
}

impl Sm2Provider {
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }
}

impl Signer for Sm2Provider {
    fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        // Log signing operation start
        AuditLogger::log("SM2_SIGN_START", Some(self.algorithm), None, Ok(()));

        let secret = key.secret_bytes()?;
        let secret_bytes = secret.as_bytes();

        // SM2 私钥长度为 32 字节
        if secret_bytes.len() != 32 {
            return Err(CryptoError::KeyError(format!(
                "Invalid SM2 private key length: expected 32, got {}",
                secret_bytes.len()
            )));
        }

        let ctx = SigCtx::new();

        // 从私钥生成签名密钥对
        let sk = ctx
            .load_seckey(secret_bytes)
            .map_err(|e| CryptoError::KeyError(format!("Invalid SM2 private key: {:?}", e)))?;

        // 从私钥生成公钥 (SM2 签名需要公钥)
        let pk = ctx
            .pk_from_sk(&sk)
            .map_err(|e| CryptoError::KeyError(format!("Failed to derive public key: {:?}", e)))?;

        // 生成签名
        let signature = ctx
            .sign(message, &sk, &pk)
            .map_err(|e| CryptoError::SigningFailed(format!("SM2 signing failed: {:?}", e)))?;

        // 将签名序列化为字节数组 (r || s)
        let mut result = Vec::with_capacity(64);
        let r_bytes = signature.get_r().to_bytes_be();
        let s_bytes = signature.get_s().to_bytes_be();

        // 确保 r 和 s 都是 32 字节
        if r_bytes.len() > 32 || s_bytes.len() > 32 {
            return Err(CryptoError::SigningFailed(
                "SM2 signature components too large".into(),
            ));
        }

        // 填充到 32 字节 (大端序)
        result.extend(vec![0u8; 32 - r_bytes.len()]);
        result.extend(r_bytes);
        result.extend(vec![0u8; 32 - s_bytes.len()]);
        result.extend(s_bytes);

        // Log signing operation complete
        AuditLogger::log("SM2_SIGN_COMPLETE", Some(self.algorithm), None, Ok(()));

        Ok(result)
    }

    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool> {
        if key.algorithm() != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch".into(),
            ));
        }

        // 验证签名长度 (64 字节 = 32 字节 r + 32 字节 s)
        if signature.len() != 64 {
            return Err(CryptoError::InvalidParameter(format!(
                "Invalid SM2 signature length: expected 64, got {}",
                signature.len()
            )));
        }

        let secret = key.secret_bytes()?;
        let secret_bytes = secret.as_bytes();

        // SM2 私钥长度为 32 字节
        if secret_bytes.len() != 32 {
            return Err(CryptoError::KeyError(format!(
                "Invalid SM2 private key length: expected 32, got {}",
                secret_bytes.len()
            )));
        }

        let ctx = SigCtx::new();

        // 从私钥生成公钥
        let sk = ctx
            .load_seckey(secret_bytes)
            .map_err(|e| CryptoError::KeyError(format!("Invalid SM2 private key: {:?}", e)))?;

        let pk = ctx
            .pk_from_sk(&sk)
            .map_err(|e| CryptoError::KeyError(format!("Failed to derive public key: {:?}", e)))?;

        // 解析签名
        let r_bytes = &signature[0..32];
        let s_bytes = &signature[32..64];

        let sig = Sm2Signature::new(r_bytes, s_bytes);

        // 验证签名
        let verify_result = match ctx.verify(message, &pk, &sig) {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            Err(e) => Err(CryptoError::InvalidParameter(format!(
                "SM2 verification error: {:?}",
                e
            ))),
        };

        // Log verification result
        AuditLogger::log(
            "SM2_VERIFY",
            Some(self.algorithm),
            None,
            verify_result.as_ref().map_err(|e| (*e).clone()).map(|_| ()),
        );

        verify_result
    }
}

/// SM2 批量签名验证提供者 - 支持并行处理
#[derive(Clone)]
#[allow(dead_code)]
pub struct Sm2BatchProvider {
    algorithm: Algorithm,
}

impl Sm2BatchProvider {
    #[allow(dead_code)]
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    /// 批量验证多个签名（并行执行）
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

        AuditLogger::log("SM2_BATCH_VERIFY_START", Some(self.algorithm), None, Ok(()));

        let secret = key.secret_bytes()?;
        let secret_bytes = secret.as_bytes();

        let ctx = SigCtx::new();
        let sk = ctx
            .load_seckey(secret_bytes)
            .map_err(|e| CryptoError::KeyError(format!("Invalid SM2 private key: {:?}", e)))?;
        let pk = ctx
            .pk_from_sk(&sk)
            .map_err(|e| CryptoError::KeyError(format!("Failed to derive public key: {:?}", e)))?;

        // 并行验证
        let results: Vec<bool> = messages
            .par_iter()
            .zip(signatures.par_iter())
            .map(|(&msg, &sig)| {
                if sig.len() != 64 {
                    return false;
                }
                let r_bytes = &sig[0..32];
                let s_bytes = &sig[32..64];
                let sm2_sig = Sm2Signature::new(r_bytes, s_bytes);
                ctx.verify(msg, &pk, &sm2_sig).unwrap_or(false)
            })
            .collect();

        AuditLogger::log(
            "SM2_BATCH_VERIFY_COMPLETE",
            Some(self.algorithm),
            None,
            Ok(()),
        );

        Ok(results)
    }

    /// 批量验证多个签名（顺序执行）
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

        let secret = key.secret_bytes()?;
        let secret_bytes = secret.as_bytes();

        let ctx = SigCtx::new();
        let sk = ctx
            .load_seckey(secret_bytes)
            .map_err(|e| CryptoError::KeyError(format!("Invalid SM2 private key: {:?}", e)))?;
        let pk = ctx
            .pk_from_sk(&sk)
            .map_err(|e| CryptoError::KeyError(format!("Failed to derive public key: {:?}", e)))?;

        let mut results = Vec::with_capacity(messages.len());
        for (&msg, &sig) in messages.iter().zip(signatures.iter()) {
            if sig.len() != 64 {
                results.push(false);
                continue;
            }
            let r_bytes = &sig[0..32];
            let s_bytes = &sig[32..64];
            let sm2_sig = Sm2Signature::new(r_bytes, s_bytes);
            let result = ctx.verify(msg, &pk, &sm2_sig).unwrap_or(false);
            results.push(result);
        }

        Ok(results)
    }
}
