// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Signature GPU Kernel 实现
//!
//! 支持 ECDSA、Ed25519 等签名算法的 GPU 加速
//! 特别优化批量签名验证场景

use super::{BatchConfig, KernelMetrics, GpuKernel, KernelType};
use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use std::sync::Mutex;

#[cfg(feature = "gpu-cuda")]
mod cuda_signature;
#[cfg(feature = "gpu-opencl")]
mod opencl_signature;

#[cfg(feature = "gpu-cuda")]
pub use cuda_signature::CudaSignatureKernel;
#[cfg(feature = "gpu-opencl")]
pub use opencl_signature::OpenclSignatureKernel;

/// Signature Kernel 内部状态
#[derive(Debug)]
pub struct SignatureKernelState {
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
    batch_config: BatchConfig,
}

impl SignatureKernelState {
    pub fn new() -> Self {
        Self {
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuEcdsa)),
            initialized: false,
            batch_config: BatchConfig::default(),
        }
    }
}

/// CPU 回退实现（当 GPU 不可用时）
pub struct CpuSignatureKernel {
    state: SignatureKernelState,
}

impl CpuSignatureKernel {
    pub fn new() -> Self {
        Self {
            state: SignatureKernelState::new(),
        }
    }
}

impl GpuKernel for CpuSignatureKernel {
    fn kernel_type(&self) -> KernelType {
        KernelType::GpuEcdsa
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![
            Algorithm::ECDSA256,
            Algorithm::ECDSA384,
            Algorithm::ECDSA521,
            Algorithm::ED25519,
        ]
    }

    fn is_available(&self) -> bool {
        true
    }

    fn initialize(&mut self) -> Result<()> {
        self.state.initialized = true;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        self.state.initialized = false;
        Ok(())
    }

    fn get_metrics(&self) -> Option<KernelMetrics> {
        Some(self.state.metrics.lock().unwrap().clone())
    }

    fn reset_metrics(&mut self) {
        let mut metrics = self.state.metrics.lock().unwrap();
        *metrics = KernelMetrics::new(KernelType::GpuEcdsa);
    }

    fn execute_hash(&self, _data: &[u8], _algorithm: Algorithm) -> Result<Vec<u8>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support hash operation".into(),
        ))
    }

    fn execute_hash_batch(&self, _data: &[Vec<u8>], _algorithm: Algorithm) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support hash operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_decrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }
}

impl CpuSignatureKernel {
    pub fn ecdsa_sign(&self, private_key: &[u8], data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
        use ecdsa::{SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let start = std::time::Instant::now();

        let signing_key = match algorithm {
            Algorithm::ECDSA256 => {
                if private_key.len() != 32 {
                    return Err(CryptoError::InvalidKeyLength(private_key.len()));
                }
                SigningKey::from_slice(private_key)
                    .map_err(|e| CryptoError::SigningFailed(e.to_string()))?
            }
            Algorithm::ECDSA384 => {
                if private_key.len() != 48 {
                    return Err(CryptoError::InvalidKeyLength(private_key.len()));
                }
                SigningKey::from_slice(private_key)
                    .map_err(|e| CryptoError::SigningFailed(e.to_string()))?
            }
            Algorithm::ECDSA521 => {
                if private_key.len() != 66 {
                    return Err(CryptoError::InvalidKeyLength(private_key.len()));
                }
                SigningKey::from_slice(private_key)
                    .map_err(|e| CryptoError::SigningFailed(e.to_string()))?
            }
            _ => {
                return Err(CryptoError::InvalidInput(
                    format!("Unsupported signature algorithm: {:?}", algorithm).into(),
                ));
            }
        };

        let signature = signing_key.sign(OsRng, data)
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps = (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + signature.as_ref().len();

        Ok(signature.as_ref().to_vec())
    }

    pub fn ecdsa_verify(&self, public_key: &[u8], data: &[u8], signature: &[u8], algorithm: Algorithm) -> Result<bool> {
        use ecdsa::{Signature, VerifyingKey};
        use zeroize::Zeroize;

        let start = std::time::Instant::now();

        let verifying_key = match algorithm {
            Algorithm::ECDSA256 => {
                if public_key.len() != 65 {
                    return Err(CryptoError::InvalidInput("Invalid public key length".into()));
                }
                VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?
            }
            Algorithm::ECDSA384 => {
                if public_key.len() != 97 {
                    return Err(CryptoError::InvalidInput("Invalid public key length".into()));
                }
                VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?
            }
            Algorithm::ECDSA521 => {
                if public_key.len() != 133 {
                    return Err(CryptoError::InvalidInput("Invalid public key length".into()));
                }
                VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?
            }
            _ => {
                return Err(CryptoError::InvalidInput(
                    format!("Unsupported signature algorithm: {:?}", algorithm).into(),
                ));
            }
        };

        let ecdsa_signature = Signature::from_slice(signature)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;

        let result = verifying_key.verify(data, &ecdsa_signature)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()));

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps = (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + signature.len();

        result
    }

    pub fn ecdsa_verify_batch(
        &self,
        public_keys: &[&[u8]],
        data: &[&[u8]],
        signatures: &[&[u8]],
        algorithm: Algorithm,
    ) -> Result<Vec<bool>> {
        if public_keys.len() != data.len() || public_keys.len() != signatures.len() {
            return Err(CryptoError::InvalidInput(
                "Batch sizes must match".into(),
            ));
        }

        let start = std::time::Instant::now();
        let mut results = Vec::with_capacity(public_keys.len());

        for i in 0..public_keys.len() {
            let result = self.ecdsa_verify(public_keys[i], data[i], signatures[i], algorithm)?;
            results.push(result);
        }

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.batch_size = public_keys.len();

        Ok(results)
    }
}

impl Default for CpuSignatureKernel {
    fn default() -> Self {
        Self::new()
    }
}

/// 创建适当的 Signature Kernel（GPU 可用时使用 GPU，否则使用 CPU）
pub fn create_signature_kernel() -> Box<dyn GpuKernel> {
    #[cfg(feature = "gpu-cuda")]
    {
        if CudaSignatureKernel::is_available() {
            return Box::new(CudaSignatureKernel::new());
        }
    }

    #[cfg(feature = "gpu-opencl")]
    {
        if OpenclSignatureKernel::is_available() {
            return Box::new(OpenclSignatureKernel::new());
        }
    }

    Box::new(CpuSignatureKernel::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_signature_kernel_available() {
        let kernel = CpuSignatureKernel::new();
        assert!(kernel.is_available());
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let kernel = CpuSignatureKernel::new();

        let private_key = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];

        let data = b"Test data for signing";

        let signature = kernel.ecdsa_sign(&private_key, data, Algorithm::ECDSA256);
        assert!(signature.is_ok());
        let signature = signature.unwrap();
        assert_eq!(signature.len(), 64);

        let public_key = [
            4u8,
            121, 190, 102, 62, 80, 82, 196, 93, 219, 89, 20, 20, 58, 111, 44, 222,
            160, 96, 116, 147, 72, 65, 189, 244, 98, 117, 80, 86, 183, 42, 170, 158,
            234, 195, 176, 244, 169, 25, 103, 73, 23, 188, 178, 105, 87, 251, 149, 210,
            67, 158, 200, 191, 238, 255, 137, 218, 66, 82, 239, 167, 235, 210,
        ];

        let result = kernel.ecdsa_verify(&public_key, data, &signature, Algorithm::ECDSA256);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_ecdsa_verify_invalid_signature() {
        let kernel = CpuSignatureKernel::new();

        let public_key = [
            4u8,
            121, 190, 102, 62, 80, 82, 196, 93, 219, 89, 20, 20, 58, 111, 44, 222,
            160, 96, 116, 147, 72, 65, 189, 244, 98, 117, 80, 86, 183, 42, 170, 158,
            234, 195, 176, 244, 169, 25, 103, 73, 23, 188, 178, 105, 87, 251, 149, 210,
            67, 158, 200, 191, 238, 255, 137, 218, 66, 82, 239, 167, 235, 210,
        ];

        let data = b"Test data";
        let invalid_signature = vec![0u8; 64];

        let result = kernel.ecdsa_verify(&public_key, data, &invalid_signature, Algorithm::ECDSA256);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_ecdsa_batch_verify() {
        let kernel = CpuSignatureKernel::new();

        let private_key = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];

        let mut public_keys = Vec::new();
        let mut data_items = Vec::new();
        let mut signatures = Vec::new();

        for i in 0..5 {
            let data = format!("Message {}", i).into_bytes();
            let signature = kernel.ecdsa_sign(&private_key, &data, Algorithm::ECDSA256).unwrap();

            public_keys.push(&[4u8, 121, 190, 102, 62, 80, 82, 196, 93, 219, 89, 20, 20, 58, 111, 44, 222, 160, 96, 116, 147, 72, 65, 189, 244, 98, 117, 80, 86, 183, 42, 170, 158, 234, 195, 176, 244, 169, 25, 103, 73, 23, 188, 178, 105, 87, 251, 149, 210, 67, 158, 200, 191, 238, 255, 137, 218, 66, 82, 239, 167, 235, 210]);
            data_items.push(data.as_slice());
            signatures.push(signature.as_slice());
        }

        let results = kernel.ecdsa_verify_batch(&public_keys, &data_items, &signatures, Algorithm::ECDSA256);
        assert!(results.is_ok());
        let results = results.unwrap();
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|b| *b));
    }

    #[test]
    fn test_ecdsa_invalid_key_length() {
        let kernel = CpuSignatureKernel::new();
        let short_key = [0u8; 16];
        let data = b"test";

        let result = kernel.ecdsa_sign(&short_key, data, Algorithm::ECDSA256);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_metrics() {
        let kernel = CpuSignatureKernel::new();
        let private_key = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let data = vec![0u8; 1024];

        let _ = kernel.ecdsa_sign(&private_key, &data, Algorithm::ECDSA256);

        let metrics = kernel.get_metrics();
        assert!(metrics.is_some());
        let metrics = metrics.unwrap();
        assert!(metrics.execution_time_us > 0);
    }
}
