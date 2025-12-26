// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! AES GPU Kernel 实现
//!
//! 支持 AES-GCM 模式的 GPU 加速加密/解密
//! 基于 CUDA 或 OpenCL 实现

use super::{AesKernelConfig, BatchConfig, GpuKernel, KernelMetrics, KernelType};
use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use std::sync::Mutex;

#[cfg(feature = "gpu-cuda")]
mod cuda_aes;
#[cfg(feature = "gpu-opencl")]
mod opencl_aes;

#[cfg(feature = "gpu-cuda")]
pub use cuda_aes::CudaAesKernel;
#[cfg(feature = "gpu-opencl")]
pub use opencl_aes::OpenclAesKernel;

/// AES 操作模式
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AesMode {
    Gcm,
    Ctr,
    Cbc,
    Ecb,
}

impl std::fmt::Display for AesMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AesMode::Gcm => write!(f, "GCM"),
            AesMode::Ctr => write!(f, "CTR"),
            AesMode::Cbc => write!(f, "CBC"),
            AesMode::Ecb => write!(f, "ECB"),
        }
    }
}

/// AES Kernel 内部状态
#[derive(Debug)]
pub struct AesKernelState {
    config: AesKernelConfig,
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
    key_size: usize,
    mode: AesMode,
}

impl AesKernelState {
    pub fn new(config: AesKernelConfig, mode: AesMode) -> Self {
        Self {
            config,
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuAes)),
            initialized: false,
            key_size: 32, // Default to AES-256
            mode,
        }
    }
}

/// CPU 回退实现（当 GPU 不可用时）
pub struct CpuAesKernel {
    state: AesKernelState,
}

impl CpuAesKernel {
    pub fn new() -> Self {
        Self {
            state: AesKernelState::new(AesKernelConfig::default(), AesMode::Gcm),
        }
    }
}

impl GpuKernel for CpuAesKernel {
    fn kernel_type(&self) -> KernelType {
        KernelType::CpuAesNi
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![
            Algorithm::AES128GCM,
            Algorithm::AES192GCM,
            Algorithm::AES256GCM,
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
        *metrics = KernelMetrics::new(KernelType::CpuAesNi);
    }

    fn execute_hash(&self, _data: &[u8], _algorithm: Algorithm) -> Result<Vec<u8>> {
        Err(CryptoError::InvalidInput(
            "AES kernel does not support hash operation".into(),
        ))
    }

    fn execute_hash_batch(&self, _data: &[Vec<u8>], _algorithm: Algorithm) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "AES kernel does not support hash operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput(
                "Nonce must be 12 bytes for GCM".into(),
            ));
        }

        let start = std::time::Instant::now();

        let key = Key::from_slice(key);
        let nonce = Nonce::from_slice(nonce);
        let cipher = Aes256Gcm::new(key);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + ciphertext.len();

        Ok(ciphertext)
    }

    fn execute_aes_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput(
                "Nonce must be 12 bytes for GCM".into(),
            ));
        }

        let start = std::time::Instant::now();

        let key = Key::from_slice(key);
        let nonce = Nonce::from_slice(nonce);
        let cipher = Aes256Gcm::new(key);

        let plaintext = cipher
            .decrypt(nonce, data)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + plaintext.len();

        Ok(plaintext)
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        if keys.len() != nonces.len() || keys.len() != data.len() {
            return Err(CryptoError::InvalidInput("Batch sizes must match".into()));
        }

        let start = std::time::Instant::now();
        let mut results = Vec::with_capacity(keys.len());

        for i in 0..keys.len() {
            let ciphertext = self.execute_aes_gcm_encrypt(keys[i], nonces[i], data[i], None)?;
            results.push(ciphertext);
        }

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.batch_size = keys.len();

        Ok(results)
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        if keys.len() != nonces.len() || keys.len() != data.len() {
            return Err(CryptoError::InvalidInput("Batch sizes must match".into()));
        }

        let start = std::time::Instant::now();
        let mut results = Vec::with_capacity(keys.len());

        for i in 0..keys.len() {
            let plaintext = self.execute_aes_gcm_decrypt(keys[i], nonces[i], data[i], None)?;
            results.push(plaintext);
        }

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.batch_size = keys.len();

        Ok(results)
    }
}

impl Default for CpuAesKernel {
    fn default() -> Self {
        Self::new()
    }
}

/// 创建适当的 AES Kernel（GPU 可用时使用 GPU，否则使用 CPU）
pub fn create_aes_kernel() -> Box<dyn GpuKernel> {
    #[cfg(feature = "gpu-cuda")]
    {
        if CudaAesKernel::is_available() {
            return Box::new(CudaAesKernel::new());
        }
    }

    #[cfg(feature = "gpu-opencl")]
    {
        if OpenclAesKernel::is_available() {
            return Box::new(OpenclAesKernel::new());
        }
    }

    Box::new(CpuAesKernel::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;

    #[test]
    fn test_cpu_aes_kernel_available() {
        let kernel = CpuAesKernel::new();
        assert!(kernel.is_available());
    }

    #[test]
    fn test_cpu_aes_gcm_encrypt_decrypt() {
        let kernel = CpuAesKernel::new();
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World! This is a test message.";

        let ciphertext = kernel.execute_aes_gcm_encrypt(&key, &nonce, plaintext, None);
        assert!(ciphertext.is_ok());

        let decrypted = kernel.execute_aes_gcm_decrypt(&key, &nonce, &ciphertext.unwrap(), None);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_cpu_aes_gcm_batch() {
        let kernel = CpuAesKernel::new();
        let key = [0u8; 32];
        let nonce_base = [0u8; 12];

        let mut keys = Vec::new();
        let mut nonces = Vec::new();
        let mut plaintexts = Vec::new();
        let mut expected = Vec::new();

        for i in 0..5 {
            let mut key_copy = key;
            key_copy[0] = i as u8;
            keys.push(key_copy.as_slice());

            let mut nonce_copy = nonce_base;
            nonce_copy[11] = i as u8;
            nonces.push(nonce_copy.as_slice());

            let plaintext = format!("Message {}", i).into_bytes();
            plaintexts.push(plaintext.as_slice());
            expected.push(plaintext);
        }

        let ciphertexts = kernel.execute_aes_gcm_encrypt_batch(&keys, &nonces, &plaintexts);
        assert!(ciphertexts.is_ok());
        assert_eq!(ciphertexts.unwrap().len(), 5);

        let decrypted = kernel.execute_aes_gcm_decrypt_batch(&keys, &nonces, &ciphertexts.unwrap());
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), expected);
    }

    #[test]
    fn test_cpu_aes_invalid_key_length() {
        let kernel = CpuAesKernel::new();
        let key = [0u8; 16]; // Invalid key length
        let nonce = [0u8; 12];
        let plaintext = b"test";

        let result = kernel.execute_aes_gcm_encrypt(&key, &nonce, plaintext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_cpu_aes_invalid_nonce_length() {
        let kernel = CpuAesKernel::new();
        let key = [0u8; 32];
        let nonce = [0u8; 8]; // Invalid nonce length
        let plaintext = b"test";

        let result = kernel.execute_aes_gcm_encrypt(&key, &nonce, plaintext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_cpu_aes_metrics() {
        let kernel = CpuAesKernel::new();
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = vec![0u8; 1024 * 1024]; // 1MB

        let _ = kernel.execute_aes_gcm_encrypt(&key, &nonce, &plaintext, None);

        let metrics = kernel.get_metrics();
        assert!(metrics.is_some());
        let metrics = metrics.unwrap();
        assert!(metrics.execution_time_us > 0);
        assert!(metrics.throughput_mbps > 0.0);
    }
}
