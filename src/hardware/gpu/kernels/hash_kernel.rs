// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SHA GPU Kernel 实现
//!
//! 支持 SHA256、SHA512、SM3 等哈希算法的 GPU 加速

use super::{BatchConfig, KernelMetrics, HashKernelConfig, GpuKernel, KernelType};
use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use std::sync::Mutex;

#[cfg(feature = "gpu-cuda")]
mod cuda_hash;
#[cfg(feature = "gpu-opencl")]
mod opencl_hash;

#[cfg(feature = "gpu-cuda")]
pub use cuda_hash::CudaHashKernel;
#[cfg(feature = "gpu-opencl")]
pub use opencl_hash::OpenclHashKernel;

/// SHA Kernel 内部状态
#[derive(Debug)]
pub struct HashKernelState {
    config: HashKernelConfig,
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
}

impl HashKernelState {
    pub fn new(config: HashKernelConfig) -> Self {
        Self {
            config,
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuSha2)),
            initialized: false,
        }
    }
}

/// CPU 回退实现（当 GPU 不可用时）
pub struct CpuHashKernel {
    state: HashKernelState,
}

impl CpuHashKernel {
    pub fn new() -> Self {
        Self {
            state: HashKernelState::new(HashKernelConfig::default()),
        }
    }
}

impl GpuKernel for CpuHashKernel {
    fn kernel_type(&self) -> KernelType {
        KernelType::CpuAesNi
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![
            Algorithm::SHA256,
            Algorithm::SHA384,
            Algorithm::SHA512,
            Algorithm::SM3,
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

    fn execute_hash(&self, data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
        use sha2::{Sha256, Sha512};
        use sm3::Sm3;

        let start = std::time::Instant::now();

        let result = match algorithm {
            Algorithm::SHA256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Algorithm::SHA384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Algorithm::SHA512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Algorithm::SM3 => {
                let mut hasher = Sm3::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            _ => {
                return Err(CryptoError::InvalidInput(
                    format!("Unsupported hash algorithm: {:?}", algorithm).into(),
                ));
            }
        };

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps = (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + result.len();

        Ok(result)
    }

    fn execute_hash_batch(&self, data: &[Vec<u8>], algorithm: Algorithm) -> Result<Vec<Vec<u8>>> {
        let start = std::time::Instant::now();
        let mut results = Vec::with_capacity(data.len());

        for chunk in data {
            let hash = self.execute_hash(chunk, algorithm)?;
            results.push(hash);
        }

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.batch_size = data.len();

        Ok(results)
    }

    fn execute_aes_gcm_encrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
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
            "Hash kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
        ))
    }
}

impl Default for CpuHashKernel {
    fn default() -> Self {
        Self::new()
    }
}

/// 创建适当的 Hash Kernel（GPU 可用时使用 GPU，否则使用 CPU）
pub fn create_hash_kernel() -> Box<dyn GpuKernel> {
    #[cfg(feature = "gpu-cuda")]
    {
        if CudaHashKernel::is_available() {
            return Box::new(CudaHashKernel::new());
        }
    }

    #[cfg(feature = "gpu-opencl")]
    {
        if OpenclHashKernel::is_available() {
            return Box::new(OpenclHashKernel::new());
        }
    }

    Box::new(CpuHashKernel::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_hash_kernel_available() {
        let kernel = CpuHashKernel::new();
        assert!(kernel.is_available());
    }

    #[test]
    fn test_cpu_sha256() {
        let kernel = CpuHashKernel::new();
        let data = b"Hello, World!";

        let result = kernel.execute_hash(data, Algorithm::SHA256);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_cpu_sha512() {
        let kernel = CpuHashKernel::new();
        let data = b"Hello, World!";

        let result = kernel.execute_hash(data, Algorithm::SHA512);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_cpu_sm3() {
        let kernel = CpuHashKernel::new();
        let data = b"Hello, World!";

        let result = kernel.execute_hash(data, Algorithm::SM3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_cpu_hash_batch() {
        let kernel = CpuHashKernel::new();
        let data: Vec<Vec<u8>> = vec![
            b"Message 1".to_vec(),
            b"Message 2".to_vec(),
            b"Message 3".to_vec(),
        ];

        let results = kernel.execute_hash_batch(&data, Algorithm::SHA256);
        assert!(results.is_ok());
        let results = results.unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].len(), 32);
        assert_eq!(results[1].len(), 32);
        assert_eq!(results[2].len(), 32);
    }

    #[test]
    fn test_cpu_hash_unsupported_algorithm() {
        let kernel = CpuHashKernel::new();
        let data = b"test";

        let result = kernel.execute_hash(data, Algorithm::Unknown);
        assert!(result.is_err());
    }

    #[test]
    fn test_cpu_hash_metrics() {
        let kernel = CpuHashKernel::new();
        let data = vec![0u8; 1024 * 1024]; // 1MB

        let _ = kernel.execute_hash(&data, Algorithm::SHA256);

        let metrics = kernel.get_metrics();
        assert!(metrics.is_some());
        let metrics = metrics.unwrap();
        assert!(metrics.execution_time_us > 0);
        assert!(metrics.throughput_mbps > 0.0);
    }

    #[test]
    fn test_hash_determinism() {
        let kernel = CpuHashKernel::new();
        let data = b"Test data for determinism";

        let result1 = kernel.execute_hash(data, Algorithm::SHA256).unwrap();
        let result2 = kernel.execute_hash(data, Algorithm::SHA256).unwrap();
        assert_eq!(result1, result2);
    }
}
