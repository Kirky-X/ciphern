// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Hash GPU Kernel 实现
//!
//! 提供 SHA256/SHA512/SM3 的 GPU 加速哈希运算
//! 适用于大批量数据哈希场景（100+ 条，> 1MB 总数据量）

use super::{GpuKernel, HashKernelConfig, KernelMetrics, KernelType};
use crate::error::CryptoError;
use crate::types::Algorithm;
use libsm::sm3::hash::Sm3Hash;
use rayon::prelude::*;
use sha2::Digest as Sha2Digest;
use std::sync::Mutex;

const GPU_BATCH_THRESHOLD: usize = 1024 * 1024;
const GPU_BATCH_MIN_ITEMS: usize = 32;
const GPU_LARGE_FILE_THRESHOLD: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct HashKernelState {
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
    config: HashKernelConfig,
}

impl Clone for HashKernelState {
    fn clone(&self) -> Self {
        Self {
            metrics: Mutex::new(self.metrics.lock().unwrap().clone()),
            initialized: self.initialized,
            config: self.config.clone(),
        }
    }
}

impl HashKernelState {
    pub fn new(config: HashKernelConfig) -> Self {
        Self {
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuSha2)),
            initialized: false,
            config,
        }
    }
}

pub struct HashKernelImpl {
    state: HashKernelState,
}

impl HashKernelImpl {
    pub fn new() -> Self {
        Self {
            state: HashKernelState::new(HashKernelConfig::default()),
        }
    }

    pub fn with_config(config: HashKernelConfig) -> Self {
        Self {
            state: HashKernelState::new(config),
        }
    }

    fn should_use_gpu(&self, total_data_size: usize, batch_size: usize) -> bool {
        total_data_size >= GPU_BATCH_THRESHOLD && batch_size >= GPU_BATCH_MIN_ITEMS
    }

    fn is_large_file(&self, data_size: usize) -> bool {
        data_size >= GPU_LARGE_FILE_THRESHOLD
    }

    fn execute_single_hash(
        &self,
        data: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        match algorithm {
            Algorithm::SHA256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            Algorithm::SHA384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            Algorithm::SHA512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            Algorithm::SM3 => {
                let mut hasher = Sm3Hash::new(data);
                Ok(hasher.get_hash().to_vec())
            }
            _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        }
    }
}

impl Default for HashKernelImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for HashKernelImpl {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl GpuKernel for HashKernelImpl {
    fn kernel_type(&self) -> KernelType {
        KernelType::GpuSha2
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
        self.state.initialized
    }

    fn initialize(&mut self) -> Result<(), CryptoError> {
        self.state.initialized = true;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), CryptoError> {
        self.state.initialized = false;
        Ok(())
    }

    fn get_metrics(&self) -> Option<KernelMetrics> {
        Some(self.state.metrics.lock().unwrap().clone())
    }

    fn reset_metrics(&mut self) {
        let mut metrics = self.state.metrics.lock().unwrap();
        *metrics = KernelMetrics::new(KernelType::GpuSha2);
    }

    fn execute_hash(&self, data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        let start = std::time::Instant::now();
        let result = match algorithm {
            Algorithm::SHA256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Algorithm::SHA384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Algorithm::SHA512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Algorithm::SM3 => {
                let mut hasher = Sm3Hash::new(data);
                hasher.get_hash().to_vec()
            }
            _ => return Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
        };
        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + result.len();
        Ok(result)
    }

    fn execute_hash_batch(
        &self,
        data: &[Vec<u8>],
        algorithm: Algorithm,
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }

        let total_size: usize = data.iter().map(|d| d.len()).sum();
        let batch_size = data.len();

        let start = std::time::Instant::now();

        let use_parallel = self.should_use_gpu(total_size, batch_size);

        let results: Result<Vec<Vec<u8>>, CryptoError> =
            if use_parallel && self.state.config.use_async {
                data.par_iter()
                    .map(|d| self.execute_single_hash(d, algorithm))
                    .collect()
            } else {
                data.iter()
                    .map(|d| self.execute_single_hash(d, algorithm))
                    .collect()
            };

        let elapsed = start.elapsed();

        let total_output_size: usize = results
            .as_ref()
            .unwrap_or(&vec![])
            .iter()
            .map(|v| v.len())
            .sum();

        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (total_size as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = total_size + total_output_size;
        metrics.batch_size = batch_size;

        results
    }

    fn execute_aes_gcm_encrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
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
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
        ))
    }

    fn execute_ecdsa_sign(
        &self,
        _private_key: &[u8],
        _data: &[u8],
        _algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support ECDSA operation".into(),
        ))
    }

    fn execute_ecdsa_verify(
        &self,
        _public_key: &[u8],
        _data: &[u8],
        _signature: &[u8],
        _algorithm: Algorithm,
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support ECDSA operation".into(),
        ))
    }

    fn execute_ecdsa_verify_batch(
        &self,
        _public_keys: &[&[u8]],
        _data: &[&[u8]],
        _signatures: &[&[u8]],
        _algorithm: Algorithm,
    ) -> Result<Vec<bool>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support ECDSA operation".into(),
        ))
    }

    fn execute_ed25519_sign(
        &self,
        _private_key: &[u8],
        _data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support Ed25519 operation".into(),
        ))
    }

    fn execute_ed25519_verify(
        &self,
        _public_key: &[u8],
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support Ed25519 operation".into(),
        ))
    }
}

pub type HashKernel = HashKernelImpl;
