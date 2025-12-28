// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! AES GPU Kernel 实现
//!
//! 提供 AES-GCM 的 GPU 加速批量加密/解密
//! 适用于大批量数据加密场景（100+ 条，> 1MB 总数据量）

use super::{AesKernelConfig, GpuKernel, KernelMetrics, KernelType};
use crate::error::CryptoError;
use crate::types::Algorithm;
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use rayon::prelude::*;
use std::sync::Mutex;

const GPU_BATCH_THRESHOLD: usize = 1024 * 1024;
const GPU_BATCH_MIN_ITEMS: usize = 16;

#[derive(Debug)]
pub struct AesKernelState {
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
    config: AesKernelConfig,
}

impl Clone for AesKernelState {
    fn clone(&self) -> Self {
        Self {
            metrics: Mutex::new(self.metrics.lock().unwrap().clone()),
            initialized: self.initialized,
            config: self.config.clone(),
        }
    }
}

impl AesKernelState {
    pub fn new(config: AesKernelConfig) -> Self {
        Self {
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuAes)),
            initialized: false,
            config,
        }
    }
}

pub struct AesKernelImpl {
    state: AesKernelState,
}

impl AesKernelImpl {
    pub fn new() -> Self {
        Self {
            state: AesKernelState::new(AesKernelConfig::default()),
        }
    }

    pub fn with_config(config: AesKernelConfig) -> Self {
        Self {
            state: AesKernelState::new(config),
        }
    }

    fn should_use_gpu(&self, total_data_size: usize, batch_size: usize) -> bool {
        total_data_size >= GPU_BATCH_THRESHOLD && batch_size >= GPU_BATCH_MIN_ITEMS
    }

    fn execute_single_aes_gcm(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key_len = key.len();
        match key_len {
            16 => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                cipher
                    .encrypt(nonce.into(), data)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
            }
            32 => {
                let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                cipher
                    .encrypt(nonce.into(), data)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
            }
            _ => Err(CryptoError::InvalidKeyLength(key_len)),
        }
    }
}

impl Default for AesKernelImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AesKernelImpl {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl GpuKernel for AesKernelImpl {
    fn kernel_type(&self) -> KernelType {
        KernelType::GpuAes
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![
            Algorithm::AES256GCM,
            Algorithm::AES128GCM,
            Algorithm::AES192GCM,
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
        *metrics = KernelMetrics::new(KernelType::GpuAes);
    }

    fn execute_hash(&self, _data: &[u8], _algorithm: Algorithm) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "AES kernel does not support hash operation".into(),
        ))
    }

    fn execute_hash_batch(
        &self,
        _data: &[Vec<u8>],
        _algorithm: Algorithm,
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
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
    ) -> Result<Vec<u8>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        let start = std::time::Instant::now();
        let result = self.execute_single_aes_gcm(key, nonce, data)?;
        let elapsed = start.elapsed();

        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + result.len();
        metrics.batch_size = 1;
        Ok(result)
    }

    fn execute_aes_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        let key_len = key.len();
        match key_len {
            16 => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                cipher
                    .decrypt(nonce.into(), data)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
            }
            32 => {
                let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                cipher
                    .decrypt(nonce.into(), data)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
            }
            _ => Err(CryptoError::InvalidKeyLength(key_len)),
        }
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
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
                    .zip(nonces.par_iter())
                    .zip(keys.par_iter())
                    .map(|((&d, &n), &k)| self.execute_single_aes_gcm(k, n, d))
                    .collect()
            } else {
                data.iter()
                    .zip(nonces.iter())
                    .zip(keys.iter())
                    .map(|((&d, &n), &k)| self.execute_single_aes_gcm(k, n, d))
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

    fn execute_aes_gcm_decrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }

        let total_size: usize = data.iter().map(|d| d.len()).sum();
        let batch_size = data.len();

        let start = std::time::Instant::now();

        let use_parallel = self.should_use_gpu(total_size, batch_size);

        let decrypt_single = |item: (&&[u8], &&[u8], &&[u8])| -> Result<Vec<u8>, CryptoError> {
            let (&k, &d, &n) = item;
            {
                let key_len = k.len();
                match key_len {
                    16 => {
                        let cipher = aes_gcm::Aes128Gcm::new_from_slice(k)
                            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                        cipher
                            .decrypt(n.into(), d)
                            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
                    }
                    32 => {
                        let cipher = aes_gcm::Aes256Gcm::new_from_slice(k)
                            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                        cipher
                            .decrypt(n.into(), d)
                            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
                    }
                    _ => Err(CryptoError::InvalidKeyLength(key_len)),
                }
            }
        };

        let results: Result<Vec<Vec<u8>>, CryptoError> =
            if use_parallel && self.state.config.use_async {
                data.par_iter()
                    .zip(nonces.par_iter())
                    .zip(keys.par_iter())
                    .map(|((&d, &n), &k)| decrypt_single((&d, &n, &k)))
                    .collect()
            } else {
                data.iter()
                    .zip(nonces.iter())
                    .zip(keys.iter())
                    .map(|((&d, &n), &k)| decrypt_single((&d, &n, &k)))
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

    fn execute_ecdsa_sign(
        &self,
        _private_key: &[u8],
        _data: &[u8],
        _algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "AES kernel does not support ECDSA operation".into(),
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
            "AES kernel does not support ECDSA operation".into(),
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
            "AES kernel does not support ECDSA operation".into(),
        ))
    }

    fn execute_ed25519_sign(
        &self,
        _private_key: &[u8],
        _data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "AES kernel does not support Ed25519 operation".into(),
        ))
    }

    fn execute_ed25519_verify(
        &self,
        _public_key: &[u8],
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::InvalidInput(
            "AES kernel does not support Ed25519 operation".into(),
        ))
    }
}

pub type AesKernel = AesKernelImpl;
