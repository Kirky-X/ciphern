// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SM4 GPU Kernel 实现
//!
//! 提供 SM4-GCM 的 GPU 加速批量加密/解密
//! 适用于大批量数据加密场景（32+ 条）

use super::{BatchConfig, GpuKernel, KernelMetrics, KernelType};
use crate::error::CryptoError;
use crate::types::Algorithm;
use rayon::prelude::*;
use std::sync::Mutex;

const GPU_BATCH_THRESHOLD: usize = 1024 * 1024;
const GPU_BATCH_MIN_ITEMS: usize = 32;

#[derive(Debug)]
pub struct Sm4KernelState {
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
    config: BatchConfig,
}

impl Sm4KernelState {
    pub fn new() -> Self {
        Self {
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuSm4)),
            initialized: false,
            config: BatchConfig::default(),
        }
    }
}

impl Default for Sm4KernelState {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Sm4KernelState {
    fn clone(&self) -> Self {
        Self {
            metrics: Mutex::new(self.metrics.lock().unwrap().clone()),
            initialized: self.initialized,
            config: self.config.clone(),
        }
    }
}

pub struct Sm4KernelImpl {
    state: Sm4KernelState,
}

impl Sm4KernelImpl {
    pub fn new() -> Self {
        Self {
            state: Sm4KernelState::new(),
        }
    }

    pub fn with_config(config: BatchConfig) -> Self {
        Self {
            state: Sm4KernelState {
                metrics: Mutex::new(KernelMetrics::new(KernelType::GpuSm4)),
                initialized: false,
                config,
            },
        }
    }

    fn should_use_gpu(&self, total_data_size: usize, batch_size: usize) -> bool {
        total_data_size >= GPU_BATCH_THRESHOLD && batch_size >= GPU_BATCH_MIN_ITEMS
    }

    fn execute_single_sm4_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }

        use sm4::cipher::{KeyIvInit, StreamCipher};

        let key_bytes: [u8; 16] = key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;

        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[15] = 2;

        type Sm4Ctr = ctr::Ctr128BE<sm4::Sm4>;
        let mut cipher = Sm4Ctr::new(&key_bytes.into(), &iv.into());

        let mut output = data.to_vec();
        cipher.apply_keystream(&mut output);

        Ok(output)
    }

    fn execute_single_sm4_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }

        use sm4::cipher::{KeyIvInit, StreamCipher};

        let key_bytes: [u8; 16] = key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;

        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[15] = 2;

        type Sm4Ctr = ctr::Ctr128BE<sm4::Sm4>;
        let mut cipher = Sm4Ctr::new(&key_bytes.into(), &iv.into());

        let mut output = data.to_vec();
        cipher.apply_keystream(&mut output);

        Ok(output)
    }
}

impl Default for Sm4KernelImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Sm4KernelImpl {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl GpuKernel for Sm4KernelImpl {
    fn kernel_type(&self) -> KernelType {
        KernelType::GpuSm4
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![Algorithm::SM4GCM]
    }

    fn is_available(&self) -> bool {
        false
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
        *metrics = KernelMetrics::new(KernelType::GpuSm4);
    }

    fn execute_hash(&self, _data: &[u8], _algorithm: Algorithm) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support hash operation".into(),
        ))
    }

    fn execute_hash_batch(
        &self,
        _data: &[Vec<u8>],
        _algorithm: Algorithm,
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support hash operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support AES-GCM operation".into(),
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
            "SM4 kernel does not support AES-GCM operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support AES-GCM operation".into(),
        ))
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support AES-GCM operation".into(),
        ))
    }

    fn execute_ecdsa_sign(
        &self,
        _private_key: &[u8],
        _data: &[u8],
        _algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support ECDSA operation".into(),
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
            "SM4 kernel does not support ECDSA operation".into(),
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
            "SM4 kernel does not support ECDSA operation".into(),
        ))
    }

    fn execute_ed25519_sign(
        &self,
        _private_key: &[u8],
        _data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support Ed25519 operation".into(),
        ))
    }

    fn execute_ed25519_verify(
        &self,
        _public_key: &[u8],
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support Ed25519 operation".into(),
        ))
    }
}

impl Sm4KernelImpl {
    pub fn sm4_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let start = std::time::Instant::now();

        let result = self.execute_single_sm4_gcm_encrypt(key, nonce, data)?;

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + result.len();

        Ok(result)
    }

    pub fn sm4_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let start = std::time::Instant::now();

        let result = self.execute_single_sm4_gcm_decrypt(key, nonce, data)?;

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + result.len();

        Ok(result)
    }

    pub fn sm4_gcm_encrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        if keys.len() != nonces.len() || keys.len() != data.len() {
            return Err(CryptoError::InvalidInput(
                "Keys, nonces, and data arrays must have the same length".into(),
            ));
        }

        let total_size: usize = data.iter().map(|d| d.len()).sum();
        let batch_size = data.len();

        let start = std::time::Instant::now();

        let use_parallel = self.should_use_gpu(total_size, batch_size);

        let encrypt_single = |item: (&&[u8], &&[u8], &&[u8])| -> Result<Vec<u8>, CryptoError> {
            let (&k, &n, &d) = item;
            {
                if k.len() != 16 {
                    return Err(CryptoError::InvalidKeyLength(k.len()));
                }

                use sm4::cipher::{KeyIvInit, StreamCipher};

                let key_bytes: [u8; 16] = k
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyLength(k.len()))?;

                let mut iv = [0u8; 16];
                iv[..12].copy_from_slice(n);
                iv[15] = 2;

                type Sm4Ctr = ctr::Ctr128BE<sm4::Sm4>;
                let mut cipher = Sm4Ctr::new(&key_bytes.into(), &iv.into());

                let mut output = d.to_vec();
                cipher.apply_keystream(&mut output);

                Ok(output)
            }
        };

        let results: Result<Vec<Vec<u8>>, CryptoError> =
            if use_parallel && self.state.config.use_async {
                data.par_iter()
                    .zip(nonces.par_iter())
                    .zip(keys.par_iter())
                    .map(|((&d, &n), &k)| encrypt_single((&d, &n, &k)))
                    .collect()
            } else {
                data.iter()
                    .zip(nonces.iter())
                    .zip(keys.iter())
                    .map(|((&d, &n), &k)| encrypt_single((&d, &n, &k)))
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

    pub fn sm4_gcm_decrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        if keys.len() != nonces.len() || keys.len() != data.len() {
            return Err(CryptoError::InvalidInput(
                "Keys, nonces, and data arrays must have the same length".into(),
            ));
        }

        let total_size: usize = data.iter().map(|d| d.len()).sum();
        let batch_size = data.len();

        let start = std::time::Instant::now();

        let use_parallel = self.should_use_gpu(total_size, batch_size);

        let decrypt_single = |item: (&&[u8], &&[u8], &&[u8])| -> Result<Vec<u8>, CryptoError> {
            let (&k, &n, &d) = item;
            {
                if k.len() != 16 {
                    return Err(CryptoError::InvalidKeyLength(k.len()));
                }

                use sm4::cipher::{KeyIvInit, StreamCipher};

                let key_bytes: [u8; 16] = k
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyLength(k.len()))?;

                let mut iv = [0u8; 16];
                iv[..12].copy_from_slice(n);
                iv[15] = 2;

                type Sm4Ctr = ctr::Ctr128BE<sm4::Sm4>;
                let mut cipher = Sm4Ctr::new(&key_bytes.into(), &iv.into());

                let mut output = d.to_vec();
                cipher.apply_keystream(&mut output);

                Ok(output)
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
}

pub type Sm4Kernel = Sm4KernelImpl;
