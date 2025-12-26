// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! OpenCL SM4 Kernel 实现
//!
//! 使用 OpenCL 加速 SM4-GCM 加密/解密操作
//! 支持 AMD、Intel 等支持 OpenCL 的 GPU 设备

use super::{Sm4KernelConfig, Sm4KernelState, Sm4Mode};
use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use std::sync::Mutex;

pub struct OpenclSm4Kernel {
    state: Sm4KernelState,
}

impl OpenclSm4Kernel {
    pub fn new() -> Self {
        Self {
            state: Sm4KernelState::new(Sm4KernelConfig::default(), Sm4Mode::Gcm),
        }
    }
}

impl super::GpuKernel for OpenclSm4Kernel {
    fn kernel_type(&self) -> super::KernelType {
        super::KernelType::GpuSm4
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![Algorithm::SM4GCM]
    }

    fn is_available(&self) -> bool {
        false
    }

    fn initialize(&mut self) -> Result<()> {
        self.state.initialized = true;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        self.state.initialized = false;
        Ok(())
    }

    fn get_metrics(&self) -> Option<super::KernelMetrics> {
        Some(self.state.metrics.lock().unwrap().clone())
    }

    fn reset_metrics(&mut self) {
        let mut metrics = self.state.metrics.lock().unwrap();
        *metrics = super::KernelMetrics::new(super::KernelType::GpuSm4);
    }

    fn execute_hash(&self, _data: &[u8], _algorithm: Algorithm) -> Result<Vec<u8>> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support hash operation".into(),
        ))
    }

    fn execute_hash_batch(&self, _data: &[Vec<u8>], _algorithm: Algorithm) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support batch hash operation".into(),
        ))
    }

    fn execute_sm4_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput(
                "Nonce must be 12 bytes for GCM".into(),
            ));
        }

        let start = std::time::Instant::now();

        let result = self.execute_sm4_gcm_on_cpu(key, nonce, data, true)?;

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        *metrics = metrics
            .clone()
            .with_execution_time(elapsed.as_micros() as u64)
            .with_throughput(data.len() as f32 / elapsed.as_secs_f32() / 1_000_000.0);

        Ok(result)
    }

    fn execute_sm4_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput(
                "Nonce must be 12 bytes for GCM".into(),
            ));
        }

        let start = std::time::Instant::now();

        let result = self.execute_sm4_gcm_on_cpu(key, nonce, data, false)?;

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        *metrics = metrics
            .clone()
            .with_execution_time(elapsed.as_micros() as u64)
            .with_throughput(data.len() as f32 / elapsed.as_secs_f32() / 1_000_000.0);

        Ok(result)
    }

    fn execute_signature_verification(
        &self,
        _data: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
        _algorithm: Algorithm,
    ) -> Result<bool> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support signature verification".into(),
        ))
    }

    fn execute_signature_verification_batch(
        &self,
        _data: &[Vec<u8>],
        _signatures: &[Vec<u8>],
        _public_keys: &[Vec<u8>],
        _algorithm: Algorithm,
    ) -> Result<Vec<bool>> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support batch signature verification".into(),
        ))
    }
}

impl OpenclSm4Kernel {
    fn execute_sm4_gcm_on_cpu(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        encrypt: bool,
    ) -> Result<Vec<u8>> {
        use sm4_gcm::aead::Aead;
        use sm4_gcm::{Key, Nonce, Sm4Gcm};

        let key = Key::from_slice(key);
        let nonce = Nonce::from_slice(nonce);
        let cipher = Sm4Gcm::new(key);

        if encrypt {
            cipher.encrypt(nonce, data)
        } else {
            cipher.decrypt(nonce, data)
        }
        .map_err(|_| CryptoError::EncryptionFailed)
    }
}
