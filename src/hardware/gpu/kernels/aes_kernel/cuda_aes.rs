// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! CUDA AES Kernel 实现
//!
//! 基于 CUDA 的 AES-GCM 加速实现

use super::{AesKernelState, AesMode};
use crate::error::{CryptoError, Result};

pub struct CudaAesKernel {
    state: AesKernelState,
}

impl CudaAesKernel {
    pub fn new() -> Self {
        Self {
            state: AesKernelState::new(Default::default(), AesMode::Gcm),
        }
    }

    pub fn is_available() -> bool {
        false
    }
}

impl super::super::GpuKernel for CudaAesKernel {
    fn kernel_type(&self) -> super::super::KernelType {
        super::super::KernelType::GpuAes
    }

    fn supported_algorithms(&self) -> Vec<crate::types::Algorithm> {
        vec![
            crate::types::Algorithm::AES128GCM,
            crate::types::Algorithm::AES192GCM,
            crate::types::Algorithm::AES256GCM,
        ]
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

    fn get_metrics(&self) -> Option<super::super::KernelMetrics> {
        Some(self.state.metrics.lock().unwrap().clone())
    }

    fn reset_metrics(&mut self) {
        let mut metrics = self.state.metrics.lock().unwrap();
        *metrics = super::super::KernelMetrics::new(super::super::KernelType::GpuAes);
    }

    fn execute_hash(&self, _data: &[u8], _algorithm: crate::types::Algorithm) -> Result<Vec<u8>> {
        Err(CryptoError::InvalidInput(
            "AES kernel does not support hash operation".into(),
        ))
    }

    fn execute_hash_batch(
        &self,
        _data: &[Vec<u8>],
        _algorithm: crate::types::Algorithm,
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "AES kernel does not support hash operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "CUDA AES kernel not available".into(),
        ))
    }

    fn execute_aes_gcm_decrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "CUDA AES kernel not available".into(),
        ))
    }
}

impl Default for CudaAesKernel {
    fn default() -> Self {
        Self::new()
    }
}
