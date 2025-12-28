// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SM4 GPU Kernel 实现

use super::{GpuKernel, KernelMetrics, KernelType};
use crate::error::CryptoError;
use crate::types::Algorithm;
use std::sync::Mutex;

#[derive(Debug)]
pub struct Sm4KernelState {
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
}

impl Sm4KernelState {
    pub fn new() -> Self {
        Self {
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuSm4)),
            initialized: false,
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
}

impl Default for Sm4KernelImpl {
    fn default() -> Self {
        Self::new()
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

pub type Sm4Kernel = Sm4KernelImpl;
