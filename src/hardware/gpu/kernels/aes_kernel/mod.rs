// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! AES GPU Kernel 实现

use super::{AesKernelConfig, GpuKernel, KernelMetrics, KernelType};
use crate::error::CryptoError;
use crate::types::Algorithm;
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use std::sync::Mutex;

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
        vec![Algorithm::AES256GCM, Algorithm::AES128GCM]
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
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        if key.len() != 32 && key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput("Invalid nonce length".into()));
        }
        let aead = aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        let tag = aead
            .encrypt(nonce.into(), data)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        Ok(tag)
    }

    fn execute_aes_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        if key.len() != 32 && key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput("Invalid nonce length".into()));
        }
        let aead = aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        let plaintext = aead
            .decrypt(nonce.into(), data)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        Ok(plaintext)
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        let mut results = Vec::with_capacity(data.len());
        for (&key, (&nonce, &d)) in keys.iter().zip(nonces.iter().zip(data.iter())) {
            results.push(self.execute_aes_gcm_encrypt(key, nonce, d, None)?);
        }
        Ok(results)
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        let mut results = Vec::with_capacity(data.len());
        for (&key, (&nonce, &d)) in keys.iter().zip(nonces.iter().zip(data.iter())) {
            results.push(self.execute_aes_gcm_decrypt(key, nonce, d, None)?);
        }
        Ok(results)
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
