// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Signature GPU Kernel 实现
//!
//! 提供 ECDSA/Ed25519 的 GPU 加速批量签名验证
//! 适用于大批量签名验证场景（32+ 条）

use super::{BatchConfig, GpuKernel, KernelMetrics, KernelType};
use crate::error::CryptoError;
use crate::types::Algorithm;
use ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use ed25519_dalek::{
    Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
};
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey};
use p521::ecdsa::{SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey};
use rayon::prelude::*;
use std::sync::Mutex;

const GPU_BATCH_THRESHOLD: usize = 1024 * 1024;
const GPU_BATCH_MIN_ITEMS: usize = 32;

#[derive(Debug)]
pub struct SignatureKernelState {
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
    config: BatchConfig,
}

impl Clone for SignatureKernelState {
    fn clone(&self) -> Self {
        Self {
            metrics: Mutex::new(self.metrics.lock().unwrap().clone()),
            initialized: self.initialized,
            config: self.config.clone(),
        }
    }
}

impl SignatureKernelState {
    pub fn new() -> Self {
        Self {
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuEcdsa)),
            initialized: false,
            config: BatchConfig::default(),
        }
    }
}

impl Default for SignatureKernelState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SignatureKernelImpl {
    state: SignatureKernelState,
}

impl SignatureKernelImpl {
    pub fn new() -> Self {
        Self {
            state: SignatureKernelState::new(),
        }
    }

    pub fn with_config(config: BatchConfig) -> Self {
        Self {
            state: SignatureKernelState {
                metrics: Mutex::new(KernelMetrics::new(KernelType::GpuEcdsa)),
                initialized: false,
                config,
            },
        }
    }

    fn should_use_gpu(&self, total_data_size: usize, batch_size: usize) -> bool {
        total_data_size >= GPU_BATCH_THRESHOLD && batch_size >= GPU_BATCH_MIN_ITEMS
    }

    fn execute_single_ecdsa_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool, CryptoError> {
        match algorithm {
            Algorithm::ECDSAP256 => {
                if public_key.len() != 65 {
                    return Err(CryptoError::InvalidInput(
                        "Invalid public key length".into(),
                    ));
                }
                let verifying_key: P256VerifyingKey = P256VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
                let ecdsa_signature = EcdsaSignature::<p256::NistP256>::from_slice(signature)
                    .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
                Ok(verifying_key.verify(data, &ecdsa_signature).is_ok())
            }
            Algorithm::ECDSAP384 => {
                if public_key.len() != 97 {
                    return Err(CryptoError::InvalidInput(
                        "Invalid public key length".into(),
                    ));
                }
                let verifying_key: P384VerifyingKey = P384VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
                let ecdsa_signature = EcdsaSignature::<p384::NistP384>::from_slice(signature)
                    .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
                Ok(verifying_key.verify(data, &ecdsa_signature).is_ok())
            }
            Algorithm::ECDSAP521 => {
                if public_key.len() != 133 {
                    return Err(CryptoError::InvalidInput(
                        "Invalid public key length".into(),
                    ));
                }
                let verifying_key: P521VerifyingKey = P521VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
                let ecdsa_signature = EcdsaSignature::<p521::NistP521>::from_slice(signature)
                    .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
                Ok(verifying_key.verify(data, &ecdsa_signature).is_ok())
            }
            _ => Err(CryptoError::InvalidInput(format!(
                "Unsupported signature algorithm: {:?}",
                algorithm
            ))),
        }
    }

    fn execute_single_ed25519_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        if public_key.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "Invalid Ed25519 public key length".into(),
            ));
        }

        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(public_key.try_into().map_err(|_| {
                CryptoError::InvalidInput("Invalid public key length for Ed25519".into())
            })?)?;

        let ed25519_signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;

        Ok(verifying_key.verify(data, &ed25519_signature).is_ok())
    }
}

impl Default for SignatureKernelImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SignatureKernelImpl {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl GpuKernel for SignatureKernelImpl {
    fn kernel_type(&self) -> KernelType {
        KernelType::GpuEcdsa
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![
            Algorithm::ECDSAP256,
            Algorithm::ECDSAP384,
            Algorithm::ECDSAP521,
            Algorithm::Ed25519,
        ]
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
        *metrics = KernelMetrics::new(KernelType::GpuEcdsa);
    }

    fn execute_hash(&self, _data: &[u8], _algorithm: Algorithm) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support hash operation".into(),
        ))
    }

    fn execute_hash_batch(
        &self,
        _data: &[Vec<u8>],
        _algorithm: Algorithm,
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
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
    ) -> Result<Vec<u8>, CryptoError> {
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
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }

    fn execute_ecdsa_sign(
        &self,
        private_key: &[u8],
        data: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        self.ecdsa_sign(private_key, data, algorithm)
    }

    fn execute_ecdsa_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        self.ecdsa_verify(public_key, data, signature, algorithm)
    }

    fn execute_ecdsa_verify_batch(
        &self,
        public_keys: &[&[u8]],
        data: &[&[u8]],
        signatures: &[&[u8]],
        algorithm: Algorithm,
    ) -> Result<Vec<bool>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        self.ecdsa_verify_batch(public_keys, data, signatures, algorithm)
    }

    fn execute_ed25519_sign(
        &self,
        private_key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        self.ed25519_sign(private_key, data)
    }

    fn execute_ed25519_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        if !self.state.initialized {
            return Err(CryptoError::NotInitialized);
        }
        self.ed25519_verify(public_key, data, signature)
    }
}

impl SignatureKernelImpl {
    pub fn ecdsa_sign(
        &self,
        private_key: &[u8],
        data: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let start = std::time::Instant::now();

        let signature_bytes: Vec<u8> = match algorithm {
            Algorithm::ECDSAP256 => {
                if private_key.len() != 32 {
                    return Err(CryptoError::InvalidKeyLength(private_key.len()));
                }
                let signing_key: P256SigningKey = P256SigningKey::from_slice(private_key)
                    .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
                let signature: ecdsa::Signature<p256::NistP256> = signing_key
                    .try_sign(data)
                    .map_err(|e: ecdsa::Error| CryptoError::SigningFailed(e.to_string()))?;
                signature.to_vec()
            }
            Algorithm::ECDSAP384 => {
                if private_key.len() != 48 {
                    return Err(CryptoError::InvalidKeyLength(private_key.len()));
                }
                let signing_key: P384SigningKey = P384SigningKey::from_slice(private_key)
                    .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
                let signature: ecdsa::Signature<p384::NistP384> = signing_key
                    .try_sign(data)
                    .map_err(|e: ecdsa::Error| CryptoError::SigningFailed(e.to_string()))?;
                signature.to_vec()
            }
            Algorithm::ECDSAP521 => {
                if private_key.len() != 66 {
                    return Err(CryptoError::InvalidKeyLength(private_key.len()));
                }
                let signing_key: P521SigningKey = P521SigningKey::from_slice(private_key)
                    .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
                let signature: ecdsa::Signature<p521::NistP521> = signing_key
                    .try_sign(data)
                    .map_err(|e: ecdsa::Error| CryptoError::SigningFailed(e.to_string()))?;
                signature.to_vec()
            }
            _ => {
                return Err(CryptoError::InvalidInput(format!(
                    "Unsupported signature algorithm: {:?}",
                    algorithm
                )));
            }
        };

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + signature_bytes.len();

        Ok(signature_bytes)
    }

    pub fn ecdsa_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool, CryptoError> {
        let start = std::time::Instant::now();

        let result = match algorithm {
            Algorithm::ECDSAP256 => {
                if public_key.len() != 65 {
                    return Err(CryptoError::InvalidInput(
                        "Invalid public key length".into(),
                    ));
                }
                let verifying_key: P256VerifyingKey = P256VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
                let ecdsa_signature = EcdsaSignature::<p256::NistP256>::from_slice(signature)
                    .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
                verifying_key.verify(data, &ecdsa_signature).is_ok()
            }
            Algorithm::ECDSAP384 => {
                if public_key.len() != 97 {
                    return Err(CryptoError::InvalidInput(
                        "Invalid public key length".into(),
                    ));
                }
                let verifying_key: P384VerifyingKey = P384VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
                let ecdsa_signature = EcdsaSignature::<p384::NistP384>::from_slice(signature)
                    .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
                verifying_key.verify(data, &ecdsa_signature).is_ok()
            }
            Algorithm::ECDSAP521 => {
                if public_key.len() != 133 {
                    return Err(CryptoError::InvalidInput(
                        "Invalid public key length".into(),
                    ));
                }
                let verifying_key: P521VerifyingKey = P521VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
                let ecdsa_signature = EcdsaSignature::<p521::NistP521>::from_slice(signature)
                    .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
                verifying_key.verify(data, &ecdsa_signature).is_ok()
            }
            _ => {
                return Err(CryptoError::InvalidInput(format!(
                    "Unsupported signature algorithm: {:?}",
                    algorithm
                )));
            }
        };

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + signature.len();

        Ok(result)
    }

    pub fn ecdsa_verify_batch(
        &self,
        public_keys: &[&[u8]],
        data: &[&[u8]],
        signatures: &[&[u8]],
        algorithm: Algorithm,
    ) -> Result<Vec<bool>, CryptoError> {
        let total_data_size: usize = data.iter().map(|d| d.len()).sum();
        let batch_size = public_keys.len();

        let start = std::time::Instant::now();

        let use_parallel = self.should_use_gpu(total_data_size, batch_size);

        let verify_closure = |item: (&&[u8], (&&[u8], &&[u8]))| {
            let (&pk, (d, s)) = item;
            self.execute_single_ecdsa_verify(pk, d, s, algorithm)
        };

        let results: Result<Vec<bool>, CryptoError> = if use_parallel && self.state.config.use_async
        {
            public_keys
                .par_iter()
                .zip(data.par_iter().zip(signatures.par_iter()))
                .map(verify_closure)
                .collect()
        } else {
            public_keys
                .iter()
                .zip(data.iter().zip(signatures.iter()))
                .map(|item| {
                    let (&pk, (d, s)) = item;
                    self.execute_single_ecdsa_verify(pk, d, s, algorithm)
                })
                .collect()
        };

        let elapsed = start.elapsed();

        let verified_count = results
            .as_ref()
            .unwrap_or(&vec![])
            .iter()
            .filter(|&&r| r)
            .count();
        let failed_count = batch_size.saturating_sub(verified_count);

        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (total_data_size as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes =
            total_data_size + signatures.iter().map(|s| s.len()).sum::<usize>();
        metrics.batch_size = batch_size;
        metrics.success_count = Some(verified_count as u64);
        metrics.error_count = Some(failed_count as u64);

        results
    }

    pub fn ed25519_sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use ed25519_dalek::SigningKey;

        let start = std::time::Instant::now();

        if private_key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength(private_key.len()));
        }

        let signing_key = SigningKey::from_bytes(private_key.try_into().map_err(|_| {
            CryptoError::InvalidInput("Invalid private key length for Ed25519".into())
        })?);
        let verifying_key: ed25519_dalek::VerifyingKey = (&signing_key).into();

        let signature = signing_key.try_sign(data)?;
        let signature_bytes: [u8; 64] = signature.to_bytes();

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes =
            data.len() + signature_bytes.len() + verifying_key.as_bytes().len();

        Ok(signature_bytes.to_vec())
    }

    pub fn ed25519_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let start = std::time::Instant::now();

        if public_key.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "Invalid Ed25519 public key length".into(),
            ));
        }

        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(public_key.try_into().map_err(|_| {
                CryptoError::InvalidInput("Invalid public key length for Ed25519".into())
            })?)?;

        let ed25519_signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;

        let result = verifying_key.verify(data, &ed25519_signature).is_ok();

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = data.len() + signature.len();

        Ok(result)
    }
}

pub type SignatureKernel = SignatureKernelImpl;
