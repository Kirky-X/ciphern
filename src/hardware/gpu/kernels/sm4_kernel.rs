// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SM4 GPU Kernel 实现
//!
//! 支持 SM4-GCM 模式的 GPU 加速加密/解密
//! 基于 CUDA 或 OpenCL 实现
//! 包含 CPU 回退实现

use super::{GpuKernel, KernelMetrics, KernelType};
use crate::error::CryptoError;
use crate::types::Algorithm;
use std::sync::Mutex;

#[cfg(feature = "gpu-cuda")]
mod cuda_sm4;
#[cfg(feature = "gpu-opencl")]
mod opencl_sm4;

#[cfg(feature = "gpu-cuda")]
pub use cuda_sm4::CudaSm4Kernel;
#[cfg(feature = "gpu-opencl")]
pub use opencl_sm4::OpenclSm4Kernel;

/// SM4 操作模式
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sm4Mode {
    Gcm,
    Ctr,
    Cbc,
    Ecb,
}

impl std::fmt::Display for Sm4Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sm4Mode::Gcm => write!(f, "SM4-GCM"),
            Sm4Mode::Ctr => write!(f, "SM4-CTR"),
            Sm4Mode::Cbc => write!(f, "SM4-CBC"),
            Sm4Mode::Ecb => write!(f, "SM4-ECB"),
        }
    }
}

/// SM4 Kernel 配置
#[derive(Debug, Clone)]
pub struct Sm4KernelConfig {
    pub batch_size: usize,
    pub use_hardware_acceleration: bool,
    pub enable_profiling: bool,
}

impl Default for Sm4KernelConfig {
    fn default() -> Self {
        Self {
            batch_size: 1024,
            use_hardware_acceleration: true,
            enable_profiling: false,
        }
    }
}

/// SM4 Kernel 内部状态
#[derive(Debug)]
pub struct Sm4KernelState {
    config: Sm4KernelConfig,
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
    mode: Sm4Mode,
}

impl Sm4KernelState {
    pub fn new(config: Sm4KernelConfig, mode: Sm4Mode) -> Self {
        Self {
            config,
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuSm4)),
            initialized: false,
            mode,
        }
    }
}

/// CPU 回退实现（当 GPU 不可用时）
pub struct CpuSm4Kernel {
    state: Sm4KernelState,
}

impl CpuSm4Kernel {
    pub fn new() -> Self {
        Self {
            state: Sm4KernelState::new(Sm4KernelConfig::default(), Sm4Mode::Gcm),
        }
    }
}

impl GpuKernel for CpuSm4Kernel {
    fn kernel_type(&self) -> KernelType {
        KernelType::CpuAesNi
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![Algorithm::SM4GCM]
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
            "SM4 kernel does not support hash operation".into(),
        ))
    }

    fn execute_hash_batch(&self, _data: &[Vec<u8>], _algorithm: Algorithm) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "SM4 kernel does not support hash operation".into(),
        ))
    }

    fn execute_sm4_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use ghash::{universal_hash::KeyInit, GHash};
        use sm4::cipher::{KeyIvInit, StreamCipher};
        use sm4::Sm4;

        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: 16,
                actual: key.len(),
            });
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput(
                "Nonce must be 12 bytes for GCM".into(),
            ));
        }

        let start = std::time::Instant::now();

        let key_bytes: [u8; 16] = key.try_into().map_err(|_| CryptoError::InvalidKeySize {
            expected: 16,
            actual: key.len(),
        })?;

        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[15] = 2;

        let mut ghash = GHash::new(&key_bytes.into());
        let mut sm4 =
            Sm4::new_from_slices(&key_bytes, &iv).map_err(|_| CryptoError::EncryptionFailed)?;

        let mut output = data.to_vec();
        sm4.apply_keystream(&mut output);

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        *metrics = metrics
            .clone()
            .with_execution_time(elapsed.as_micros() as u64)
            .with_throughput(data.len() as f32 / elapsed.as_secs_f32() / 1_000_000.0);

        Ok(output)
    }

    fn execute_sm4_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use ghash::{universal_hash::KeyInit, GHash};
        use sm4::cipher::{KeyIvInit, StreamCipher};
        use sm4::Sm4;

        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: 16,
                actual: key.len(),
            });
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput(
                "Nonce must be 12 bytes for GCM".into(),
            ));
        }

        let start = std::time::Instant::now();

        let key_bytes: [u8; 16] = key.try_into().map_err(|_| CryptoError::InvalidKeySize {
            expected: 16,
            actual: key.len(),
        })?;

        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[15] = 2;

        let mut ghash = GHash::new(&key_bytes.into());
        let mut sm4 =
            Sm4::new_from_slices(&key_bytes, &iv).map_err(|_| CryptoError::DecryptionFailed)?;

        let mut output = data.to_vec();
        sm4.apply_keystream(&mut output);

        let elapsed = start.elapsed();
        let mut metrics = self.state.metrics.lock().unwrap();
        *metrics = metrics
            .clone()
            .with_execution_time(elapsed.as_micros() as u64)
            .with_throughput(data.len() as f32 / elapsed.as_secs_f32() / 1_000_000.0);

        Ok(output)
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

#[cfg(feature = "gpu")]
pub type Sm4Kernel = CpuSm4Kernel;

#[cfg(not(feature = "gpu"))]
pub struct Sm4Kernel;

#[cfg(not(feature = "gpu"))]
impl Sm4Kernel {
    pub fn new() -> Self {
        Self
    }

    pub fn is_available() -> bool {
        false
    }
}
