// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! GPU/XPU 加速模块
//!
//! 支持 NVIDIA CUDA、AMD ROCm/OpenCL、Intel SYCL/oneAPI
//! 采用分层加速策略，CPU 优先，GPU 作为大数据量加速器

use crate::error::CryptoError;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "gpu")]
mod device;
#[cfg(feature = "gpu")]
mod kernels;
#[cfg(feature = "gpu")]
mod memory;

#[cfg(feature = "gpu")]
pub use device::{XpuDevice, XpuManager, XpuType};
#[cfg(feature = "gpu")]
pub use kernels::{GpuKernel, XpuKernel};
#[cfg(feature = "gpu")]
pub use memory::{XpuBuffer, XpuMemory};

/// GPU 功能是否启用
pub static GPU_ENABLED: AtomicBool = AtomicBool::new(false);

/// 是否已初始化 GPU
pub static GPU_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// 当前活跃的 XPU 类型
pub static ACTIVE_XPU_TYPE: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn is_gpu_enabled() -> bool {
    GPU_ENABLED.load(Ordering::Relaxed)
}

#[inline]
pub fn is_gpu_initialized() -> bool {
    GPU_INITIALIZED.load(Ordering::Relaxed)
}

/// 初始化 GPU 加速
#[cfg(feature = "gpu")]
pub fn init_gpu() -> Result<()> {
    if GPU_INITIALIZED.load(Ordering::Relaxed) {
        return Ok(());
    }

    let manager = XpuManager::new()?;
    if manager.has_available_device() {
        GPU_ENABLED.store(true, Ordering::Relaxed);
        GPU_INITIALIZED.store(true, Ordering::Relaxed);
        Ok(())
    } else {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "No compatible GPU device found".into(),
        ))
    }
}

/// 初始化 GPU 加速（无 GPU 静默失败）
#[cfg(not(feature = "gpu"))]
pub fn init_gpu() -> Result<()> {
    Err(CryptoError::HardwareAccelerationUnavailable(
        "GPU support not enabled".into(),
    ))
}

/// GPU 加速阈值配置
#[derive(Debug, Clone)]
pub struct GpuThresholdConfig {
    /// 最小数据大小（字节），超过此值才使用 GPU
    pub min_data_size: usize,
    /// 批处理阈值，超过此数量使用 GPU
    pub batch_threshold: usize,
    /// 内存池预分配大小
    pub memory_pool_size: usize,
    /// 同步等待超时（毫秒）
    pub sync_timeout_ms: u64,
}

impl Default for GpuThresholdConfig {
    fn default() -> Self {
        Self {
            min_data_size: 32 * 1024,            // 32KB
            batch_threshold: 100,                // 100 个操作
            memory_pool_size: 256 * 1024 * 1024, // 256MB
            sync_timeout_ms: 5000,               // 5秒
        }
    }
}

impl GpuThresholdConfig {
    /// 实时加密场景配置（低延迟优先）
    pub fn realtime() -> Self {
        Self {
            min_data_size: 64 * 1024, // 64KB
            batch_threshold: 10,
            memory_pool_size: 128 * 1024 * 1024,
            sync_timeout_ms: 1000,
        }
    }

    /// 批量处理场景配置（吞吐量优先）
    pub fn batch() -> Self {
        Self {
            min_data_size: 16 * 1024, // 16KB
            batch_threshold: 1000,
            memory_pool_size: 1024 * 1024 * 1024, // 1GB
            sync_timeout_ms: 30000,
        }
    }

    /// 判断是否应该使用 GPU
    #[inline]
    pub fn should_use_gpu(&self, data_size: usize, batch_count: usize) -> bool {
        data_size >= self.min_data_size || batch_count >= self.batch_threshold
    }
}

/// 全局 GPU 配置
static GPU_CONFIG: once_cell::sync::Lazy<GpuThresholdConfig> =
    once_cell::sync::Lazy::new(GpuThresholdConfig::realtime);

#[inline]
pub fn get_gpu_config() -> &'static GpuThresholdConfig {
    &GPU_CONFIG
}

#[inline]
pub fn set_gpu_config(config: GpuThresholdConfig) {
    let mut config_ref = unsafe {
        let ptr = &GPU_CONFIG as *const _ as *mut GpuThresholdConfig;
        &mut *ptr
    };
    *config_ref = config;
}

/// GPU 加速的哈希函数
#[cfg(feature = "gpu")]
pub fn accelerated_hash_gpu(data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
    use crate::hardware::GpuThresholdConfig;

    if !is_gpu_enabled() {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "GPU not enabled".into(),
        ));
    }

    let config = get_gpu_config();
    if !config.should_use_gpu(data.len(), 1) {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "Data size too small for GPU acceleration".into(),
        ));
    }

    let manager = XpuManager::get();
    let device = manager.get_primary_device()?;

    let kernel = device.get_kernel(algorithm)?;
    kernel.hash(data, algorithm)
}

/// GPU 加速的 AES 加密
#[cfg(feature = "gpu")]
pub fn accelerated_aes_gpu(
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>> {
    if !is_gpu_enabled() {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "GPU not enabled".into(),
        ));
    }

    let config = get_gpu_config();
    if !config.should_use_gpu(data.len(), 1) {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "Data size too small for GPU acceleration".into(),
        ));
    }

    let manager = XpuManager::get();
    let device = manager.get_primary_device()?;

    if encrypt {
        device.aes_gcm_encrypt(key, nonce, data)
    } else {
        device.aes_gcm_decrypt(key, nonce, data)
    }
}

/// GPU 加速的 ECDSA 签名
#[cfg(feature = "gpu")]
pub fn accelerated_ecdsa_sign_gpu(
    private_key: &[u8],
    data: &[u8],
    algorithm: Algorithm,
) -> Result<Vec<u8>> {
    if !is_gpu_enabled() {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "GPU not enabled".into(),
        ));
    }

    let config = get_gpu_config();
    if !config.should_use_gpu(data.len(), 1) {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "Data size too small for GPU acceleration".into(),
        ));
    }

    let manager = XpuManager::get();
    let device = manager.get_primary_device()?;

    let kernel = device.get_kernel(algorithm)?;
    kernel.sign_ecdsa(private_key, data, algorithm)
}

/// GPU 加速的 ECDSA 验证
#[cfg(feature = "gpu")]
pub fn accelerated_ecdsa_verify_gpu(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
    algorithm: Algorithm,
) -> Result<bool> {
    if !is_gpu_enabled() {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "GPU not enabled".into(),
        ));
    }

    let config = get_gpu_config();
    if !config.should_use_gpu(data.len(), 1) {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "Data size too small for GPU acceleration".into(),
        ));
    }

    let manager = XpuManager::get();
    let device = manager.get_primary_device()?;

    let kernel = device.get_kernel(algorithm)?;
    kernel.verify_ecdsa(public_key, data, signature, algorithm)
}

/// GPU 加速的 ECDSA 批量验证
#[cfg(feature = "gpu")]
pub fn accelerated_ecdsa_verify_batch_gpu(
    public_keys: &[&[u8]],
    data: &[&[u8]],
    signatures: &[&[u8]],
    algorithm: Algorithm,
) -> Result<Vec<bool>> {
    if !is_gpu_enabled() {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "GPU not enabled".into(),
        ));
    }

    let config = get_gpu_config();
    let batch_count = public_keys.len();
    if !config.should_use_gpu(0, batch_count) {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "Batch size too small for GPU acceleration".into(),
        ));
    }

    let manager = XpuManager::get();
    let device = manager.get_primary_device()?;

    let kernel = device.get_kernel(algorithm)?;
    kernel.verify_ecdsa_batch(public_keys, data, signatures, algorithm)
}

/// GPU 加速的 Ed25519 签名
#[cfg(feature = "gpu")]
pub fn accelerated_ed25519_sign_gpu(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if !is_gpu_enabled() {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "GPU not enabled".into(),
        ));
    }

    let config = get_gpu_config();
    if !config.should_use_gpu(data.len(), 1) {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "Data size too small for GPU acceleration".into(),
        ));
    }

    let manager = XpuManager::get();
    let device = manager.get_primary_device()?;

    let kernel = device.get_kernel(Algorithm::ED25519)?;
    kernel.sign_ed25519(private_key, data)
}

/// GPU 加速的 Ed25519 验证
#[cfg(feature = "gpu")]
pub fn accelerated_ed25519_verify_gpu(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    if !is_gpu_enabled() {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "GPU not enabled".into(),
        ));
    }

    let config = get_gpu_config();
    if !config.should_use_gpu(data.len(), 1) {
        return Err(CryptoError::HardwareAccelerationUnavailable(
            "Data size too small for GPU acceleration".into(),
        ));
    }

    let manager = XpuManager::get();
    let device = manager.get_primary_device()?;

    let kernel = device.get_kernel(Algorithm::ED25519)?;
    kernel.verify_ed25519(public_key, data, signature)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "gpu")]
    mod gpu_tests {
        use super::super::*;

        #[test]
        fn test_gpu_threshold_config() {
            let config = GpuThresholdConfig::default();
            assert!(!config.should_use_gpu(1024, 1));
            assert!(config.should_use_gpu(1024 * 1024, 1));
            assert!(config.should_use_gpu(1024, 200));
        }

        #[test]
        fn test_realtime_config() {
            let config = GpuThresholdConfig::realtime();
            assert!(config.min_data_size > GpuThresholdConfig::default().min_data_size);
            assert!(config.batch_threshold < GpuThresholdConfig::default().batch_threshold);
        }

        #[test]
        fn test_batch_config() {
            let config = GpuThresholdConfig::batch();
            assert!(config.min_data_size < GpuThresholdConfig::default().min_data_size);
            assert!(config.batch_threshold > GpuThresholdConfig::default().batch_threshold);
        }
    }

    #[cfg(not(feature = "gpu"))]
    mod cpu_only_tests {
        #[test]
        fn test_gpu_not_enabled() {
            let result = init_gpu();
            assert!(result.is_err());
        }
    }
}
