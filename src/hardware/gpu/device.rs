// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! XPU 设备管理模块
//!
//! 支持多种 GPU 后端的统一抽象：
//! - NVIDIA CUDA (通过 cudarc)
//! - AMD ROCm/OpenCL (通过 ocl)
//! - Intel SYCL/oneAPI (通过 oneDPL)
//!
//! 设备检测、初始化、资源管理

use crate::error::CryptoError;
use crate::types::Algorithm;
use std::sync::Arc;

#[cfg(feature = "gpu-cuda")]
pub mod cuda;
#[cfg(feature = "gpu-opencl")]
pub mod opencl;

#[cfg(feature = "gpu-cuda")]
pub use cuda::CudaDevice;
#[cfg(feature = "gpu-opencl")]
pub use opencl::OpenclDevice;

/// XPU 设备类型枚举
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum XpuType {
    /// NVIDIA CUDA GPU
    NvidiaCuda,
    /// AMD GPU (ROCm/OpenCL)
    AmdGpu,
    /// Intel GPU (集成显卡/Arc)
    IntelGpu,
    /// Intel CPU (SYCL CPU fallback)
    IntelCpu,
    /// 虚拟设备（测试用）
    Virtual,
    /// 未知设备
    Unknown,
}

impl std::fmt::Display for XpuType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XpuType::NvidiaCuda => write!(f, "NVIDIA CUDA"),
            XpuType::AmdGpu => write!(f, "AMD GPU"),
            XpuType::IntelGpu => write!(f, "Intel GPU"),
            XpuType::IntelCpu => write!(f, "Intel CPU (SYCL)"),
            XpuType::Virtual => write!(f, "Virtual Device"),
            XpuType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// 设备能力描述
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DeviceCapabilities {
    pub device_type: XpuType,
    pub device_name: String,
    pub compute_units: u32,
    pub max_work_group_size: usize,
    pub global_memory: usize,
    pub max_alloc_size: usize,
    pub supported_algorithms: Vec<Algorithm>,
    pub has_local_memory: bool,
    pub ecc_supported: bool,
}

/// 设备状态
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum DeviceState {
    Uninitialized,
    Initializing,
    Ready,
    Busy,
    Error(String),
    Shutdown,
}

/// 设备健康检查结果
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DeviceHealth {
    pub is_healthy: bool,
    pub temperature: Option<f32>,
    pub memory_used: usize,
    pub memory_total: usize,
    pub compute_utilization: f32,
    pub error_count: u32,
}

impl Default for DeviceHealth {
    fn default() -> Self {
        Self {
            is_healthy: true,
            temperature: None,
            memory_used: 0,
            memory_total: 0,
            compute_utilization: 0.0,
            error_count: 0,
        }
    }
}

/// 统一的 XPU 设备 trait
pub trait XpuDevice: Send + Sync {
    fn device_type(&self) -> XpuType;
    fn device_name(&self) -> &str;
    fn capabilities(&self) -> &DeviceCapabilities;
    fn state(&self) -> DeviceState;
    fn is_available(&self) -> bool;
    fn initialize(&mut self) -> Result<(), CryptoError>;
    fn shutdown(&mut self) -> Result<(), CryptoError>;

    fn check_health(&self) -> Result<DeviceHealth, CryptoError>;

    fn allocate_host_buffer(&self, size: usize) -> Result<Vec<u8>, CryptoError>;
    fn allocate_device_buffer(&self, size: usize) -> Result<(), CryptoError>;
    fn deallocate_device_buffer(&self, buffer_id: u64) -> Result<(), CryptoError>;
    fn copy_to_device(&self, host_data: &[u8], device_offset: usize) -> Result<(), CryptoError>;
    fn copy_from_device(&self, device_offset: usize, size: usize) -> Result<Vec<u8>, CryptoError>;

    fn supports_algorithm(&self, algorithm: Algorithm) -> bool {
        self.capabilities()
            .supported_algorithms
            .contains(&algorithm)
    }

    fn get_kernel(&self, algorithm: Algorithm) -> Result<Arc<dyn XpuKernel>, CryptoError>;

    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let kernel = self.get_kernel(Algorithm::AES256GCM)?;
        kernel.aes_gcm_encrypt(key, nonce, data)
    }

    fn aes_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let kernel = self.get_kernel(Algorithm::AES256GCM)?;
        kernel.aes_gcm_decrypt(key, nonce, data)
    }
}

/// GPU Kernel trait - 加密操作抽象
pub trait XpuKernel: Send + Sync {
    fn supported_algorithms(&self) -> Vec<Algorithm>;

    fn hash(&self, data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>, CryptoError>;
    fn hash_batch(
        &self,
        data: &[Vec<u8>],
        algorithm: Algorithm,
    ) -> Result<Vec<Vec<u8>>, CryptoError>;

    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    fn aes_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn sm4_encrypt(&self, key: &[u8], data: &[u8], mode: &str) -> Result<Vec<u8>, CryptoError>;
    fn sm4_decrypt(&self, key: &[u8], data: &[u8], mode: &str) -> Result<Vec<u8>, CryptoError>;

    fn ecdsa_sign(
        &self,
        private_key: &[u8],
        data: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError>;
    fn ecdsa_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool, CryptoError>;
    fn ecdsa_verify_batch(
        &self,
        public_keys: &[&[u8]],
        data: &[&[u8]],
        signatures: &[&[u8]],
        algorithm: Algorithm,
    ) -> Result<Vec<bool>, CryptoError>;

    fn ed25519_sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn ed25519_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError>;
}

/// XPU 设备管理器
pub struct XpuManager {
    devices: Vec<Arc<dyn XpuDevice>>,
    primary_device: Option<usize>,
    default_device_type: XpuType,
}

impl std::fmt::Debug for XpuManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XpuManager")
            .field("device_count", &self.devices.len())
            .field("primary_device", &self.primary_device)
            .field("default_device_type", &self.default_device_type)
            .finish()
    }
}

/// XPU 管理器单例（延迟初始化，使用 Mutex 支持内部可变性）
static MANAGER: once_cell::sync::Lazy<std::sync::Mutex<Option<XpuManager>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

impl XpuManager {
    pub fn new() -> Result<Self, CryptoError> {
        let mut manager = Self {
            devices: Vec::new(),
            primary_device: None,
            default_device_type: XpuType::Unknown,
        };

        #[cfg(feature = "gpu-cuda")]
        manager.try_add_cuda_devices()?;

        #[cfg(feature = "gpu-opencl")]
        manager.try_add_opencl_devices()?;

        if manager.devices.is_empty() {
            return Err(CryptoError::HardwareAccelerationUnavailable(
                "No compatible XPU device found".into(),
            ));
        }

        manager.select_primary_device();
        Ok(manager)
    }

    #[cfg(feature = "gpu-cuda")]
    fn try_add_cuda_devices(&mut self) -> Result<(), CryptoError> {
        match CudaDevice::enumerate() {
            Ok(cuda_devices) => {
                for mut device in cuda_devices {
                    if device.initialize().is_ok() {
                        self.devices.push(Arc::new(device));
                        if self.primary_device.is_none() {
                            self.primary_device = Some(self.devices.len() - 1);
                            self.default_device_type = XpuType::NvidiaCuda;
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("CUDA device detection failed: {:?}", e);
            }
        }
        Ok(())
    }

    #[cfg(feature = "gpu-opencl")]
    fn try_add_opencl_devices(&mut self) -> Result<(), CryptoError> {
        match OpenclDevice::enumerate() {
            Ok(opencl_devices) => {
                for mut device in opencl_devices {
                    if device.initialize().is_ok() {
                        self.devices.push(Arc::new(device));
                        if self.primary_device.is_none() {
                            self.primary_device = Some(self.devices.len() - 1);
                            self.default_device_type = XpuType::AmdGpu;
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("OpenCL device detection failed: {:?}", e);
            }
        }
        Ok(())
    }

    fn select_primary_device(&mut self) {
        if self.primary_device.is_some() {
            return;
        }

        let mut best_score = 0i32;
        let mut best_index = 0usize;

        for (index, device) in self.devices.iter().enumerate() {
            let score = device_capability_score(device.as_ref());
            if score > best_score {
                best_score = score;
                best_index = index;
            }
        }

        self.primary_device = Some(best_index);
        self.default_device_type = self.devices[best_index].device_type();
    }

    pub fn has_available_device(&self) -> bool {
        !self.devices.is_empty()
    }

    pub fn get_primary_device(&self) -> Result<Arc<dyn XpuDevice>, CryptoError> {
        let index = self.primary_device.ok_or_else(|| {
            CryptoError::HardwareAccelerationUnavailable("No primary device selected".into())
        })?;

        let device = self.devices.get(index).ok_or_else(|| {
            CryptoError::HardwareAccelerationUnavailable("Primary device not found".into())
        })?;

        if !device.is_available() {
            return Err(CryptoError::HardwareAccelerationUnavailable(format!(
                "Primary device {} is not available",
                device.device_name()
            )));
        }

        Ok(Arc::clone(device))
    }

    pub fn get_device_by_type(&self, device_type: XpuType) -> Option<Arc<dyn XpuDevice>> {
        self.devices
            .iter()
            .find(|d| d.device_type() == device_type)
            .cloned()
    }

    pub fn get_all_devices(&self) -> Vec<Arc<dyn XpuDevice>> {
        self.devices.to_vec()
    }

    pub fn get_device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn default_device_type(&self) -> XpuType {
        self.default_device_type.clone()
    }

    pub fn shutdown_all_devices(&mut self) -> Result<(), CryptoError> {
        self.devices.clear();
        self.primary_device = None;
        Ok(())
    }

    pub fn get() -> std::sync::MutexGuard<'static, Option<XpuManager>> {
        let mut manager = MANAGER.lock().expect("Mutex poisoned");
        if manager.is_none() {
            *manager = XpuManager::new().ok().map(|mut m| {
                if !m.has_available_device() {
                    m.devices.clear();
                }
                m
            });
        }
        manager
    }

    pub fn has_instance() -> bool {
        MANAGER.lock().map(|m| m.is_some()).unwrap_or(false)
    }
}

fn device_capability_score(device: &dyn XpuDevice) -> i32 {
    let caps = device.capabilities();
    let mut score = 0i32;

    match caps.device_type {
        XpuType::NvidiaCuda => score += 100,
        XpuType::AmdGpu => score += 80,
        XpuType::IntelGpu => score += 60,
        XpuType::IntelCpu => score += 20,
        _ => {}
    }

    score += (caps.compute_units / 10) as i32;
    score += (caps.global_memory / (1024 * 1024 * 1024)) as i32;
    score += if caps.ecc_supported { 10 } else { 0 };
    score += if caps.max_work_group_size >= 256 {
        10
    } else {
        0
    };

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xpu_type_display() {
        assert_eq!(XpuType::NvidiaCuda.to_string(), "NVIDIA CUDA");
        assert_eq!(XpuType::AmdGpu.to_string(), "AMD GPU");
    }

    #[test]
    fn test_device_health_default() {
        let health = DeviceHealth::default();
        assert!(health.is_healthy);
        assert_eq!(health.error_count, 0);
    }

    #[test]
    fn test_xpu_manager_empty() {
        let manager = XpuManager {
            devices: Vec::new(),
            primary_device: None,
            default_device_type: XpuType::Unknown,
        };
        assert!(!manager.has_available_device());
        assert_eq!(manager.get_device_count(), 0);
    }
}
