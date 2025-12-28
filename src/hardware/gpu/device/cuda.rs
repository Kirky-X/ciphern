// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! CUDA 设备实现
//!
//! 使用 cudarc 库与 NVIDIA GPU 通信

use crate::error::CryptoError;
use crate::hardware::gpu::device::{
    DeviceCapabilities, DeviceHealth, DeviceState, XpuDevice, XpuKernel, XpuType,
};
use crate::hardware::gpu::kernels::{AesKernel, GpuKernel, HashKernel};
use crate::types::Algorithm;
use std::sync::{Arc, Mutex, RwLock};

#[cfg(feature = "gpu-cuda")]
fn cuda_error_to_string(error: cudarc::driver::result::DriverError) -> String {
    format!("CUDA error code: {:?}", error.0)
}

#[cfg(feature = "gpu-cuda")]
pub struct CudaDevice {
    device_id: usize,
    device_name: String,
    capabilities: DeviceCapabilities,
    state: Mutex<DeviceState>,
    hash_kernel: RwLock<HashKernel>,
    aes_kernel: RwLock<AesKernel>,
}

#[cfg(feature = "gpu-cuda")]
impl CudaDevice {
    pub fn enumerate() -> Result<Vec<Self>, CryptoError> {
        use cudarc::driver::{result, CudaContext};
        let mut devices = Vec::new();

        let device_count = CudaContext::device_count()?;
        for id in 0..device_count {
            let ctx = CudaContext::new(id as usize)
                .map_err(|e| CryptoError::HardwareInitializationFailed(cuda_error_to_string(e)))?;
            let name = ctx
                .name()
                .unwrap_or_else(|_| format!("CUDA Device {} (Name Unavailable)", id))
                .to_string();

            let global_memory = unsafe { result::device::total_mem(ctx.cu_device()) }.unwrap_or(0);

            let capabilities = DeviceCapabilities {
                device_type: XpuType::NvidiaCuda,
                device_name: name.clone(),
                compute_units: 1,
                max_work_group_size: 1024,
                global_memory,
                max_alloc_size: 1024 * 1024,
                supported_algorithms: vec![
                    Algorithm::SHA256,
                    Algorithm::SHA512,
                    Algorithm::AES256GCM,
                    Algorithm::ECDSAP256,
                    Algorithm::ECDSAP384,
                    Algorithm::Ed25519,
                ],
                has_local_memory: true,
                ecc_supported: false,
            };

            devices.push(Self {
                device_id: id as usize,
                device_name: name,
                capabilities,
                state: Mutex::new(DeviceState::Uninitialized),
                hash_kernel: RwLock::new(HashKernel::new()),
                aes_kernel: RwLock::new(AesKernel::new()),
            });
        }

        Ok(devices)
    }
}

#[cfg(not(feature = "gpu-cuda"))]
impl CudaDevice {
    pub fn enumerate() -> Result<Vec<Self>, CryptoError> {
        Ok(Vec::new())
    }
}

#[cfg(feature = "gpu-cuda")]
impl XpuDevice for CudaDevice {
    fn device_type(&self) -> XpuType {
        XpuType::NvidiaCuda
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }

    fn capabilities(&self) -> &DeviceCapabilities {
        &self.capabilities
    }

    fn state(&self) -> DeviceState {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn is_available(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        *state == DeviceState::Ready
    }

    fn initialize(&mut self) -> Result<(), CryptoError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if *state == DeviceState::Ready {
            return Ok(());
        }
        *state = DeviceState::Ready;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), CryptoError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        *state = DeviceState::Shutdown;
        Ok(())
    }

    fn check_health(&self) -> Result<DeviceHealth, CryptoError> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let health = DeviceHealth {
            is_healthy: *state == DeviceState::Ready,
            temperature: None,
            memory_used: 0,
            memory_total: self.capabilities.global_memory,
            compute_utilization: 0.0,
            error_count: 0,
        };

        Ok(health)
    }

    fn allocate_host_buffer(&self, _size: usize) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![0u8; _size])
    }

    fn allocate_device_buffer(&self, _size: usize) -> Result<(), CryptoError> {
        Ok(())
    }

    fn deallocate_device_buffer(&self, _buffer_id: u64) -> Result<(), CryptoError> {
        Ok(())
    }

    fn copy_to_device(&self, _host_data: &[u8], _device_offset: usize) -> Result<(), CryptoError> {
        Ok(())
    }

    fn copy_from_device(
        &self,
        _device_offset: usize,
        _size: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![0u8; _size])
    }

    fn get_kernel(
        &self,
        algorithm: crate::types::Algorithm,
    ) -> Result<Arc<dyn XpuKernel>, CryptoError> {
        match algorithm {
            Algorithm::SHA256 | Algorithm::SHA512 => {
                let mut kernel = self.hash_kernel.write().map_err(|_| {
                    CryptoError::HardwareAccelerationUnavailable("Hash kernel lock failed".into())
                })?;
                if !kernel.is_available() {
                    kernel.initialize().map_err(|e| {
                        CryptoError::HardwareInitializationFailed(format!(
                            "Hash kernel init failed: {:?}",
                            e
                        ))
                    })?;
                }
                Ok(Arc::new(kernel.clone()))
            }
            Algorithm::AES256GCM => {
                let mut kernel = self.aes_kernel.write().map_err(|_| {
                    CryptoError::HardwareAccelerationUnavailable("AES kernel lock failed".into())
                })?;
                if !kernel.is_available() {
                    kernel.initialize().map_err(|e| {
                        CryptoError::HardwareInitializationFailed(format!(
                            "AES kernel init failed: {:?}",
                            e
                        ))
                    })?;
                }
                Ok(Arc::new(kernel.clone()))
            }
            _ => Err(CryptoError::HardwareAccelerationUnavailable(
                format!("Algorithm {:?} not supported on CUDA device", algorithm).into(),
            )),
        }
    }
}
