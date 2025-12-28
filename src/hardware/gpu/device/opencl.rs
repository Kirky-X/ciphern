// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! OpenCL 设备实现
//!
//! 使用 ocl 库与 AMD/Intel GPU 通信

use crate::error::CryptoError;
use crate::hardware::gpu::device::{
    DeviceCapabilities, DeviceHealth, DeviceState, XpuDevice, XpuKernel, XpuType,
};
use crate::types::Algorithm;
use std::sync::Arc;

#[cfg(feature = "gpu-opencl")]
use ocl::{Context, Device, DeviceType, Platform};

#[cfg(feature = "gpu-opencl")]
use ocl::enums::DeviceInfo;

#[cfg(feature = "gpu-opencl")]
pub struct OpenclDevice {
    device_id: usize,
    device_name: String,
    capabilities: DeviceCapabilities,
    state: DeviceState,
    platform: Option<Platform>,
    device: Option<Device>,
    context: Option<Context>,
}

#[cfg(feature = "gpu-opencl")]
impl OpenclDevice {
    pub fn enumerate() -> Result<Vec<Self>, CryptoError> {
        let mut devices = Vec::new();

        let platforms = Platform::list();

        let mut device_count = 0usize;
        for platform in &platforms {
            let platform_devices = Device::list(platform, None)
                .map_err(|e| CryptoError::HardwareAccelerationUnavailable(e.to_string()))?;

            for device in platform_devices {
                let name = device
                    .name()
                    .unwrap_or_else(|_| "Unknown OpenCL Device".to_string());

                let compute_units = match device.info(DeviceInfo::MaxComputeUnits) {
                    Ok(ocl::enums::DeviceInfoResult::MaxComputeUnits(val)) => val,
                    _ => 1,
                };
                let max_work_group_size = match device.info(DeviceInfo::MaxWorkGroupSize) {
                    Ok(ocl::enums::DeviceInfoResult::MaxWorkGroupSize(val)) => val,
                    _ => 256,
                };
                let global_memory = match device.info(DeviceInfo::GlobalMemSize) {
                    Ok(ocl::enums::DeviceInfoResult::GlobalMemSize(val)) => val,
                    _ => 0,
                };
                let max_alloc_size = match device.info(DeviceInfo::MaxMemAllocSize) {
                    Ok(ocl::enums::DeviceInfoResult::MaxMemAllocSize(val)) => val,
                    _ => 1024 * 1024 * 1024,
                };

                let device_type_info = device.info(DeviceInfo::Type);
                let device_type = match device_type_info {
                    Ok(ocl::enums::DeviceInfoResult::Type(dt)) => {
                        if dt.contains(DeviceType::GPU) {
                            if name.contains("AMD") || name.contains("Radeon") {
                                XpuType::AmdGpu
                            } else if name.contains("Intel") {
                                XpuType::IntelGpu
                            } else {
                                XpuType::Unknown
                            }
                        } else if dt.contains(DeviceType::CPU) {
                            XpuType::IntelCpu
                        } else {
                            XpuType::Unknown
                        }
                    }
                    _ => XpuType::Unknown,
                };

                let capabilities = DeviceCapabilities {
                    device_type,
                    device_name: name.clone(),
                    compute_units,
                    max_work_group_size,
                    global_memory: global_memory as usize,
                    max_alloc_size: max_alloc_size as usize,
                    supported_algorithms: vec![
                        crate::types::Algorithm::SHA256,
                        crate::types::Algorithm::SHA512,
                        crate::types::Algorithm::AES256GCM,
                        crate::types::Algorithm::ECDSAP256,
                        crate::types::Algorithm::ECDSAP384,
                        crate::types::Algorithm::Ed25519,
                    ],
                    has_local_memory: true,
                    ECC_supported: false,
                };

                devices.push(Self {
                    device_id: device_count,
                    device_name: name,
                    capabilities,
                    state: DeviceState::Uninitialized,
                    platform: Some(platform.clone()),
                    device: Some(device),
                    context: None,
                });

                device_count += 1;
            }
        }

        Ok(devices)
    }
}

#[cfg(not(feature = "gpu-opencl"))]
impl OpenclDevice {
    pub fn enumerate() -> Result<Vec<Self>, CryptoError> {
        Ok(Vec::new())
    }
}

#[cfg(feature = "gpu-opencl")]
impl XpuDevice for OpenclDevice {
    fn device_type(&self) -> XpuType {
        XpuType::AmdGpu
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }

    fn capabilities(&self) -> &DeviceCapabilities {
        &self.capabilities
    }

    fn state(&self) -> &DeviceState {
        &self.state
    }

    fn is_available(&self) -> bool {
        self.state == DeviceState::Ready
    }

    fn initialize(&mut self) -> Result<(), CryptoError> {
        if self.state == DeviceState::Ready {
            return Ok(());
        }

        let device = self.device.as_ref().ok_or_else(|| {
            CryptoError::HardwareAccelerationUnavailable("OpenCL device not found".into())
        })?;

        let context = Context::builder()
            .devices(device.clone())
            .build()
            .map_err(|e| CryptoError::HardwareAccelerationUnavailable(e.to_string()))?;

        self.context = Some(context);
        self.state = DeviceState::Ready;

        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), CryptoError> {
        self.context.take();
        self.state = DeviceState::Shutdown;
        Ok(())
    }

    fn check_health(&mut self) -> Result<DeviceHealth, CryptoError> {
        let health = DeviceHealth {
            is_healthy: self.state == DeviceState::Ready,
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

    fn get_kernel(&self, _algorithm: Algorithm) -> Result<Arc<dyn XpuKernel>, CryptoError> {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "OpenCL kernel not implemented".into(),
        ))
    }
}
