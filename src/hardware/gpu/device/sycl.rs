// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SYCL 设备实现
//!
//! 使用 oneAPI SYCL 与 Intel GPU/CPU 通信

#[cfg(feature = "gpu-sycl")]
pub struct SyclDevice {
    device_id: usize,
    device_name: String,
    capabilities: DeviceCapabilities,
    state: DeviceState,
    context: Option<sycl::Context>,
    queue: Option<sycl::Queue>,
}

#[cfg(feature = "gpu-sycl")]
impl SyclDevice {
    pub fn enumerate() -> Result<Vec<Self>> {
        let mut devices = Vec::new();

        let devices_info = sycl::device::Device::enumerate()
            .map_err(|e| CryptoError::HardwareAccelerationUnavailable(e.to_string()))?;

        for (id, device) in devices_info.iter().enumerate() {
            let name = device
                .get_info::<sycl::info::Device::name>()
                .unwrap_or("Unknown SYCL Device")
                .to_string();

            let device_type = device
                .get_info::<sycl::info::Device::device_type>()
                .map(|dt| match dt {
                    sycl::info::DeviceType::GPU => {
                        if name.contains("Intel") {
                            XpuType::IntelGpu
                        } else {
                            XpuType::Unknown
                        }
                    }
                    sycl::info::DeviceType::CPU => XpuType::IntelCpu,
                    _ => XpuType::Unknown,
                })
                .unwrap_or(XpuType::Unknown);

            let compute_units = device
                .get_info::<sycl::info::Device::max_compute_units>()
                .unwrap_or(1) as u32;
            let max_work_group_size = device
                .get_info::<sycl::info::Device::max_work_group_size>()
                .unwrap_or(256) as usize;
            let global_memory = device
                .get_info::<sycl::info::Device::global_mem_size>()
                .unwrap_or(0);

            let capabilities = DeviceCapabilities {
                device_type,
                device_name: name.clone(),
                compute_units,
                max_work_group_size,
                global_memory: global_memory as usize,
                max_alloc_size: device
                    .get_info::<sycl::info::Device::max_mem_alloc_size>()
                    .unwrap_or(1024 * 1024 * 1024) as usize,
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
                device_id: id,
                device_name: name,
                capabilities,
                state: DeviceState::Uninitialized,
                context: None,
                queue: None,
            });
        }

        Ok(devices)
    }
}

#[cfg(feature = "gpu-sycl")]
impl XpuDevice for SyclDevice {
    fn device_type(&self) -> XpuType {
        self.capabilities.device_type
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }

    fn capabilities(&self) -> &DeviceCapabilities {
        &self.capabilities
    }

    fn state(&self) -> DeviceState {
        self.state.clone()
    }

    fn is_available(&self) -> bool {
        self.state == DeviceState::Ready
    }

    fn initialize(&mut self) -> Result<()> {
        if self.state == DeviceState::Ready {
            return Ok(());
        }

        let devices = sycl::device::Device::enumerate()
            .map_err(|e| CryptoError::HardwareAccelerationUnavailable(e.to_string()))?;

        let device = devices.get(self.device_id).ok_or_else(|| {
            CryptoError::HardwareAccelerationUnavailable("SYCL device not found".into())
        })?;

        let context = sycl::Context::builder()
            .devices([device.clone()])
            .build()
            .map_err(|e| CryptoError::HardwareAccelerationUnavailable(e.to_string()))?;

        let queue = sycl::Queue::new(&context, device.clone())
            .map_err(|e| CryptoError::HardwareAccelerationUnavailable(e.to_string()))?;

        self.context = Some(context);
        self.queue = Some(queue);
        self.state = DeviceState::Ready;

        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        self.queue.take();
        self.context.take();
        self.state = DeviceState::Shutdown;
        Ok(())
    }

    fn check_health(&self) -> Result<DeviceHealth> {
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

    fn allocate_host_buffer(&self, _size: usize) -> Result<Vec<u8>> {
        Ok(vec![0u8; _size])
    }

    fn allocate_device_buffer(&self, _size: usize) -> Result<()> {
        Ok(())
    }

    fn deallocate_device_buffer(&self, _buffer_id: u64) -> Result<()> {
        Ok(())
    }

    fn copy_to_device(&self, _host_data: &[u8], _device_offset: usize) -> Result<()> {
        Ok(())
    }

    fn copy_from_device(&self, _device_offset: usize, _size: usize) -> Result<Vec<u8>> {
        Ok(vec![0u8; _size])
    }

    fn get_kernel(&self, _algorithm: crate::types::Algorithm) -> Result<Arc<dyn XpuKernel>> {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "SYCL kernel not implemented".into(),
        ))
    }
}
