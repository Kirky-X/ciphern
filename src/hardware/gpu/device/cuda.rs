// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! CUDA 设备实现
//!
//! 使用 cudarc 库与 NVIDIA GPU 通信

#[cfg(feature = "gpu-cuda")]
pub struct CudaDevice {
    device_id: usize,
    device_name: String,
    capabilities: DeviceCapabilities,
    state: DeviceState,
    context: Option<cudarc::driver::Context>,
}

#[cfg(feature = "gpu-cuda")]
impl CudaDevice {
    pub fn enumerate() -> Result<Vec<Self>> {
        let mut devices = Vec::new();

        let cuda_devices = cudarc::driver::CudaDevice::list()?;
        for (id, cuda_device) in cuda_devices.iter().enumerate() {
            let name = cuda_device
                .name()
                .unwrap_or("Unknown CUDA Device")
                .to_string();
            let compute_units = cuda_device
                .get_attribute(cudarc::driver::DeviceAttribute::MultiprocessorCount)
                .unwrap_or(1);
            let max_threads_per_block = cuda_device
                .get_attribute(cudarc::driver::DeviceAttribute::MaxThreadsPerBlock)
                .unwrap_or(1024);

            let capabilities = DeviceCapabilities {
                device_type: XpuType::NvidiaCuda,
                device_name: name.clone(),
                compute_units: compute_units as u32,
                max_work_group_size: max_threads_per_block as usize,
                global_memory: cuda_device.total_mem().unwrap_or(0),
                max_alloc_size: cuda_device.max_texture1d_width().unwrap_or(1024 * 1024),
                supported_algorithms: vec![
                    crate::types::Algorithm::SHA256,
                    crate::types::Algorithm::SHA512,
                    crate::types::Algorithm::AES256GCM,
                    crate::types::Algorithm::ECDSAP256,
                    crate::types::Algorithm::ECDSAP384,
                    crate::types::Algorithm::Ed25519,
                ],
                has_local_memory: true,
                ECC_supported: cuda_device
                    .get_attribute(cudarc::driver::DeviceAttribute::EccEnabled)
                    .unwrap_or(false)
                    != 0,
            };

            devices.push(Self {
                device_id: id,
                device_name: name,
                capabilities,
                state: DeviceState::Uninitialized,
                context: None,
            });
        }

        Ok(devices)
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

    fn state(&self) -> &DeviceState {
        &self.state
    }

    fn is_available(&self) -> bool {
        self.state == DeviceState::Ready
    }

    fn initialize(&mut self) -> Result<()> {
        if self.state == DeviceState::Ready {
            return Ok(());
        }

        let cuda_devices = cudarc::driver::CudaDevice::list()
            .map_err(|e| CryptoError::HardwareAccelerationUnavailable(e.to_string()))?;

        let device = cuda_devices.get(self.device_id).ok_or_else(|| {
            CryptoError::HardwareAccelerationUnavailable("CUDA device not found".into())
        })?;

        let ctx = device
            .new_context()
            .map_err(|e| CryptoError::HardwareAccelerationUnavailable(e.to_string()))?;

        self.context = Some(ctx);
        self.state = DeviceState::Ready;

        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        self.context.take();
        self.state = DeviceState::Shutdown;
        Ok(())
    }

    fn check_health(&mut self) -> Result<DeviceHealth> {
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
            "CUDA kernel not implemented".into(),
        ))
    }
}
