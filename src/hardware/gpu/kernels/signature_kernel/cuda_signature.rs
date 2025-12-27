// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! CUDA Signature Kernel 实现
//!
//! 使用 CUDA 加速 ECDSA、Ed25519 签名验证
//! 特别优化批量签名验证场景，支持 MB/GB 级数据处理

#[cfg(feature = "gpu-cuda")]
const ECDSA256_SIGNATURE_SIZE: usize = 64;
#[cfg(feature = "gpu-cuda")]
const ECDSA384_SIGNATURE_SIZE: usize = 96;
#[cfg(feature = "gpu-cuda")]
const ECDSA521_SIGNATURE_SIZE: usize = 132;
#[cfg(feature = "gpu-cuda")]
const ED25519_SIGNATURE_SIZE: usize = 64;
#[cfg(feature = "gpu-cuda")]
const ECDSA256_PUBLIC_KEY_SIZE: usize = 65;
#[cfg(feature = "gpu-cuda")]
const ECDSA384_PUBLIC_KEY_SIZE: usize = 97;
#[cfg(feature = "gpu-cuda")]
const ECDSA521_PUBLIC_KEY_SIZE: usize = 133;
#[cfg(feature = "gpu-cuda")]
const ED25519_PUBLIC_KEY_SIZE: usize = 32;

#[cfg(feature = "gpu-cuda")]
const CUDA_ECDSA_KERNEL: &[u8] = include_bytes!("shaders/ecdsa.ptx");
#[cfg(feature = "gpu-cuda")]
const CUDA_ED25519_KERNEL: &[u8] = include_bytes!("shaders/ed25519.ptx");

#[cfg(feature = "gpu-cuda")]
struct CudaSignatureKernelState {
    context: Option<CudaContext>,
    device: Option<CudaDevice>,
    stream: Option<CudaStream>,
    ecdsa256_kernel: Option<CudaKernel>,
    ecdsa384_kernel: Option<CudaKernel>,
    ecdsa521_kernel: Option<CudaKernel>,
    ed25519_kernel: Option<CudaKernel>,
    memory_pool: Vec<CudaMemory>,
    config: super::BatchConfig,
    metrics: Mutex<super::KernelMetrics>,
    initialized: bool,
}

#[cfg(feature = "gpu-cuda")]
impl CudaSignatureKernelState {
    pub fn new(config: super::BatchConfig) -> Self {
        Self {
            context: None,
            device: None,
            stream: None,
            ecdsa256_kernel: None,
            ecdsa384_kernel: None,
            ecdsa521_kernel: None,
            ed25519_kernel: None,
            memory_pool: Vec::new(),
            config,
            metrics: Mutex::new(super::KernelMetrics::new(super::KernelType::GpuEcdsa)),
            initialized: false,
        }
    }

    fn allocate_from_pool(&mut self, size: usize) -> Result<CudaMemory> {
        let index = self
            .memory_pool
            .iter()
            .position(|m| m.size() >= size && m.is_free());

        if let Some(idx) = index {
            let mem = self.memory_pool.remove(idx);
            mem.set_used(true);
            return Ok(mem);
        }

        let new_mem = CudaMemory::new(size)?;
        new_mem.set_used(true);
        self.memory_pool.push(new_mem.clone());
        Ok(new_mem)
    }

    fn release_to_pool(&mut self, memory: CudaMemory) {
        memory.set_used(false);
        if !self.memory_pool.contains(&memory) {
            self.memory_pool.push(memory);
        }
    }
}

#[cfg(feature = "gpu-cuda")]
pub struct CudaSignatureKernel {
    state: Mutex<CudaSignatureKernelState>,
    is_available: bool,
}

#[cfg(feature = "gpu-cuda")]
impl CudaSignatureKernel {
    pub fn new() -> Self {
        let config = super::BatchConfig::default();
        let state = Mutex::new(CudaSignatureKernelState::new(config));
        let is_available = Self::check_cuda_availability();
        Self {
            state,
            is_available,
        }
    }

    fn check_cuda_availability() -> bool {
        match CudaDevice::enumerate() {
            Ok(devices) => !devices.is_empty(),
            Err(_) => false,
        }
    }

    pub fn is_available_static() -> bool {
        Self::check_cuda_availability()
    }

    fn initialize_internal(&mut self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| CryptoError::InitializationFailed(format!("Mutex poisoned: {}", e)))?;

        if state.initialized {
            return Ok(());
        }

        let devices = CudaDevice::enumerate().map_err(|e| {
            CryptoError::InitializationFailed(format!("Failed to enumerate CUDA devices: {}", e))
        })?;

        if devices.is_empty() {
            return Err(CryptoError::HardwareAccelerationUnavailable(
                "No CUDA devices found".into(),
            ));
        }

        let device = devices.into_iter().next().unwrap();
        let context = CudaContext::new(&device).map_err(|e| {
            CryptoError::InitializationFailed(format!("Failed to create CUDA context: {}", e))
        })?;

        let stream = CudaStream::new().map_err(|e| {
            CryptoError::InitializationFailed(format!("Failed to create CUDA stream: {}", e))
        })?;

        let ecdsa256_kernel = CudaKernel::new(&context, CUDA_ECDSA_KERNEL, "ecdsa256_verify").ok();

        let ecdsa384_kernel = CudaKernel::new(&context, CUDA_ECDSA_KERNEL, "ecdsa384_verify").ok();

        let ecdsa521_kernel = CudaKernel::new(&context, CUDA_ECDSA_KERNEL, "ecdsa521_verify").ok();

        let ed25519_kernel = CudaKernel::new(&context, CUDA_ED25519_KERNEL, "ed25519_verify").ok();

        state.context = Some(context);
        state.device = Some(device);
        state.stream = Some(stream);
        state.ecdsa256_kernel = ecdsa256_kernel;
        state.ecdsa384_kernel = ecdsa384_kernel;
        state.ecdsa521_kernel = ecdsa521_kernel;
        state.ed25519_kernel = ed25519_kernel;
        state.initialized = true;

        Ok(())
    }

    fn shutdown_internal(&mut self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| CryptoError::InitializationFailed(format!("Mutex poisoned: {}", e)))?;

        if !state.initialized {
            return Ok(());
        }

        state.ecdsa256_kernel = None;
        state.ecdsa384_kernel = None;
        state.ecdsa521_kernel = None;
        state.ed25519_kernel = None;
        state.stream = None;
        state.context = None;
        state.memory_pool.clear();
        state.initialized = false;

        Ok(())
    }

    fn execute_ecdsa_verify_gpu(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|e| CryptoError::OperationFailed(format!("Mutex poisoned: {}", e)))?;

        let start = std::time::Instant::now();

        let ctx = state
            .context
            .as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("CUDA context not initialized".into()))?;

        let (kernel, key_size, sig_size) = match algorithm {
            Algorithm::ECDSA256 => (
                state.ecdsa256_kernel.as_ref(),
                ECDSA256_PUBLIC_KEY_SIZE,
                ECDSA256_SIGNATURE_SIZE,
            ),
            Algorithm::ECDSA384 => (
                state.ecdsa384_kernel.as_ref(),
                ECDSA384_PUBLIC_KEY_SIZE,
                ECDSA384_SIGNATURE_SIZE,
            ),
            Algorithm::ECDSA521 => (
                state.ecdsa521_kernel.as_ref(),
                ECDSA521_PUBLIC_KEY_SIZE,
                ECDSA521_SIGNATURE_SIZE,
            ),
            _ => {
                return Err(CryptoError::InvalidInput(
                    format!("Unsupported signature algorithm: {:?}", algorithm).into(),
                ));
            }
        };

        let kernel = kernel.ok_or_else(|| {
            CryptoError::NotInitialized(format!("{} kernel not loaded", algorithm).into())
        })?;

        let stream = state
            .stream
            .as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("CUDA stream not initialized".into()))?;

        if public_key.len() != key_size || signature.len() != sig_size {
            return Err(CryptoError::InvalidInput(
                format!("Invalid key or signature size for {:?}", algorithm).into(),
            ));
        }

        let total_size = key_size + data.len() + sig_size;
        let memory = Self::allocate_from_pool(&mut state.clone(), total_size)?;

        let memory_slice =
            unsafe { std::slice::from_raw_parts_mut(memory.as_ptr() as *mut u8, total_size) };
        memory_slice[..key_size].copy_from_slice(public_key);
        memory_slice[key_size..key_size + data.len()].copy_from_slice(data);
        memory_slice[key_size + data.len()..].copy_from_slice(signature);

        let key_ptr = memory.as_ptr() as *mut std::ffi::c_void;
        let data_ptr = (memory.as_ptr() as *mut u8).wrapping_add(key_size) as *mut std::ffi::c_void;
        let sig_ptr = (memory.as_ptr() as *mut u8).wrapping_add(key_size + data.len())
            as *mut std::ffi::c_void;
        let result_ptr =
            (memory.as_ptr() as *mut u8).wrapping_add(total_size - 4) as *mut std::ffi::c_void;

        let grid_dim = (1, 1, 1);
        let block_dim = (1, 1, 1);

        kernel
            .launch(
                &stream,
                grid_dim,
                block_dim,
                &[key_ptr, data_ptr, sig_ptr, &(data.len() as u32), result_ptr],
            )
            .map_err(|e| {
                CryptoError::KernelLaunchFailed(format!(
                    "Failed to launch {} kernel: {}",
                    algorithm, e
                ))
            })?;

        stream.synchronize().map_err(|e| {
            CryptoError::SynchronizationFailed(format!("Failed to synchronize stream: {}", e))
        })?;

        let result = unsafe { std::ptr::read(result_ptr as *const u32) != 0 };

        let elapsed = start.elapsed();
        let mut metrics = state
            .metrics
            .lock()
            .map_err(|e| CryptoError::OperationFailed(format!("Mutex poisoned: {}", e)))?;

        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = key_size + data.len() + sig_size + 4;
        metrics.compute_units_used = state
            .device
            .as_ref()
            .map(|d| d.compute_capability().0)
            .unwrap_or(0) as u32;

        Ok(result)
    }

    fn execute_ecdsa_verify_batch_gpu(
        &self,
        public_keys: &[&[u8]],
        data: &[&[u8]],
        signatures: &[&[u8]],
        algorithm: Algorithm,
    ) -> Result<Vec<bool>> {
        if public_keys.len() != data.len() || public_keys.len() != signatures.len() {
            return Err(CryptoError::InvalidInput("Batch sizes must match".into()));
        }

        let batch_size = public_keys.len();
        let start = std::time::Instant::now();

        let state = self
            .state
            .lock()
            .map_err(|e| CryptoError::OperationFailed(format!("Mutex poisoned: {}", e)))?;

        let stream = state
            .stream
            .as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("CUDA stream not initialized".into()))?;

        let (kernel, key_size, sig_size) = match algorithm {
            Algorithm::ECDSA256 => (
                state.ecdsa256_kernel.as_ref(),
                ECDSA256_PUBLIC_KEY_SIZE,
                ECDSA256_SIGNATURE_SIZE,
            ),
            Algorithm::ECDSA384 => (
                state.ecdsa384_kernel.as_ref(),
                ECDSA384_PUBLIC_KEY_SIZE,
                ECDSA384_SIGNATURE_SIZE,
            ),
            Algorithm::ECDSA521 => (
                state.ecdsa521_kernel.as_ref(),
                ECDSA521_PUBLIC_KEY_SIZE,
                ECDSA521_SIGNATURE_SIZE,
            ),
            _ => {
                return Err(CryptoError::InvalidInput(
                    format!("Unsupported signature algorithm: {:?}", algorithm).into(),
                ));
            }
        };

        let kernel = kernel.ok_or_else(|| {
            CryptoError::NotInitialized(format!("{} kernel not loaded", algorithm).into())
        })?;

        let max_data_len = data.iter().map(|d| d.len()).max().unwrap_or(0);
        let item_size = key_size + max_data_len + sig_size;
        let total_size = item_size * batch_size + batch_size * 4;

        let memory = CudaMemory::new(total_size).map_err(|e| {
            CryptoError::MemoryAllocationFailed(format!("Failed to allocate batch memory: {}", e))
        })?;

        let mem_ptr = memory.as_ptr() as *mut u8;

        for (i, (key, d, sig)) in public_keys
            .iter()
            .zip(data.iter())
            .zip(signatures.iter())
            .enumerate()
        {
            let offset = i * item_size;
            unsafe {
                std::ptr::copy(key.as_ptr(), mem_ptr.wrapping_add(offset), key_size);
                std::ptr::copy(d.as_ptr(), mem_ptr.wrapping_add(offset + key_size), d.len());
                std::ptr::copy(
                    sig.as_ptr(),
                    mem_ptr.wrapping_add(offset + key_size + d.len()),
                    sig_size,
                );
            }
        }

        let results_offset = batch_size * item_size;
        let result_ptr = mem_ptr.wrapping_add(results_offset) as *mut std::ffi::c_void;

        let grid_dim = (batch_size as u32, 1, 1);
        let block_dim = (1, 1, 1);

        let key_base_ptr = memory.as_ptr() as *mut std::ffi::c_void;
        let data_base_ptr =
            (memory.as_ptr() as *mut u8).wrapping_add(key_size) as *mut std::ffi::c_void;
        let sig_base_ptr = (memory.as_ptr() as *mut u8).wrapping_add(key_size + max_data_len)
            as *mut std::ffi::c_void;

        kernel
            .launch(
                &stream,
                grid_dim,
                block_dim,
                &[
                    key_base_ptr,
                    data_base_ptr,
                    sig_base_ptr,
                    &(max_data_len as u32),
                    result_ptr,
                ],
            )
            .map_err(|e| {
                CryptoError::KernelLaunchFailed(format!(
                    "Failed to launch batch {} kernel: {}",
                    algorithm, e
                ))
            })?;

        stream.synchronize().map_err(|e| {
            CryptoError::SynchronizationFailed(format!("Failed to synchronize stream: {}", e))
        })?;

        let mut results = Vec::with_capacity(batch_size);
        unsafe {
            let result_bytes = std::slice::from_raw_parts(result_ptr as *const u8, batch_size);
            for i in 0..batch_size {
                results.push(result_bytes[i] != 0);
            }
        }

        let elapsed = start.elapsed();
        let mut metrics = state
            .metrics
            .lock()
            .map_err(|e| CryptoError::OperationFailed(format!("Mutex poisoned: {}", e)))?;

        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.batch_size = batch_size;
        let total_data_size: usize = data.iter().map(|d| d.len()).sum();
        metrics.throughput_mbps =
            (total_data_size as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = total_size;

        Ok(results)
    }

    fn execute_ed25519_verify_gpu(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|e| CryptoError::OperationFailed(format!("Mutex poisoned: {}", e)))?;

        let start = std::time::Instant::now();

        let kernel = state
            .ed25519_kernel
            .as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("Ed25519 kernel not loaded".into()))?;

        let stream = state
            .stream
            .as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("CUDA stream not initialized".into()))?;

        if public_key.len() != ED25519_PUBLIC_KEY_SIZE || signature.len() != ED25519_SIGNATURE_SIZE
        {
            return Err(CryptoError::InvalidInput(
                "Invalid Ed25519 key or signature size".into(),
            ));
        }

        let total_size = ED25519_PUBLIC_KEY_SIZE + data.len() + ED25519_SIGNATURE_SIZE + 4;
        let memory = CudaMemory::new(total_size).map_err(|e| {
            CryptoError::MemoryAllocationFailed(format!("Failed to allocate memory: {}", e))
        })?;

        let mem_ptr = memory.as_ptr() as *mut u8;
        unsafe {
            std::ptr::copy(public_key.as_ptr(), mem_ptr, ED25519_PUBLIC_KEY_SIZE);
            std::ptr::copy(
                data.as_ptr(),
                mem_ptr.wrapping_add(ED25519_PUBLIC_KEY_SIZE),
                data.len(),
            );
            std::ptr::copy(
                signature.as_ptr(),
                mem_ptr.wrapping_add(ED25519_PUBLIC_KEY_SIZE + data.len()),
                ED25519_SIGNATURE_SIZE,
            );
        }

        let key_ptr = memory.as_ptr() as *mut std::ffi::c_void;
        let data_ptr = (memory.as_ptr() as *mut u8).wrapping_add(ED25519_PUBLIC_KEY_SIZE)
            as *mut std::ffi::c_void;
        let sig_ptr = (memory.as_ptr() as *mut u8)
            .wrapping_add(ED25519_PUBLIC_KEY_SIZE + data.len())
            as *mut std::ffi::c_void;
        let result_ptr =
            (memory.as_ptr() as *mut u8).wrapping_add(total_size - 4) as *mut std::ffi::c_void;

        let grid_dim = (1, 1, 1);
        let block_dim = (1, 1, 1);

        kernel
            .launch(
                &stream,
                grid_dim,
                block_dim,
                &[key_ptr, data_ptr, sig_ptr, &(data.len() as u32), result_ptr],
            )
            .map_err(|e| {
                CryptoError::KernelLaunchFailed(format!("Failed to launch Ed25519 kernel: {}", e))
            })?;

        stream.synchronize().map_err(|e| {
            CryptoError::SynchronizationFailed(format!("Failed to synchronize stream: {}", e))
        })?;

        let result = unsafe { std::ptr::read(result_ptr as *const u32) != 0 };

        let elapsed = start.elapsed();
        let mut metrics = state
            .metrics
            .lock()
            .map_err(|e| CryptoError::OperationFailed(format!("Mutex poisoned: {}", e)))?;

        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps =
            (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = total_size;

        Ok(result)
    }
}

#[cfg(feature = "gpu-cuda")]
impl super::GpuKernel for CudaSignatureKernel {
    fn kernel_type(&self) -> super::KernelType {
        super::KernelType::GpuEcdsa
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![
            Algorithm::ECDSA256,
            Algorithm::ECDSA384,
            Algorithm::ECDSA521,
            Algorithm::ED25519,
        ]
    }

    fn is_available(&self) -> bool {
        self.is_available
    }

    fn initialize(&mut self) -> Result<()> {
        self.initialize_internal()
    }

    fn shutdown(&mut self) -> Result<()> {
        self.shutdown_internal()
    }

    fn get_metrics(&self) -> Option<super::KernelMetrics> {
        self.state
            .lock()
            .ok()
            .map(|s| s.metrics.lock().unwrap().clone())
    }

    fn reset_metrics(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            let mut metrics = state.metrics.lock().unwrap();
            *metrics = super::KernelMetrics::new(super::KernelType::GpuEcdsa);
        }
    }

    fn execute_hash(&self, _data: &[u8], _algorithm: Algorithm) -> Result<Vec<u8>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support hash operation".into(),
        ))
    }

    fn execute_hash_batch(&self, _data: &[Vec<u8>], _algorithm: Algorithm) -> Result<Vec<Vec<u8>>> {
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
    ) -> Result<Vec<u8>> {
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
    ) -> Result<Vec<u8>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Signature kernel does not support AES operation".into(),
        ))
    }
}

#[cfg(feature = "gpu-cuda")]
impl Default for CudaSignatureKernel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "gpu-cuda")]
mod cuda_driver {
    use super::*;

    pub struct CudaContext {
        device: CudaDevice,
        primary: bool,
    }

    impl CudaContext {
        pub fn new(device: &CudaDevice) -> Result<Self> {
            Ok(Self {
                device: device.clone(),
                primary: true,
            })
        }
    }

    #[derive(Clone)]
    pub struct CudaDevice {
        id: usize,
        name: String,
        compute_capability: (u32, u32),
        total_memory: usize,
        max_threads_per_block: i32,
    }

    impl CudaDevice {
        pub fn enumerate() -> Result<Vec<Self>> {
            Ok(Vec::new())
        }

        pub fn compute_capability(&self) -> (u32, u32) {
            self.compute_capability
        }
    }

    pub struct CudaKernel {
        module: Vec<u8>,
        function_name: String,
    }

    impl CudaKernel {
        pub fn new(_context: &CudaContext, _ptx_code: &[u8], _name: &str) -> Result<Self> {
            Ok(Self {
                module: Vec::new(),
                function_name: String::new(),
            })
        }

        pub fn launch<S: AsRef<str>>(
            &self,
            _stream: &CudaStream,
            _grid_dim: (u32, u32, u32),
            _block_dim: (u32, u32, u32),
            _arguments: &[*mut std::ffi::c_void],
        ) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct CudaMemory {
        size: usize,
        ptr: *mut std::ffi::c_void,
        is_used: std::sync::atomic::AtomicBool,
    }

    impl CudaMemory {
        pub fn new(size: usize) -> Result<Self> {
            Ok(Self {
                size,
                ptr: std::ptr::null_mut(),
                is_used: std::sync::atomic::AtomicBool::new(false),
            })
        }

        pub fn size(&self) -> usize {
            self.size
        }

        pub fn is_free(&self) -> bool {
            !self.is_used.load(std::sync::atomic::Ordering::Relaxed)
        }

        pub fn set_used(&self, used: bool) {
            self.is_used
                .store(used, std::sync::atomic::Ordering::Relaxed);
        }

        pub fn as_ptr(&self) -> *mut std::ffi::c_void {
            self.ptr
        }

        pub fn copy_from(&self, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        pub fn copy_to(&self, _buffer: &mut [u8]) -> Result<()> {
            Ok(())
        }
    }

    pub struct CudaStream {
        id: u64,
    }

    impl CudaStream {
        pub fn new() -> Result<Self> {
            Ok(Self { id: 0 })
        }

        pub fn synchronize(&self) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(not(feature = "gpu-cuda"))]
pub struct CudaSignatureKernel;

#[cfg(not(feature = "gpu-cuda"))]
impl CudaSignatureKernel {
    pub fn new() -> Self {
        Self
    }

    pub fn is_available() -> bool {
        false
    }

    pub fn is_available_static() -> bool {
        false
    }
}
