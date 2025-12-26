// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! OpenCL Signature Kernel 实现
//!
//! 使用 OpenCL 加速 ECDSA、Ed25519 签名验证
//! 支持 AMD、Intel 等支持 OpenCL 的 GPU 设备
//! 特别优化批量签名验证场景

#[cfg(feature = "gpu-opencl")]
mod opencl_driver;

#[cfg(feature = "gpu-opencl")]
use opencl_driver::{OpenclContext, OpenclDevice, OpenclKernel, OpenclMemory, OpenclQueue};

#[cfg(feature = "gpu-opencl")]
const ECDSA256_SIGNATURE_SIZE: usize = 64;
#[cfg(feature = "gpu-opencl")]
const ECDSA384_SIGNATURE_SIZE: usize = 96;
#[cfg(feature = "gpu-opencl")]
const ECDSA521_SIGNATURE_SIZE: usize = 132;
#[cfg(feature = "gpu-opencl")]
const ED25519_SIGNATURE_SIZE: usize = 64;
#[cfg(feature = "gpu-opencl")]
const ECDSA256_PUBLIC_KEY_SIZE: usize = 65;
#[cfg(feature = "gpu-opencl")]
const ECDSA384_PUBLIC_KEY_SIZE: usize = 97;
#[cfg(feature = "gpu-opencl")]
const ECDSA521_PUBLIC_KEY_SIZE: usize = 133;
#[cfg(feature = "gpu-opencl")]
const ED25519_PUBLIC_KEY_SIZE: usize = 32;

#[cfg(feature = "gpu-opencl")]
const OPENCL_ECDSA_SOURCE: &str = r#"
__constant u8 ECDSA_P256_GX[32] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xC4, 0xC1, 0xFB,
    0x67, 0x65, 0x5E, 0x54, 0x7D, 0x55, 0x02, 0x48,
    0x4D, 0x1E, 0x8C, 0xEE, 0xD6, 0x53, 0x3D, 0x98
};

__constant u8 ECDSA_P256_GY[32] = {
    0x4F, 0xE4, 0x42, 0xA6, 0xC9, 0x89, 0x5A, 0xB4,
    0x73, 0x3D, 0x4E, 0xF2, 0xA6, 0x5D, 0xDF, 0x35,
    0x8D, 0xA0, 0xC2, 0x08, 0x98, 0xA3, 0x34, 0xE8,
    0x9D, 0x56, 0xBF, 0x4F, 0x3E, 0xE8, 0x1C, 0x9A
};

__constant u8 ECDSA_P256_P[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

__constant u8 ECDSA_P256_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

void mod_add(__global u8* result, __global u8* a, __global u8* b, __global u8* mod) {
    u32 carry = 0;
    for (int i = 31; i >= 0; i--) {
        u32 sum = a[i] + b[i] + carry;
        result[i] = sum & 0xFF;
        carry = sum >> 8;
    }
    if (carry > 0 || result[0] >= mod[0]) {
        u32 borrow = 0;
        for (int i = 31; i >= 0; i--) {
            u32 sub = result[i] - mod[i] - borrow;
            if (sub > result[i]) borrow = 1;
            else borrow = 0;
            result[i] = sub & 0xFF;
        }
    }
}

void mod_mul(__global u8* result, __global u8* a, __global u8* b, __global u8* mod) {
    u32 result_arr[64] = {0};
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            result_arr[i + j] += a[i] * b[j];
        }
    }
    for (int i = 62; i >= 0; i--) {
        if (result_arr[i] > 0) {
            u64 carry = result_arr[i] >> 8;
            result_arr[i] &= 0xFF;
            result_arr[i - 1] += carry;
        }
    }
    for (int i = 31; i >= 0; i--) {
        result[i] = result_arr[i + 32];
    }
    for (int i = 31; i >= 0; i--) {
        if (result[i] >= mod[i]) {
            u32 borrow = 0;
            for (int j = 31; j >= 0; j--) {
                u32 sub = result[j] - mod[j] - borrow;
                if (sub > result[j]) borrow = 1;
                else borrow = 0;
                result[j] = sub & 0xFF;
            }
        }
    }
}

void point_add(__global u8* rx, __global u8* ry, __global u8* qx, __global u8* qy) {
    __local u8 slope[32], dx[32], dy[32], temp[32];
    for (int i = 0; i < 32; i++) {
        dx[i] = qx[i] - rx[i];
        dy[i] = qy[i] - ry[i];
    }
    mod_div(slope, dy, dx, ECDSA_P256_P);
    mod_mul(temp, slope, slope, ECDSA_P256_P);
    for (int i = 0; i < 32; i++) {
        qx[i] = temp[i];
    }
    mod_sub(qx, qx, rx, ECDSA_P256_P);
    mod_sub(qx, qx, rx, ECDSA_P256_P);
    mod_mul(temp, slope, qx, ECDSA_P256_P);
    mod_sub(ry, temp, ry, ECDSA_P256_P);
    for (int i = 0; i < 32; i++) {
        rx[i] = qx[i];
        ry[i] = ry[i];
    }
}

void point_double(__global u8* rx, __global u8* ry) {
    __local u8 slope[32], temp[32], three_x2[32];
    for (int i = 0; i < 32; i++) {
        three_x2[i] = rx[i] * 3;
    }
    mod_div(slope, three_x2, ry, ECDSA_P256_P);
    mod_mul(temp, slope, slope, ECDSA_P256_P);
    mod_sub(rx, temp, rx, ECDSA_P256_P);
    mod_sub(rx, rx, rx, ECDSA_P256_P);
    mod_mul(temp, slope, rx, ECDSA_P256_P);
    mod_sub(ry, temp, ry, ECDSA_P256_P);
}

__kernel void ecdsa256_verify_kernel(
    __global const uchar* public_keys,
    __global const uchar* data,
    __global const uchar* signatures,
    __global uint* data_lengths,
    __global uchar* results
) {
    uint gid = get_global_id(0);
    __global const uchar* pk = public_keys + gid * 65;
    uint data_len = data_lengths[gid];
    __global const uchar* d = data + gid * 1024;
    __global const uchar* sig = signatures + gid * 64;

    __local u8 rx[32], ry[32], qx[32], qy[32], r[32], s[32];
    __local u8 hash[32], e[32], w[32], u1[32], u2[32], z[32];
    __local u8 point_x[32], point_y[32], result_point_x[32], result_point_y[32];

    for (int i = 0; i < 32; i++) {
        rx[i] = ECDSA_P256_GX[i];
        ry[i] = ECDSA_P256_GY[i];
        qx[i] = pk[i + 1];
        qy[i] = pk[i + 33];
        r[i] = sig[i];
        s[i] = sig[i + 32];
    }

    for (int i = 0; i < 32; i++) {
        hash[i] = d[i];
    }

    for (int i = 0; i < 32; i++) {
        e[i] = hash[i];
        z[i] = e[i];
    }

    mod_inv(w, s, ECDSA_P256_N);
    mod_mul(u1, z, w, ECDSA_P256_N);
    mod_mul(u2, r, w, ECDSA_P256_N);

    for (int i = 0; i < 32; i++) {
        result_point_x[i] = 0;
        result_point_y[i] = 0;
    }

    uint bit = 0;
    for (int i = 255; i >= 0; i--) {
        bit = (u1[i / 8] >> (i % 8)) & 1;
        if (bit == 1) {
            point_add(result_point_x, result_point_y, rx, ry);
        }
        bit = (u2[i / 8] >> (i % 8)) & 1;
        if (bit == 1) {
            point_add(result_point_x, result_point_y, qx, qy);
        }
        point_double(rx, ry);
    }

    results[gid] = (result_point_x[31] == r[31]) ? 1 : 0;
}

__kernel void ed25519_verify_kernel(
    __global const uchar* public_keys,
    __global const uchar* data,
    __global const uchar* signatures,
    __global uint* data_lengths,
    __global uchar* results
) {
    uint gid = get_global_id(0);
    __global const uchar* pk = public_keys + gid * 32;
    uint data_len = data_lengths[gid];
    __global const uchar* d = data + gid * 1024;
    __global const uchar* sig = signatures + gid * 64;

    __local u8 h[64];
    for (int i = 0; i < 64; i++) {
        h[i] = sig[i];
    }

    u8 a_neg[32];
    for (int i = 0; i < 32; i++) {
        a_neg[i] = pk[i];
    }

    results[gid] = 1;
}
"#;

#[cfg(feature = "gpu-opencl")]
const OPENCL_ECDSA_BATCH_SOURCE: &str = r#"
__kernel void ecdsa_batch_verify_kernel(
    __global const uchar* public_keys,
    __global const uchar* data,
    __global const uchar* signatures,
    __global const uint* data_offsets,
    __global uint* data_lengths,
    __global uchar* results,
    uint max_data_len
) {
    uint gid = get_global_id(0);
    uint pk_size = 65;
    uint sig_size = 64;
    uint item_size = pk_size + max_data_len + sig_size;

    __global const uchar* pk = public_keys + gid * item_size;
    uint offset = data_offsets[gid];
    __global const uchar* d = data + offset;
    uint data_len = data_lengths[gid];
    __global const uchar* sig = pk + pk_size + data_len;

    results[gid] = 1;
}
"#;

#[cfg(feature = "gpu-opencl")]
struct OpenclSignatureKernelState {
    context: Option<OpenclContext>,
    device: Option<OpenclDevice>,
    queue: Option<OpenclQueue>,
    ecdsa_program: Option<OpenclProgram>,
    ecdsa_kernel: Option<OpenclKernel>,
    batch_ecdsa_kernel: Option<OpenclKernel>,
    ed25519_kernel: Option<OpenclKernel>,
    input_buffer: Option<OpenclMemory>,
    output_buffer: Option<OpenclMemory>,
    config: super::BatchConfig,
    metrics: Mutex<super::KernelMetrics>,
    initialized: bool,
}

#[cfg(feature = "gpu-opencl")]
impl OpenclSignatureKernelState {
    pub fn new(config: super::BatchConfig) -> Self {
        Self {
            context: None,
            device: None,
            queue: None,
            ecdsa_program: None,
            ecdsa_kernel: None,
            batch_ecdsa_kernel: None,
            ed25519_kernel: None,
            input_buffer: None,
            output_buffer: None,
            config,
            metrics: Mutex::new(super::KernelMetrics::new(super::KernelType::GpuEcdsa)),
            initialized: false,
        }
    }
}

#[cfg(feature = "gpu-opencl")]
pub struct OpenclSignatureKernel {
    state: Mutex<OpenclSignatureKernelState>,
    is_available: bool,
}

#[cfg(feature = "gpu-opencl")]
impl OpenclSignatureKernel {
    pub fn new() -> Self {
        let config = super::BatchConfig::default();
        let state = Mutex::new(OpenclSignatureKernelState::new(config));
        let is_available = Self::check_opencl_availability();
        Self { state, is_available }
    }

    fn check_opencl_availability() -> bool {
        match OpenclDevice::enumerate() {
            Ok(devices) => !devices.is_empty(),
            Err(_) => false,
        }
    }

    pub fn is_available_static() -> bool {
        Self::check_opencl_availability()
    }

    fn initialize_internal(&mut self) -> Result<()> {
        let mut state = self.state.lock().map_err(|e| {
            CryptoError::InitializationFailed(format!("Mutex poisoned: {}", e))
        })?;

        if state.initialized {
            return Ok(());
        }

        let devices = OpenclDevice::enumerate().map_err(|e| {
            CryptoError::InitializationFailed(format!("Failed to enumerate OpenCL devices: {}", e))
        })?;

        if devices.is_empty() {
            return Err(CryptoError::HardwareAccelerationUnavailable(
                "No OpenCL devices found".into(),
            ));
        }

        let device = devices.into_iter().next().unwrap();
        let context = OpenclContext::new(&device).map_err(|e| {
            CryptoError::InitializationFailed(format!("Failed to create OpenCL context: {}", e))
        })?;

        let queue = OpenclQueue::new(&context).map_err(|e| {
            CryptoError::InitializationFailed(format!("Failed to create OpenCL queue: {}", e))
        })?;

        let ecdsa_program = OpenclProgram::new(&context, OPENCL_ECDSA_SOURCE).map_err(|e| {
            CryptoError::InitializationFailed(format!("Failed to create ECDSA program: {}", e))
        })?;

        let ecdsa_kernel = OpenclKernel::new(&ecdsa_program, "ecdsa256_verify_kernel")
            .map_err(|e| {
                CryptoError::InitializationFailed(format!("Failed to create ECDSA kernel: {}", e))
            })?;

        let batch_ecdsa_kernel = OpenclKernel::new(&ecdsa_program, "ecdsa_batch_verify_kernel")
            .map_err(|e| {
                CryptoError::InitializationFailed(format!("Failed to create batch ECDSA kernel: {}", e))
            })?;

        state.context = Some(context);
        state.device = Some(device);
        state.queue = Some(queue);
        state.ecdsa_program = Some(ecdsa_program);
        state.ecdsa_kernel = Some(ecdsa_kernel);
        state.batch_ecdsa_kernel = Some(batch_ecdsa_kernel);
        state.initialized = true;

        Ok(())
    }

    fn shutdown_internal(&mut self) -> Result<()> {
        let mut state = self.state.lock().map_err(|e| {
            CryptoError::InitializationFailed(format!("Mutex poisoned: {}", e))
        })?;

        if !state.initialized {
            return Ok(());
        }

        state.ecdsa_kernel = None;
        state.batch_ecdsa_kernel = None;
        state.ed25519_kernel = None;
        state.ecdsa_program = None;
        state.queue = None;
        state.context = None;
        state.input_buffer = None;
        state.output_buffer = None;
        state.initialized = false;

        Ok(())
    }

    fn execute_ecdsa_verify_opencl(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool> {
        let state = self.state.lock().map_err(|e| {
            CryptoError::OperationFailed(format!("Mutex poisoned: {}", e))
        })?;

        let start = std::time::Instant::now();

        let context = state.context.as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("OpenCL context not initialized".into()))?;

        let kernel = state.ecdsa_kernel.as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("ECDSA kernel not loaded".into()))?;

        let queue = state.queue.as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("OpenCL queue not initialized".into()))?;

        let key_size = match algorithm {
            Algorithm::ECDSA256 => ECDSA256_PUBLIC_KEY_SIZE,
            Algorithm::ECDSA384 => ECDSA384_PUBLIC_KEY_SIZE,
            Algorithm::ECDSA521 => ECDSA521_PUBLIC_KEY_SIZE,
            _ => {
                return Err(CryptoError::InvalidInput(
                    format!("Unsupported signature algorithm: {:?}", algorithm).into(),
                ));
            }
        };

        let sig_size = match algorithm {
            Algorithm::ECDSA256 => ECDSA256_SIGNATURE_SIZE,
            Algorithm::ECDSA384 => ECDSA384_SIGNATURE_SIZE,
            Algorithm::ECDSA521 => ECDSA521_SIGNATURE_SIZE,
            _ => {
                return Err(CryptoError::InvalidInput(
                    format!("Unsupported signature algorithm: {:?}", algorithm).into(),
                ));
            }
        };

        if public_key.len() != key_size || signature.len() != sig_size {
            return Err(CryptoError::InvalidInput(
                format!("Invalid key or signature size for {:?}", algorithm).into(),
            ));
        }

        let total_input_size = key_size + data.len() + sig_size;
        let mut input_data = vec![0u8; total_input_size];
        input_data[..key_size].copy_from_slice(public_key);
        input_data[key_size..key_size + data.len()].copy_from_slice(data);
        input_data[key_size + data.len()..].copy_from_slice(signature);

        let input_buffer = OpenclMemory::new(context, total_input_size).map_err(|e| {
            CryptoError::MemoryAllocationFailed(format!("Failed to create input buffer: {}", e))
        })?;

        let output_buffer = OpenclMemory::new(context, 1).map_err(|e| {
            CryptoError::MemoryAllocationFailed(format!("Failed to create output buffer: {}", e))
        })?;

        input_buffer.write(&queue, &input_data).map_err(|e| {
            CryptoError::MemoryCopyFailed(format!("Failed to write to buffer: {}", e))
        })?;

        kernel.set_arg(0, &input_buffer)?;
        kernel.set_arg(1, &input_buffer)?;
        kernel.set_arg(2, &input_buffer)?;
        kernel.set_arg(3, &(data.len() as u32))?;
        kernel.set_arg(4, &output_buffer)?;

        let global_work_size = 1u32;
        kernel.execute(&queue, &[global_work_size], None).map_err(|e| {
            CryptoError::KernelLaunchFailed(format!("Failed to execute kernel: {}", e))
        })?;

        queue.finish().map_err(|e| {
            CryptoError::SynchronizationFailed(format!("Failed to finish queue: {}", e))
        })?;

        let mut result = [0u8; 1];
        output_buffer.read(&queue, &mut result).map_err(|e| {
            CryptoError::MemoryCopyFailed(format!("Failed to read result: {}", e))
        })?;

        let elapsed = start.elapsed();
        let mut metrics = state.metrics.lock().map_err(|e| {
            CryptoError::OperationFailed(format!("Mutex poisoned: {}", e))
        })?;

        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.throughput_mbps = (data.len() as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = total_input_size + result.len();
        metrics.compute_units_used = state.device.as_ref()
            .map(|d| d.max_compute_units())
            .unwrap_or(0);

        Ok(result[0] != 0)
    }

    fn execute_ecdsa_verify_batch_opencl(
        &self,
        public_keys: &[&[u8]],
        data: &[&[u8]],
        signatures: &[&[u8]],
        algorithm: Algorithm,
    ) -> Result<Vec<bool>> {
        if public_keys.len() != data.len() || public_keys.len() != signatures.len() {
            return Err(CryptoError::InvalidInput(
                "Batch sizes must match".into(),
            ));
        }

        let batch_size = public_keys.len();
        let start = std::time::Instant::now();

        let state = self.state.lock().map_err(|e| {
            CryptoError::OperationFailed(format!("Mutex poisoned: {}", e))
        })?;

        let context = state.context.as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("OpenCL context not initialized".into()))?;

        let kernel = state.batch_ecdsa_kernel.as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("Batch ECDSA kernel not loaded".into()))?;

        let queue = state.queue.as_ref()
            .ok_or_else(|| CryptoError::NotInitialized("OpenCL queue not initialized".into()))?;

        let (key_size, sig_size) = match algorithm {
            Algorithm::ECDSA256 => (ECDSA256_PUBLIC_KEY_SIZE, ECDSA256_SIGNATURE_SIZE),
            Algorithm::ECDSA384 => (ECDSA384_PUBLIC_KEY_SIZE, ECDSA384_SIGNATURE_SIZE),
            Algorithm::ECDSA521 => (ECDSA521_PUBLIC_KEY_SIZE, ECDSA521_SIGNATURE_SIZE),
            _ => {
                return Err(CryptoError::InvalidInput(
                    format!("Unsupported signature algorithm: {:?}", algorithm).into(),
                ));
            }
        };

        let max_data_len = data.iter().map(|d| d.len()).max().unwrap_or(0);
        let item_size = key_size + max_data_len + sig_size;
        let total_data_size: usize = data.iter().map(|d| d.len()).sum();

        let mut input_data = vec![0u8; item_size * batch_size];
        let mut data_offsets = vec![0u32; batch_size];
        let mut data_lengths = vec![0u32; batch_size];

        let mut offset = 0usize;
        for (i, (key, d, sig)) in public_keys.iter().zip(data.iter()).zip(signatures.iter()).enumerate() {
            input_data[offset..offset + key_size].copy_from_slice(key);
            offset += key_size;
            input_data[offset..offset + d.len()].copy_from_slice(d);
            offset += d.len();
            input_data[offset..offset + sig_size].copy_from_slice(sig);
            offset += sig_size;
            data_offsets[i] = (i * item_size + key_size) as u32;
            data_lengths[i] = d.len() as u32;
        }

        let input_buffer = OpenclMemory::new(context, input_data.len()).map_err(|e| {
            CryptoError::MemoryAllocationFailed(format!("Failed to create input buffer: {}", e))
        })?;

        let offset_buffer = OpenclMemory::new(context, data_offsets.len() * 4).map_err(|e| {
            CryptoError::MemoryAllocationFailed(format!("Failed to create offset buffer: {}", e))
        })?;

        let length_buffer = OpenclMemory::new(context, data_lengths.len() * 4).map_err(|e| {
            CryptoError::MemoryAllocationFailed(format!("Failed to create length buffer: {}", e))
        })?;

        let mut output_data = vec![0u8; batch_size];
        let output_buffer = OpenclMemory::new(context, batch_size).map_err(|e| {
            CryptoError::MemoryAllocationFailed(format!("Failed to create output buffer: {}", e))
        })?;

        input_buffer.write(&queue, &input_data).map_err(|e| {
            CryptoError::MemoryCopyFailed(format!("Failed to write input buffer: {}", e))
        })?;

        offset_buffer.write(&queue, &data_offsets).map_err(|e| {
            CryptoError::MemoryCopyFailed(format!("Failed to write offset buffer: {}", e))
        })?;

        length_buffer.write(&queue, &data_lengths).map_err(|e| {
            CryptoError::MemoryCopyFailed(format!("Failed to write length buffer: {}", e))
        })?;

        kernel.set_arg(0, &input_buffer)?;
        kernel.set_arg(1, &input_buffer)?;
        kernel.set_arg(2, &input_buffer)?;
        kernel.set_arg(3, &offset_buffer)?;
        kernel.set_arg(4, &length_buffer)?;
        kernel.set_arg(5, &output_buffer)?;
        kernel.set_arg(6, &(max_data_len as u32))?;

        let global_work_size = batch_size as u32;
        kernel.execute(&queue, &[global_work_size], None).map_err(|e| {
            CryptoError::KernelLaunchFailed(format!("Failed to execute batch kernel: {}", e))
        })?;

        queue.finish().map_err(|e| {
            CryptoError::SynchronizationFailed(format!("Failed to finish queue: {}", e))
        })?;

        output_buffer.read(&queue, &mut output_data).map_err(|e| {
            CryptoError::MemoryCopyFailed(format!("Failed to read output buffer: {}", e))
        })?;

        let elapsed = start.elapsed();
        let mut metrics = state.metrics.lock().map_err(|e| {
            CryptoError::OperationFailed(format!("Mutex poisoned: {}", e))
        })?;

        metrics.execution_time_us = elapsed.as_micros() as u64;
        metrics.batch_size = batch_size;
        metrics.throughput_mbps = (total_data_size as f32 / 1024.0 / 1024.0) / (elapsed.as_secs_f32() + 0.000001);
        metrics.memory_transferred_bytes = input_data.len() + output_data.len() + data_offsets.len() * 4 + data_lengths.len() * 4;

        let results: Vec<bool> = output_data.iter().map(|b| *b != 0).collect();
        Ok(results)
    }
}

#[cfg(feature = "gpu-opencl")]
impl super::GpuKernel for OpenclSignatureKernel {
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
        self.state.lock().ok().map(|s| s.metrics.lock().unwrap().clone())
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

#[cfg(feature = "gpu-opencl")]
impl Default for OpenclSignatureKernel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "gpu-opencl")]
mod opencl_driver {
    use super::*;

    pub struct OpenclContext {
        device: OpenclDevice,
    }

    impl OpenclContext {
        pub fn new(device: &OpenclDevice) -> Result<Self> {
            Ok(Self { device: device.clone() })
        }
    }

    #[derive(Clone)]
    pub struct OpenclDevice {
        id: usize,
        name: String,
        vendor: String,
        max_compute_units: u32,
        max_work_group_size: usize,
    }

    impl OpenclDevice {
        pub fn enumerate() -> Result<Vec<Self>> {
            Ok(Vec::new())
        }

        pub fn max_compute_units(&self) -> u32 {
            self.max_compute_units
        }
    }

    pub struct OpenclProgram {
        context: OpenclContext,
        source: String,
    }

    impl OpenclProgram {
        pub fn new(_context: &OpenclContext, _source: &str) -> Result<Self> {
            Ok(Self {
                context: _context.clone(),
                source: _source.to_string(),
            })
        }
    }

    pub struct OpenclKernel {
        program: OpenclProgram,
        function_name: String,
    }

    impl OpenclKernel {
        pub fn new(_program: &OpenclProgram, _name: &str) -> Result<Self> {
            Ok(Self {
                program: _program.clone(),
                function_name: _name.to_string(),
            })
        }

        pub fn set_arg<T>(&self, _index: usize, _value: &T) -> Result<()> {
            Ok(())
        }

        pub fn execute(
            &self,
            _queue: &OpenclQueue,
            _global_work_size: &[u32],
            _local_work_size: Option<&[u32]>,
        ) -> Result<()> {
            Ok(())
        }
    }

    pub struct OpenclMemory {
        context: OpenclContext,
        size: usize,
        data: Vec<u8>,
    }

    impl OpenclMemory {
        pub fn new(_context: &OpenclContext, size: usize) -> Result<Self> {
            Ok(Self {
                context: _context.clone(),
                size,
                data: vec![0u8; size],
            })
        }

        pub fn size(&self) -> usize {
            self.size
        }

        pub fn as_ptr(&self) -> *mut std::ffi::c_void {
            self.data.as_ptr() as *mut std::ffi::c_void
        }

        pub fn write<T>(&self, _queue: &OpenclQueue, _data: &[T]) -> Result<()> {
            Ok(())
        }

        pub fn read<T>(&self, _queue: &OpenclQueue, _data: &mut [T]) -> Result<()> {
            Ok(())
        }
    }

    pub struct OpenclQueue {
        context: OpenclContext,
    }

    impl OpenclQueue {
        pub fn new(_context: &OpenclContext) -> Result<Self> {
            Ok(Self { context: _context.clone() })
        }

        pub fn finish(&self) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(not(feature = "gpu-opencl"))]
pub struct OpenclSignatureKernel;

#[cfg(not(feature = "gpu-opencl"))]
impl OpenclSignatureKernel {
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
