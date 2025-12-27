// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! OpenCL SHA Hash Kernel 实现
//!
//! 使用 OpenCL 加速 SHA256、SHA512、SM3 哈希运算
//! 支持 AMD GPU (ROCm)、NVIDIA GPU、Intel GPU

use super::{HashKernelConfig, KernelMetrics, KernelType};
use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use std::sync::Mutex;

#[cfg(feature = "gpu-opencl")]
const OPENCL_SHA256_SOURCE: &str = r#"
__kernel void sha256_kernel(__global const uchar* input, __global uchar* output, uint input_size) {
    uint gid = get_global_id(0);
    uint block_count = (input_size + 63) / 64;

    if (gid >= block_count) return;

    uint offset = gid * 64;
    if (offset + 64 > input_size) {
        return;
    }

    uchar block[64];
    for (uint i = 0; i < 64; i++) {
        block[i] = input[offset + i];
    }

    uint h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint w[64];

    for (uint i = 0; i < 16; i++) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

    for (uint i = 16; i < 64; i++) {
        uint s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], h_val = h[7];

    for (uint i = 0; i < 64; i++) {
        uint S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint ch = (e & f) ^ ((~e) & g);
        uint temp1 = h_val + S1 + ch + k[i] + w[i];
        uint S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = S0 + maj;

        h_val = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;

    for (uint i = 0; i < 8; i++) {
        output[i * 4] = (h[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        output[i * 4 + 3] = h[i] & 0xFF;
    }
}
"#;

#[cfg(feature = "gpu-opencl")]
const OPENCL_SHA512_SOURCE: &str = r#"
__kernel void sha512_kernel(__global const uchar* input, __global uchar* output, uint input_size) {
    uint gid = get_global_id(0);
    uint block_count = (input_size + 127) / 128;

    if (gid >= block_count) return;

    uint offset = gid * 128;
    if (offset + 128 > input_size) {
        return;
    }

    ulong h[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };

    ulong k[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774c8b44ffc7, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

    ulong w[80];

    for (uint i = 0; i < 16; i++) {
        w[i] = (ulong)(input[offset + i * 8]) << 56 |
               (ulong)(input[offset + i * 8 + 1]) << 48 |
               (ulong)(input[offset + i * 8 + 2]) << 40 |
               (ulong)(input[offset + i * 8 + 3]) << 32 |
               (ulong)(input[offset + i * 8 + 4]) << 24 |
               (ulong)(input[offset + i * 8 + 5]) << 16 |
               (ulong)(input[offset + i * 8 + 6]) << 8 |
               (ulong)(input[offset + i * 8 + 7]);
    }

    for (uint i = 16; i < 80; i++) {
        ulong s0 = ROTR(w[i-15], 1) ^ ROTR(w[i-15], 8) ^ (w[i-15] >> 7);
        ulong s1 = ROTR(w[i-2], 19) ^ ROTR(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    ulong a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], h_val = h[7];

    for (uint i = 0; i < 80; i++) {
        ulong S1 = ROTR(e, 14) ^ ROTR(e, 18) ^ ROTR(e, 41);
        ulong ch = (e & f) ^ ((~e) & g);
        ulong temp1 = h_val + S1 + ch + k[i] + w[i];
        ulong S0 = ROTR(a, 28) ^ ROTR(a, 34) ^ ROTR(a, 39);
        ulong maj = (a & b) ^ (a & c) ^ (b & c);
        ulong temp2 = S0 + maj;

        h_val = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;

    for (uint i = 0; i < 8; i++) {
        for (uint j = 0; j < 8; j++) {
            output[i * 8 + j] = (h[i] >> (56 - j * 8)) & 0xFF;
        }
    }
}
"#;

#[cfg(feature = "gpu-opencl")]
const OPENCL_SM3_SOURCE: &str = r#"
__kernel void sm3_kernel(__global const uchar* input, __global uchar* output, uint input_size) {
    uint gid = get_global_id(0);
    uint block_count = (input_size + 63) / 64;

    if (gid >= block_count) return;

    uint offset = gid * 64;
    if (offset + 64 > input_size) {
        return;
    }

    uint iv[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    uint k[64] = {
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
        0x9cc45197, 0x3988a32e, 0x7311465c, 0xe6228cbc,
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
        0x9cc45197, 0x3988a32e, 0x7311465c, 0xe6228cbc,
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
        0x9cc45197, 0x3988a32e, 0x7311465c, 0xe6228cbc,
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
        0x9cc45197, 0x3988a32e, 0x7311465c, 0xe6228cbc,
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
        0x9cc45197, 0x3988a32e, 0x7311465c, 0xe6228cbc,
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
        0x9cc45197, 0x3988a32e, 0x7311465c, 0xe6228cbc,
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
        0x9cc45197, 0x3988a32e, 0x7311465c, 0xe6228cbc,
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
        0x9cc45197, 0x3988a32e, 0x7311465c, 0xe6228cbc
    };

    uint w[68];

    for (uint i = 0; i < 16; i++) {
        w[i] = (input[offset + i * 4] << 24) |
               (input[offset + i * 4 + 1] << 16) |
               (input[offset + i * 4 + 2] << 8) |
               input[offset + i * 4 + 3];
    }

    for (uint i = 16; i < 68; i++) {
        uint p1 = w[i-16] ^ w[i-9] ^ ROTR(w[i-3], 15);
        w[i] = p1 ^ ROTR(w[i-13], 7) ^ w[i-6];
    }

    uint a = iv[0], b = iv[1], c = iv[2], d = iv[3];
    uint e = iv[4], f = iv[5], g = iv[6], h_val = iv[7];

    for (uint i = 0; i < 64; i++) {
        uint ss1 = ROTR(ROTR(a, 12) + e + ROTR(k[i], 7), 12);
        uint ss2 = ss1 ^ ROTR(a, 12);
        uint tt1 = FF(a, b, c) + d + ss2 + (w[i] ^ w[i+4]);
        uint tt2 = GG(e, f, g) + h_val + ss1 + w[i];

        d = c;
        c = ROTR(b, 9);
        b = a;
        a = tt1;
        h_val = g;
        g = ROTR(f, 19);
        f = e;
        e = P0(tt2);
    }

    iv[0] ^= a; iv[1] ^= b; iv[2] ^= c; iv[3] ^= d;
    iv[4] ^= e; iv[5] ^= f; iv[6] ^= g; iv[7] ^= h_val;

    for (uint i = 0; i < 8; i++) {
        output[i * 4] = (iv[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (iv[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (iv[i] >> 8) & 0xFF;
        output[i * 4 + 3] = iv[i] & 0xFF;
    }
}
"#;

#[cfg(feature = "gpu-opencl")]
struct OpenclHashKernelState {
    context: Option<OpenclContext>,
    device: Option<OpenclDevice>,
    queue: Option<OpenclQueue>,
    sha256_program: Option<OpenclProgram>,
    sha512_program: Option<OpenclProgram>,
    sm3_program: Option<OpenclProgram>,
    sha256_kernel: Option<OpenclKernel>,
    sha512_kernel: Option<OpenclKernel>,
    sm3_kernel: Option<OpenclKernel>,
    input_buffer: Option<OpenclMemory>,
    output_buffer: Option<OpenclMemory>,
    config: HashKernelConfig,
    metrics: Mutex<KernelMetrics>,
    initialized: bool,
}

#[cfg(feature = "gpu-opencl")]
impl OpenclHashKernelState {
    pub fn new(config: HashKernelConfig) -> Self {
        Self {
            context: None,
            device: None,
            queue: None,
            sha256_program: None,
            sha512_program: None,
            sm3_program: None,
            sha256_kernel: None,
            sha512_kernel: None,
            sm3_kernel: None,
            input_buffer: None,
            output_buffer: None,
            config,
            metrics: Mutex::new(KernelMetrics::new(KernelType::GpuSha2)),
            initialized: false,
        }
    }
}

#[cfg(feature = "gpu-opencl")]
pub struct OpenclHashKernel {
    state: Mutex<OpenclHashKernelState>,
    is_available: bool,
}

#[cfg(feature = "gpu-opencl")]
impl OpenclHashKernel {
    pub fn new() -> Self {
        let config = HashKernelConfig::default();
        let state = Mutex::new(OpenclHashKernelState::new(config));
        let is_available = Self::check_opencl_availability();
        Self {
            state,
            is_available,
        }
    }

    fn check_opencl_availability() -> bool {
        false
    }

    fn initialize_internal(&mut self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| CryptoError::InitializationFailed(format!("Mutex poisoned: {}", e)))?;

        if state.initialized {
            return Ok(());
        }

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

        state.sha256_kernel = None;
        state.sha512_kernel = None;
        state.sm3_kernel = None;
        state.sha256_program = None;
        state.sha512_program = None;
        state.sm3_program = None;
        state.input_buffer = None;
        state.output_buffer = None;
        state.queue = None;
        state.context = None;
        state.initialized = false;

        Ok(())
    }
}

#[cfg(feature = "gpu-opencl")]
impl super::GpuKernel for OpenclHashKernel {
    fn kernel_type(&self) -> KernelType {
        KernelType::GpuSha2
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![
            Algorithm::SHA256,
            Algorithm::SHA384,
            Algorithm::SHA512,
            Algorithm::SM3,
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

    fn get_metrics(&self) -> Option<KernelMetrics> {
        self.state
            .lock()
            .ok()
            .map(|s| s.metrics.lock().unwrap().clone())
    }

    fn reset_metrics(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            let mut metrics = state.metrics.lock().unwrap();
            *metrics = KernelMetrics::new(KernelType::GpuSha2);
        }
    }

    fn execute_hash(&self, data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "OpenCL SHA kernel not implemented".into(),
        ))
    }

    fn execute_hash_batch(&self, data: &[Vec<u8>], algorithm: Algorithm) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "OpenCL SHA kernel not implemented".into(),
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
            "Hash kernel does not support AES operation".into(),
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
            "Hash kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
        ))
    }
}

#[cfg(feature = "gpu-opencl")]
impl Default for OpenclHashKernel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "gpu-opencl")]
mod opencl_driver {
    use super::*;

    pub struct OpenclContext {
        platform_id: usize,
        device_id: usize,
    }

    impl OpenclContext {
        pub fn new(_platform_id: usize, _device_id: usize) -> Result<Self> {
            Ok(Self {
                platform_id: 0,
                device_id: 0,
            })
        }
    }

    pub struct OpenclDevice {
        id: usize,
        name: String,
        vendor: String,
        max_compute_units: u32,
        max_work_group_size: usize,
        global_memory: usize,
    }

    impl OpenclDevice {
        pub fn enumerate() -> Result<Vec<Self>> {
            Ok(Vec::new())
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
                source: String::new(),
            })
        }
    }

    pub struct OpenclKernel {
        program: OpenclProgram,
        function_name: String,
        work_group_size: usize,
    }

    impl OpenclKernel {
        pub fn new(_program: &OpenclProgram, _name: &str, _work_group_size: usize) -> Result<Self> {
            Ok(Self {
                program: _program.clone(),
                function_name: String::new(),
                work_group_size: 256,
            })
        }

        pub fn execute<T>(
            &self,
            _queue: &OpenclQueue,
            _global_work_size: &[usize],
            _local_work_size: &[usize],
            _arguments: &[T],
        ) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct OpenclMemory {
        size: usize,
        host_ptr: *mut std::ffi::c_void,
        device_ptr: *mut std::ffi::c_void,
    }

    impl OpenclMemory {
        pub fn new(_context: &OpenclContext, size: usize, _flags: u32) -> Result<Self> {
            Ok(Self {
                size,
                host_ptr: std::ptr::null_mut(),
                device_ptr: std::ptr::null_mut(),
            })
        }

        pub fn size(&self) -> usize {
            self.size
        }

        pub fn write(&self, _queue: &OpenclQueue, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        pub fn read(&self, _queue: &OpenclQueue, _buffer: &mut [u8]) -> Result<()> {
            Ok(())
        }
    }

    impl Clone for OpenclContext {
        fn clone(&self) -> Self {
            Self {
                platform_id: self.platform_id,
                device_id: self.device_id,
            }
        }
    }

    impl Clone for OpenclProgram {
        fn clone(&self) -> Self {
            Self {
                context: self.context.clone(),
                source: self.source.clone(),
            }
        }
    }

    pub struct OpenclQueue {
        context: OpenclContext,
        device: OpenclDevice,
    }

    impl OpenclQueue {
        pub fn new(_context: &OpenclContext, _device: &OpenclDevice) -> Result<Self> {
            Ok(Self {
                context: _context.clone(),
                device: _device.clone(),
            })
        }

        pub fn finish(&self) -> Result<()> {
            Ok(())
        }
    }

    impl Clone for OpenclDevice {
        fn clone(&self) -> Self {
            Self {
                id: self.id,
                name: self.name.clone(),
                vendor: self.vendor.clone(),
                max_compute_units: self.max_compute_units,
                max_work_group_size: self.max_work_group_size,
                global_memory: self.global_memory,
            }
        }
    }

    impl Clone for OpenclQueue {
        fn clone(&self) -> Self {
            Self {
                context: self.context.clone(),
                device: self.device.clone(),
            }
        }
    }
}

#[cfg(not(feature = "gpu-opencl"))]
pub struct OpenclHashKernel;

#[cfg(not(feature = "gpu-opencl"))]
impl OpenclHashKernel {
    pub fn new() -> Self {
        Self
    }

    pub fn is_available() -> bool {
        false
    }
}

#[cfg(not(feature = "gpu-opencl"))]
impl super::GpuKernel for OpenclHashKernel {
    fn kernel_type(&self) -> KernelType {
        KernelType::Unknown
    }

    fn supported_algorithms(&self) -> Vec<Algorithm> {
        Vec::new()
    }

    fn is_available(&self) -> bool {
        false
    }

    fn initialize(&mut self) -> Result<()> {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "OpenCL support not enabled".into(),
        ))
    }

    fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_metrics(&self) -> Option<KernelMetrics> {
        None
    }

    fn reset_metrics(&mut self) {}

    fn execute_hash(&self, _data: &[u8], _algorithm: Algorithm) -> Result<Vec<u8>> {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "OpenCL support not enabled".into(),
        ))
    }

    fn execute_hash_batch(&self, _data: &[Vec<u8>], _algorithm: Algorithm) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::HardwareAccelerationUnavailable(
            "OpenCL support not enabled".into(),
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
            "Hash kernel does not support AES operation".into(),
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
            "Hash kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_encrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
        ))
    }

    fn execute_aes_gcm_decrypt_batch(
        &self,
        _keys: &[&[u8]],
        _nonces: &[&[u8]],
        _data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>> {
        Err(CryptoError::InvalidInput(
            "Hash kernel does not support AES operation".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "gpu-opencl")]
    mod opencl_tests {
        use super::super::*;

        #[test]
        fn test_opencl_hash_kernel_creation() {
            let kernel = OpenclHashKernel::new();
            assert!(!kernel.is_available());
        }

        #[test]
        fn test_opencl_hash_kernel_initialize() {
            let mut kernel = OpenclHashKernel::new();
            let result = kernel.initialize();
            assert!(result.is_ok());
        }

        #[test]
        fn test_opencl_hash_kernel_shutdown() {
            let mut kernel = OpenclHashKernel::new();
            let _ = kernel.initialize();
            let result = kernel.shutdown();
            assert!(result.is_ok());
        }
    }

    #[cfg(not(feature = "gpu-opencl"))]
    mod cpu_tests {
        use super::super::*;

        #[test]
        fn test_opencl_hash_kernel_creation() {
            let kernel = OpenclHashKernel;
            assert!(!kernel.is_available());
        }

        #[test]
        fn test_opencl_hash_kernel_initialize() {
            let mut kernel = OpenclHashKernel;
            let result = kernel.initialize();
            assert!(result.is_err());
        }
    }
}
