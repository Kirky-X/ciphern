// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! GPU Kernel 模块
//!
//! 提供加密和哈希操作的 GPU Kernel 抽象
//! 每个 Algorithm 对应一个或多个 Kernel 实现

use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use std::sync::Arc;

#[cfg(feature = "gpu")]
pub mod aes_kernel;
#[cfg(feature = "gpu")]
pub mod hash_kernel;
#[cfg(feature = "gpu")]
pub mod signature_kernel;
#[cfg(feature = "gpu")]
pub mod sm4_kernel;

#[cfg(feature = "gpu")]
pub use aes_kernel::AesKernel;
#[cfg(feature = "gpu")]
pub use hash_kernel::HashKernel;
#[cfg(feature = "gpu")]
pub use signature_kernel::SignatureKernel;
#[cfg(feature = "gpu")]
pub use sm4_kernel::Sm4Kernel;

/// Kernel 类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelType {
    /// AES-NI (CPU fallback)
    CpuAesNi,
    /// AES GPU Kernel
    GpuAes,
    /// SHA2 GPU Kernel
    GpuSha2,
    /// SM4 GPU Kernel
    GpuSm4,
    /// ECDSA GPU Kernel
    GpuEcdsa,
    /// Ed25519 GPU Kernel
    GpuEd25519,
    /// 虚拟 Kernel（测试用）
    Virtual,
    /// 未知
    Unknown,
}

impl std::fmt::Display for KernelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelType::CpuAesNi => write!(f, "CPU AES-NI"),
            KernelType::GpuAes => write!(f, "GPU AES"),
            KernelType::GpuSha2 => write!(f, "GPU SHA2"),
            KernelType::GpuSm4 => write!(f, "GPU SM4"),
            KernelType::GpuEcdsa => write!(f, "GPU ECDSA"),
            KernelType::GpuEd25519 => write!(f, "GPU Ed25519"),
            KernelType::Virtual => write!(f, "Virtual Kernel"),
            KernelType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Kernel 性能指标
#[derive(Debug, Clone)]
pub struct KernelMetrics {
    pub kernel_type: KernelType,
    pub execution_time_us: u64,
    pub throughput_mbps: f32,
    pub memory_transferred_bytes: usize,
    pub compute_units_used: u32,
    pub batch_size: usize,
}

impl KernelMetrics {
    pub fn new(kernel_type: KernelType) -> Self {
        Self {
            kernel_type,
            execution_time_us: 0,
            throughput_mbps: 0.0,
            memory_transferred_bytes: 0,
            compute_units_used: 0,
            batch_size: 0,
        }
    }

    #[inline]
    pub fn with_execution_time(mut self, us: u64) -> Self {
        self.execution_time_us = us;
        self
    }

    #[inline]
    pub fn with_throughput(mut self, mbps: f32) -> Self {
        self.throughput_mbps = mbps;
        self
    }

    #[inline]
    pub fn with_memory(mut self, bytes: usize) -> Self {
        self.memory_transferred_bytes = bytes;
        self
    }

    #[inline]
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }
}

/// 统一的 GPU Kernel trait
pub trait GpuKernel: Send + Sync {
    fn kernel_type(&self) -> KernelType;
    fn supported_algorithms(&self) -> Vec<Algorithm>;
    fn is_available(&self) -> bool;

    fn initialize(&mut self) -> Result<()>;
    fn shutdown(&mut self) -> Result<()>;

    fn get_metrics(&self) -> Option<KernelMetrics>;
    fn reset_metrics(&mut self);

    fn execute_hash(&self, data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>>;
    fn execute_hash_batch(&self, data: &[Vec<u8>], algorithm: Algorithm) -> Result<Vec<Vec<u8>>>;

    fn execute_aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn execute_aes_gcm_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn execute_aes_gcm_encrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>>;
    fn execute_aes_gcm_decrypt_batch(
        &self,
        keys: &[&[u8]],
        nonces: &[&[u8]],
        data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>>;

    fn execute_ecdsa_sign(
        &self,
        private_key: &[u8],
        data: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>>;
    fn execute_ecdsa_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool>;
    fn execute_ecdsa_verify_batch(
        &self,
        public_keys: &[&[u8]],
        data: &[&[u8]],
        signatures: &[&[u8]],
        algorithm: Algorithm,
    ) -> Result<Vec<bool>>;
    fn execute_ed25519_sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    fn execute_ed25519_verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool>;
}

/// Kernel 管理器
#[derive(Debug)]
pub struct KernelManager {
    kernels: Vec<Arc<dyn GpuKernel>>,
    algorithm_kernel_map: std::collections::HashMap<Algorithm, Arc<dyn GpuKernel>>,
}

impl KernelManager {
    pub fn new() -> Self {
        Self {
            kernels: Vec::new(),
            algorithm_kernel_map: std::collections::HashMap::new(),
        }
    }

    pub fn register_kernel(&mut self, kernel: Arc<dyn GpuKernel>) {
        for algo in kernel.supported_algorithms() {
            self.algorithm_kernel_map.insert(algo, Arc::clone(&kernel));
        }
        self.kernels.push(Arc::clone(&kernel));
    }

    pub fn get_kernel(&self, algorithm: Algorithm) -> Option<Arc<dyn GpuKernel>> {
        self.algorithm_kernel_map.get(&algorithm).map(Arc::clone)
    }

    pub fn get_kernel_by_type(&self, kernel_type: KernelType) -> Option<Arc<dyn GpuKernel>> {
        self.kernels
            .iter()
            .find(|k| k.kernel_type() == kernel_type)
            .map(Arc::clone)
    }

    pub fn get_all_kernels(&self) -> Vec<Arc<dyn GpuKernel>> {
        self.kernels.iter().map(Arc::clone).collect()
    }

    pub fn shutdown_all(&self) -> Result<()> {
        for kernel in &self.kernels {
            if kernel.is_available() {
                if let Ok(mut k) = Arc::clone(kernel).lock() {
                    let _ = k.shutdown();
                }
            }
        }
        Ok(())
    }

    pub fn total_kernel_count(&self) -> usize {
        self.kernels.len()
    }
}

impl Default for KernelManager {
    fn default() -> Self {
        Self::new()
    }
}

/// AES Kernel 配置
#[derive(Debug, Clone)]
pub struct AesKernelConfig {
    pub use_async: bool,
    pub batch_size: usize,
    pub work_group_size: usize,
    pub use_local_memory: bool,
    pub prefetch_enabled: bool,
    pub stream_count: usize,
}

impl Default for AesKernelConfig {
    fn default() -> Self {
        Self {
            use_async: true,
            batch_size: 32,
            work_group_size: 256,
            use_local_memory: true,
            prefetch_enabled: true,
            stream_count: 4,
        }
    }
}

impl AesKernelConfig {
    /// 高性能配置
    pub fn high_performance() -> Self {
        Self {
            use_async: true,
            batch_size: 128,
            work_group_size: 512,
            use_local_memory: true,
            prefetch_enabled: true,
            stream_count: 8,
        }
    }

    /// 低延迟配置
    pub fn low_latency() -> Self {
        Self {
            use_async: true,
            batch_size: 8,
            work_group_size: 128,
            use_local_memory: true,
            prefetch_enabled: false,
            stream_count: 2,
        }
    }
}

/// Hash Kernel 配置
#[derive(Debug, Clone)]
pub struct HashKernelConfig {
    pub use_async: bool,
    pub chunk_size: usize,
    pub pipeline_depth: usize,
    pub use_texture_memory: bool,
}

impl Default for HashKernelConfig {
    fn default() -> Self {
        Self {
            use_async: true,
            chunk_size: 64 * 1024, // 64KB chunks
            pipeline_depth: 4,
            use_texture_memory: false,
        }
    }
}

impl HashKernelConfig {
    /// 大数据量配置
    pub fn large_data() -> Self {
        Self {
            use_async: true,
            chunk_size: 256 * 1024, // 256KB chunks
            pipeline_depth: 8,
            use_texture_memory: true,
        }
    }

    /// 实时配置
    pub fn realtime() -> Self {
        Self {
            use_async: true,
            chunk_size: 64 * 1024,
            pipeline_depth: 2,
            use_texture_memory: false,
        }
    }
}

/// 批量操作配置
#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub max_batch_size: usize,
    pub use_stream_parallelism: bool,
    pub stream_count: usize,
    pub split_large_items: bool,
    pub split_threshold: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 1024,
            use_stream_parallelism: true,
            stream_count: 4,
            split_large_items: true,
            split_threshold: 1024 * 1024, // 1MB
        }
    }
}

impl BatchConfig {
    /// 实时批量配置
    pub fn realtime() -> Self {
        Self {
            max_batch_size: 256,
            use_stream_parallelism: true,
            stream_count: 2,
            split_large_items: true,
            split_threshold: 512 * 1024,
        }
    }

    /// 吞吐量优先配置
    pub fn throughput() -> Self {
        Self {
            max_batch_size: 4096,
            use_stream_parallelism: true,
            stream_count: 8,
            split_large_items: true,
            split_threshold: 2 * 1024 * 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_type_display() {
        assert_eq!(KernelType::GpuAes.to_string(), "GPU AES");
        assert_eq!(KernelType::CpuAesNi.to_string(), "CPU AES-NI");
    }

    #[test]
    fn test_kernel_manager() {
        let manager = KernelManager::new();
        assert_eq!(manager.total_kernel_count(), 0);
    }

    #[test]
    fn test_aes_kernel_config() {
        let config = AesKernelConfig::default();
        assert_eq!(config.work_group_size, 256);

        let perf_config = AesKernelConfig::high_performance();
        assert_eq!(perf_config.work_group_size, 512);
    }

    #[test]
    fn test_hash_kernel_config() {
        let config = HashKernelConfig::default();
        assert_eq!(config.chunk_size, 64 * 1024);

        let large_config = HashKernelConfig::large_data();
        assert!(large_config.chunk_size > config.chunk_size);
    }

    #[test]
    fn test_batch_config() {
        let config = BatchConfig::default();
        assert_eq!(config.max_batch_size, 1024);

        let rt_config = BatchConfig::realtime();
        assert!(rt_config.max_batch_size < config.max_batch_size);
    }

    #[test]
    fn test_kernel_metrics() {
        let metrics = KernelMetrics::new(KernelType::GpuAes)
            .with_execution_time(1000)
            .with_throughput(1000.0)
            .with_memory(1024)
            .with_batch_size(10);

        assert_eq!(metrics.kernel_type, KernelType::GpuAes);
        assert_eq!(metrics.execution_time_us, 1000);
        assert_eq!(metrics.throughput_mbps, 1000.0);
    }
}
