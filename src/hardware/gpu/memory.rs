// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! GPU 内存管理模块
//!
//! 提供统一的内存管理抽象，支持：
//! - 主机内存（page-locked/pinned）
//! - 设备显存
//! - 统一内存（CUDA UM / SVM）
//! - 内存池优化

use crate::error::CryptoError;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

/// 内存类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryType {
    /// 主机可分页内存
    HostPageable,
    /// 主机固定内存（pinned）
    HostPinned,
    /// 设备显存
    Device,
    /// 统一内存
    Unified,
    /// 共享内存
    Shared,
}

/// 内存标志
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryFlags {
    pub read: bool,
    pub write: bool,
    pub map_to_host: bool,
    pub use_cache: bool,
    pub prefer_device: bool,
}

impl Default for MemoryFlags {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            map_to_host: false,
            use_cache: true,
            prefer_device: false,
        }
    }
}

/// GPU 缓冲区抽象
#[derive(Debug)]
pub struct GpuBuffer<T: Copy> {
    ptr: NonNull<T>,
    size: usize,
    memory_type: MemoryType,
    device_id: u32,
    is_owner: bool,
}

impl<T: Copy> GpuBuffer<T> {
    pub fn new(size: usize, memory_type: MemoryType, device_id: u32) -> Result<Self, CryptoError> {
        if size == 0 {
            return Err(CryptoError::InvalidInput(
                "Buffer size cannot be zero".into(),
            ));
        }

        let ptr = match memory_type {
            MemoryType::Device => {
                #[cfg(feature = "gpu-cuda")]
                {
                    let layout = std::alloc::Layout::array::<T>(size)
                        .map_err(|_| CryptoError::MemoryAllocationFailed("Layout error".into()))?;
                    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
                    if ptr.is_null() {
                        return Err(CryptoError::MemoryAllocationFailed(
                            "Allocation failed".into(),
                        ));
                    }
                    NonNull::new(ptr as *mut T).unwrap()
                }
                #[cfg(not(feature = "gpu-cuda"))]
                {
                    return Err(CryptoError::HardwareAccelerationUnavailable(
                        "GPU support not enabled".into(),
                    ));
                }
            }
            MemoryType::HostPinned => {
                #[cfg(feature = "gpu-cuda")]
                {
                    let layout = std::alloc::Layout::array::<T>(size)
                        .map_err(|_| CryptoError::MemoryAllocationFailed("Layout error".into()))?;
                    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
                    if ptr.is_null() {
                        return Err(CryptoError::MemoryAllocationFailed(
                            "Allocation failed".into(),
                        ));
                    }
                    NonNull::new(ptr as *mut T).unwrap()
                }
                #[cfg(not(feature = "gpu-cuda"))]
                {
                    let layout = std::alloc::Layout::array::<T>(size)
                        .map_err(|_| CryptoError::MemoryAllocationFailed("Layout error".into()))?;
                    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
                    if ptr.is_null() {
                        return Err(CryptoError::MemoryAllocationFailed(
                            "Allocation failed".into(),
                        ));
                    }
                    NonNull::new(ptr as *mut T).unwrap()
                }
            }
            MemoryType::HostPageable => {
                let layout = std::alloc::Layout::array::<T>(size)
                    .map_err(|_| CryptoError::MemoryAllocationFailed("Layout error".into()))?;
                let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
                if ptr.is_null() {
                    return Err(CryptoError::MemoryAllocationFailed(
                        "Allocation failed".into(),
                    ));
                }
                NonNull::new(ptr as *mut T).unwrap()
            }
            MemoryType::Unified => {
                #[cfg(feature = "gpu-cuda")]
                {
                    let layout = std::alloc::Layout::array::<T>(size)
                        .map_err(|_| CryptoError::MemoryAllocationFailed("Layout error".into()))?;
                    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
                    if ptr.is_null() {
                        return Err(CryptoError::MemoryAllocationFailed(
                            "Allocation failed".into(),
                        ));
                    }
                    NonNull::new(ptr as *mut T).unwrap()
                }
                #[cfg(not(feature = "gpu-cuda"))]
                {
                    return Err(CryptoError::HardwareAccelerationUnavailable(
                        "GPU support not enabled".into(),
                    ));
                }
            }
            _ => {
                return Err(CryptoError::InvalidInput("Unsupported memory type".into()));
            }
        };

        Ok(Self {
            ptr,
            size,
            memory_type,
            device_id,
            is_owner: true,
        })
    }

    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    #[inline]
    pub fn memory_type(&self) -> MemoryType {
        self.memory_type.clone()
    }

    #[inline]
    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    #[inline]
    pub fn size_bytes(&self) -> usize {
        self.size * std::mem::size_of::<T>()
    }

    pub fn memset(&self, value: u8) -> Result<(), CryptoError> {
        unsafe {
            std::ptr::write_bytes(self.ptr.as_ptr(), value, self.size);
        }
        Ok(())
    }

    pub fn copy_from_host(&mut self, host_data: &[T]) -> Result<(), CryptoError> {
        if host_data.len() != self.size {
            return Err(CryptoError::InvalidInput("Host data size mismatch".into()));
        }

        match self.memory_type {
            MemoryType::Device => {
                #[cfg(feature = "gpu-cuda")]
                {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            host_data.as_ptr(),
                            self.ptr.as_ptr(),
                            self.size,
                        );
                    }
                    Ok(())
                }
                #[cfg(not(feature = "gpu-cuda"))]
                {
                    Err(CryptoError::HardwareAccelerationUnavailable(
                        "GPU support not enabled".into(),
                    ))
                }
            }
            MemoryType::HostPinned | MemoryType::HostPageable | MemoryType::Unified => {
                unsafe {
                    std::ptr::copy_nonoverlapping(host_data.as_ptr(), self.ptr.as_ptr(), self.size);
                }
                Ok(())
            }
            _ => Err(CryptoError::InvalidInput(
                "Unsupported memory type for copy".into(),
            )),
        }
    }

    pub fn copy_to_host(&self, host_data: &mut [T]) -> Result<(), CryptoError> {
        if host_data.len() != self.size {
            return Err(CryptoError::InvalidInput("Host data size mismatch".into()));
        }

        match self.memory_type {
            MemoryType::Device => {
                #[cfg(feature = "gpu-cuda")]
                {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            self.ptr.as_ptr(),
                            host_data.as_mut_ptr(),
                            self.size,
                        );
                    }
                    Ok(())
                }
                #[cfg(not(feature = "gpu-cuda"))]
                {
                    Err(CryptoError::HardwareAccelerationUnavailable(
                        "GPU support not enabled".into(),
                    ))
                }
            }
            MemoryType::HostPinned | MemoryType::HostPageable | MemoryType::Unified => {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        self.ptr.as_ptr(),
                        host_data.as_mut_ptr(),
                        self.size,
                    );
                }
                Ok(())
            }
            _ => Err(CryptoError::InvalidInput(
                "Unsupported memory type for copy".into(),
            )),
        }
    }

    pub fn copy_to_device(&self, device: &GpuBuffer<T>, offset: usize) -> Result<(), CryptoError> {
        if offset + self.size > device.size {
            return Err(CryptoError::InvalidInput(
                "Copy would exceed destination buffer".into(),
            ));
        }

        #[cfg(feature = "gpu-cuda")]
        {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.ptr.as_ptr(),
                    device.ptr.as_ptr().add(offset),
                    self.size,
                );
            }
            Ok(())
        }
        #[cfg(not(feature = "gpu-cuda"))]
        {
            Err(CryptoError::HardwareAccelerationUnavailable(
                "GPU support not enabled".into(),
            ))
        }
    }
}

impl<T: Copy> Drop for GpuBuffer<T> {
    fn drop(&mut self) {
        if !self.is_owner {
            return;
        }

        match self.memory_type {
            MemoryType::Device => {
                #[cfg(feature = "gpu-cuda")]
                {
                    let _ = self.ptr.as_ptr();
                }
            }
            MemoryType::HostPinned => {
                #[cfg(feature = "gpu-cuda")]
                {
                    let layout = std::alloc::Layout::array::<T>(self.size).unwrap();
                    unsafe {
                        std::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
                    }
                }
                #[cfg(not(feature = "gpu-cuda"))]
                {
                    let layout = std::alloc::Layout::array::<T>(self.size).unwrap();
                    unsafe {
                        std::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
                    }
                }
            }
            MemoryType::HostPageable | MemoryType::Unified => {
                let layout = std::alloc::Layout::array::<T>(self.size).unwrap();
                unsafe {
                    std::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
                }
            }
            _ => {}
        }
    }
}

impl<T: Copy> Clone for GpuBuffer<T> {
    fn clone(&self) -> Self {
        Self {
            ptr: self.ptr,
            size: self.size,
            memory_type: self.memory_type.clone(),
            device_id: self.device_id,
            is_owner: false,
        }
    }
}

/// 内存池管理器
#[derive(Debug)]
pub struct MemoryPool {
    pool_id: u64,
    device_id: u32,
    total_capacity: usize,
    used_memory: AtomicU64,
    allocations: AtomicU64,
}

impl MemoryPool {
    pub fn new(device_id: u32, capacity: usize) -> Self {
        static POOL_COUNTER: AtomicU64 = AtomicU64::new(0);
        let pool_id = POOL_COUNTER.fetch_add(1, Ordering::SeqCst);

        Self {
            pool_id,
            device_id,
            total_capacity: capacity,
            used_memory: AtomicU64::new(0),
            allocations: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn pool_id(&self) -> u64 {
        self.pool_id
    }

    #[inline]
    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.total_capacity
    }

    #[inline]
    pub fn used(&self) -> usize {
        self.used_memory.load(Ordering::Relaxed) as usize
    }

    #[inline]
    pub fn available(&self) -> usize {
        self.total_capacity.saturating_sub(self.used())
    }

    #[inline]
    pub fn allocation_count(&self) -> u64 {
        self.allocations.load(Ordering::Relaxed)
    }

    pub fn allocate(&self, size: usize) -> Result<Option<GpuBuffer<u8>>, CryptoError> {
        let new_used = self.used_memory.load(Ordering::Relaxed) as usize + size;
        if new_used > self.total_capacity {
            return Ok(None);
        }

        match GpuBuffer::new(size, MemoryType::Device, self.device_id) {
            Ok(buffer) => {
                self.used_memory.fetch_add(size as u64, Ordering::Relaxed);
                self.allocations.fetch_add(1, Ordering::Relaxed);
                Ok(Some(buffer))
            }
            Err(e) => Err(e),
        }
    }

    pub fn deallocate(&self, buffer: GpuBuffer<u8>) -> usize {
        let size = buffer.size_bytes();
        self.used_memory.fetch_sub(size as u64, Ordering::Relaxed);
        size
    }

    pub fn utilization(&self) -> f32 {
        self.used() as f32 / self.total_capacity as f32
    }

    pub fn reset(&self) {
        self.used_memory.store(0, Ordering::Relaxed);
    }
}

/// 内存统计
#[derive(Debug)]
pub struct MemoryStats {
    pub allocated_buffers: AtomicU64,
    pub freed_buffers: AtomicU64,
    pub total_allocated_bytes: AtomicU64,
    pub total_freed_bytes: AtomicU64,
    pub active_allocations: AtomicU64,
    pub peak_concurrent_allocations: AtomicU64,
}

impl Default for MemoryStats {
    fn default() -> Self {
        Self {
            allocated_buffers: AtomicU64::new(0),
            freed_buffers: AtomicU64::new(0),
            total_allocated_bytes: AtomicU64::new(0),
            total_freed_bytes: AtomicU64::new(0),
            active_allocations: AtomicU64::new(0),
            peak_concurrent_allocations: AtomicU64::new(0),
        }
    }
}

impl Clone for MemoryStats {
    fn clone(&self) -> Self {
        Self {
            allocated_buffers: AtomicU64::new(self.allocated_buffers.load(Ordering::Relaxed)),
            freed_buffers: AtomicU64::new(self.freed_buffers.load(Ordering::Relaxed)),
            total_allocated_bytes: AtomicU64::new(
                self.total_allocated_bytes.load(Ordering::Relaxed),
            ),
            total_freed_bytes: AtomicU64::new(self.total_freed_bytes.load(Ordering::Relaxed)),
            active_allocations: AtomicU64::new(self.active_allocations.load(Ordering::Relaxed)),
            peak_concurrent_allocations: AtomicU64::new(
                self.peak_concurrent_allocations.load(Ordering::Relaxed),
            ),
        }
    }
}

impl MemoryStats {
    #[inline]
    pub fn record_allocation(&self, size: usize) {
        self.allocated_buffers.fetch_add(1, Ordering::Relaxed);
        self.total_allocated_bytes
            .fetch_add(size as u64, Ordering::Relaxed);
        let active = self.active_allocations.fetch_add(1, Ordering::Relaxed) + 1;

        let mut peak = self.peak_concurrent_allocations.load(Ordering::Relaxed);
        while active > peak {
            match self.peak_concurrent_allocations.compare_exchange(
                peak,
                active,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(new_peak) => peak = new_peak,
            }
        }
    }

    #[inline]
    pub fn record_deallocation(&self, size: usize) {
        self.freed_buffers.fetch_add(1, Ordering::Relaxed);
        self.total_freed_bytes
            .fetch_add(size as u64, Ordering::Relaxed);
        self.active_allocations.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn active_allocations(&self) -> u64 {
        self.active_allocations.load(Ordering::Relaxed)
    }

    pub fn peak_concurrent(&self) -> u64 {
        self.peak_concurrent_allocations.load(Ordering::Relaxed)
    }
}

static MEMORY_STATS: LazyLock<MemoryStats> = LazyLock::new(MemoryStats::default);

pub fn get_memory_stats() -> MemoryStats {
    (*MEMORY_STATS).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_flags_default() {
        let flags = MemoryFlags::default();
        assert!(flags.read);
        assert!(flags.write);
        assert!(!flags.map_to_host);
    }

    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::new(0, 1024 * 1024);
        assert_eq!(pool.device_id(), 0);
        assert_eq!(pool.capacity(), 1024 * 1024);
        assert_eq!(pool.used(), 0);
        assert!(pool.available() > 0);
    }

    #[test]
    #[cfg(feature = "gpu-cuda")]
    fn test_memory_pool_utilization() {
        let pool = MemoryPool::new(0, 1024);
        assert_eq!(pool.utilization(), 0.0);

        let buffer = pool.allocate(512);
        assert!(buffer.is_ok());
        assert!(buffer.unwrap().is_some());
        let utilization = pool.utilization();
        assert!(
            utilization >= 0.5,
            "utilization should be at least 0.5 after allocating 512/1024 bytes, got {}",
            utilization
        );
        assert!(
            utilization <= 1.0,
            "utilization should not exceed 1.0, got {}",
            utilization
        );
    }

    #[test]
    fn test_memory_stats() {
        let stats = MemoryStats::default();
        stats.record_allocation(100);
        assert_eq!(stats.active_allocations(), 1);
        stats.record_allocation(200);
        assert_eq!(stats.active_allocations(), 2);
        stats.record_deallocation(100);
        assert_eq!(stats.active_allocations(), 1);
    }
}
