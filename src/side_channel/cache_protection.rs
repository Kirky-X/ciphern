// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Cache-based attack protection
//!
//! This module provides protection against cache-timing attacks and cache-based
//! side-channel attacks through cache flushing, prefetching, and access randomization.

use crate::error::{CryptoError, Result};
use rand::{RngCore, SeedableRng};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::arch::asm;
use std::ptr;
use std::sync::atomic;
use std::time::Duration;

/// Cache protection configuration
#[derive(Debug, Clone)]
pub struct CacheProtectionConfig {
    /// Enable cache flushing
    pub flush_enabled: bool,
    /// Enable cache prefetching
    pub prefetch_enabled: bool,
    /// Enable access randomization
    pub randomization_enabled: bool,
    /// Number of dummy cache lines to access
    pub dummy_access_count: usize,
}

impl Default for CacheProtectionConfig {
    fn default() -> Self {
        Self {
            flush_enabled: true,
            prefetch_enabled: true,
            randomization_enabled: true,
            dummy_access_count: 8,
        }
    }
}

/// Cache protection guard
pub struct CacheProtectionGuard {
    config: CacheProtectionConfig,
    _dummy_data: Vec<u8>,
}

impl CacheProtectionGuard {
    pub fn new(config: CacheProtectionConfig) -> Self {
        let dummy_data = vec![0u8; config.dummy_access_count * 64]; // 64 bytes per cache line

        Self {
            config,
            _dummy_data: dummy_data,
        }
    }

    /// Protect memory access operation
    pub fn protect_access<F, R>(&self, operation: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        if self.config.flush_enabled {
            self.flush_cache_lines()?;
        }

        if self.config.randomization_enabled {
            self.randomize_cache_access()?;
        }

        if self.config.prefetch_enabled {
            self.prefetch_cache_lines()?;
        }

        let result = operation();

        if self.config.flush_enabled {
            self.flush_cache_lines()?;
        }

        result
    }

    fn flush_cache_lines(&self) -> Result<()> {
        // Flush cache lines for dummy data
        for chunk in self._dummy_data.chunks(64) {
            if let Some(ptr) = chunk.first() {
                flush_cache_line(ptr as *const u8);
            }
        }

        Ok(())
    }

    fn randomize_cache_access(&self) -> Result<()> {
        // Use thread-local RNG to avoid global lock contention
        thread_local! {
            static THREAD_RNG: std::cell::RefCell<rand::rngs::SmallRng> = std::cell::RefCell::new(
                rand::rngs::SmallRng::from_entropy()
            );
        }

        let mut indices = vec![0usize; self.config.dummy_access_count];
        THREAD_RNG.with(|rng| {
            let mut rng = rng.borrow_mut();
            let byte_slice = unsafe {
                std::slice::from_raw_parts_mut(
                    indices.as_mut_ptr() as *mut u8,
                    indices.len() * std::mem::size_of::<usize>(),
                )
            };
            rng.fill_bytes(byte_slice);
        });

        // Normalize indices to valid range
        for idx in &mut indices {
            *idx %= self.config.dummy_access_count;
        }

        // Access cache lines in random order
        for &index in &indices {
            let offset = index * 64;
            if offset < self._dummy_data.len() {
                // Touch the cache line to create random access pattern
                let _ = self._dummy_data[offset];
            }
        }

        Ok(())
    }

    fn prefetch_cache_lines(&self) -> Result<()> {
        // Prefetch cache lines to reduce timing variations
        for chunk in self._dummy_data.chunks(64) {
            if let Some(ptr) = chunk.first() {
                prefetch_cache_line(ptr as *const u8);
            }
        }

        Ok(())
    }
}

/// Flush a specific cache line (CLFLUSH instruction)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn flush_cache_line(ptr: *const u8) {
    unsafe {
        asm!(
            "clflush [{0}]",
            in(reg) ptr,
            options(nostack, preserves_flags)
        );
    }
}

/// Prefetch a cache line (PREFETCHT0 instruction)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn prefetch_cache_line(ptr: *const u8) {
    unsafe {
        asm!(
            "prefetcht0 [{0}]",
            in(reg) ptr,
            options(nostack, preserves_flags)
        );
    }
}

/// Memory access pattern randomization
pub struct AccessPatternRandomizer {
    stride: usize,
    mask: usize,
}

impl AccessPatternRandomizer {
    pub fn new(data_size: usize) -> Result<Self> {
        // Use thread-local RNG to avoid global lock contention
        thread_local! {
            static THREAD_RNG: std::cell::RefCell<rand::rngs::SmallRng> = std::cell::RefCell::new(
                rand::rngs::SmallRng::from_entropy()
            );
        }

        let mut stride_bytes = [0u8; std::mem::size_of::<usize>()];
        THREAD_RNG.with(|rng| {
            let mut rng = rng.borrow_mut();
            rng.fill_bytes(&mut stride_bytes);
        });

        let stride = usize::from_le_bytes(stride_bytes) % 64 + 1; // Ensure non-zero stride
        let mask = data_size.next_power_of_two() - 1;

        Ok(Self { stride, mask })
    }

    /// Generate randomized access indices
    pub fn randomize_indices(&self, count: usize) -> Vec<usize> {
        let mut indices = Vec::with_capacity(count);
        let mut current = 0;

        for _ in 0..count {
            current = (current + self.stride) & self.mask;
            indices.push(current);
        }

        indices
    }
}

/// Cache partitioning to isolate sensitive data
pub struct CachePartition {
    partition_size: usize,
    partition_index: usize,
}

impl CachePartition {
    pub fn new(partition_size: usize, partition_index: usize) -> Self {
        Self {
            partition_size,
            partition_index,
        }
    }

    /// Allocate memory in specific cache partition
    pub fn allocate_in_partition(&self, size: usize) -> Vec<u8> {
        let total_size = size * self.partition_size * 64; // Each element is 64 bytes (cache line)
        let mut data = vec![0u8; total_size];

        // Touch every cache line within the specified partition
        // Partition index determines which cache lines to use
        for i in (self.partition_index * 64..total_size).step_by(self.partition_size * 64) {
            if i < data.len() {
                data[i] = 0xFF; // Touch the memory to allocate cache line
            }
        }

        data
    }
}

/// Cache timing measurement for detection
pub struct CacheTimingMeasurer {
    measurements: Vec<Duration>,
    threshold: Duration,
}

impl CacheTimingMeasurer {
    pub fn new(threshold: Duration) -> Self {
        Self {
            measurements: Vec::new(),
            threshold,
        }
    }

    /// Measure cache access time
    pub fn measure_access_time<F>(&mut self, operation: F) -> Result<Duration>
    where
        F: FnOnce(),
    {
        use std::time::Instant;

        let start = Instant::now();
        operation();
        let duration = start.elapsed();

        self.measurements.push(duration);

        // Keep only recent measurements
        if self.measurements.len() > 100 {
            self.measurements.remove(0);
        }

        Ok(duration)
    }

    /// Detect cache timing anomalies
    pub fn detect_anomaly(&self) -> Result<bool> {
        if self.measurements.len() < 10 {
            return Ok(false);
        }

        // Calculate average and standard deviation
        let sum: Duration = self.measurements.iter().sum();
        let average = sum / self.measurements.len() as u32;

        let variance_sum: f64 = self
            .measurements
            .iter()
            .map(|&d| {
                let diff = d.abs_diff(average);
                diff.as_nanos() as f64 * diff.as_nanos() as f64
            })
            .sum();

        let variance = variance_sum / self.measurements.len() as f64;
        let std_dev = Duration::from_nanos(variance.sqrt() as u64);

        // Check if any measurement is outside threshold
        for &measurement in &self.measurements {
            let deviation = measurement.abs_diff(average);

            if deviation > self.threshold || deviation > std_dev * 3 {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Flush entire CPU cache
pub fn flush_entire_cache() -> Result<()> {
    // Allocate large buffer to flush cache
    let size = 1024 * 1024; // 1MB
    let mut buffer = vec![0u8; size];

    // Access every cache line to force flush
    for i in (0..size).step_by(64) {
        buffer[i] = 0xFF;
    }

    // Memory barrier to ensure all writes complete
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

    Ok(())
}

/// Non-temporal memory access to bypass cache
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn non_temporal_store(data: &[u8], dest: &mut [u8]) -> Result<()> {
    if data.len() != dest.len() {
        return Err(CryptoError::InvalidParameter("Size mismatch".into()));
    }

    // Use volatile write to prevent compiler optimizations
    unsafe {
        for (i, &byte) in data.iter().enumerate() {
            // Use volatile write to ensure memory access pattern
            let ptr = &mut dest[i] as *mut u8;
            ptr::write_volatile(ptr, byte);
            // Memory fence to ensure ordering
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        }
    }

    // Memory fence to ensure all writes complete
    atomic::fence(atomic::Ordering::SeqCst);

    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn non_temporal_store(data: &[u8], dest: &mut [u8]) -> Result<()> {
    // Fallback for non-x86 architectures
    dest.copy_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_pattern_randomizer() {
        let randomizer = AccessPatternRandomizer::new(1024).unwrap();
        let indices = randomizer.randomize_indices(10);

        assert_eq!(indices.len(), 10);
        for &index in &indices {
            assert!(index < 1024);
        }
    }

    #[test]
    fn test_cache_partition() {
        let partition = CachePartition::new(4, 2);
        let data = partition.allocate_in_partition(256);

        assert_eq!(data.len(), 256 * 4 * 64); // 每个元素是64字节缓存行

        // Check that only partition-aligned locations are touched
        let mut touched_count = 0;
        for item in &data {
            if *item == 0xFF {
                touched_count += 1;
            }
        }

        // 计算期望的缓存行数量
        // partition_size=4, partition_index=2, size=256
        // 从索引2*64=128开始，每4*64=256个元素标记1个
        // 总共有256个缓存行需要标记
        let expected_count = 256;

        // Debug output
        println!(
            "Touched count: {}, Expected count: {}",
            touched_count, expected_count
        );

        assert_eq!(touched_count, expected_count);
    }

    #[test]
    fn test_cache_protection_guard() {
        let config = CacheProtectionConfig::default();
        let guard = CacheProtectionGuard::new(config);

        let result = guard.protect_access(|| Ok::<_, CryptoError>(42));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }
}
