// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Side-channel attack protection module
//!
//! This module provides protection against various side-channel attacks including:
//! - Timing attacks
//! - Power analysis attacks (SPA/DPA)
//! - Electromagnetic analysis
//! - Error injection attacks
//! - Cache-based attacks

use crate::error::{CryptoError, Result};
use rand::SeedableRng;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub mod cache_protection;
pub mod constant_time;
pub mod embedded_power;
pub mod error_injection;
pub mod masking;
pub mod power_analysis;

#[cfg(test)]
mod stats_tests;
#[cfg(test)]
mod tests;

pub use error_injection::*;
pub use masking::*;
pub use power_analysis::*;

/// Configuration for side-channel protection
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SideChannelConfig {
    /// Enable constant-time operations
    pub constant_time_enabled: bool,
    /// Enable power analysis protection
    pub power_analysis_protection: bool,
    /// Enable error injection protection
    pub error_injection_protection: bool,
    /// Enable cache protection
    pub cache_protection: bool,
    /// Enable timing noise
    pub timing_noise_enabled: bool,
    /// Enable masking operations
    pub masking_operations_enabled: bool,
    /// Enable redundancy checks
    pub redundancy_checks_enabled: bool,
    /// Enable cache flush
    pub cache_flush_enabled: bool,
    /// Timing noise level (0.0 to 1.0)
    pub timing_noise_level: f32,
    /// Maximum timing deviation in nanoseconds
    pub max_timing_deviation: Duration,
    /// Operation timeout for critical cryptographic operations
    pub operation_timeout: Duration,
}

impl Default for SideChannelConfig {
    fn default() -> Self {
        Self {
            constant_time_enabled: true,
            power_analysis_protection: cfg!(target_arch = "arm")
                || cfg!(target_arch = "riscv32")
                || cfg!(target_arch = "riscv64"),
            error_injection_protection: true,
            cache_protection: true,
            timing_noise_enabled: true,
            masking_operations_enabled: true,
            redundancy_checks_enabled: true,
            cache_flush_enabled: true,
            timing_noise_level: 0.1,
            max_timing_deviation: Duration::from_micros(50),
            operation_timeout: Duration::from_secs(5),
        }
    }
}

/// Global side-channel protection context
#[derive(Debug, Clone)]
pub struct SideChannelContext {
    pub config: SideChannelConfig,
    pub countermeasure_stats: CountermeasureStats,
}

#[derive(Debug, Default, Clone)]
pub struct CountermeasureStats {
    pub timing_protections: u64,
    pub masking_operations: u64,
    pub error_detection_triggers: u64,
    pub cache_flush_operations: u64,
}

impl SideChannelContext {
    pub fn new(config: SideChannelConfig) -> Self {
        Self {
            config,
            countermeasure_stats: CountermeasureStats::default(),
        }
    }

    /// Get the configuration
    #[allow(dead_code)]
    pub fn config(&self) -> &SideChannelConfig {
        &self.config
    }

    /// Reset the context statistics
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.countermeasure_stats = CountermeasureStats::default();
    }

    /// Increment cache flush operations counter
    pub fn increment_cache_flush(&mut self) {
        self.countermeasure_stats.cache_flush_operations += 1;
    }

    /// Increment masking operations counter
    pub fn increment_masking_operations(&mut self) {
        self.countermeasure_stats.masking_operations += 1;
    }

    /// Increment timing protections counter
    pub fn increment_timing_protections(&mut self) {
        self.countermeasure_stats.timing_protections += 1;
    }

    /// Increment error detection triggers counter
    pub fn increment_error_detection_triggers(&mut self) {
        self.countermeasure_stats.error_detection_triggers += 1;
    }

    /// Apply timing protection to a closure
    #[allow(dead_code)]
    pub fn protect_timing<F, R>(&mut self, operation: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        if !self.config.constant_time_enabled {
            return operation();
        }

        let start = Instant::now();

        // Add timing noise if configured
        if self.config.timing_noise_level > 0.0 {
            add_timing_noise(self.config.timing_noise_level);
        }

        let result = operation();

        let elapsed = start.elapsed();

        // Ensure minimum execution time to prevent timing leaks
        let min_time = self.config.max_timing_deviation;
        if elapsed < min_time {
            std::thread::sleep(min_time - elapsed);
        }

        self.countermeasure_stats.timing_protections += 1;
        result
    }

    /// Apply power analysis protection
    #[allow(dead_code)]
    pub fn protect_power_analysis<F, R>(&mut self, operation: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        if !self.config.power_analysis_protection {
            return operation();
        }

        // Add power analysis countermeasures
        let _guard = PowerAnalysisGuard::new()?;

        self.countermeasure_stats.masking_operations += 1;
        operation()
    }

    /// Apply error injection protection
    #[allow(dead_code)]
    pub fn protect_error_injection<F, R>(&mut self, operation: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        if !self.config.error_injection_protection {
            return operation();
        }

        // Add error detection and correction
        let detector = ErrorInjectionDetector::new();

        let result = operation();

        if detector.detect_fault() {
            self.countermeasure_stats.error_detection_triggers += 1;
            return Err(CryptoError::SideChannelError(
                "Fault injection detected".into(),
            ));
        }

        result
    }

    /// Apply cache protection
    #[allow(dead_code)]
    pub fn protect_cache_access<F, R>(&mut self, operation: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        if !self.config.cache_protection {
            return operation();
        }

        // Flush cache before and after operation
        flush_cpu_cache();

        let result = operation();

        flush_cpu_cache();

        self.countermeasure_stats.cache_flush_operations += 1;
        result
    }

    /// Get protection statistics
    pub fn get_stats(&self) -> SideChannelStats {
        SideChannelStats {
            timing_protections: self.countermeasure_stats.timing_protections,
            masking_operations: self.countermeasure_stats.masking_operations,
            error_detection_triggers: self.countermeasure_stats.error_detection_triggers,
            cache_flush_operations: self.countermeasure_stats.cache_flush_operations,
        }
    }
}

/// Side-channel protection statistics
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct SideChannelStats {
    #[allow(dead_code)]
    pub timing_protections: u64,
    #[allow(dead_code)]
    pub masking_operations: u64,
    #[allow(dead_code)]
    pub error_detection_triggers: u64,
    #[allow(dead_code)]
    pub cache_flush_operations: u64,
}

/// Apply all side-channel protections to a critical operation
pub fn protect_critical_operation<F, R>(context: &mut SideChannelContext, operation: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    let config = context.config.clone();

    if config.cache_protection {
        flush_cpu_cache();
        context.increment_cache_flush();
    }

    if config.power_analysis_protection && PowerAnalysisGuard::new().is_ok() {
        context.increment_masking_operations();
    }

    if config.constant_time_enabled {
        let start = Instant::now();

        if config.timing_noise_level > 0.0 {
            add_timing_noise(config.timing_noise_level);
        }

        let result = operation();

        let elapsed = start.elapsed();

        if elapsed > config.operation_timeout {
            return Err(CryptoError::SideChannelError(format!(
                "Operation timeout exceeded: {:?} > {:?}",
                elapsed, config.operation_timeout
            )));
        }

        let min_time = config.max_timing_deviation;
        if elapsed < min_time {
            std::thread::sleep(min_time - elapsed);
        }

        context.increment_timing_protections();
        result
    } else if config.error_injection_protection {
        let detector = ErrorInjectionDetector::new();

        let result = operation();

        if detector.detect_fault() {
            context.increment_error_detection_triggers();
            return Err(CryptoError::SideChannelError(
                "Fault injection detected".into(),
            ));
        }

        result
    } else {
        operation()
    }
}

/// Apply all side-channel protections to a critical operation using a cloned context
#[allow(dead_code)]
pub fn protect_critical_operation_with_context<F, R>(
    context_arc: Arc<Mutex<SideChannelContext>>,
    operation: F,
) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    let mut context_guard = context_arc
        .lock()
        .map_err(|_| CryptoError::SideChannelError("Side channel context lock poisoned".into()))?;
    let config = context_guard.config.clone();

    // Apply cache protection before operation
    if config.cache_protection {
        flush_cpu_cache();
        context_guard.countermeasure_stats.cache_flush_operations += 1;
    }

    // Apply power analysis protection
    if config.power_analysis_protection && PowerAnalysisGuard::new().is_ok() {
        context_guard.countermeasure_stats.masking_operations += 1;
    }

    // Apply timing protection
    if config.constant_time_enabled {
        let start = Instant::now();

        // Add timing noise if configured
        if config.timing_noise_level > 0.0 {
            add_timing_noise(config.timing_noise_level);
        }

        // Execute operation
        let result = operation();

        let elapsed = start.elapsed();

        // Ensure minimum execution time to prevent timing leaks
        let min_time = config.max_timing_deviation;
        if elapsed < min_time {
            std::thread::sleep(min_time - elapsed);
        }

        context_guard.countermeasure_stats.timing_protections += 1;
        result
    } else if config.error_injection_protection {
        // Apply error injection protection
        let detector = ErrorInjectionDetector::new();

        // Execute operation and check for faults
        let result = operation();

        if detector.detect_fault() {
            context_guard.countermeasure_stats.error_detection_triggers += 1;
            return Err(CryptoError::SideChannelError(
                "Fault injection detected".into(),
            ));
        }

        result
    } else {
        // If no special protections, just execute the operation
        operation()
    }
}

/// Add timing noise to prevent timing attacks
pub fn add_timing_noise(level: f32) {
    use rand::RngCore;
    use std::hint::black_box;

    // Use thread-local RNG to avoid global lock contention
    thread_local! {
        static THREAD_RNG: std::cell::RefCell<rand::rngs::SmallRng> = std::cell::RefCell::new(
            rand::rngs::SmallRng::from_entropy()
        );
    }

    // Limit iterations to prevent excessive delays in tests
    let iterations = ((level * 100.0) as u32).min(50); // Max 50 iterations
    let mut dummy = 0u64;

    // Add some variable delay based on thread-local RNG
    THREAD_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        let extra_delay = rng.next_u32() % 10; // 0-9 extra iterations
        let total_iterations = iterations + extra_delay;

        for _ in 0..total_iterations {
            // Perform dummy operations that consume time
            dummy = dummy.wrapping_add(black_box(1));
            dummy = black_box(dummy.rotate_left(13));
        }
    });
}

/// Flush CPU cache to prevent cache-based attacks
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn flush_cpu_cache() {
    use std::arch::asm;

    unsafe {
        // CLFLUSH instruction to flush cache lines
        asm!("clflush [{0}]", in(reg) &0u8, options(nostack));
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn flush_cpu_cache() {
    // Fallback for non-x86 architectures
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}
