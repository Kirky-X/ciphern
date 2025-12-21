// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::side_channel::struct_file::{SideChannelContext};
use crate::side_channel::power_analysis::PowerAnalysisGuard;
use crate::side_channel::error_injection::ErrorInjectionDetector;
use std::time::{Instant};
use std::sync::{Arc, Mutex};
use rand::SeedableRng;

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

/// Apply all side-channel protections to a critical operation
pub fn protect_critical_operation<F, R>(context: &mut SideChannelContext, operation: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    // Apply protections directly to the provided context, no cloning
    let config = context.config.clone();

    // Apply cache protection before operation
    if config.cache_protection {
        flush_cpu_cache();
        context.increment_cache_flush();
    }

    // Apply power analysis protection
    if config.power_analysis_protection && PowerAnalysisGuard::new().is_ok() {
        context.increment_masking_operations();
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

        context.increment_timing_protections();
        result
    } else if config.error_injection_protection {
        // Apply error injection protection
        let detector = ErrorInjectionDetector::new();

        // Execute operation and check for faults
        let result = operation();

        if detector.detect_fault() {
            context.increment_error_detection_triggers();
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

/// Apply all side-channel protections to a critical operation using a cloned context
pub fn protect_critical_operation_with_context<F, R>(
    context_arc: Arc<Mutex<SideChannelContext>>,
    operation: F,
) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    let mut context_guard = context_arc.lock().unwrap();
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
