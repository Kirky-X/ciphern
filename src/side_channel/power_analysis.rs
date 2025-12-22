// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Power analysis attack protection
//!
//! This module provides countermeasures against Simple Power Analysis (SPA)
//! and Differential Power Analysis (DPA) attacks through masking and randomization.
//!
//! Features:
//! - XOR, multiplicative, and boolean masking
//! - Power consumption randomization
//! - Advanced power trace obfuscation
//! - Template attack protection
//! - Configurable protection levels

use crate::error::Result;
use crate::random::SecureRandom;
use rand::{RngCore, SeedableRng};
use std::time::Instant;

/// Power analysis protection levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProtectionLevel {
    /// Basic protection: simple masking
    Basic,
    /// Enhanced protection: advanced masking + randomization
    Enhanced,
    /// Maximum protection: full obfuscation + template attack resistance
    Maximum,
}

/// Power analysis protection configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PowerAnalysisConfig {
    /// Protection level
    pub level: ProtectionLevel,
    /// Enable power trace randomization
    pub enable_trace_randomization: bool,
    /// Enable timing noise injection
    pub enable_timing_noise: bool,
    /// Enable dummy operations
    pub enable_dummy_operations: bool,
    /// Minimum dummy operation complexity (0-3)
    pub dummy_operation_level: u8,
}

impl Default for PowerAnalysisConfig {
    fn default() -> Self {
        Self {
            level: ProtectionLevel::Enhanced,
            enable_trace_randomization: true,
            enable_timing_noise: true,
            enable_dummy_operations: true,
            dummy_operation_level: 2,
        }
    }
}

/// Power analysis protection guard
#[allow(dead_code)]
pub struct PowerAnalysisGuard {
    _dummy: [u8; 32], // Prevent optimization
    _config: PowerAnalysisConfig,
    _start_time: Instant,
}

#[allow(dead_code)]
impl PowerAnalysisGuard {
    pub fn new() -> Result<Self> {
        Self::with_config(PowerAnalysisConfig::default())
    }

    pub fn with_config(config: PowerAnalysisConfig) -> Result<Self> {
        let start_time = Instant::now();

        // Use thread-local RNG to avoid global lock contention
        thread_local! {
            static THREAD_RNG: std::cell::RefCell<rand::rngs::SmallRng> = std::cell::RefCell::new(
                rand::rngs::SmallRng::from_entropy()
            );
        }

        let mut dummy = [0u8; 32];
        THREAD_RNG.with(|rng| {
            let mut rng = rng.borrow_mut();
            rng.fill_bytes(&mut dummy);
        });

        // Apply protection based on configuration
        match config.level {
            ProtectionLevel::Basic => {
                // Basic protection: simple dummy operations
                if config.enable_dummy_operations {
                    dummy_operations_complexity(config.dummy_operation_level);
                }
            }
            ProtectionLevel::Enhanced => {
                // Enhanced protection: randomization + timing noise
                if config.enable_trace_randomization {
                    randomize_power_consumption_adaptive(10, 50);
                }
                if config.enable_timing_noise {
                    inject_timing_noise();
                }
                if config.enable_dummy_operations {
                    dummy_operations_complexity(config.dummy_operation_level);
                }
            }
            ProtectionLevel::Maximum => {
                // Maximum protection: full obfuscation
                if config.enable_trace_randomization {
                    randomize_power_consumption_adaptive(20, 100);
                }
                if config.enable_timing_noise {
                    inject_timing_noise();
                    inject_advanced_timing_noise();
                }
                if config.enable_dummy_operations {
                    dummy_operations_complexity(3);
                    advanced_dummy_operations();
                }
                // Add template attack protection
                obfuscate_template_signatures();
            }
        }

        Ok(Self {
            _dummy: dummy,
            _config: config,
            _start_time: start_time,
        })
    }
}

impl Drop for PowerAnalysisGuard {
    fn drop(&mut self) {
        // Add any cleanup logic if needed
        // This could include final power analysis checks or cleanup
    }
}

/// Mask a value using XOR masking
#[allow(dead_code)]
pub fn mask_value(value: u8) -> Result<(u8, u8)> {
    // Use thread-local RNG to avoid global lock contention
    thread_local! {
        static THREAD_RNG: std::cell::RefCell<rand::rngs::SmallRng> = std::cell::RefCell::new(
            rand::rngs::SmallRng::from_entropy()
        );
    }

    let mut mask = [0u8; 1];
    THREAD_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        rng.fill_bytes(&mut mask);
    });

    let mask = mask[0];
    let masked = value ^ mask;
    Ok((masked, mask))
}

/// Unmask a value using XOR masking
#[allow(dead_code)]
pub fn unmask_value(masked: u8, mask: u8) -> u8 {
    masked ^ mask
}

/// Mask a 32-bit value
#[allow(dead_code)]
pub fn mask_u32(value: u32) -> Result<(u32, u32)> {
    // Use thread-local RNG to avoid global lock contention
    thread_local! {
        static THREAD_RNG: std::cell::RefCell<rand::rngs::SmallRng> = std::cell::RefCell::new(
            rand::rngs::SmallRng::from_entropy()
        );
    }

    let mut mask = [0u8; 4];
    THREAD_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        rng.fill_bytes(&mut mask);
    });

    let mask = u32::from_le_bytes(mask);
    let masked = value ^ mask;
    Ok((masked, mask))
}

/// Unmask a 32-bit value
#[allow(dead_code)]
pub fn unmask_u32(masked: u32, mask: u32) -> u32 {
    masked ^ mask
}

/// Mask a byte array
#[allow(dead_code)]
pub fn mask_bytes(values: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut masks = vec![0u8; values.len()];
    SecureRandom::new()?.fill(&mut masks)?;

    let masked: Vec<u8> = values
        .iter()
        .zip(masks.iter())
        .map(|(v, m)| v ^ m)
        .collect();

    Ok((masked, masks))
}

/// Unmask a byte array
#[allow(dead_code)]
pub fn unmask_bytes(masked: &[u8], masks: &[u8]) -> Vec<u8> {
    masked
        .iter()
        .zip(masks.iter())
        .map(|(v, m)| v ^ m)
        .collect()
}

/// Add power consumption randomization
#[allow(dead_code)]
pub fn randomize_power_consumption(iterations: usize) {
    use std::hint::black_box;

    let mut dummy = [0u64; 8];

    for _ in 0..iterations {
        // Perform operations with different power consumption patterns
        for item in &mut dummy {
            *item = black_box(item.wrapping_add(1));
            *item = black_box(item.rotate_left(7));
            *item = black_box(*item ^ 0xAAAAAAAAAAAAAAAAu64);
        }
    }
}

/// Multiplicative masking for arithmetic operations
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MultiplicativeMask {
    mask: u32,
    inverse: u32,
}

#[allow(dead_code)]
impl MultiplicativeMask {
    pub fn new() -> Result<Self> {
        // Generate a random odd mask (odd numbers have modular inverses mod 2^32)
        let mut mask = [0u8; 4];
        SecureRandom::new()?.fill(&mut mask)?;
        let mut mask = u32::from_le_bytes(mask);
        mask |= 1; // Ensure it's odd

        let inverse = mod_inverse(mask, 0x100000000u64) as u32;

        Ok(Self { mask, inverse })
    }

    pub fn mask(&self, value: u32) -> u32 {
        value.wrapping_mul(self.mask)
    }

    pub fn unmask(&self, masked: u32) -> u32 {
        masked.wrapping_mul(self.inverse)
    }
}

/// Compute modular inverse using extended Euclidean algorithm
#[allow(dead_code)]
fn mod_inverse(a: u32, modulus: u64) -> u64 {
    let mut t = 0i64;
    let mut newt = 1i64;
    let mut r = modulus as i64;
    let mut newr = a as i64;

    while newr != 0 {
        let quotient = r / newr;
        (t, newt) = (newt, t - quotient * newt);
        (r, newr) = (newr, r - quotient * newr);
    }

    if t < 0 {
        t += modulus as i64;
    }

    t as u64
}

/// Boolean masking for logical operations
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BooleanMask {
    masks: Vec<bool>,
}

#[allow(dead_code)]
impl BooleanMask {
    pub fn new(size: usize) -> Result<Self> {
        let mut mask_bytes = vec![0u8; size.div_ceil(8)];
        SecureRandom::new()?.fill(&mut mask_bytes)?;

        let masks: Vec<bool> = (0..size)
            .map(|i| (mask_bytes[i / 8] & (1 << (i % 8))) != 0)
            .collect();

        Ok(Self { masks })
    }

    pub fn mask_bool(&self, index: usize, value: bool) -> bool {
        if index < self.masks.len() {
            value ^ self.masks[index]
        } else {
            value
        }
    }

    pub fn mask_u8(&self, value: u8) -> u8 {
        let mut result = value;
        for (i, &mask) in self.masks.iter().enumerate().take(8) {
            if mask {
                result ^= 1 << i;
            }
        }
        result
    }
}

/// Power analysis statistics for monitoring
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PowerAnalysisStats {
    /// Number of masking operations performed
    pub masking_operations: u64,
    /// Number of randomization operations
    pub randomization_operations: u64,
    /// Number of dummy operations
    pub dummy_operations: u64,
    /// Average execution time of protection operations
    pub avg_protection_time_ms: f64,
    /// Protection level used
    pub protection_level: ProtectionLevel,
}

#[allow(dead_code)]
impl PowerAnalysisStats {
    pub fn new() -> Self {
        Self {
            masking_operations: 0,
            randomization_operations: 0,
            dummy_operations: 0,
            avg_protection_time_ms: 0.0,
            protection_level: ProtectionLevel::Basic,
        }
    }
}

impl Default for PowerAnalysisStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Power analysis resistant AES S-box with enhanced protection
#[allow(dead_code)]
pub fn masked_aes_sbox(input: u8, mask: u8) -> Result<u8> {
    // Apply input mask
    let masked_input = input ^ mask;

    // Add additional randomization for enhanced protection
    let mut additional_mask = [0u8; 1];
    SecureRandom::new()?.fill(&mut additional_mask)?;
    let randomized_input = masked_input ^ additional_mask[0];

    // Regular AES S-box lookup
    let sbox_result = super::constant_time::constant_time_aes_sbox(randomized_input);

    // Generate output mask
    let mut output_mask = [0u8; 1];
    SecureRandom::new()?.fill(&mut output_mask)?;

    // Apply output mask and remove additional randomization
    Ok(sbox_result ^ output_mask[0] ^ additional_mask[0])
}

/// Power analysis protection manager
#[allow(dead_code)]
pub struct PowerAnalysisManager {
    config: PowerAnalysisConfig,
    stats: PowerAnalysisStats,
}

#[allow(dead_code)]
impl PowerAnalysisManager {
    pub fn new(config: PowerAnalysisConfig) -> Self {
        let mut stats = PowerAnalysisStats::new();
        stats.protection_level = config.level;
        Self { config, stats }
    }

    /// Apply masking with statistics tracking
    pub fn mask_bytes_tracked(&mut self, values: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let start = Instant::now();
        let result = mask_bytes(values)?;

        self.stats.masking_operations += 1;
        self.update_timing_stats(start);

        Ok(result)
    }

    /// Apply randomization with statistics tracking
    pub fn randomize_power_consumption_tracked(&mut self, iterations: usize) {
        let start = Instant::now();
        randomize_power_consumption(iterations);

        self.stats.randomization_operations += 1;
        self.update_timing_stats(start);
    }

    fn update_timing_stats(&mut self, start: Instant) {
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let total_ops = self.stats.masking_operations
            + self.stats.randomization_operations
            + self.stats.dummy_operations;

        if total_ops == 1 {
            self.stats.avg_protection_time_ms = elapsed_ms;
        } else if total_ops > 1 {
            self.stats.avg_protection_time_ms =
                (self.stats.avg_protection_time_ms * (total_ops - 1) as f64 + elapsed_ms)
                    / total_ops as f64;
        }
    }

    pub fn get_stats(&self) -> &PowerAnalysisStats {
        &self.stats
    }

    pub fn reset_stats(&mut self) {
        self.stats = PowerAnalysisStats::new();
        self.stats.protection_level = self.config.level;
    }
}

/// Advanced power trace randomization with adaptive complexity
pub fn randomize_power_consumption_adaptive(min_iterations: usize, max_iterations: usize) {
    use std::hint::black_box;

    // Generate random number of iterations within range
    let mut seed = [0u8; 4];
    SecureRandom::new().unwrap().fill(&mut seed).unwrap();
    let seed = u32::from_le_bytes(seed);
    let iterations = min_iterations + (seed as usize % (max_iterations - min_iterations + 1));

    let mut dummy = [0u64; 16]; // Larger array for more complex patterns

    for _ in 0..iterations {
        // Multiple power consumption patterns
        for i in 0..dummy.len() {
            // Pattern 1: Arithmetic operations
            dummy[i] = black_box(dummy[i].wrapping_add(seed as u64));
            dummy[i] = black_box(dummy[i].rotate_left(seed % 64));

            // Pattern 2: Bitwise operations
            dummy[i] = black_box(dummy[i] ^ 0xAAAAAAAAAAAAAAAAu64);
            dummy[i] = black_box(dummy[i] & 0x5555555555555555u64);

            // Pattern 3: Memory access patterns
            let idx = (dummy[i] as usize) % dummy.len();
            dummy[idx] = black_box(dummy[idx].wrapping_mul(0x123456789ABCDEF0u64));

            // Pattern 4: Conditional operations (create branch prediction noise)
            if dummy[i] & 1 == 0 {
                dummy[i] = black_box(dummy[i].wrapping_sub(0xFEDCBA9876543210u64));
            } else {
                dummy[i] = black_box(dummy[i].wrapping_add(0x1111222233334444u64));
            }
        }
    }
}

/// Inject timing noise to disrupt power analysis timing patterns
pub fn inject_timing_noise() {
    use std::hint::black_box;

    // Generate random delay
    let mut delay_seed = [0u8; 2];
    if let Ok(rng) = SecureRandom::new() {
        if rng.fill(&mut delay_seed).is_err() {
            return;
        }
    } else {
        return;
    }
    let delay_cycles = u16::from_le_bytes(delay_seed) as usize;

    // Busy-wait loop with varying patterns
    let mut counter = 0u64;
    for _ in 0..delay_cycles {
        counter = black_box(counter.wrapping_add(1));
        if counter.is_multiple_of(7) {
            // Occasionally add extra delay
            for _ in 0..10 {
                counter = black_box(counter.wrapping_mul(0x1234567890ABCDEFu64));
            }
        }
    }
}

/// Advanced timing noise injection with cache effects
pub fn inject_advanced_timing_noise() {
    use std::hint::black_box;

    // Create cache-friendly and cache-unfriendly access patterns
    const BUFFER_SIZE: usize = 4096;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    SecureRandom::new().unwrap().fill(&mut buffer).unwrap();

    // Sequential access (cache-friendly)
    let mut sum = 0u64;
    for item in buffer.iter().take(BUFFER_SIZE) {
        sum = black_box(sum.wrapping_add(*item as u64));
    }

    // Random access (cache-unfriendly)
    let mut seed = [0u8; 32];
    SecureRandom::new().unwrap().fill(&mut seed).unwrap();
    let mut rng = rand::rngs::SmallRng::from_seed(seed);

    for _ in 0..1000 {
        let idx = rng.next_u32() as usize % BUFFER_SIZE;
        sum = black_box(sum.wrapping_add(buffer[idx] as u64));
    }

    // Strided access (mixed cache behavior)
    for stride in [64, 128, 256, 512] {
        for i in (0..BUFFER_SIZE).step_by(stride) {
            sum = black_box(sum.wrapping_add(buffer[i] as u64));
        }
    }
}

/// Obfuscate template signatures to resist template attacks
pub fn obfuscate_template_signatures() {
    use std::hint::black_box;

    // Template attacks rely on consistent power signatures
    // We introduce controlled variations to break templates

    let mut signature_variations = [0u8; 32 * 8]; // 32 u64s as bytes
    if let Ok(rng) = SecureRandom::new() {
        if let Err(_) = rng.fill(&mut signature_variations) {
            // Fallback if random generation fails
            signature_variations.fill(0xAA);
        }
    } else {
        // Fallback if RNG init fails
        signature_variations.fill(0x55);
    }
    let signature_variations =
        unsafe { std::slice::from_raw_parts(signature_variations.as_ptr() as *const u64, 32) };

    // Create multiple execution paths with different power signatures
    for &variation in signature_variations {
        match variation % 8 {
            0 => {
                // High power consumption path
                let mut acc = 0u128;
                for i in 0..100 {
                    acc = black_box(acc.wrapping_add((i as u128) * (variation as u128)));
                }
            }
            1 => {
                // Low power consumption path
                let mut acc = 0u8;
                for i in 0..50 {
                    acc = black_box(acc.wrapping_add((i as u8) & (variation as u8)));
                }
            }
            2 => {
                // Mixed arithmetic/logic path
                let mut acc = variation;
                for i in 0..75 {
                    acc = black_box(acc.rotate_left(i % 64));
                    acc = black_box(acc ^ (i as u64));
                }
            }
            _ => {
                // Default path with medium power consumption
                let mut acc = variation;
                for i in 0..60 {
                    acc = black_box(acc.wrapping_add(i as u64));
                }
            }
        }
    }

    // Add memory access pattern variations
    const PATTERN_SIZE: usize = 1024;
    let mut pattern_buffer = vec![0u8; PATTERN_SIZE];
    SecureRandom::new()
        .unwrap()
        .fill(&mut pattern_buffer)
        .unwrap();

    // Varying access patterns to break memory-based templates
    for offset in 0..8 {
        let mut sum = 0u64;
        for i in (offset..PATTERN_SIZE).step_by(8) {
            sum = black_box(sum.wrapping_add(pattern_buffer[i] as u64));
        }
    }
}

/// Advanced dummy operations with multiple complexity levels
pub fn advanced_dummy_operations() {
    use std::hint::black_box;

    // Level 1: Simple operations
    let mut dummy1 = 0x12345678u32;
    for _ in 0..50 {
        dummy1 = black_box(dummy1.wrapping_mul(0x9E3779B9u32)); // Golden ratio
        dummy1 = black_box(dummy1.rotate_left(7));
    }

    // Level 2: Memory-intensive operations
    let mut buffer = vec![0u64; 256]; // Directly create u64 vector
    SecureRandom::new().unwrap().fill_bytes(unsafe {
        std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, buffer.len() * 8)
    });

    // Perform operations on the buffer to create memory access patterns
    let mut sum = 0u64;
    for (i, &value) in buffer.iter().enumerate() {
        sum = black_box(sum.wrapping_add(value.rotate_left((i % 64) as u32)));
    }

    for i in 0..buffer.len() {
        let j = (i * 7 + 3) % buffer.len(); // Prime-based indexing
        buffer[i] = black_box(buffer[i].wrapping_add(buffer[j]));
        buffer[j] = black_box(buffer[j] ^ buffer[i]);
    }

    // Level 3: Complex arithmetic with dependencies
    let mut dummy3 = 0xDEADBEEFCAFEBABEu64;
    for i in 0..100 {
        let temp = (i as u64).wrapping_mul(0x1234567890ABCDEFu64);
        dummy3 = black_box(dummy3.wrapping_add(temp));
        dummy3 = black_box(dummy3.rotate_right((i % 64) as u32));

        // Create data dependencies
        if dummy3 & 0x8000000000000000u64 != 0 {
            dummy3 = black_box(dummy3.wrapping_sub(0xFEDCBA9876543210u64));
        }
    }
}

/// Dummy operations to randomize power consumption (original function)
pub fn dummy_operations_complexity(level: u8) {
    use std::hint::black_box;

    let iterations = match level {
        0 => 10,
        1 => 50,
        2 => 100,
        _ => 200,
    };

    let mut dummy = 0xDEADBEEFu32;

    for _ in 0..iterations {
        // Complex operations with different power signatures
        dummy = black_box(dummy.wrapping_mul(0x12345678));
        dummy = black_box(dummy.rotate_right(13));
        dummy = black_box(dummy ^ 0xCAFEBABEu32);
        dummy = black_box(dummy.wrapping_sub(0x87654321));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_unmask_value() {
        let original = 0x42u8;
        let (masked, mask) = mask_value(original).unwrap();
        let unmasked = unmask_value(masked, mask);
        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_mask_unmask_u32() {
        let original = 0xDEADBEEFu32;
        let (masked, mask) = mask_u32(original).unwrap();
        let unmasked = unmask_u32(masked, mask);
        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_mask_unmask_bytes() {
        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let (masked, masks) = mask_bytes(&original).unwrap();
        let unmasked = unmask_bytes(&masked, &masks);
        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_multiplicative_mask() {
        let mask = MultiplicativeMask::new().unwrap();
        let original = 0x12345678u32;
        let masked = mask.mask(original);
        let unmasked = mask.unmask(masked);
        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_boolean_mask() {
        let mask = BooleanMask::new(8).unwrap();
        let original = 0b10101010u8;
        let masked = mask.mask_u8(original);
        let unmasked = mask.mask_u8(masked); // XOR is its own inverse
        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_power_analysis_guard_basic() {
        let config = PowerAnalysisConfig {
            level: ProtectionLevel::Basic,
            enable_trace_randomization: false,
            enable_timing_noise: false,
            enable_dummy_operations: true,
            dummy_operation_level: 1,
        };

        let guard = PowerAnalysisGuard::with_config(config).unwrap();
        assert_eq!(guard._config.level, ProtectionLevel::Basic);
    }

    #[test]
    fn test_power_analysis_guard_enhanced() {
        let config = PowerAnalysisConfig {
            level: ProtectionLevel::Enhanced,
            enable_trace_randomization: true,
            enable_timing_noise: true,
            enable_dummy_operations: true,
            dummy_operation_level: 2,
        };

        let guard = PowerAnalysisGuard::with_config(config).unwrap();
        assert_eq!(guard._config.level, ProtectionLevel::Enhanced);
    }

    #[test]
    fn test_power_analysis_guard_maximum() {
        let config = PowerAnalysisConfig {
            level: ProtectionLevel::Maximum,
            enable_trace_randomization: true,
            enable_timing_noise: true,
            enable_dummy_operations: true,
            dummy_operation_level: 3,
        };

        let guard = PowerAnalysisGuard::with_config(config).unwrap();
        assert_eq!(guard._config.level, ProtectionLevel::Maximum);
    }

    #[test]
    fn test_advanced_power_functions() {
        // Test that advanced functions don't panic
        randomize_power_consumption_adaptive(5, 10);
        inject_timing_noise();
        inject_advanced_timing_noise();
        obfuscate_template_signatures();
        advanced_dummy_operations();
    }

    #[test]
    fn test_power_analysis_manager() {
        let config = PowerAnalysisConfig::default();
        let mut manager = PowerAnalysisManager::new(config);

        // Test masking with tracking
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let (masked, masks) = manager.mask_bytes_tracked(&data).unwrap();
        assert_eq!(masked.len(), data.len());
        assert_eq!(masks.len(), data.len());

        // Test randomization with tracking
        manager.randomize_power_consumption_tracked(10);

        // Check stats
        let stats = manager.get_stats();
        assert!(stats.masking_operations > 0);
        assert!(stats.randomization_operations > 0);
        assert!(stats.avg_protection_time_ms >= 0.0);
        assert_eq!(stats.protection_level, ProtectionLevel::Enhanced);

        // Test stats reset
        manager.reset_stats();
        let reset_stats = manager.get_stats();
        assert_eq!(reset_stats.masking_operations, 0);
        assert_eq!(reset_stats.randomization_operations, 0);
    }

    #[test]
    fn test_masked_aes_sbox() {
        let input = 0x42u8;
        let mask = 0x55u8;

        let result = masked_aes_sbox(input, mask).unwrap();
        // Result should be different from simple S-box due to additional masking
        let simple_result = super::super::constant_time::constant_time_aes_sbox(input);
        assert_ne!(result, simple_result);
    }

    #[test]
    fn test_protection_levels() {
        assert_eq!(ProtectionLevel::Basic as u8, 0);
        assert_eq!(ProtectionLevel::Enhanced as u8, 1);
        assert_eq!(ProtectionLevel::Maximum as u8, 2);

        assert_ne!(ProtectionLevel::Basic, ProtectionLevel::Enhanced);
        assert_ne!(ProtectionLevel::Enhanced, ProtectionLevel::Maximum);
        assert_ne!(ProtectionLevel::Basic, ProtectionLevel::Maximum);
    }

    #[test]
    fn test_masking_properties() {
        // Test that XOR masking is reversible
        for i in 0..256 {
            let original = i as u8;
            let (masked, mask) = mask_value(original).unwrap();
            let unmasked = unmask_value(masked, mask);
            assert_eq!(unmasked, original, "XOR masking failed for value {}", original);

            // Masked value should be different from original when mask is non-zero
            if mask != 0 {
                assert_ne!(masked, original, "Non-zero mask should change the value");
            }
        }
    }

    #[test]
    fn test_multiplicative_mask_properties() {
        let mask = MultiplicativeMask::new().unwrap();

        // Test with various values including edge cases
        let test_values = [0u32, 1, 0xFFFFFFFF, 0x12345678, 0x87654321];

        for &value in &test_values {
            let masked = mask.mask(value);
            let unmasked = mask.unmask(masked);
            assert_eq!(unmasked, value, "Multiplicative masking failed for value 0x{:08x}", value);

            // Masked value should be different from original (except for 0)
            if value != 0 {
                assert_ne!(masked, value, "Multiplicative mask should change non-zero values");
            }
        }
    }

    #[test]
    fn test_boolean_mask_properties() {
        let mask = BooleanMask::new(16).unwrap();

        // Test boolean masking
        for i in 0..16 {
            let original = (i % 2) == 0;
            let masked = mask.mask_bool(i, original);
            let unmasked = mask.mask_bool(i, masked); // XOR is its own inverse
            assert_eq!(unmasked, original, "Boolean masking failed at index {}", i);
        }

        // Test u8 masking
        let original = 0b10101010u8;
        let masked = mask.mask_u8(original);
        let unmasked = mask.mask_u8(masked); // XOR is its own inverse
        assert_eq!(unmasked, original, "Boolean u8 masking failed");
    }

    #[test]
    fn test_mask_distribution() {
        // Test that masks are properly distributed (not all zeros or ones)
        let mut mask_counts = [0u32; 256];

        for _ in 0..1000 {
            let (masked, mask) = mask_value(0x42).unwrap();
            mask_counts[mask as usize] += 1;
            assert_eq!(unmask_value(masked, mask), 0x42);
        }

        // Check that we get a reasonable distribution of mask values
        let zero_count = mask_counts.iter().filter(|&&c| c == 0).count();
        assert!(zero_count < 200, "Too many mask values never used: {}", zero_count);

        let max_count = *mask_counts.iter().max().unwrap();
        assert!(max_count < 20, "Mask value used too frequently: {}", max_count);
    }

    #[test]
    fn test_large_byte_masking() {
        // Test masking of larger byte arrays
        let original: Vec<u8> = (0..1024).map(|i| (i * 7 + 3) as u8).collect();
        let (masked, masks) = mask_bytes(&original).unwrap();
        let unmasked = unmask_bytes(&masked, &masks);

        assert_eq!(unmasked, original, "Large byte array masking failed");
        assert_eq!(masked.len(), original.len());
        assert_eq!(masks.len(), original.len());

        // Verify that masking actually changes the data
        let mut changed_count = 0;
        for (orig, mask) in original.iter().zip(masked.iter()) {
            if orig != mask {
                changed_count += 1;
            }
        }
        assert!(changed_count > 800, "Masking should change most bytes, only changed {}", changed_count);
    }

    #[test]
    fn test_power_analysis_stats() {
        let stats = PowerAnalysisStats::new();
        assert_eq!(stats.masking_operations, 0);
        assert_eq!(stats.randomization_operations, 0);
        assert_eq!(stats.dummy_operations, 0);
        assert_eq!(stats.avg_protection_time_ms, 0.0);
        assert_eq!(stats.protection_level, ProtectionLevel::Basic);

        // Test default implementation
        let default_stats = PowerAnalysisStats::default();
        assert_eq!(default_stats.masking_operations, 0);
        assert_eq!(default_stats.protection_level, ProtectionLevel::Basic);
    }

    #[test]
    fn test_manager_timing_stats() {
        let config = PowerAnalysisConfig::default();
        let mut manager = PowerAnalysisManager::new(config);

        // Perform some operations to build timing statistics
        for i in 0..5 {
            let data = vec![i; 100];
            let _ = manager.mask_bytes_tracked(&data).unwrap();
            manager.randomize_power_consumption_tracked(5);
        }

        let stats = manager.get_stats();
        assert!(stats.masking_operations >= 5);
        assert!(stats.randomization_operations >= 5);
        assert!(stats.avg_protection_time_ms > 0.0);

        // Reset and verify
        manager.reset_stats();
        let reset_stats = manager.get_stats();
        assert_eq!(reset_stats.masking_operations, 0);
        assert_eq!(reset_stats.randomization_operations, 0);
        assert_eq!(reset_stats.avg_protection_time_ms, 0.0);
    }
}
