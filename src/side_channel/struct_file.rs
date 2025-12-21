// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use std::time::Duration;

/// Configuration for side-channel protection
#[derive(Debug, Clone)]
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
            timing_noise_level: 0.1, // 10% timing noise for better protection
            max_timing_deviation: Duration::from_micros(50), // 50μs minimum timing
        }
    }
}

/// Global side-channel protection context
#[derive(Clone)]
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

/// Side-channel protection statistics
#[derive(Debug, Clone)]
pub struct SideChannelStats {
    pub timing_protections: u64,
    pub masking_operations: u64,
    pub error_detection_triggers: u64,
    pub cache_flush_operations: u64,
}
