// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::side_channel::struct_file::{
    CountermeasureStats, SideChannelConfig, SideChannelContext, SideChannelStats,
};
use crate::side_channel::power_analysis::PowerAnalysisGuard;
use crate::side_channel::error_injection::ErrorInjectionDetector;
use crate::side_channel::fn_file::{add_timing_noise, flush_cpu_cache};
use std::time::{Instant};
use std::sync::{Arc, Mutex};

impl SideChannelContext {
    pub fn new(config: SideChannelConfig) -> Self {
        Self {
            config,
            countermeasure_stats: CountermeasureStats::default(),
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &SideChannelConfig {
        &self.config
    }

    /// Reset the context statistics
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
