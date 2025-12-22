// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::random::SecureRandom;

use super::r#struct::{
    EmbeddedPowerConfig, EmbeddedPowerProtector, EmbeddedPowerProtectorBuilder, EmbeddedPowerStats,
};

// === Implementation: EmbeddedPowerConfig ===

impl Default for EmbeddedPowerConfig {
    /// 创建默认配置
    fn default() -> Self {
        Self {
            cortex_m_optimization: cfg!(target_arch = "arm"),
            power_masking_strength: 0.8,
            random_delay_range_us: (10, 100),
            clock_jitter_enabled: true,
            clock_jitter_strength: 0.3,
            power_noise_injection: true,
            power_noise_strength: 0.5,
        }
    }
}

// === Implementation: EmbeddedPowerProtector ===

impl EmbeddedPowerProtector {
    /// 创建新的嵌入式功耗防护器
    pub fn new(config: EmbeddedPowerConfig) -> Self {
        Self {
            config,
            operation_counter: AtomicU32::new(0),
            last_operation_time: Mutex::new(None),
        }
    }

    /// 执行功耗分析防护操作
    #[allow(dead_code)]
    pub fn protect_operation<F, R>(&self, operation: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        let start_time = Instant::now();

        self.apply_power_masking()?;
        self.add_random_delay()?;

        if self.config.clock_jitter_enabled {
            self.apply_clock_jitter()?;
        }

        if self.config.power_noise_injection {
            self.inject_power_noise()?;
        }

        let result = operation();
        let operation_time = start_time.elapsed();

        self.operation_counter.fetch_add(1, Ordering::SeqCst);

        {
            let mut last_time = self.last_operation_time.lock().unwrap();
            *last_time = Some(Instant::now());
        }

        self.post_operation_protection(operation_time)?;

        result
    }

    /// 获取统计信息
    #[allow(dead_code)]
    pub fn stats(&self) -> EmbeddedPowerStats {
        let operation_count = self.operation_counter.load(Ordering::SeqCst);
        let last_time = *self.last_operation_time.lock().unwrap();

        EmbeddedPowerStats {
            total_operations: operation_count,
            last_operation_time: last_time,
            cortex_m_optimization_enabled: self.config.cortex_m_optimization,
            power_masking_strength: self.config.power_masking_strength,
        }
    }

    /// 更新配置
    #[allow(dead_code)]
    pub fn set_config(&mut self, config: EmbeddedPowerConfig) {
        self.config = config;
    }

    /// 应用功耗掩码
    fn apply_power_masking(&self) -> Result<()> {
        let masking_strength = self.config.power_masking_strength;

        if self.config.cortex_m_optimization && cfg!(target_arch = "arm") {
            self.apply_cortex_m_masking(masking_strength)?;
        } else {
            self.apply_generic_masking(masking_strength)?;
        }

        Ok(())
    }

    /// ARM Cortex-M特定掩码技术
    fn apply_cortex_m_masking(&self, strength: f32) -> Result<()> {
        let mask_operations = (strength * 100.0) as usize;

        unsafe {
            for _ in 0..mask_operations {
                std::arch::asm!(
                    "nop",
                    "nop",
                    "nop",
                    "nop",
                    options(nostack, preserves_flags)
                );
            }
        }

        self.cortex_m_register_operations(strength)?;

        Ok(())
    }

    /// Cortex-M寄存器操作以创建功耗变化
    fn cortex_m_register_operations(&self, strength: f32) -> Result<()> {
        let iterations = (strength * 50.0) as usize;

        unsafe {
            std::arch::asm!(
                "mov r0, #0",
                "mov r1, #1",
                "mov r2, #2",
                "mov r3, #3",
                options(nostack, preserves_flags)
            );

            for i in 0..iterations {
                let mask = (i as u32 * 0x9E3779B9u32) as i32;
                std::arch::asm!(
                    "eor r0, r0, {mask:e}",
                    "eor r1, r1, {mask:e}",
                    "eor r2, r2, {mask:e}",
                    "eor r3, r3, {mask:e}",
                    mask = in(reg) mask,
                    options(nostack, preserves_flags)
                );
            }

            std::arch::asm!(
                "mov r0, #0",
                "mov r1, #0",
                "mov r2, #0",
                "mov r3, #0",
                options(nostack, preserves_flags)
            );
        }

        Ok(())
    }

    /// 通用掩码技术
    fn apply_generic_masking(&self, strength: f32) -> Result<()> {
        let mask_operations = (strength * 200.0) as usize;
        let mut mask_data = vec![0u8; mask_operations * 8];

        SecureRandom::new()?.fill(&mut mask_data)?;

        let mut accumulator = 0u64;
        for chunk in mask_data.chunks_exact(8) {
            let value = u64::from_le_bytes(chunk.try_into().unwrap());
            accumulator = accumulator.wrapping_add(value);
            accumulator = accumulator.rotate_left(7);
        }

        std::hint::black_box(accumulator);

        Ok(())
    }

    /// 添加随机延迟
    fn add_random_delay(&self) -> Result<()> {
        let (min_us, max_us) = self.config.random_delay_range_us;
        let delay_range = max_us - min_us;

        if delay_range == 0 {
            if min_us > 0 {
                std::thread::sleep(Duration::from_micros(min_us as u64));
            }
            return Ok(());
        }

        let mut random_bytes = [0u8; 4];
        SecureRandom::new()?.fill(&mut random_bytes)?;

        let random_value = u32::from_le_bytes(random_bytes);
        let delay_us = min_us + (random_value % delay_range);

        if delay_us > 0 {
            std::thread::sleep(Duration::from_micros(delay_us as u64));
        }

        Ok(())
    }

    /// 应用时钟抖动
    fn apply_clock_jitter(&self) -> Result<()> {
        let jitter_strength = self.config.clock_jitter_strength;
        let jitter_operations = (jitter_strength * 100.0) as usize;

        for _ in 0..jitter_operations {
            let start = Instant::now();
            let mut temp = 0u64;

            for i in 0..100 {
                temp = temp.wrapping_add(i as u64);
            }

            let elapsed = start.elapsed();

            if elapsed.as_nanos() < 100 {
                std::thread::sleep(Duration::from_nanos(50));
            }

            std::hint::black_box(temp);
        }

        Ok(())
    }

    /// 注入功耗噪声
    fn inject_power_noise(&self) -> Result<()> {
        let noise_strength = self.config.power_noise_strength;
        let noise_operations = (noise_strength * 150.0) as usize;
        let mut noise_data = vec![0u8; noise_operations * 16];

        SecureRandom::new()?.fill(&mut noise_data)?;

        for chunk in noise_data.chunks_exact(16) {
            let mut accumulator = 0u128;

            for (i, &byte) in chunk.iter().enumerate() {
                accumulator = accumulator.wrapping_add((byte as u128) << (i * 8));
            }

            for _ in 0..10 {
                accumulator = accumulator.wrapping_mul(0x9E3779B97F4A7C15u128);
                accumulator = accumulator.rotate_left(17);
            }

            std::hint::black_box(accumulator);
        }

        Ok(())
    }

    /// 操作后防护
    fn post_operation_protection(&self, operation_time: Duration) -> Result<()> {
        if operation_time.as_micros() < 50 {
            self.add_random_delay()?;
        }

        let mut random_byte = [0u8; 1];
        SecureRandom::new()?.fill(&mut random_byte)?;

        if random_byte[0] % 3 == 0 {
            self.inject_power_noise()?;
        }

        Ok(())
    }
}

// === Implementation: EmbeddedPowerProtectorBuilder ===

impl EmbeddedPowerProtectorBuilder {
    /// 创建新的构建器
    pub fn new() -> Self {
        Self {
            config: EmbeddedPowerConfig::default(),
        }
    }

    /// 设置Cortex-M优化
    #[allow(dead_code)]
    pub fn cortex_m_optimization(mut self, enabled: bool) -> Self {
        self.config.cortex_m_optimization = enabled;
        self
    }

    /// 设置功耗掩码强度
    #[allow(dead_code)]
    pub fn power_masking_strength(mut self, strength: f32) -> Self {
        self.config.power_masking_strength = strength.clamp(0.0, 1.0);
        self
    }

    /// 设置随机延迟范围
    #[allow(dead_code)]
    pub fn random_delay_range(mut self, min_us: u32, max_us: u32) -> Self {
        self.config.random_delay_range_us = (min_us, max_us);
        self
    }

    /// 设置时钟抖动
    #[allow(dead_code)]
    pub fn clock_jitter(mut self, enabled: bool, strength: f32) -> Self {
        self.config.clock_jitter_enabled = enabled;
        self.config.clock_jitter_strength = strength.clamp(0.0, 1.0);
        self
    }

    /// 设置功耗噪声
    #[allow(dead_code)]
    pub fn power_noise(mut self, enabled: bool, strength: f32) -> Self {
        self.config.power_noise_injection = enabled;
        self.config.power_noise_strength = strength.clamp(0.0, 1.0);
        self
    }

    /// 构建防护器
    #[allow(dead_code)]
    pub fn build(self) -> EmbeddedPowerProtector {
        EmbeddedPowerProtector::new(self.config)
    }
}

#[allow(dead_code)]
impl Default for EmbeddedPowerProtectorBuilder {
    fn default() -> Self {
        Self::new()
    }
}
