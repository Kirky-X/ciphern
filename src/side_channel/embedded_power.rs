// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{Result, CryptoError};
use crate::random::SecureRandom;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// 嵌入式功耗分析防护配置
#[derive(Debug, Clone)]
pub struct EmbeddedPowerConfig {
    /// 是否启用ARM Cortex-M特定优化
    pub cortex_m_optimization: bool,
    /// 功耗掩码强度 (0.0 - 1.0)
    pub power_masking_strength: f32,
    /// 随机延迟范围（微秒）
    pub random_delay_range_us: (u32, u32),
    /// 是否启用时钟抖动
    pub clock_jitter_enabled: bool,
    /// 时钟抖动强度 (0.0 - 1.0)
    pub clock_jitter_strength: f32,
    /// 是否启用功耗噪声注入
    pub power_noise_injection: bool,
    /// 功耗噪声强度 (0.0 - 1.0)
    pub power_noise_strength: f32,
}

impl Default for EmbeddedPowerConfig {
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

/// 嵌入式功耗分析防护器
pub struct EmbeddedPowerProtector {
    config: EmbeddedPowerConfig,
    operation_counter: AtomicU32,
    last_operation_time: std::sync::Mutex<Option<Instant>>,
}

impl EmbeddedPowerProtector {
    /// 创建新的嵌入式功耗防护器
    pub fn new(config: EmbeddedPowerConfig) -> Self {
        Self {
            config,
            operation_counter: AtomicU32::new(0),
            last_operation_time: std::sync::Mutex::new(None),
        }
    }

    /// 执行功耗分析防护操作
    pub fn protect_operation<F, R>(&self, operation: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        // 记录操作开始时间
        let start_time = Instant::now();
        
        // 应用功耗掩码
        self.apply_power_masking()?;
        
        // 添加随机延迟
        self.add_random_delay()?;
        
        // 应用时钟抖动
        if self.config.clock_jitter_enabled {
            self.apply_clock_jitter()?;
        }
        
        // 注入功耗噪声
        if self.config.power_noise_injection {
            self.inject_power_noise()?;
        }
        
        // 执行实际操作
        let result = operation();
        
        // 记录操作结束时间
        let operation_time = start_time.elapsed();
        
        // 更新操作计数器
        self.operation_counter.fetch_add(1, Ordering::SeqCst);
        
        // 更新最后操作时间
        {
            let mut last_time = self.last_operation_time.lock().unwrap();
            *last_time = Some(Instant::now());
        }
        
        // 应用操作后防护
        self.post_operation_protection(operation_time)?;
        
        result
    }

    /// 应用功耗掩码
    fn apply_power_masking(&self) -> Result<()> {
        let masking_strength = self.config.power_masking_strength;
        
        // ARM Cortex-M特定优化
        if self.config.cortex_m_optimization && cfg!(target_arch = "arm") {
            self.apply_cortex_m_masking(masking_strength)?;
        } else {
            self.apply_generic_masking(masking_strength)?;
        }
        
        Ok(())
    }

    /// ARM Cortex-M特定掩码技术
    fn apply_cortex_m_masking(&self, strength: f32) -> Result<()> {
        // 使用ARM特定的指令序列创建功耗掩码
        let mask_operations = (strength * 100.0) as usize;
        
        unsafe {
            // 使用内联汇编创建功耗变化
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
        
        // Cortex-M特定的寄存器操作
        self.cortex_m_register_operations(strength)?;
        
        Ok(())
    }

    /// Cortex-M寄存器操作以创建功耗变化
    fn cortex_m_register_operations(&self, strength: f32) -> Result<()> {
        let iterations = (strength * 50.0) as usize;
        
        unsafe {
            // 使用ARM Cortex-M的寄存器创建功耗变化
            std::arch::asm!(
                "mov r0, #0",
                "mov r1, #1", 
                "mov r2, #2",
                "mov r3, #3",
                options(nostack, preserves_flags)
            );
            
            for i in 0..iterations {
                let mask = (i as u32 * 0x9E3779B9u32) as i32; // 黄金比例
                std::arch::asm!(
                    "eor r0, r0, {mask:e}",
                    "eor r1, r1, {mask:e}",
                    "eor r2, r2, {mask:e}",
                    "eor r3, r3, {mask:e}",
                    mask = in(reg) mask,
                    options(nostack, preserves_flags)
                );
            }
            
            // 清理寄存器
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
        
        // 创建随机掩码数据
        let mut mask_data = vec![0u8; mask_operations * 8];
        SecureRandom::new()?.fill(&mut mask_data)?;
        
        // 执行掩码操作
        let mut accumulator = 0u64;
        for chunk in mask_data.chunks_exact(8) {
            let value = u64::from_le_bytes(chunk.try_into().unwrap());
            accumulator = accumulator.wrapping_add(value);
            accumulator = accumulator.rotate_left(7);
        }
        
        // 使用black_box防止编译器优化
        std::hint::black_box(accumulator);
        
        Ok(())
    }

    /// 添加随机延迟
    fn add_random_delay(&self) -> Result<()> {
        let (min_us, max_us) = self.config.random_delay_range_us;
        
        // 生成随机延迟时间
        let delay_range = max_us - min_us;
        let mut random_bytes = [0u8; 4];
        SecureRandom::new()?.fill(&mut random_bytes)?;
        
        let random_value = u32::from_le_bytes(random_bytes);
        let delay_us = min_us + (random_value % delay_range);
        
        // 执行延迟
        if delay_us > 0 {
            std::thread::sleep(Duration::from_micros(delay_us as u64));
        }
        
        Ok(())
    }

    /// 应用时钟抖动
    fn apply_clock_jitter(&self) -> Result<()> {
        let jitter_strength = self.config.clock_jitter_strength;
        
        // 创建时钟抖动
        let jitter_operations = (jitter_strength * 100.0) as usize;
        
        for _ in 0..jitter_operations {
            // 使用高精度计时器创建抖动
            let start = Instant::now();
            
            // 执行一些操作
            let mut temp = 0u64;
            for i in 0..100 {
                temp = temp.wrapping_add(i as u64);
            }
            
            let elapsed = start.elapsed();
            
            // 基于实际执行时间调整后续操作
            if elapsed.as_nanos() < 100 {
                // 如果执行太快，添加额外延迟
                std::thread::sleep(Duration::from_nanos(50));
            }
        }
        
        Ok(())
    }

    /// 注入功耗噪声
    fn inject_power_noise(&self) -> Result<()> {
        let noise_strength = self.config.power_noise_strength;
        
        // 创建功耗噪声
        let noise_operations = (noise_strength * 150.0) as usize;
        let mut noise_data = vec![0u8; noise_operations * 16];
        SecureRandom::new()?.fill(&mut noise_data)?;
        
        // 执行噪声操作
        for chunk in noise_data.chunks_exact(16) {
            let mut accumulator = 0u128;
            
            // 将数据加载到寄存器
            for (i, &byte) in chunk.iter().enumerate() {
                accumulator = accumulator.wrapping_add((byte as u128) << (i * 8));
            }
            
            // 执行功耗密集型操作
            for _ in 0..10 {
                accumulator = accumulator.wrapping_mul(0x9E3779B97F4A7C15u128); // 128位黄金比例
                accumulator = accumulator.rotate_left(17);
            }
            
            std::hint::black_box(accumulator);
        }
        
        Ok(())
    }

    /// 操作后防护
    fn post_operation_protection(&self, operation_time: Duration) -> Result<()> {
        // 基于操作时间调整后续防护
        if operation_time.as_micros() < 50 {
            // 快速操作，增加额外防护
            self.add_random_delay()?;
        }
        
        // 随机决定是否添加额外防护
        let mut random_byte = [0u8; 1];
        SecureRandom::new()?.fill(&mut random_byte)?;
        
        if random_byte[0] % 3 == 0 {
            // 33%概率添加额外防护
            self.inject_power_noise()?;
        }
        
        Ok(())
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> EmbeddedPowerStats {
        let operation_count = self.operation_counter.load(Ordering::SeqCst);
        let last_time = self.last_operation_time.lock().unwrap().clone();
        
        EmbeddedPowerStats {
            total_operations: operation_count,
            last_operation_time: last_time,
            cortex_m_optimization_enabled: self.config.cortex_m_optimization,
            power_masking_strength: self.config.power_masking_strength,
        }
    }

    /// 更新配置
    pub fn update_config(&mut self, config: EmbeddedPowerConfig) {
        self.config = config;
    }
}

/// 嵌入式功耗防护统计信息
#[derive(Debug, Clone)]
pub struct EmbeddedPowerStats {
    pub total_operations: u32,
    pub last_operation_time: Option<Instant>,
    pub cortex_m_optimization_enabled: bool,
    pub power_masking_strength: f32,
}

/// 嵌入式功耗防护构建器
pub struct EmbeddedPowerProtectorBuilder {
    config: EmbeddedPowerConfig,
}

impl EmbeddedPowerProtectorBuilder {
    pub fn new() -> Self {
        Self {
            config: EmbeddedPowerConfig::default(),
        }
    }

    pub fn cortex_m_optimization(mut self, enabled: bool) -> Self {
        self.config.cortex_m_optimization = enabled;
        self
    }

    pub fn power_masking_strength(mut self, strength: f32) -> Self {
        self.config.power_masking_strength = strength.clamp(0.0, 1.0);
        self
    }

    pub fn random_delay_range(mut self, min_us: u32, max_us: u32) -> Self {
        self.config.random_delay_range_us = (min_us, max_us);
        self
    }

    pub fn clock_jitter(mut self, enabled: bool, strength: f32) -> Self {
        self.config.clock_jitter_enabled = enabled;
        self.config.clock_jitter_strength = strength.clamp(0.0, 1.0);
        self
    }

    pub fn power_noise(mut self, enabled: bool, strength: f32) -> Self {
        self.config.power_noise_injection = enabled;
        self.config.power_noise_strength = strength.clamp(0.0, 1.0);
        self
    }

    pub fn build(self) -> EmbeddedPowerProtector {
        EmbeddedPowerProtector::new(self.config)
    }
}

impl Default for EmbeddedPowerProtectorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CryptoError;

    #[test]
    fn test_embedded_power_protector_creation() {
        let protector = EmbeddedPowerProtector::new(EmbeddedPowerConfig::default());
        let stats = protector.get_stats();
        
        assert_eq!(stats.total_operations, 0);
        assert!(stats.last_operation_time.is_none());
    }

    #[test]
    fn test_embedded_power_protector_builder() {
        let protector = EmbeddedPowerProtectorBuilder::new()
            .cortex_m_optimization(true)
            .power_masking_strength(0.9)
            .random_delay_range(20, 80)
            .clock_jitter(true, 0.4)
            .power_noise(true, 0.6)
            .build();
        
        let stats = protector.get_stats();
        assert_eq!(stats.power_masking_strength, 0.9);
        assert!(stats.cortex_m_optimization_enabled);
    }

    #[test]
    fn test_protect_operation() {
        let protector = EmbeddedPowerProtector::new(EmbeddedPowerConfig::default());
        
        let result = protector.protect_operation(|| {
            Ok::<_, CryptoError>(42)
        });
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        
        let stats = protector.get_stats();
        assert_eq!(stats.total_operations, 1);
        assert!(stats.last_operation_time.is_some());
    }

    #[test]
    fn test_multiple_operations() {
        let protector = EmbeddedPowerProtector::new(EmbeddedPowerConfig::default());
        
        for i in 0..5 {
            let result = protector.protect_operation(|| {
                Ok::<_, CryptoError>(i)
            });
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), i);
        }
        
        let stats = protector.get_stats();
        assert_eq!(stats.total_operations, 5);
    }
}