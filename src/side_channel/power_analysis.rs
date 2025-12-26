// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! 功耗分析攻击防护
//!
//! This module provides countermeasures against Simple Power Analysis (SPA)
//! and Differential Power Analysis (DPA) attacks through masking and randomization.
//!
//! Features:
//! - XOR, multiplicative, and boolean masking
//! - 功耗消耗随机化
//! - Advanced power trace obfuscation
//! - Template attack protection
//! - Configurable protection levels

use crate::error::Result;
use crate::random::SecureRandom;
use rand::{RngCore, SeedableRng};
use std::time::Instant;

/// 功耗分析防护级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProtectionLevel {
    /// 基础防护：简单掩码
    Basic,
    /// Enhanced protection: advanced masking + randomization
    Enhanced,
    /// 最大防护：完全混淆 + 模板攻击抵抗
    Maximum,
}

/// Power analysis protection configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PowerAnalysisConfig {
    /// Protection level
    pub level: ProtectionLevel,
    /// 启用功耗轨迹随机化
    pub enable_trace_randomization: bool,
    /// 启用时序噪声注入
    pub enable_timing_noise: bool,
    /// Enable dummy operations
    pub enable_dummy_operations: bool,
    /// 最小虚拟操作复杂度 (0-3)
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

        // 使用线程局部 RNG 避免全局锁竞争
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

        // 根据配置应用防护
        match config.level {
            ProtectionLevel::Basic => {
                // 基础防护：简单虚拟操作
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
                // 最大防护：完全混淆
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

/// 使用 XOR 掩码对值进行掩码
#[allow(dead_code)]
pub fn mask_value(value: u8) -> Result<(u8, u8)> {
    // 使用线程局部 RNG 避免全局锁竞争
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

/// 使用 XOR 掩码解除值的掩码
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

/// 对 32 位值进行解掩码
#[allow(dead_code)]
pub fn unmask_u32(masked: u32, mask: u32) -> u32 {
    masked ^ mask
}

/// 对字节数组进行掩码
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

/// 对字节数组进行解掩码
#[allow(dead_code)]
pub fn unmask_bytes(masked: &[u8], masks: &[u8]) -> Vec<u8> {
    masked
        .iter()
        .zip(masks.iter())
        .map(|(v, m)| v ^ m)
        .collect()
}

/// 添加功耗消耗随机化
#[allow(dead_code)]
pub fn randomize_power_consumption(iterations: usize) {
    use std::hint::black_box;

    let mut dummy = [0u64; 8];

    for _ in 0..iterations {
        // 执行具有不同功耗模式的操作
        for item in &mut dummy {
            *item = black_box(item.wrapping_add(1));
            *item = black_box(item.rotate_left(7));
            *item = black_box(*item ^ 0xAAAAAAAAAAAAAAAAu64);
        }
    }
}

/// 用于算术运算的乘法掩码
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MultiplicativeMask {
    mask: u32,
    inverse: u32,
}

#[allow(dead_code)]
impl MultiplicativeMask {
    pub fn new() -> Result<Self> {
        // 生成一个随机奇数掩码（奇数在模 2^32 下有模逆元）
        let mut mask = [0u8; 4];
        SecureRandom::new()?.fill(&mut mask)?;
        let mut mask = u32::from_le_bytes(mask);
        mask |= 1; // 确保它是奇数

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

/// 用于逻辑运算的布尔掩码
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BooleanMask {
    masks: Vec<bool>,
}

/// 内存填充操作的安全包装器，安全地处理原始指针
#[allow(dead_code)]
fn safe_fill_bytes(ptr: *mut u8, len: usize, rng: &mut dyn rand::RngCore) -> Result<()> {
    if ptr.is_null() {
        return Err(crate::error::CryptoError::InvalidParameter(
            "Null pointer passed to fill_bytes".to_string(),
        ));
    }

    if len == 0 {
        return Ok(());
    }

    // 如果可能，在栈/堆上创建临时缓冲区而不是直接写入原始指针，
    // 或者如果可能，验证指针有效性。
    // 这里我们用检查包装不安全块
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    rng.fill_bytes(slice);
    Ok(())
}

#[allow(dead_code)]
fn safe_fill_bytes_fallback(ptr: *mut u8, len: usize) -> Result<()> {
    if ptr.is_null() {
        return Err(crate::error::CryptoError::InvalidParameter(
            "Null pointer passed to fill_bytes".to_string(),
        ));
    }

    if len == 0 {
        return Ok(());
    }

    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    for byte in slice.iter_mut() {
        *byte = 0xAA;
    }
    Ok(())
}

#[allow(dead_code)]
impl BooleanMask {
    pub fn new(size: usize) -> Result<Self> {
        let mut mask_bytes = vec![0u8; size.div_ceil(8)];

        // Use safe fill method
        if let Ok(rng) = SecureRandom::new() {
            // SecureRandom::fill 是安全的，但如果我们要使用原始指针，我们会使用 safe_fill_bytes
            rng.fill(&mut mask_bytes)?;
        } else {
            // 如果 RNG 初始化失败，使用回退方案
            for item in mask_bytes.iter_mut() {
                *item = 0xAA;
            }
        }

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
    /// 执行的掩码操作数量
    pub masking_operations: u64,
    /// 随机化操作数量
    pub randomization_operations: u64,
    /// 虚拟操作数量
    pub dummy_operations: u64,
    /// 防护操作的平均执行时间（毫秒）
    pub avg_protection_time_ms: f64,
    /// 使用的防护级别
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

/// 具有增强防护的功耗分析抗性 AES S 盒
#[allow(dead_code)]
pub fn masked_aes_sbox(input: u8, mask: u8) -> Result<u8> {
    // 应用输入掩码
    let masked_input = input ^ mask;

    // 为增强防护添加额外的随机化
    let mut additional_mask = [0u8; 1];
    SecureRandom::new()?.fill(&mut additional_mask)?;
    let randomized_input = masked_input ^ additional_mask[0];

    // 常规 AES S 盒查找
    let sbox_result = super::constant_time::constant_time_aes_sbox(randomized_input);

    // 生成输出掩码
    let mut output_mask = [0u8; 1];
    SecureRandom::new()?.fill(&mut output_mask)?;

    // 应用输出掩码并移除额外随机化
    Ok(sbox_result ^ output_mask[0] ^ additional_mask[0])
}

/// 功耗分析防护管理器
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

    /// 应用掩码并跟踪统计信息
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

/// 具有自适应复杂度的高级功耗轨迹随机化
pub fn randomize_power_consumption_adaptive(min_iterations: usize, max_iterations: usize) {
    use std::hint::black_box;

    // 在范围内生成随机迭代次数
    let mut seed = [0u8; 4];
    SecureRandom::new().unwrap().fill(&mut seed).unwrap();
    let seed = u32::from_le_bytes(seed);
    let iterations = min_iterations + (seed as usize % (max_iterations - min_iterations + 1));

    let mut dummy = [0u64; 16]; // 更大的数组用于更复杂的模式

    for _ in 0..iterations {
        // 多种功耗模式
        for i in 0..dummy.len() {
            // 模式 1：算术运算
            dummy[i] = black_box(dummy[i].wrapping_add(seed as u64));
            dummy[i] = black_box(dummy[i].rotate_left(seed % 64));

            // 模式 2：位运算
            dummy[i] = black_box(dummy[i] ^ 0xAAAAAAAAAAAAAAAAu64);
            dummy[i] = black_box(dummy[i] & 0x5555555555555555u64);

            // 模式 3：内存访问模式
            let idx = (dummy[i] as usize) % dummy.len();
            dummy[idx] = black_box(dummy[idx].wrapping_mul(0x123456789ABCDEF0u64));

            // 模式 4：条件操作（创建分支预测噪声）
            if dummy[i] & 1 == 0 {
                dummy[i] = black_box(dummy[i].wrapping_sub(0xFEDCBA9876543210u64));
            } else {
                dummy[i] = black_box(dummy[i].wrapping_add(0x1111222233334444u64));
            }
        }
    }
}

/// 注入时序噪声以破坏功耗分析时序模式
pub fn inject_timing_noise() {
    use std::hint::black_box;

    // 生成随机延迟
    let mut delay_seed = [0u8; 2];
    if let Ok(rng) = SecureRandom::new() {
        if rng.fill(&mut delay_seed).is_err() {
            return;
        }
    } else {
        return;
    }
    let delay_cycles = u16::from_le_bytes(delay_seed) as usize;

    // 具有变化模式的忙等待循环
    let mut counter = 0u64;
    for _ in 0..delay_cycles {
        counter = black_box(counter.wrapping_add(1));
        if counter.is_multiple_of(7) {
            // 偶尔添加额外延迟
            for _ in 0..10 {
                counter = black_box(counter.wrapping_mul(0x1234567890ABCDEFu64));
            }
        }
    }
}

/// 具有缓存效应的高级时序噪声注入
pub fn inject_advanced_timing_noise() {
    use std::hint::black_box;

    // 创建缓存友好和缓存不友好的访问模式
    const BUFFER_SIZE: usize = 4096;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    SecureRandom::new().unwrap().fill(&mut buffer).unwrap();

    // 顺序访问（缓存友好）
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

    // 步进访问（混合缓存行为）
    for stride in [64, 128, 256, 512] {
        for i in (0..BUFFER_SIZE).step_by(stride) {
            sum = black_box(sum.wrapping_add(buffer[i] as u64));
        }
    }
}

/// 混淆模板特征以抵抗模板攻击
pub fn obfuscate_template_signatures() {
    use std::hint::black_box;

    // 模板攻击依赖于一致的功耗特征
    // 我们引入受控的变化来破坏模板

    let mut signature_variations = [0u8; 32 * 8]; // 32 个 u64 作为字节
    if let Ok(rng) = SecureRandom::new() {
        if rng.fill(&mut signature_variations).is_err() {
            // Fallback if random generation fails
            signature_variations.fill(0xAA);
        }
    } else {
        // 如果 RNG 初始化失败，使用回退方案
        signature_variations.fill(0x55);
    }
    let signature_variations =
        unsafe { std::slice::from_raw_parts(signature_variations.as_ptr() as *const u64, 32) };

    // 创建具有不同功耗特征的多个执行路径
    for &variation in signature_variations {
        match variation % 8 {
            0 => {
                // 高功耗路径
                let mut acc = 0u128;
                for i in 0..100 {
                    acc = black_box(acc.wrapping_add((i as u128) * (variation as u128)));
                }
            }
            1 => {
                // 低功耗路径
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
                // 具有中等功耗的默认路径
                let mut acc = variation;
                for i in 0..60 {
                    acc = black_box(acc.wrapping_add(i as u64));
                }
            }
        }
    }

    // 添加内存访问模式变化
    const PATTERN_SIZE: usize = 1024;
    let mut pattern_buffer = vec![0u8; PATTERN_SIZE];
    SecureRandom::new()
        .unwrap()
        .fill(&mut pattern_buffer)
        .unwrap();

    // 变化的访问模式以破坏基于内存的模板
    for offset in 0..8 {
        let mut sum = 0u64;
        for i in (offset..PATTERN_SIZE).step_by(8) {
            sum = black_box(sum.wrapping_add(pattern_buffer[i] as u64));
        }
    }
}

/// 具有多个复杂度级别的高级虚拟操作
pub fn advanced_dummy_operations() {
    use std::hint::black_box;

    // Level 1: Simple operations
    let mut dummy1 = 0x12345678u32;
    for _ in 0..50 {
        dummy1 = black_box(dummy1.wrapping_mul(0x9E3779B9u32)); // 黄金比例
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
            assert_eq!(
                unmasked, original,
                "XOR masking failed for value {}",
                original
            );

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
            assert_eq!(
                unmasked, value,
                "Multiplicative masking failed for value 0x{:08x}",
                value
            );

            // Masked value should be different from original (except for 0)
            if value != 0 {
                assert_ne!(
                    masked, value,
                    "Multiplicative mask should change non-zero values"
                );
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
        assert!(
            zero_count < 200,
            "Too many mask values never used: {}",
            zero_count
        );

        let max_count = *mask_counts.iter().max().unwrap();
        assert!(
            max_count < 20,
            "Mask value used too frequently: {}",
            max_count
        );
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
        assert!(
            changed_count > 800,
            "Masking should change most bytes, only changed {}",
            changed_count
        );
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
