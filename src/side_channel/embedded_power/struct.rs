// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use std::sync::atomic::AtomicU32;
use std::sync::Mutex;
use std::time::Instant;

// === Struct Definitions ===

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

/// 嵌入式功耗分析防护器
pub struct EmbeddedPowerProtector {
    pub(crate) config: EmbeddedPowerConfig,
    pub(crate) operation_counter: AtomicU32,
    pub(crate) last_operation_time: Mutex<Option<Instant>>,
}

/// 嵌入式功耗防护统计信息
#[derive(Debug, Clone)]
pub struct EmbeddedPowerStats {
    /// 总操作次数
    pub total_operations: u32,
    /// 最后一次操作时间
    pub last_operation_time: Option<Instant>,
    /// 是否启用Cortex-M优化
    pub cortex_m_optimization_enabled: bool,
    /// 功耗掩码强度
    pub power_masking_strength: f32,
}

/// 嵌入式功耗防护构建器
pub struct EmbeddedPowerProtectorBuilder {
    pub(crate) config: EmbeddedPowerConfig,
}
