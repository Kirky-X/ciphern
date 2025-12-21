// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! FIPS 140-3 合规模块
//!
//! 提供 FIPS 140-3 Level 1 合规性支持，包括：
//! - 算法白名单验证
//! - 自检测试引擎 (POST, Conditional, Periodic)
//! - 错误状态管理
//! - 审计日志

use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

pub mod self_test;
mod validator;

pub use self_test::{
    Alert, AlertCategory, AlertHandler, AlertSeverity, FipsSelfTestEngine, FipsSelfTestType,
    SelfTestResult,
};
pub use validator::FipsAlgorithmValidator;

/// FIPS 模式状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsMode {
    Enabled,
    Disabled,
}

/// FIPS 错误状态
#[derive(Debug, thiserror::Error, Clone)]
pub enum FipsError {
    #[error("Algorithm not FIPS 140-3 approved: {0}")]
    AlgorithmNotApproved(String),

    #[error("Self test failed: {0}")]
    SelfTestFailed(String),

    #[error("FIPS mode required but disabled")]
    FipsModeRequired,

    #[error("Invalid key size for FIPS algorithm: {0}")]
    InvalidKeySize(String),

    #[error("Memory protection violation in FIPS mode: {0}")]
    MemoryProtectionViolation(String),

    #[error("Random number generator health check failed: {0}")]
    RngHealthCheckFailed(String),

    #[error("Conditional self test failed for algorithm {0}: {1}")]
    ConditionalSelfTestFailed(String, String),
}

/// FIPS 错误状态管理
#[derive(Debug)]
pub struct FipsErrorState {
    is_error: AtomicBool,
    error_type: Mutex<Option<FipsError>>,
    error_count: AtomicUsize,
}

impl Default for FipsErrorState {
    fn default() -> Self {
        Self {
            is_error: AtomicBool::new(false),
            error_type: Mutex::new(None),
            error_count: AtomicUsize::new(0),
        }
    }
}

impl FipsErrorState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_error(&self, error: FipsError) {
        self.is_error.store(true, Ordering::SeqCst);
        *self.error_type.lock().unwrap() = Some(error.clone());
        self.error_count.fetch_add(1, Ordering::SeqCst);

        // 记录到审计日志
        crate::audit::AuditLogger::log(
            "FIPS_ERROR",
            None,
            None,
            Err(&format!("FIPS error: {}", error)),
        );
    }

    pub fn is_in_error_state(&self) -> bool {
        self.is_error.load(Ordering::SeqCst)
    }

    pub fn get_error(&self) -> Option<FipsError> {
        self.error_type.lock().unwrap().clone()
    }

    pub fn get_error_count(&self) -> usize {
        self.error_count.load(Ordering::SeqCst)
    }

    pub fn clear_error(&self) {
        self.is_error.store(false, Ordering::SeqCst);
        *self.error_type.lock().unwrap() = None;
    }
}

/// FIPS 上下文管理器
pub struct FipsContext {
    mode: FipsMode,
    _validator: FipsAlgorithmValidator,
    self_test_engine: FipsSelfTestEngine,
    error_state: FipsErrorState,
    algorithm_usage_stats: Mutex<HashMap<Algorithm, usize>>,
}

impl FipsContext {
    /// 创建新的 FIPS 上下文
    pub fn new(mode: FipsMode) -> Result<Self> {
        let validator = FipsAlgorithmValidator;
        let self_test_engine = FipsSelfTestEngine::new();
        let error_state = FipsErrorState::new();
        let algorithm_usage_stats = Mutex::new(HashMap::new());

        let context = Self {
            mode,
            _validator: validator,
            self_test_engine,
            error_state,
            algorithm_usage_stats,
        };

        // 如果启用 FIPS 模式，运行上电自检
        if mode == FipsMode::Enabled {
            context.self_test_engine.run_power_on_self_tests()?;
        }

        Ok(context)
    }

    /// 启用 FIPS 模式
    pub fn enable() -> Result<()> {
        // 创建临时上下文进行自检
        let _temp_context = Self::new(FipsMode::Enabled)?;

        // 设置全局 FIPS 模式
        set_fips_mode(FipsMode::Enabled);

        // 记录到审计日志
        crate::audit::AuditLogger::log("FIPS_MODE_ENABLED", None, None, Ok(()));

        Ok(())
    }

    /// 禁用 FIPS 模式
    pub fn disable() -> Result<()> {
        set_fips_mode(FipsMode::Disabled);

        // 记录到审计日志
        crate::audit::AuditLogger::log("FIPS_MODE_DISABLED", None, None, Ok(()));

        Ok(())
    }

    /// 检查是否启用 FIPS 模式
    pub fn is_enabled() -> bool {
        get_fips_mode() == FipsMode::Enabled
    }

    /// 验证算法是否符合 FIPS 要求
    pub fn validate_algorithm(&self, algorithm: &Algorithm) -> Result<()> {
        if self.mode != FipsMode::Enabled {
            return Ok(());
        }

        // 验证算法是否在白名单中
        FipsAlgorithmValidator::validate_fips_compliance(algorithm)?;

        // 记录算法使用统计
        {
            let mut stats = self.algorithm_usage_stats.lock().unwrap();
            *stats.entry(*algorithm).or_insert(0) += 1;
        }

        // 执行条件自检
        if let Err(e) = self.self_test_engine.run_conditional_self_test(*algorithm) {
            self.error_state
                .set_error(FipsError::ConditionalSelfTestFailed(
                    format!("{:?}", algorithm),
                    e.to_string(),
                ));
            return Err(e);
        }

        Ok(())
    }

    /// 运行条件自检
    pub fn run_conditional_self_test(&self, algorithm: Algorithm) -> Result<()> {
        self.self_test_engine.run_conditional_self_test(algorithm)
    }

    /// 验证密钥大小是否符合 FIPS 要求
    pub fn validate_key_size(&self, algorithm: &Algorithm, key_size: usize) -> Result<()> {
        if self.mode != FipsMode::Enabled {
            return Ok(());
        }

        FipsAlgorithmValidator::validate_key_size(algorithm, key_size)
    }

    /// 获取算法使用统计
    pub fn get_algorithm_usage_stats(&self) -> HashMap<Algorithm, usize> {
        self.algorithm_usage_stats.lock().unwrap().clone()
    }

    /// 获取自检测试结果
    pub fn get_self_test_results(&self) -> HashMap<String, SelfTestResult> {
        self.self_test_engine.get_test_results()
    }

    /// 获取特定测试的结果
    pub fn get_self_test_result(&self, test_name: &str) -> Option<SelfTestResult> {
        self.self_test_engine.get_test_result(test_name)
    }

    /// 检查是否所有必需的测试都通过
    pub fn all_required_tests_passed(&self) -> bool {
        self.self_test_engine.all_required_tests_passed()
    }

    /// 检查是否处于错误状态
    pub fn is_in_error_state(&self) -> bool {
        self.error_state.is_in_error_state()
    }

    /// 获取错误状态
    pub fn get_error_state(&self) -> Option<FipsError> {
        self.error_state.get_error()
    }

    /// 清除错误状态
    pub fn clear_error_state(&self) {
        self.error_state.clear_error()
    }

    /// 运行定期自检 (应该定期调用，例如每小时)
    pub fn run_periodic_self_tests(&self) -> Result<()> {
        if self.mode != FipsMode::Enabled {
            return Ok(());
        }

        // 运行 RNG 健康检查
        let rng_test = self.self_test_engine.rng_health_test()?;
        if !rng_test.passed {
            self.error_state.set_error(FipsError::RngHealthCheckFailed(
                rng_test
                    .error_message
                    .unwrap_or_else(|| "Unknown RNG error".to_string()),
            ));
            return Err(CryptoError::FipsError(
                "Periodic self test failed".to_string(),
            ));
        }

        Ok(())
    }
}

/// 全局 FIPS 模式状态
static FIPS_MODE: std::sync::OnceLock<FipsMode> = std::sync::OnceLock::new();

/// 设置全局 FIPS 模式
fn set_fips_mode(mode: FipsMode) {
    let _ = FIPS_MODE.set(mode);
}

/// 获取全局 FIPS 模式
fn get_fips_mode() -> FipsMode {
    *FIPS_MODE.get().unwrap_or(&FipsMode::Disabled)
}

/// 验证算法是否在 FIPS 模式下被允许
pub fn validate_algorithm_fips(algorithm: &Algorithm) -> Result<()> {
    if !is_fips_enabled() {
        return Ok(());
    }

    if !algorithm.is_fips_approved() {
        return Err(CryptoError::FipsError(format!(
            "Algorithm {:?} is not FIPS 140-3 approved",
            algorithm
        )));
    }

    Ok(())
}

/// 检查是否启用 FIPS 模式
pub fn is_fips_enabled() -> bool {
    get_fips_mode() == FipsMode::Enabled
}

/// 获取 FIPS 批准的算法列表
pub fn get_fips_approved_algorithms() -> Vec<Algorithm> {
    FipsAlgorithmValidator::get_approved_algorithms()
}

/// 获取非 FIPS 批准的算法列表
pub fn get_non_fips_approved_algorithms() -> Vec<Algorithm> {
    FipsAlgorithmValidator::get_non_approved_algorithms()
}
