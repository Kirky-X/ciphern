// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::Result;
use crate::fips::self_test::{Alert, AlertCategory, AlertHandler, AlertSeverity};
use chrono::Utc;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// RNG 健康状态指标
#[derive(Debug, Clone)]
pub struct RngHealthMetrics {
    pub entropy_bits: f64,
    pub failure_rate: f64,
    pub consecutive_failures: u32,
    pub total_tests: u64,
    pub failed_tests: u64,
    pub last_test_timestamp: chrono::DateTime<Utc>,
    pub health_score: f64, // 0.0 - 1.0, 1.0 表示完全健康
}

impl Default for RngHealthMetrics {
    fn default() -> Self {
        Self {
            entropy_bits: 8.0,
            failure_rate: 0.0,
            consecutive_failures: 0,
            total_tests: 0,
            failed_tests: 0,
            last_test_timestamp: Utc::now(),
            health_score: 1.0,
        }
    }
}

/// RNG 监控配置
#[derive(Debug, Clone)]
pub struct RngMonitorConfig {
    pub sample_size: usize,                // 每次测试的样本大小
    pub test_interval: Duration,           // 测试间隔
    pub entropy_threshold: f64,            // 熵值阈值
    pub max_consecutive_failures: u32,     // 最大连续失败次数
    pub failure_rate_threshold: f64,       // 失败率阈值
    pub enable_real_time_monitoring: bool, // 启用实时监控
}

impl Default for RngMonitorConfig {
    fn default() -> Self {
        Self {
            sample_size: 25000,                      // NIST SP 800-22 建议的最小样本量
            test_interval: Duration::from_secs(300), // 每5分钟测试一次
            entropy_threshold: 7.5,                  // NIST 建议的最小熵值
            max_consecutive_failures: 3,             // 最多3次连续失败
            failure_rate_threshold: 0.1,             // 10% 失败率阈值
            enable_real_time_monitoring: true,       // 默认启用实时监控
        }
    }
}

/// RNG 监控器
pub struct RngMonitor {
    config: RngMonitorConfig,
    metrics: Arc<RwLock<RngHealthMetrics>>,
    alert_handler: Arc<Mutex<Option<Arc<dyn AlertHandler + Send + Sync>>>>,
    test_history: Arc<Mutex<VecDeque<bool>>>,
    last_test_time: Arc<Mutex<Instant>>,
}

impl RngMonitor {
    pub fn new(config: RngMonitorConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(RngHealthMetrics::default())),
            alert_handler: Arc::new(Mutex::new(None)),
            test_history: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            last_test_time: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// 设置告警处理器
    pub fn set_alert_handler(&self, handler: Arc<dyn AlertHandler + Send + Sync>) {
        if let Ok(mut handler_guard) = self.alert_handler.lock() {
            *handler_guard = Some(handler);
        }
    }

    /// 获取当前健康指标
    pub fn get_health_metrics(&self) -> RngHealthMetrics {
        self.metrics
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// 执行 RNG 健康检查
    pub fn perform_health_check(&self) -> Result<bool> {
        use crate::fips::self_test::FipsSelfTestEngine;

        let mut random_bytes = vec![0u8; self.config.sample_size];

        // 生成随机数
        if let Err(e) =
            crate::random::SecureRandom::new().and_then(|rng| rng.fill(&mut random_bytes))
        {
            self.record_test_result(false);
            self.trigger_alert(
                AlertSeverity::Critical,
                AlertCategory::SystemMalfunction,
                format!("RNG generation failed: {}", e),
                Some("rng_generation".to_string()),
            );
            return Ok(false);
        }

        // 执行基本随机性检查
        let all_zeros = random_bytes.iter().all(|&b| b == 0);
        let all_ones = random_bytes.iter().all(|&b| b == 0xFF);

        if all_zeros || all_ones {
            self.record_test_result(false);
            self.trigger_alert(
                AlertSeverity::Critical,
                AlertCategory::TestFailure,
                "RNG output is not random: all bytes are identical".to_string(),
                Some("basic_randomness_check".to_string()),
            );
            return Ok(false);
        }

        // 执行 NIST 随机性测试（简化版本）
        let test_engine = FipsSelfTestEngine::new();
        let nist_result = test_engine.nist_randomness_tests(&random_bytes);

        let passed = nist_result.passed;
        self.record_test_result(passed);

        // 更新健康指标
        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.entropy_bits = nist_result.entropy_bits;
            metrics.last_test_timestamp = Utc::now();

            // 计算失败率
            let history = self.test_history.lock().unwrap();
            let recent_tests: Vec<bool> = history.iter().cloned().collect();
            let recent_failures = recent_tests.iter().filter(|&&x| !x).count();
            metrics.failure_rate = recent_failures as f64 / recent_tests.len() as f64;

            // 计算健康评分
            let entropy_score = (metrics.entropy_bits / 8.0).min(1.0);
            let failure_rate_score = (1.0 - metrics.failure_rate).max(0.0);
            let consecutive_failures_score = if metrics.consecutive_failures == 0 {
                1.0
            } else {
                0.5_f64.powi(metrics.consecutive_failures as i32)
            };

            metrics.health_score =
                (entropy_score * 0.4 + failure_rate_score * 0.4 + consecutive_failures_score * 0.2)
                    .min(1.0);
        }

        // 检查是否需要触发告警
        if !passed {
            self.trigger_alert(
                AlertSeverity::Warning,
                AlertCategory::TestFailure,
                format!(
                    "NIST randomness test failed: {}",
                    nist_result.error_message.unwrap_or_default()
                ),
                Some("nist_randomness_test".to_string()),
            );
        }

        // 检查熵值是否过低
        if nist_result.entropy_bits < self.config.entropy_threshold {
            self.trigger_alert(
                AlertSeverity::Warning,
                AlertCategory::EntropyDegradation,
                format!("Low entropy detected: {:.2} bits", nist_result.entropy_bits),
                Some("entropy_check".to_string()),
            );
        }

        // 检查连续失败次数
        let metrics = self.metrics.read().unwrap();
        if metrics.consecutive_failures >= self.config.max_consecutive_failures {
            self.trigger_alert(
                AlertSeverity::Critical,
                AlertCategory::SystemMalfunction,
                format!(
                    "Too many consecutive RNG test failures: {}",
                    metrics.consecutive_failures
                ),
                Some("consecutive_failures".to_string()),
            );
        }

        // 检查失败率
        if metrics.failure_rate > self.config.failure_rate_threshold {
            self.trigger_alert(
                AlertSeverity::Warning,
                AlertCategory::TestFailure,
                format!(
                    "RNG failure rate too high: {:.2}%",
                    metrics.failure_rate * 100.0
                ),
                Some("failure_rate".to_string()),
            );
        }

        Ok(passed)
    }

    /// 记录测试结果
    fn record_test_result(&self, passed: bool) {
        let mut metrics = self.metrics.write().unwrap();
        metrics.total_tests += 1;

        if !passed {
            metrics.failed_tests += 1;
            metrics.consecutive_failures += 1;
        } else {
            metrics.consecutive_failures = 0;
        }

        // 记录到历史队列
        let mut history = self.test_history.lock().unwrap();
        history.push_back(passed);
        if history.len() > 100 {
            history.pop_front();
        }

        // 更新时间戳
        *self.last_test_time.lock().unwrap() = Instant::now();
    }

    /// 触发告警
    fn trigger_alert(
        &self,
        severity: AlertSeverity,
        category: AlertCategory,
        message: String,
        test_name: Option<String>,
    ) {
        // 记录到审计日志
        crate::audit::AuditLogger::log(
            "RNG_HEALTH_ALERT",
            None,
            None,
            Err(&format!(
                "[{:?}] Category: {:?}, Message: {}",
                severity, category, message
            )),
        );

        // 调用告警处理器
        if let Some(handler) = self.alert_handler.lock().unwrap().as_ref() {
            let alert = Alert {
                severity,
                category: match category {
                    AlertCategory::EntropyDegradation => AlertCategory::EntropyDegradation,
                    AlertCategory::TestFailure => AlertCategory::TestFailure,
                    AlertCategory::SystemMalfunction => AlertCategory::SystemMalfunction,
                },
                message,
                timestamp: Utc::now(),
                test_name,
            };
            handler.handle_alert(&alert);
        }
    }

    /// 记录外部测试结果（用于集成）
    pub fn record_external_test_result(&self, passed: bool, test_type: &str) {
        self.record_test_result(passed);

        if !passed {
            self.trigger_alert(
                AlertSeverity::Warning,
                AlertCategory::TestFailure,
                format!("External RNG test failed: {}", test_type),
                Some(test_type.to_string()),
            );
        }
    }

    /// 检查是否需要执行测试
    pub fn should_run_test(&self) -> bool {
        let last_test = *self.last_test_time.lock().unwrap();
        Instant::now().duration_since(last_test) >= self.config.test_interval
    }

    /// 启动实时监控（后台任务）
    pub fn start_real_time_monitoring(self: Arc<Self>) {
        if !self.config.enable_real_time_monitoring {
            return;
        }

        std::thread::spawn(move || {
            loop {
                if self.should_run_test() {
                    if let Err(e) = self.perform_health_check() {
                        log::error!("RNG health check failed: {}", e);
                    }
                }
                std::thread::sleep(Duration::from_secs(60)); // 每分钟检查一次
            }
        });
    }
}

/// RNG 监控管理器
pub struct RngMonitorManager {
    monitors: Arc<Mutex<Vec<Arc<RngMonitor>>>>,
}

impl RngMonitorManager {
    pub fn new() -> Self {
        Self {
            monitors: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 添加监控器
    pub fn add_monitor(&self, monitor: Arc<RngMonitor>) {
        self.monitors.lock().unwrap().push(monitor);
    }

    /// 获取第一个监控器
    pub fn get_first_monitor(&self) -> Option<Arc<RngMonitor>> {
        self.monitors.lock().ok()?.first().cloned()
    }

    /// 获取所有监控器的健康指标
    pub fn get_all_health_metrics(&self) -> Vec<RngHealthMetrics> {
        self.monitors
            .lock()
            .map(|guard| {
                guard
                    .iter()
                    .map(|monitor| monitor.get_health_metrics())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 执行所有监控器的健康检查
    pub fn perform_all_health_checks(&self) -> Result<Vec<bool>> {
        let monitors = self.monitors.lock().unwrap();
        let mut results = Vec::new();

        for monitor in monitors.iter() {
            match monitor.perform_health_check() {
                Ok(result) => results.push(result),
                Err(e) => {
                    log::error!("Health check failed for monitor: {}", e);
                    results.push(false);
                }
            }
        }

        Ok(results)
    }
}

impl Default for RngMonitorManager {
    fn default() -> Self {
        Self::new()
    }
}
