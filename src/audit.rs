// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::types::Algorithm;
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use prometheus::{Counter, Histogram, HistogramOpts, Registry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref CRYPTO_OPERATIONS_TOTAL: Counter = Counter::new(
        "crypto_operations_total",
        "Total number of cryptographic operations"
    )
    .unwrap();
    pub static ref CRYPTO_OPERATION_LATENCY: Histogram = Histogram::with_opts(HistogramOpts::new(
        "crypto_operation_latency_seconds",
        "Latency of cryptographic operations in seconds"
    ))
    .unwrap();
    pub static ref SECURITY_ALERTS_TOTAL: Counter =
        Counter::new("security_alerts_total", "Total number of security alerts").unwrap();
}

// 注册指标到注册表
fn register_metrics() {
    let _ = REGISTRY.register(Box::new(CRYPTO_OPERATIONS_TOTAL.clone()));
    let _ = REGISTRY.register(Box::new(CRYPTO_OPERATION_LATENCY.clone()));
    let _ = REGISTRY.register(Box::new(SECURITY_ALERTS_TOTAL.clone()));
}

// === Performance Metrics ===
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Operation latency in microseconds
    pub latency_us: u64,
    /// Throughput in operations per second
    pub throughput_ops_per_sec: f64,
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
    /// Memory usage in bytes
    pub memory_usage_bytes: usize,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
    /// Operation timestamp
    pub timestamp: DateTime<Utc>,
    /// Operation type
    pub operation_type: String,
    /// Algorithm used
    pub algorithm: Option<Algorithm>,
    /// Data size processed
    pub data_size_bytes: usize,
}

/// Aggregated performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    /// Total operations performed
    pub total_operations: u64,
    /// Average latency in microseconds
    pub avg_latency_us: f64,
    /// Minimum latency in microseconds
    pub min_latency_us: u64,
    /// Maximum latency in microseconds
    pub max_latency_us: u64,
    /// Average throughput in operations per second
    pub avg_throughput_ops_per_sec: f64,
    /// Average cache hit rate
    pub avg_cache_hit_rate: f64,
    /// Total data processed in bytes
    pub total_data_processed_bytes: u64,
    /// Performance trend (improving/stable/degrading)
    pub performance_trend: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuditLog {
    pub timestamp: DateTime<Utc>,
    pub operation: String,
    pub algorithm: Option<Algorithm>,
    pub key_id: Option<String>,
    pub tenant_id: Option<String>,
    pub status: String,
    pub details: String,
    pub access_type: String,
}

/// Performance monitor for tracking cryptographic operation metrics
pub struct PerformanceMonitor {
    /// Individual operation metrics
    metrics_history: Arc<RwLock<Vec<PerformanceMetrics>>>,
    /// Aggregated statistics
    stats: Arc<RwLock<PerformanceStats>>,
    /// Operation start times for latency calculation
    operation_start_times: Arc<Mutex<HashMap<String, Instant>>>,
    /// Cache simulation for hit rate calculation
    cache_simulator: Arc<Mutex<CacheSimulator>>,
}

/// Simple cache simulator for hit rate calculation
struct CacheSimulator {
    /// Cache size in entries
    size: usize,
    /// Cache entries (simplified as hash set)
    entries: HashMap<u64, Instant>,
    /// Total accesses
    total_accesses: u64,
    /// Hit count
    hit_count: u64,
}

impl CacheSimulator {
    fn new(size: usize) -> Self {
        Self {
            size,
            entries: HashMap::new(),
            total_accesses: 0,
            hit_count: 0,
        }
    }

    fn access(&mut self, key: u64) -> bool {
        self.total_accesses += 1;
        let now = Instant::now();

        if self.entries.contains_key(&key) {
            self.hit_count += 1;
            self.entries.insert(key, now);
            true
        } else {
            // Cache miss - add to cache (simplified LRU)
            if self.entries.len() >= self.size {
                // Remove oldest entry
                if let Some((oldest_key, _)) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, instant)| *instant)
                    .map(|(k, _)| (*k, *k))
                {
                    self.entries.remove(&oldest_key);
                }
            }
            self.entries.insert(key, now);
            false
        }
    }

    fn hit_rate(&self) -> f64 {
        if self.total_accesses > 0 {
            self.hit_count as f64 / self.total_accesses as f64
        } else {
            0.0
        }
    }

    fn reset(&mut self) {
        self.entries.clear();
        self.total_accesses = 0;
        self.hit_count = 0;
    }
}

impl PerformanceMonitor {
    // Remove duplicate new() method - already defined below
}

/// Global performance monitoring functions
pub fn start_performance_operation(operation_id: &str) {
    PERFORMANCE_MONITOR.start_operation(operation_id);
}

pub fn record_performance_operation(
    operation_id: &str,
    operation_type: &str,
    algorithm: Option<Algorithm>,
    data_size_bytes: usize,
    cache_key: Option<u64>,
) -> Result<(), String> {
    PERFORMANCE_MONITOR.record_operation(
        operation_id,
        operation_type,
        algorithm,
        data_size_bytes,
        cache_key,
    )
}

pub fn get_performance_stats() -> PerformanceStats {
    PERFORMANCE_MONITOR.get_stats()
}

pub fn get_recent_performance_metrics(count: usize) -> Vec<PerformanceMetrics> {
    PERFORMANCE_MONITOR.get_recent_metrics(count)
}

pub fn reset_performance_stats() {
    PERFORMANCE_MONITOR.reset_stats()
}

pub struct AuditLogger {
    // In production, this would be a file writer or SIEM connector
    buffer: Mutex<Vec<String>>,
}

lazy_static! {
    static ref LOGGER: AuditLogger = AuditLogger {
        buffer: Mutex::new(Vec::new()),
    };
    static ref PERFORMANCE_MONITOR: Arc<PerformanceMonitor> = Arc::new(PerformanceMonitor::new());
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(PerformanceStats {
                total_operations: 0,
                avg_latency_us: 0.0,
                min_latency_us: u64::MAX,
                max_latency_us: 0,
                avg_throughput_ops_per_sec: 0.0,
                avg_cache_hit_rate: 0.0,
                total_data_processed_bytes: 0,
                performance_trend: "stable".to_string(),
            })),
            operation_start_times: Arc::new(Mutex::new(HashMap::new())),
            cache_simulator: Arc::new(Mutex::new(CacheSimulator::new(1024))), // 1024-entry cache
        }
    }

    /// Start timing an operation
    pub fn start_operation(&self, operation_id: &str) {
        let mut start_times = self.operation_start_times.lock().unwrap();
        start_times.insert(operation_id.to_string(), Instant::now());
    }

    /// Record operation metrics
    pub fn record_operation(
        &self,
        operation_id: &str,
        operation_type: &str,
        algorithm: Option<Algorithm>,
        data_size_bytes: usize,
        cache_key: Option<u64>,
    ) -> Result<(), String> {
        let start_time = {
            let mut start_times = self.operation_start_times.lock().unwrap();
            start_times
                .remove(operation_id)
                .ok_or_else(|| "Operation not started or already recorded".to_string())?
        };

        let latency = start_time.elapsed();
        let latency_us = latency.as_micros() as u64;

        // Simulate cache access
        let cache_hit_rate = if let Some(key) = cache_key {
            let mut cache = self.cache_simulator.lock().unwrap();
            cache.access(key);
            cache.hit_rate()
        } else {
            0.0
        };

        // Calculate throughput (operations per second)
        let throughput = if latency.as_secs_f64() > 0.0 {
            1.0 / latency.as_secs_f64()
        } else {
            0.0
        };

        // Get memory usage (simplified)
        let memory_usage_bytes = self.estimate_memory_usage();

        // Get CPU usage (simplified estimation)
        let cpu_usage_percent = self.estimate_cpu_usage();

        let metrics = PerformanceMetrics {
            latency_us,
            throughput_ops_per_sec: throughput,
            cache_hit_rate,
            memory_usage_bytes,
            cpu_usage_percent,
            timestamp: Utc::now(),
            operation_type: operation_type.to_string(),
            algorithm,
            data_size_bytes,
        };

        // Store metrics
        {
            let mut history = self.metrics_history.write().unwrap();
            history.push(metrics.clone());

            // Update Prometheus metrics
            CRYPTO_OPERATIONS_TOTAL.inc();
            CRYPTO_OPERATION_LATENCY.observe(latency.as_secs_f64());

            // Keep only last 10000 entries to prevent memory bloat
            if history.len() > 10000 {
                let new_len = history.len() - 10000;
                history.drain(0..new_len);
            }
        }

        // Update statistics
        self.update_stats(&metrics);

        Ok(())
    }

    /// Get current performance statistics
    pub fn get_stats(&self) -> PerformanceStats {
        self.stats.read().unwrap().clone()
    }

    /// Get recent metrics (last N operations)
    pub fn get_recent_metrics(&self, count: usize) -> Vec<PerformanceMetrics> {
        let history = self.metrics_history.read().unwrap();
        let start_idx = history.len().saturating_sub(count);
        history[start_idx..].to_vec()
    }

    /// Reset all statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write().unwrap();
        *stats = PerformanceStats {
            total_operations: 0,
            avg_latency_us: 0.0,
            min_latency_us: u64::MAX,
            max_latency_us: 0,
            avg_throughput_ops_per_sec: 0.0,
            avg_cache_hit_rate: 0.0,
            total_data_processed_bytes: 0,
            performance_trend: "stable".to_string(),
        };

        self.metrics_history.write().unwrap().clear();
        self.cache_simulator.lock().unwrap().reset();
    }

    /// Estimate memory usage (simplified)
    fn estimate_memory_usage(&self) -> usize {
        // This is a simplified estimation
        // In a real implementation, you'd use system calls or memory profiling
        let history_size =
            self.metrics_history.read().unwrap().len() * std::mem::size_of::<PerformanceMetrics>();
        let cache_size = 1024 * 64; // Approximate cache size
        history_size + cache_size
    }

    /// Estimate CPU usage (simplified)
    fn estimate_cpu_usage(&self) -> f64 {
        // This is a simplified estimation
        // In a real implementation, you'd use system monitoring APIs
        // For now, return a placeholder value
        15.0 // 15% baseline usage
    }

    /// Update aggregated statistics
    fn update_stats(&self, metrics: &PerformanceMetrics) {
        let mut stats = self.stats.write().unwrap();

        stats.total_operations += 1;
        stats.total_data_processed_bytes += metrics.data_size_bytes as u64;

        // Update latency statistics
        if stats.total_operations == 1 {
            stats.avg_latency_us = metrics.latency_us as f64;
            stats.min_latency_us = metrics.latency_us;
            stats.max_latency_us = metrics.latency_us;
        } else {
            let old_avg = stats.avg_latency_us;
            stats.avg_latency_us =
                old_avg + (metrics.latency_us as f64 - old_avg) / stats.total_operations as f64;
            stats.min_latency_us = stats.min_latency_us.min(metrics.latency_us);
            stats.max_latency_us = stats.max_latency_us.max(metrics.latency_us);
        }

        // Update throughput statistics
        if stats.total_operations == 1 {
            stats.avg_throughput_ops_per_sec = metrics.throughput_ops_per_sec;
        } else {
            let old_avg = stats.avg_throughput_ops_per_sec;
            stats.avg_throughput_ops_per_sec = old_avg
                + (metrics.throughput_ops_per_sec - old_avg) / stats.total_operations as f64;
        }

        // Update cache hit rate
        if stats.total_operations == 1 {
            stats.avg_cache_hit_rate = metrics.cache_hit_rate;
        } else {
            let old_avg = stats.avg_cache_hit_rate;
            stats.avg_cache_hit_rate =
                old_avg + (metrics.cache_hit_rate - old_avg) / stats.total_operations as f64;
        }

        // Determine performance trend
        stats.performance_trend = self.calculate_performance_trend();
    }

    /// Calculate performance trend based on recent metrics
    fn calculate_performance_trend(&self) -> String {
        let history = self.metrics_history.read().unwrap();
        if history.len() < 20 {
            return "stable".to_string();
        }

        let recent_count = 10;
        let recent_start = history.len() - recent_count;
        let recent_metrics = &history[recent_start..];
        let older_start = history.len() - recent_count * 2;
        let older_metrics = &history[older_start..recent_start];

        let recent_avg_latency: f64 = recent_metrics
            .iter()
            .map(|m| m.latency_us as f64)
            .sum::<f64>()
            / recent_count as f64;
        let older_avg_latency: f64 = older_metrics
            .iter()
            .map(|m| m.latency_us as f64)
            .sum::<f64>()
            / recent_count as f64;

        let latency_change = if older_avg_latency > 0.0 {
            (recent_avg_latency - older_avg_latency) / older_avg_latency
        } else {
            0.0
        };

        if latency_change > 0.1 {
            "degrading".to_string()
        } else if latency_change < -0.1 {
            "improving".to_string()
        } else {
            "stable".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_performance_monitor_basic() {
        let monitor = PerformanceMonitor::new();

        // Test basic operation recording
        monitor.start_operation("test_op_1");
        thread::sleep(Duration::from_millis(10)); // Simulate work

        let result = monitor.record_operation(
            "test_op_1",
            "encryption",
            Some(Algorithm::AES128GCM),
            1024,
            Some(0x1234),
        );

        assert!(result.is_ok());

        // Check stats
        let stats = monitor.get_stats();
        assert_eq!(stats.total_operations, 1);
        assert!(stats.avg_latency_us > 0.0);
        assert_eq!(stats.performance_trend, "stable");
    }

    #[test]
    fn test_performance_monitor_multiple_operations() {
        let monitor = PerformanceMonitor::new();

        // Record multiple operations
        for i in 0..5 {
            let op_id = format!("test_op_{}", i);
            monitor.start_operation(&op_id);
            thread::sleep(Duration::from_millis(5));

            monitor
                .record_operation(
                    &op_id,
                    "decryption",
                    Some(Algorithm::AES256GCM),
                    2048,
                    Some(i as u64),
                )
                .unwrap();
        }

        let stats = monitor.get_stats();
        assert_eq!(stats.total_operations, 5);
        assert!(stats.avg_latency_us > 0.0);
        assert!(stats.avg_cache_hit_rate >= 0.0 && stats.avg_cache_hit_rate <= 1.0);
    }

    #[test]
    fn test_performance_monitor_cache_simulation() {
        let monitor = PerformanceMonitor::new();

        // Access same cache key multiple times
        for i in 0..3 {
            let op_id = format!("cache_test_{}", i);
            monitor.start_operation(&op_id);
            monitor
                .record_operation(
                    &op_id,
                    "hash",
                    Some(Algorithm::SHA256),
                    512,
                    Some(0xABCD), // Same cache key
                )
                .unwrap();
        }

        let stats = monitor.get_stats();
        assert!(stats.avg_cache_hit_rate > 0.0); // Should have some cache hits
    }

    #[test]
    fn test_performance_trend_calculation() {
        let monitor = PerformanceMonitor::new();

        // Record operations with varying latencies
        for i in 0..20 {
            let op_id = format!("trend_test_{}", i);
            monitor.start_operation(&op_id);

            // Varying sleep times to create trend
            let sleep_ms = if i < 10 { 10 } else { 5 }; // Faster in second half
            thread::sleep(Duration::from_millis(sleep_ms));

            monitor
                .record_operation(&op_id, "sign", Some(Algorithm::ECDSAP256), 256, None)
                .unwrap();
        }

        let stats = monitor.get_stats();
        // Should detect improving trend due to faster operations in second half
        assert!(stats.performance_trend == "improving" || stats.performance_trend == "stable");
    }

    #[test]
    fn test_performance_stats_reset() {
        let monitor = PerformanceMonitor::new();

        // Record some operations
        monitor.start_operation("reset_test");
        monitor
            .record_operation("reset_test", "verify", Some(Algorithm::Ed25519), 128, None)
            .unwrap();

        let stats_before = monitor.get_stats();
        assert_eq!(stats_before.total_operations, 1);

        // Reset stats
        monitor.reset_stats();

        let stats_after = monitor.get_stats();
        assert_eq!(stats_after.total_operations, 0);
        assert_eq!(stats_after.performance_trend, "stable");
    }

    #[test]
    fn test_recent_metrics_retrieval() {
        let monitor = PerformanceMonitor::new();

        // Record multiple operations
        for i in 0..15 {
            let op_id = format!("recent_test_{}", i);
            monitor.start_operation(&op_id);
            thread::sleep(Duration::from_millis(1));

            monitor
                .record_operation(&op_id, "keygen", Some(Algorithm::Ed25519), 32, None)
                .unwrap();
        }

        // Get recent metrics
        let recent = monitor.get_recent_metrics(10);
        assert_eq!(recent.len(), 10);

        // Verify they are the most recent
        let all_metrics = monitor.get_recent_metrics(100); // Get all
        assert_eq!(all_metrics.len(), 15);

        // Recent should be subset of all
        for (_, metric) in recent.iter().enumerate() {
            assert_eq!(metric.operation_type, "keygen");
            assert_eq!(metric.algorithm, Some(Algorithm::Ed25519));
        }
    }

    #[test]
    fn test_global_performance_functions() {
        // Test global functions
        reset_performance_stats();

        start_performance_operation("global_test");
        thread::sleep(Duration::from_millis(5));

        let result = record_performance_operation(
            "global_test",
            "encrypt",
            Some(Algorithm::AES128GCM),
            1024,
            Some(0x5678),
        );

        assert!(result.is_ok());

        let stats = get_performance_stats();
        assert_eq!(stats.total_operations, 1);
        assert!(stats.avg_latency_us > 0.0);

        let recent = get_recent_performance_metrics(5);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].operation_type, "encrypt");
    }
}

impl AuditLogger {
    pub fn init() {
        // Initialize audit logger - in production this would set up file handles, etc.
        let _logger = &*LOGGER;
    }

    pub fn log(
        operation: &str,
        algo: Option<Algorithm>,
        key_id: Option<&str>,
        result: Result<(), &str>,
    ) {
        let status = match result {
            Ok(_) => "SUCCESS",
            Err(_) => "FAILURE",
        };

        let details = match result {
            Ok(_) => String::new(),
            Err(e) => e.to_string(),
        };

        let entry = AuditLog {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            algorithm: algo,
            key_id: key_id.map(|s| s.to_string()),
            tenant_id: None,
            status: status.to_string(),
            details,
            access_type: "authorized".to_string(),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            // In a real app, write to protected log file
            if let Ok(mut buf) = LOGGER.buffer.lock() {
                buf.push(json.clone());
            }
            // Also print to stdout for demo
            log::info!("{}", json);
        }
    }

    /// 记录带有租户ID的审计日志
    pub fn log_with_tenant(
        operation: &str,
        algo: Option<Algorithm>,
        key_id: Option<&str>,
        tenant_id: Option<&str>,
        result: Result<(), &str>,
        access_type: &str,
    ) {
        let status = match result {
            Ok(_) => "SUCCESS",
            Err(_) => "FAILURE",
        };

        let details = match result {
            Ok(_) => String::new(),
            Err(e) => e.to_string(),
        };

        let entry = AuditLog {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            algorithm: algo,
            key_id: key_id.map(|s| s.to_string()),
            tenant_id: tenant_id.map(|s| s.to_string()),
            status: status.to_string(),
            details,
            access_type: access_type.to_string(),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            // In a real app, write to protected log file
            if let Ok(mut buf) = LOGGER.buffer.lock() {
                buf.push(json.clone());
            }
            // Also print to stdout for demo
            log::info!("{}", json);
        }
    }

    /// 记录非授权访问尝试
    pub fn log_unauthorized_access(
        operation: &str,
        algo: Option<Algorithm>,
        key_id: Option<&str>,
        tenant_id: Option<&str>,
        details: &str,
    ) {
        let entry = AuditLog {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            algorithm: algo,
            key_id: key_id.map(|s| s.to_string()),
            tenant_id: tenant_id.map(|s| s.to_string()),
            status: "UNAUTHORIZED".to_string(),
            details: format!("SECURITY ALERT: {}", details),
            access_type: "unauthorized".to_string(),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            // Update Prometheus security alerts
            SECURITY_ALERTS_TOTAL.inc();

            // In a real app, write to protected log file and trigger security alerts
            if let Ok(mut buf) = LOGGER.buffer.lock() {
                buf.push(json.clone());
            }
            // 记录到安全日志并触发警报
            log::warn!("SECURITY ALERT: Unauthorized access attempt - {}", json);
        }
    }

    /// 获取审计日志缓冲区（用于测试）
    pub fn get_logs() -> Vec<String> {
        let logs = LOGGER.buffer.lock().unwrap().clone();
        // 增加调试输出
        for (i, log) in logs.iter().enumerate() {
            if log.contains("KEY_GENERATE") {
                log::debug!("FOUND KEY_GENERATE at index {}", i);
            }
        }
        logs
    }

    /// 导出 Prometheus 指标
    pub fn gather_metrics() -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = REGISTRY.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    /// 启动 Prometheus Exporter 服务（在后台运行）
    ///
    /// # Arguments
    /// * `port` - 导出器监听的端口
    pub fn start_exporter(port: u16) {
        use std::io::{Read, Write};
        use std::net::SocketAddr;
        use std::net::TcpListener;
        use std::thread;

        // 注册指标
        register_metrics();

        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        thread::spawn(move || {
            let listener = match TcpListener::bind(addr) {
                Ok(l) => l,
                Err(e) => {
                    log::error!("Failed to bind Prometheus exporter to {}: {}", addr, e);
                    return;
                }
            };

            log::info!("Prometheus exporter listening on http://{}", addr);

            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let mut buffer = [0; 1024];
                        match stream.read(&mut buffer) {
                            Ok(n) if n > 0 => {
                                let metrics = Self::gather_metrics();
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    metrics.len(),
                                    metrics
                                );

                                if let Err(e) = stream.write_all(response.as_bytes()) {
                                    log::error!("Failed to write response: {}", e);
                                }
                                let _ = stream.flush();
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        log::error!("Error accepting connection in Prometheus exporter: {}", e);
                    }
                }
            }
        });
    }

    /// 清空审计日志缓冲区（用于测试）
    pub fn clear_logs() {
        if let Ok(mut buf) = LOGGER.buffer.lock() {
            buf.clear();
        }
    }
}
