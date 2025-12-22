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
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

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
struct OperationMetrics {
    total_latency_us: u64,
    min_latency_us: u64,
    max_latency_us: u64,
    operation_count: u64,
    total_data_size: u64,
    cache_hits: u64,
    cache_misses: u64,
}

impl Default for OperationMetrics {
    fn default() -> Self {
        Self {
            total_latency_us: 0,
            min_latency_us: u64::MAX,
            max_latency_us: 0,
            operation_count: 0,
            total_data_size: 0,
            cache_hits: 0,
            cache_misses: 0,
        }
    }
}

impl OperationMetrics {
    fn update(&mut self, latency_us: u64, data_size: usize, cache_hit: bool) {
        self.total_latency_us += latency_us;
        self.min_latency_us = self.min_latency_us.min(latency_us);
        self.max_latency_us = self.max_latency_us.max(latency_us);
        self.operation_count += 1;
        self.total_data_size += data_size as u64;
        if cache_hit {
            self.cache_hits += 1;
        } else {
            self.cache_misses += 1;
        }
    }

    fn to_stats(&self) -> PerformanceStats {
        let avg_latency = if self.operation_count > 0 {
            self.total_latency_us as f64 / self.operation_count as f64
        } else {
            0.0
        };

        let avg_throughput = if self.operation_count > 0 {
            (self.operation_count as f64 * 1_000_000.0) / self.total_latency_us as f64
        } else {
            0.0
        };

        let avg_cache_hit_rate = if self.cache_hits + self.cache_misses > 0 {
            self.cache_hits as f64 / (self.cache_hits + self.cache_misses) as f64
        } else {
            0.0
        };

        let performance_trend = if avg_throughput > 1000.0 {
            "improving"
        } else if avg_throughput > 500.0 {
            "stable"
        } else {
            "degrading"
        };

        PerformanceStats {
            total_operations: self.operation_count,
            avg_latency_us: avg_latency,
            min_latency_us: if self.operation_count > 0 {
                self.min_latency_us
            } else {
                0
            },
            max_latency_us: self.max_latency_us,
            avg_throughput_ops_per_sec: avg_throughput,
            avg_cache_hit_rate,
            total_data_processed_bytes: self.total_data_size,
            performance_trend: performance_trend.to_string(),
        }
    }
}

/// Performance monitoring system
#[derive(Clone)]
pub struct PerformanceMonitor {
    metrics: Arc<RwLock<HashMap<String, OperationMetrics>>>,
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record performance metrics for an operation
    pub fn record_operation(
        &self,
        operation: &str,
        algo: Option<Algorithm>,
        latency_us: u64,
        data_size: usize,
        cache_hit: bool,
    ) {
        let key = format!("{}_{:?}", operation, algo);

        // Use write lock for minimal time
        if let Ok(mut metrics) = self.metrics.write() {
            metrics
                .entry(key)
                .or_default()
                .update(latency_us, data_size, cache_hit);
        }

        // Update Prometheus metrics
        CRYPTO_OPERATIONS_TOTAL.inc();
        CRYPTO_OPERATION_LATENCY.observe(latency_us as f64 / 1_000_000.0);
    }

    /// Get performance statistics for a specific operation
    pub fn get_stats(&self, operation: &str, algo: Option<Algorithm>) -> Option<PerformanceStats> {
        let key = format!("{}_{:?}", operation, algo);

        if let Ok(metrics) = self.metrics.read() {
            metrics.get(&key).map(|m| m.to_stats())
        } else {
            None
        }
    }

    /// Get all performance statistics
    pub fn get_all_stats(&self) -> HashMap<String, PerformanceStats> {
        if let Ok(metrics) = self.metrics.read() {
            metrics
                .iter()
                .map(|(k, v)| (k.clone(), v.to_stats()))
                .collect()
        } else {
            HashMap::new()
        }
    }

    /// Reset statistics for a specific operation
    pub fn reset_stats(&self, operation: &str, algo: Option<Algorithm>) {
        let key = format!("{}_{:?}", operation, algo);

        if let Ok(mut metrics) = self.metrics.write() {
            metrics.remove(&key);
        }
    }

    /// Reset all statistics
    pub fn reset_all_stats(&self) {
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.clear();
        }
    }
}

// === Audit Logging ===

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// Timestamp of the operation
    pub timestamp: DateTime<Utc>,
    /// Operation type (e.g., "KEY_GENERATE", "ENCRYPT", "DECRYPT")
    pub operation: String,
    /// Algorithm used (if applicable)
    pub algorithm: Option<Algorithm>,
    /// Key ID (if applicable)
    pub key_id: Option<String>,
    /// Tenant ID (if applicable)
    pub tenant_id: Option<String>,
    /// Operation status ("SUCCESS", "FAILURE", "UNAUTHORIZED")
    pub status: String,
    /// Additional details
    pub details: String,
    /// Access type (e.g., "authorized", "unauthorized")
    pub access_type: String,
}

/// Audit logger with channel-based logging to reduce lock contention
pub struct AuditLogger {
    sender: Sender<String>,
    sync_buffer: Mutex<Vec<String>>,
    _handle: Option<thread::JoinHandle<()>>, // Keep the handle to prevent thread from being dropped
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    pub fn new() -> Self {
        let (sender, receiver) = channel();

        // Spawn background thread for logging
        let handle = thread::spawn(move || {
            for log_entry in receiver {
                log::info!("AUDIT: {}", log_entry);
            }
        });

        Self {
            sender,
            sync_buffer: Mutex::new(Vec::new()),
            _handle: Some(handle),
        }
    }

    /// Initialize the audit logger (for backward compatibility)
    pub fn init() {
        // Logger is already initialized via lazy_static
        log::info!("Audit logger initialized");
    }

    /// Log with tenant information (for backward compatibility)
    pub fn log_with_tenant(
        operation: &str,
        algo: Option<Algorithm>,
        key_id: Option<&str>,
        tenant_id: Option<&str>,
        result: Result<(), &str>,
        access_type: &str,
    ) {
        let entry = AuditLog {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            algorithm: algo,
            key_id: key_id.map(|s| s.to_string()),
            tenant_id: tenant_id.map(|s| s.to_string()),
            status: if result.is_ok() { "SUCCESS" } else { "FAILURE" }.to_string(),
            details: result.err().unwrap_or("").to_string(),
            access_type: access_type.to_string(),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            // Always store in sync buffer for testing
            if let Ok(mut buf) = LOGGER.sync_buffer.lock() {
                if buf.len() < 1000 {
                    buf.push(json.clone());
                }
            }

            // Try to send via channel for background processing
            let _ = LOGGER.sender.send(json);
        }
    }

    /// Record a cryptographic operation
    pub fn log(
        operation: &str,
        algo: Option<Algorithm>,
        key_id: Option<&str>,
        result: Result<(), &str>,
    ) {
        let entry = AuditLog {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            algorithm: algo,
            key_id: key_id.map(|s| s.to_string()),
            tenant_id: None,
            status: if result.is_ok() { "SUCCESS" } else { "FAILURE" }.to_string(),
            details: result.err().unwrap_or("").to_string(),
            access_type: "system".to_string(),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            // Always store in sync buffer for testing
            if let Ok(mut buf) = LOGGER.sync_buffer.lock() {
                if buf.len() < 1000 {
                    buf.push(json.clone());
                }
            }

            // Try to send via channel for background processing
            let _ = LOGGER.sender.send(json.clone());

            // Also print to stdout for demo
            log::info!("AUDIT: {}", json);
        }
    }

    /// Record an authorized access
    pub fn log_authorized_access(
        operation: &str,
        algo: Option<Algorithm>,
        key_id: Option<&str>,
        tenant_id: Option<&str>,
        details: &str,
        access_type: &str,
    ) {
        let entry = AuditLog {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            algorithm: algo,
            key_id: key_id.map(|s| s.to_string()),
            tenant_id: tenant_id.map(|s| s.to_string()),
            status: "SUCCESS".to_string(),
            details: details.to_string(),
            access_type: access_type.to_string(),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            // Always store in sync buffer for testing
            if let Ok(mut buf) = LOGGER.sync_buffer.lock() {
                if buf.len() < 1000 {
                    buf.push(json.clone());
                }
            }

            // Try to send via channel for background processing
            let _ = LOGGER.sender.send(json);
        }
    }

    /// Record an unauthorized access attempt
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

            // Always store in sync buffer for testing
            if let Ok(mut buf) = LOGGER.sync_buffer.lock() {
                if buf.len() < 1000 {
                    buf.push(json.clone());
                }
            }

            // Try to send via channel for background processing
            let _ = LOGGER.sender.send(json.clone());

            // 记录到安全日志并触发警报
            log::warn!("SECURITY ALERT: {}", json);
        }
    }

    /// Record a key operation
    pub fn log_key_operation(
        operation: &str,
        algo: Algorithm,
        key_id: &str,
        tenant_id: Option<&str>,
        success: bool,
        details: &str,
    ) {
        let entry = AuditLog {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            algorithm: Some(algo),
            key_id: Some(key_id.to_string()),
            tenant_id: tenant_id.map(|s| s.to_string()),
            status: if success { "SUCCESS" } else { "FAILURE" }.to_string(),
            details: details.to_string(),
            access_type: "key_operation".to_string(),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            // Always store in sync buffer for testing
            if let Ok(mut buf) = LOGGER.sync_buffer.lock() {
                if buf.len() < 1000 {
                    buf.push(json.clone());
                }
            }

            // Try to send via channel for background processing
            let _ = LOGGER.sender.send(json.clone());

            // Also print to stdout for demo
            log::info!("AUDIT: {}", json);
        }
    }

    /// 获取审计日志缓冲区（用于测试）
    pub fn get_logs() -> Vec<String> {
        let logs = LOGGER.sync_buffer.lock().unwrap().clone();
        // 增加调试输出
        for (i, log) in logs.iter().enumerate() {
            if log.contains("KEY_GENERATE") {
                log::debug!("FOUND KEY_GENERATE at index {}", i);
            }
        }
        logs
    }

    /// 清空审计日志缓冲区（用于测试）
    pub fn clear_logs() {
        LOGGER.sync_buffer.lock().unwrap().clear();
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

    /// 启动 Prometheus 指标导出器
    ///
    /// # 参数
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
}

lazy_static! {
    static ref LOGGER: AuditLogger = AuditLogger::new();
    static ref PERFORMANCE_MONITOR: Arc<PerformanceMonitor> = Arc::new(PerformanceMonitor::new());
}

// Global performance monitoring functions
pub fn record_operation(
    operation: &str,
    algo: Option<Algorithm>,
    latency_us: u64,
    data_size: usize,
    cache_hit: bool,
) {
    PERFORMANCE_MONITOR.record_operation(operation, algo, latency_us, data_size, cache_hit);
}

pub fn get_performance_stats(operation: &str, algo: Option<Algorithm>) -> Option<PerformanceStats> {
    PERFORMANCE_MONITOR.get_stats(operation, algo)
}

pub fn get_all_performance_stats() -> HashMap<String, PerformanceStats> {
    PERFORMANCE_MONITOR.get_all_stats()
}

pub fn reset_performance_stats(operation: &str, algo: Option<Algorithm>) {
    PERFORMANCE_MONITOR.reset_stats(operation, algo);
}

pub fn reset_all_performance_stats() {
    PERFORMANCE_MONITOR.reset_all_stats();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_performance_monitor_basic() {
        let monitor = PerformanceMonitor::new();

        // Record some operations
        monitor.record_operation("encrypt", Some(Algorithm::AES256GCM), 1000, 1024, true);
        monitor.record_operation("encrypt", Some(Algorithm::AES256GCM), 1200, 1024, false);
        monitor.record_operation("decrypt", Some(Algorithm::AES256GCM), 800, 1024, true);

        // Get stats
        let stats = monitor
            .get_stats("encrypt", Some(Algorithm::AES256GCM))
            .unwrap();
        assert_eq!(stats.total_operations, 2);
        assert!(stats.avg_latency_us > 0.0);
        assert!(stats.avg_throughput_ops_per_sec > 0.0);
    }

    #[test]
    fn test_performance_monitor_multiple_operations() {
        let monitor = PerformanceMonitor::new();

        // Record multiple operations concurrently
        let handles: Vec<_> = (0..100)
            .map(|i| {
                let monitor = monitor.clone();
                thread::spawn(move || {
                    monitor.record_operation(
                        "test_op",
                        Some(Algorithm::AES256GCM),
                        1000 + (i * 10) as u64,
                        1024,
                        i % 2 == 0,
                    );
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let stats = monitor
            .get_stats("test_op", Some(Algorithm::AES256GCM))
            .unwrap();
        assert_eq!(stats.total_operations, 100);
        assert!(stats.avg_latency_us > 0.0);
    }

    #[test]
    fn test_performance_stats_reset() {
        let monitor = PerformanceMonitor::new();

        // Record some operations
        monitor.record_operation("encrypt", Some(Algorithm::AES256GCM), 1000, 1024, true);

        // Verify stats exist
        let stats = monitor.get_stats("encrypt", Some(Algorithm::AES256GCM));
        assert!(stats.is_some());

        // Reset stats
        monitor.reset_stats("encrypt", Some(Algorithm::AES256GCM));

        // Verify stats are gone
        let stats = monitor.get_stats("encrypt", Some(Algorithm::AES256GCM));
        assert!(stats.is_none());
    }

    #[test]
    fn test_audit_logger_basic() {
        // Clear logs first
        AuditLogger::clear_logs();

        // Log some operations
        AuditLogger::log(
            "KEY_GENERATE",
            Some(Algorithm::AES256GCM),
            Some("test_key"),
            Ok(()),
        );
        AuditLogger::log(
            "ENCRYPT",
            Some(Algorithm::AES256GCM),
            Some("test_key"),
            Err("test error"),
        );

        // Get logs
        let logs = AuditLogger::get_logs();

        // Find the logs we're interested in
        let keygen_logs: Vec<_> = logs
            .iter()
            .filter(|log| log.contains("KEY_GENERATE"))
            .collect();
        let encrypt_logs: Vec<_> = logs.iter().filter(|log| log.contains("ENCRYPT")).collect();

        // Verify we have at least the logs we expect
        assert!(
            keygen_logs.len() >= 1,
            "Should have at least 1 KEY_GENERATE log"
        );
        assert!(
            encrypt_logs.len() >= 1,
            "Should have at least 1 ENCRYPT log"
        );

        // Parse and verify one of the KEY_GENERATE logs
        let audit_log: AuditLog = serde_json::from_str(&keygen_logs[0]).unwrap();
        assert_eq!(audit_log.operation, "KEY_GENERATE");
        assert_eq!(audit_log.status, "SUCCESS");
    }

    #[test]
    fn test_audit_logger_concurrent() {
        // Clear logs first
        AuditLogger::clear_logs();

        // Log operations concurrently
        let handles: Vec<_> = (0..100)
            .map(|i| {
                thread::spawn(move || {
                    AuditLogger::log(
                        "test_op",
                        Some(Algorithm::AES256GCM),
                        Some(&format!("key_{}", i)),
                        if i % 2 == 0 {
                            Ok(())
                        } else {
                            Err("test error")
                        },
                    );
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let logs = AuditLogger::get_logs();
        // Check that at least 100 logs are present (other tests might be running concurrently)
        assert!(
            logs.len() >= 100,
            "Expected at least 100 logs, got {}",
            logs.len()
        );
    }

    #[test]
    fn test_audit_logger_unauthorized_access() {
        // Clear logs first
        AuditLogger::clear_logs();

        // Log unauthorized access
        AuditLogger::log_unauthorized_access(
            "KEY_ACCESS",
            Some(Algorithm::AES256GCM),
            Some("test_key"),
            Some("tenant_123"),
            "Test unauthorized access",
        );

        // Get logs
        let logs = AuditLogger::get_logs();
        // Check that at least 1 log is present (other tests might be running concurrently)
        assert!(
            logs.len() >= 1,
            "Expected at least 1 log, got {}",
            logs.len()
        );

        // Find the unauthorized access log
        let unauthorized_log = logs
            .iter()
            .find(|log| log.contains("UNAUTHORIZED"))
            .expect("Should find an unauthorized access log");

        // Parse and verify
        let audit_log: AuditLog = serde_json::from_str(unauthorized_log).unwrap();
        assert_eq!(audit_log.status, "UNAUTHORIZED");
        assert!(audit_log.details.contains("SECURITY ALERT"));
        assert_eq!(audit_log.tenant_id, Some("tenant_123".to_string()));
    }

    #[test]
    fn test_performance_monitor_cache_simulation() {
        let monitor = PerformanceMonitor::new();

        // Simulate cache hits and misses
        for i in 0..100 {
            monitor.record_operation(
                "encrypt",
                Some(Algorithm::AES256GCM),
                1000,
                1024,
                i % 3 == 0, // 33% cache hit rate
            );
        }

        let stats = monitor
            .get_stats("encrypt", Some(Algorithm::AES256GCM))
            .unwrap();
        assert_eq!(stats.total_operations, 100);
        assert!(stats.avg_cache_hit_rate > 0.3 && stats.avg_cache_hit_rate < 0.4);
    }

    #[test]
    fn test_performance_trend_calculation() {
        let monitor = PerformanceMonitor::new();

        // Record operations with improving performance
        for i in 0..50 {
            monitor.record_operation(
                "encrypt",
                Some(Algorithm::AES256GCM),
                2000 - (i * 20), // Decreasing latency = improving performance
                1024,
                true,
            );
        }

        let stats = monitor
            .get_stats("encrypt", Some(Algorithm::AES256GCM))
            .unwrap();
        assert_eq!(stats.performance_trend, "stable"); // Should be stable based on throughput calculation
    }

    #[test]
    fn test_recent_metrics_retrieval() {
        let monitor = PerformanceMonitor::new();

        // Record operations for different algorithms
        monitor.record_operation("encrypt", Some(Algorithm::AES128GCM), 1000, 1024, true);
        monitor.record_operation("encrypt", Some(Algorithm::AES256GCM), 1200, 1024, false);
        monitor.record_operation("decrypt", Some(Algorithm::SM4GCM), 800, 1024, true);

        // Get all stats
        let all_stats = monitor.get_all_stats();
        assert_eq!(all_stats.len(), 3);

        // Verify each operation has stats
        assert!(all_stats.contains_key(&format!("encrypt_{:?}", Some(Algorithm::AES128GCM))));
        assert!(all_stats.contains_key(&format!("encrypt_{:?}", Some(Algorithm::AES256GCM))));
        assert!(all_stats.contains_key(&format!("decrypt_{:?}", Some(Algorithm::SM4GCM))));
    }

    #[test]
    fn test_global_performance_functions() {
        // Reset all stats first
        reset_all_performance_stats();

        // Use global functions
        record_operation("test_op", Some(Algorithm::AES256GCM), 1000, 1024, true);

        let stats = get_performance_stats("test_op", Some(Algorithm::AES256GCM));
        assert!(stats.is_some());
        assert_eq!(stats.unwrap().total_operations, 1);

        // Test reset
        reset_performance_stats("test_op", Some(Algorithm::AES256GCM));
        let stats = get_performance_stats("test_op", Some(Algorithm::AES256GCM));
        assert!(stats.is_none());
    }
}
