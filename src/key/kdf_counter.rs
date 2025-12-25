// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::audit::AuditLogger;
use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum KdfUsageType {
    Hkdf,
    Pbkdf2,
    Argon2id,
    Sm3Kdf,
    Scrypt,
    Custom(String),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KdfUsageRecord {
    pub usage_type: KdfUsageType,
    pub algorithm: Algorithm,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub input_length: usize,
    pub output_length: usize,
    pub iterations: Option<u32>,
    pub memory_usage: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct KdfUsageParams {
    pub usage_type: KdfUsageType,
    pub algorithm: Algorithm,
    pub input_length: usize,
    pub output_length: usize,
    pub iterations: Option<u32>,
    pub memory_usage: Option<usize>,
    pub success: bool,
}

impl KdfUsageRecord {
    pub fn new(params: KdfUsageParams) -> Self {
        Self {
            usage_type: params.usage_type,
            algorithm: params.algorithm,
            timestamp: Utc::now(),
            success: params.success,
            input_length: params.input_length,
            output_length: params.output_length,
            iterations: params.iterations,
            memory_usage: params.memory_usage,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct KdfUsageStats {
    pub total_operations: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub total_bytes_derived: usize,
    pub last_used: Option<DateTime<Utc>>,
    pub algorithm_usage: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KdfUsagePolicy {
    pub max_operations_per_period: Option<usize>,
    pub max_bytes_derived_per_period: Option<usize>,
    pub period_duration: chrono::Duration,
    pub require_audit_log: bool,
    pub block_on_limit: bool,
    pub custom_limits: HashMap<KdfUsageType, KdfUsageLimit>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KdfUsageLimit {
    pub max_operations: Option<usize>,
    pub max_bytes: Option<usize>,
    pub period: chrono::Duration,
}

impl Default for KdfUsagePolicy {
    fn default() -> Self {
        Self {
            max_operations_per_period: Some(10000),
            max_bytes_derived_per_period: Some(1024 * 1024 * 1024),
            period_duration: chrono::Duration::days(1),
            require_audit_log: true,
            block_on_limit: false,
            custom_limits: HashMap::new(),
        }
    }
}

impl Default for KdfUsageLimit {
    fn default() -> Self {
        Self {
            max_operations: Some(1000000),
            max_bytes: Some(1024 * 1024 * 1024 * 10),
            period: chrono::Duration::days(1),
        }
    }
}

#[allow(dead_code)]
pub struct KdfUsageCounter {
    usage_records: Arc<RwLock<Vec<KdfUsageRecord>>>,
    current_stats: Arc<RwLock<KdfUsageStats>>,
    policy: Arc<RwLock<KdfUsagePolicy>>,
    period_start: Arc<RwLock<DateTime<Utc>>>,
}

impl KdfUsageCounter {
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
        Ok(Self {
            usage_records: Arc::new(RwLock::new(Vec::new())),
            current_stats: Arc::new(RwLock::new(KdfUsageStats::default())),
            policy: Arc::new(RwLock::new(KdfUsagePolicy::default())),
            period_start: Arc::new(RwLock::new(Utc::now())),
        })
    }

    #[allow(dead_code)]
    pub fn set_policy(&self, policy: KdfUsagePolicy) {
        let mut write_policy = self.policy.write().unwrap();
        *write_policy = policy;
    }

    #[allow(dead_code)]
    pub fn get_policy(&self) -> KdfUsagePolicy {
        let read_policy = self.policy.read().unwrap();
        read_policy.clone()
    }

    #[allow(dead_code)]
    pub fn record_usage(&self, params: KdfUsageParams) -> Result<()> {
        self.check_limits(&params.usage_type, params.output_length)?;

        let record = KdfUsageRecord::new(params.clone());

        {
            let mut records = self.usage_records.write().unwrap();
            records.push(record.clone());

            if records.len() > 10000 {
                records.truncate(5000);
            }
        }

        {
            let mut stats = self.current_stats.write().unwrap();
            stats.total_operations += 1;
            if params.success {
                stats.successful_operations += 1;
                stats.total_bytes_derived += params.output_length;
                stats.last_used = Some(Utc::now());
            } else {
                stats.failed_operations += 1;
            }

            let algo_key = format!("{:?}", params.algorithm);
            *stats.algorithm_usage.entry(algo_key).or_insert(0) += 1;
        }

        if self.policy.read().unwrap().require_audit_log {
            AuditLogger::log(
                "KDF_USAGE",
                Some(params.algorithm),
                Some(&format!("{:?}", params.usage_type)),
                Ok(()),
            );
        }

        Ok(())
    }

    fn check_limits(&self, usage_type: &KdfUsageType, output_length: usize) -> Result<()> {
        let policy = self.policy.read().unwrap();
        let stats = self.current_stats.read().unwrap();

        if let Some(limit) = policy.max_operations_per_period {
            if stats.total_operations >= limit && policy.block_on_limit {
                return Err(CryptoError::SecurityError(
                    "KDF usage limit exceeded".to_string(),
                ));
            }
        }

        if let Some(limit) = policy.max_bytes_derived_per_period {
            if stats.total_bytes_derived + output_length > limit && policy.block_on_limit {
                return Err(CryptoError::SecurityError(
                    "KDF byte limit exceeded".to_string(),
                ));
            }
        }

        if let Some(type_limit) = policy.custom_limits.get(usage_type) {
            if let Some(max_ops) = type_limit.max_operations {
                let type_ops: usize = self
                    .usage_records
                    .read()
                    .unwrap()
                    .iter()
                    .filter(|r| r.usage_type == *usage_type)
                    .count();

                if type_ops >= max_ops && policy.block_on_limit {
                    return Err(CryptoError::SecurityError(format!(
                        "KDF usage limit exceeded for {:?}",
                        usage_type
                    )));
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_stats(&self) -> KdfUsageStats {
        let stats = self.current_stats.read().unwrap();
        stats.clone()
    }

    #[allow(dead_code)]
    pub fn get_recent_usage(&self, limit: usize) -> Vec<KdfUsageRecord> {
        let records = self.usage_records.read().unwrap();
        records.iter().rev().take(limit).cloned().collect()
    }

    #[allow(dead_code)]
    pub fn get_usage_by_type(&self, usage_type: &KdfUsageType) -> Vec<KdfUsageRecord> {
        let records = self.usage_records.read().unwrap();
        records
            .iter()
            .filter(|r| &r.usage_type == usage_type)
            .cloned()
            .collect()
    }

    #[allow(dead_code)]
    pub fn reset_period(&self) {
        let mut stats = self.current_stats.write().unwrap();
        *stats = KdfUsageStats::default();

        let mut period = self.period_start.write().unwrap();
        *period = Utc::now();
    }

    #[allow(dead_code)]
    pub fn check_compliance(&self) -> Vec<String> {
        let mut issues = Vec::new();
        let stats = self.current_stats.read().unwrap();
        let policy = self.policy.read().unwrap();

        if let Some(limit) = policy.max_operations_per_period {
            let usage_percent = (stats.total_operations as f64 / limit as f64) * 100.0;
            if usage_percent >= 90.0 {
                issues.push(format!(
                    "KDF operations at {:.1}% of limit ({}/{})",
                    usage_percent, stats.total_operations, limit
                ));
            }
        }

        if let Some(limit) = policy.max_bytes_derived_per_period {
            let usage_percent = (stats.total_bytes_derived as f64 / limit as f64) * 100.0;
            if usage_percent >= 90.0 {
                issues.push(format!(
                    "KDF bytes derived at {:.1}% of limit ({}/{})",
                    usage_percent,
                    humanize_bytes(stats.total_bytes_derived),
                    humanize_bytes(limit)
                ));
            }
        }

        issues
    }
}

#[allow(dead_code)]
fn humanize_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

impl Default for KdfUsageCounter {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
