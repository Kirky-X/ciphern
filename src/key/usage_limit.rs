// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::audit::AuditLogger;
use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UsageLimitType {
    Total,
    Encryption,
    Decryption,
    Signature,
    Verification,
    Derivation,
    KeyAgreement,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UsageLimitPolicy {
    pub limit_type: UsageLimitType,
    pub max_count: usize,
    pub warning_threshold: f64,
    pub reset_strategy: ResetStrategy,
    pub reset_period: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ResetStrategy {
    None,
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

impl Default for UsageLimitPolicy {
    fn default() -> Self {
        Self {
            limit_type: UsageLimitType::Total,
            max_count: 1_000_000,
            warning_threshold: 0.8,
            reset_strategy: ResetStrategy::None,
            reset_period: None,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KeyUsageLimit {
    key_id: String,
    algorithm: Algorithm,
    policies: Vec<UsageLimitPolicy>,
    current_usage: HashMap<UsageLimitType, usize>,
    last_reset: HashMap<UsageLimitType, DateTime<Utc>>,
    created_at: DateTime<Utc>,
    last_accessed_at: DateTime<Utc>,
}

#[allow(dead_code)]
impl KeyUsageLimit {
    pub fn new(key_id: String, algorithm: Algorithm) -> Self {
        let mut current_usage = HashMap::new();
        current_usage.insert(UsageLimitType::Total, 0);
        current_usage.insert(UsageLimitType::Encryption, 0);
        current_usage.insert(UsageLimitType::Decryption, 0);
        current_usage.insert(UsageLimitType::Signature, 0);
        current_usage.insert(UsageLimitType::Verification, 0);
        current_usage.insert(UsageLimitType::Derivation, 0);
        current_usage.insert(UsageLimitType::KeyAgreement, 0);

        let mut last_reset = HashMap::new();
        let now = Utc::now();
        for limit_type in [
            UsageLimitType::Total,
            UsageLimitType::Encryption,
            UsageLimitType::Decryption,
            UsageLimitType::Signature,
            UsageLimitType::Verification,
            UsageLimitType::Derivation,
            UsageLimitType::KeyAgreement,
        ] {
            last_reset.insert(limit_type, now);
        }

        Self {
            key_id,
            algorithm,
            policies: Vec::new(),
            current_usage,
            last_reset,
            created_at: now,
            last_accessed_at: now,
        }
    }

    pub fn add_policy(&mut self, policy: UsageLimitPolicy) {
        self.policies.push(policy);
    }

    pub fn record_usage(&mut self, usage_type: UsageLimitType) -> Result<()> {
        self.check_limits(&usage_type)?;

        self.current_usage
            .entry(usage_type.clone())
            .and_modify(|count| *count += 1);

        self.current_usage
            .entry(UsageLimitType::Total)
            .and_modify(|count| *count += 1);

        self.last_accessed_at = Utc::now();

        AuditLogger::log(
            "KEY_USAGE_RECORDED",
            Some(self.algorithm),
            Some(&self.key_id),
            Ok(()),
        );

        Ok(())
    }

    pub fn record_usage_bulk(&mut self, usage_types: &[UsageLimitType]) -> Result<()> {
        for usage_type in usage_types {
            self.check_limits(usage_type)?;
        }

        for usage_type in usage_types {
            self.current_usage
                .entry(usage_type.clone())
                .and_modify(|count| *count += 1);
        }

        self.current_usage
            .entry(UsageLimitType::Total)
            .and_modify(|count| *count += usage_types.len());

        self.last_accessed_at = Utc::now();

        Ok(())
    }

    fn check_limits(&self, usage_type: &UsageLimitType) -> Result<()> {
        let current_count = self.current_usage.get(usage_type).copied().unwrap_or(0);

        for policy in &self.policies {
            if policy.limit_type == *usage_type {
                if current_count >= policy.max_count {
                    return Err(CryptoError::KeyUsageLimitExceeded {
                        key_id: self.key_id.clone(),
                        limit_type: format!("{:?}", usage_type),
                        current_count,
                        max_count: policy.max_count,
                    });
                }

                let warning_count = (policy.max_count as f64 * policy.warning_threshold) as usize;
                if current_count >= warning_count && current_count < policy.max_count {
                    AuditLogger::log(
                        "KEY_USAGE_WARNING",
                        Some(self.algorithm),
                        Some(&self.key_id),
                        Ok(()),
                    );
                }
            }
        }

        Ok(())
    }

    pub fn get_usage(&self, usage_type: &UsageLimitType) -> usize {
        self.current_usage.get(usage_type).copied().unwrap_or(0)
    }

    pub fn get_total_usage(&self) -> usize {
        self.current_usage
            .get(&UsageLimitType::Total)
            .copied()
            .unwrap_or(0)
    }

    pub fn get_usage_percentage(&self, usage_type: &UsageLimitType) -> f64 {
        let current = self.get_usage(usage_type);
        for policy in &self.policies {
            if policy.limit_type == *usage_type {
                return if policy.max_count > 0 {
                    current as f64 / policy.max_count as f64
                } else {
                    0.0
                };
            }
        }
        0.0
    }

    pub fn get_usage_report(&self) -> Vec<UsageReportEntry> {
        let mut report = Vec::new();

        for usage_type in [
            UsageLimitType::Total,
            UsageLimitType::Encryption,
            UsageLimitType::Decryption,
            UsageLimitType::Signature,
            UsageLimitType::Verification,
            UsageLimitType::Derivation,
            UsageLimitType::KeyAgreement,
        ] {
            let current = self.get_usage(&usage_type);
            let max = self
                .policies
                .iter()
                .find(|p| p.limit_type == usage_type)
                .map(|p| p.max_count)
                .unwrap_or(0);

            report.push(UsageReportEntry {
                usage_type: usage_type.clone(),
                current_count: current,
                max_count: max,
                percentage: if max > 0 {
                    (current as f64 / max as f64) * 100.0
                } else {
                    0.0
                },
                last_reset: self.last_reset.get(&usage_type).copied(),
            });
        }

        report
    }

    pub fn reset_usage(&mut self, usage_type: &UsageLimitType) {
        self.current_usage.insert(usage_type.clone(), 0);
        self.last_reset.insert(usage_type.clone(), Utc::now());

        AuditLogger::log(
            "KEY_USAGE_RESET",
            Some(self.algorithm),
            Some(&self.key_id),
            Ok(()),
        );
    }

    pub fn check_rotation_needed(&self) -> (bool, Option<UsageLimitType>, usize, usize) {
        for policy in &self.policies {
            let current = self.get_usage(&policy.limit_type);
            if current >= policy.max_count {
                return (
                    true,
                    Some(policy.limit_type.clone()),
                    current,
                    policy.max_count,
                );
            }
        }
        (false, None, 0, 0)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UsageReportEntry {
    pub usage_type: UsageLimitType,
    pub current_count: usize,
    pub max_count: usize,
    pub percentage: f64,
    pub last_reset: Option<DateTime<Utc>>,
}

#[allow(dead_code)]
pub struct UsageLimitManager {
    key_limits: Arc<RwLock<HashMap<String, KeyUsageLimit>>>,
    default_policies: Arc<RwLock<HashMap<Algorithm, Vec<UsageLimitPolicy>>>>,
}

#[allow(dead_code)]
impl UsageLimitManager {
    pub fn new() -> Self {
        let mut default_policies = HashMap::new();

        let symmetric_policy = UsageLimitPolicy {
            limit_type: UsageLimitType::Encryption,
            max_count: 10_000_000,
            warning_threshold: 0.8,
            reset_strategy: ResetStrategy::None,
            reset_period: None,
        };

        let _decryption_policy = UsageLimitPolicy {
            limit_type: UsageLimitType::Decryption,
            max_count: 10_000_000,
            warning_threshold: 0.8,
            reset_strategy: ResetStrategy::None,
            reset_period: None,
        };

        let signature_policy = UsageLimitPolicy {
            limit_type: UsageLimitType::Signature,
            max_count: 1_000_000,
            warning_threshold: 0.8,
            reset_strategy: ResetStrategy::None,
            reset_period: None,
        };

        let _verification_policy = UsageLimitPolicy {
            limit_type: UsageLimitType::Verification,
            max_count: 10_000_000,
            warning_threshold: 0.8,
            reset_strategy: ResetStrategy::None,
            reset_period: None,
        };

        default_policies.insert(Algorithm::AES128GCM, vec![symmetric_policy.clone()]);
        default_policies.insert(Algorithm::AES256GCM, vec![symmetric_policy.clone()]);
        default_policies.insert(Algorithm::SM4GCM, vec![symmetric_policy.clone()]);
        default_policies.insert(Algorithm::Ed25519, vec![signature_policy.clone()]);
        default_policies.insert(Algorithm::ECDSAP256, vec![signature_policy.clone()]);
        default_policies.insert(Algorithm::ECDSAP384, vec![signature_policy.clone()]);
        default_policies.insert(Algorithm::RSA2048, vec![signature_policy.clone()]);
        default_policies.insert(Algorithm::RSA3072, vec![signature_policy.clone()]);
        default_policies.insert(Algorithm::RSA4096, vec![signature_policy.clone()]);

        Self {
            key_limits: Arc::new(RwLock::new(HashMap::new())),
            default_policies: Arc::new(RwLock::new(default_policies)),
        }
    }

    pub fn create_key_limit(&self, key_id: String, algorithm: Algorithm) -> Result<KeyUsageLimit> {
        let mut limit = KeyUsageLimit::new(key_id.clone(), algorithm);

        {
            let policies = self
                .default_policies
                .read()
                .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
            if let Some(policies) = policies.get(&algorithm) {
                for policy in policies {
                    limit.add_policy(policy.clone());
                }
            }
        }

        let mut limits = self
            .key_limits
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        limits.insert(key_id, limit.clone());

        Ok(limit)
    }

    pub fn get_key_limit(&self, key_id: &str) -> Result<KeyUsageLimit> {
        let limits = self
            .key_limits
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        limits
            .get(key_id)
            .cloned()
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))
    }

    pub fn get_key_limit_mut(&self, key_id: &str) -> Result<KeyUsageLimit> {
        let mut limits = self
            .key_limits
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        limits
            .get_mut(key_id)
            .cloned()
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))
    }

    pub fn remove_key_limit(&self, key_id: &str) -> Result<()> {
        let mut limits = self
            .key_limits
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        limits.remove(key_id);

        AuditLogger::log("KEY_USAGE_LIMIT_REMOVED", None, Some(key_id), Ok(()));

        Ok(())
    }

    pub fn add_policy(&self, algorithm: Algorithm, policy: UsageLimitPolicy) {
        let mut policies = self
            .default_policies
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))
            .unwrap();
        policies.entry(algorithm).or_default().push(policy);
    }

    pub fn check_all_keys_rotation(&self) -> Vec<(String, UsageLimitType, usize, usize)> {
        let limits = self
            .key_limits
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))
            .unwrap();

        let mut needs_rotation = Vec::new();

        for (key_id, limit) in limits.iter() {
            let (needed, limit_type, current, max) = limit.check_rotation_needed();
            if needed {
                if let Some(lt) = limit_type {
                    needs_rotation.push((key_id.clone(), lt, current, max));
                }
            }
        }

        needs_rotation
    }

    pub fn get_all_usage_reports(&self) -> Vec<(String, Vec<UsageReportEntry>)> {
        let limits = self
            .key_limits
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))
            .unwrap();

        limits
            .iter()
            .map(|(key_id, limit)| (key_id.clone(), limit.get_usage_report()))
            .collect()
    }
}

impl Default for UsageLimitManager {
    fn default() -> Self {
        Self::new()
    }
}
