// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use super::KeyManagerOperations;
use crate::audit::AuditLogger;
use crate::error::{CryptoError, Result};
use crate::random::SecureRandom;
use crate::types::{Algorithm, KeyState};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// 密钥生命周期策略
#[derive(Debug, Clone)]
pub struct KeyLifecyclePolicy {
    /// 密钥有效期 (秒)
    pub key_lifetime: Duration,

    /// 密钥轮换间隔 (秒)
    pub rotation_interval: Duration,

    /// 密钥轮换前警告时间 (秒)
    pub rotation_warning_period: Duration,

    /// 最大密钥使用次数
    pub max_key_usage: Option<usize>,

    /// 是否启用自动轮换
    pub auto_rotation_enabled: bool,

    /// 是否启用密钥版本管理
    pub version_management_enabled: bool,
}

impl Default for KeyLifecyclePolicy {
    fn default() -> Self {
        Self {
            key_lifetime: Duration::days(365),           // 1年
            rotation_interval: Duration::days(90),       // 90天
            rotation_warning_period: Duration::days(30), // 30天警告
            max_key_usage: Some(1_000_000),              // 100万次使用
            auto_rotation_enabled: true,
            version_management_enabled: true,
        }
    }
}

/// 密钥版本信息
#[derive(Debug, Clone)]
pub struct KeyVersion {
    pub version_id: String,
    pub key_id: String,
    pub algorithm: Algorithm,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
    pub usage_count: usize,
    pub state: KeyState,
}

/// 密钥生命周期管理器
pub struct KeyLifecycleManager {
    policies: Arc<RwLock<HashMap<Algorithm, KeyLifecyclePolicy>>>,
    key_versions: Arc<RwLock<HashMap<String, Vec<KeyVersion>>>>,
    rotation_schedule: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    _rng: SecureRandom,
}

impl KeyLifecycleManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            key_versions: Arc::new(RwLock::new(HashMap::new())),
            rotation_schedule: Arc::new(RwLock::new(HashMap::new())),
            _rng: SecureRandom::new()?,
        })
    }

    /// 设置算法的生命周期策略
    pub fn set_policy(&self, algorithm: Algorithm, policy: KeyLifecyclePolicy) -> Result<()> {
        let mut policies = self
            .policies
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        policies.insert(algorithm, policy);

        AuditLogger::log("KEY_POLICY_SET", Some(algorithm), None, Ok(()));

        Ok(())
    }

    /// 获取算法的生命周期策略
    pub fn get_policy(&self, algorithm: Algorithm) -> Option<KeyLifecyclePolicy> {
        let policies = self.policies.read().ok()?;
        policies.get(&algorithm).cloned()
    }

    /// 创建密钥版本
    pub fn create_key_version(
        &self,
        key_manager: &dyn KeyManagerOperations,
        algorithm: Algorithm,
    ) -> Result<String> {
        let policy = self.get_policy(algorithm).unwrap_or_default();

        // 生成新的密钥
        let key_id = key_manager.generate_key_operation(algorithm)?;

        // 创建版本信息
        let version = KeyVersion {
            version_id: format!("v_{}", chrono::Utc::now().timestamp_millis()),
            key_id: key_id.clone(),
            algorithm,
            created_at: Utc::now(),
            expires_at: Utc::now() + policy.key_lifetime,
            is_active: true,
            usage_count: 0,
            state: KeyState::Active,
        };

        // 存储版本信息
        let mut versions = self
            .key_versions
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        let entry = versions.entry(key_id.clone()).or_insert_with(Vec::new);

        // 如果有旧的活跃版本，将其标记为非活跃
        for old_version in entry.iter_mut() {
            if old_version.is_active {
                old_version.is_active = false;
            }
        }

        entry.push(version);

        // 设置轮换计划
        if policy.auto_rotation_enabled {
            let mut schedule = self
                .rotation_schedule
                .write()
                .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
            schedule.insert(key_id.clone(), Utc::now() + policy.rotation_interval);
        }

        AuditLogger::log(
            "KEY_VERSION_CREATED",
            Some(algorithm),
            Some(&key_id),
            Ok(()),
        );

        Ok(key_id)
    }

    /// 获取活跃密钥版本
    pub fn get_active_version(&self, key_id: &str) -> Result<KeyVersion> {
        let versions = self
            .key_versions
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        let key_versions = versions
            .get(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))?;

        key_versions
            .iter()
            .find(|v| v.is_active && v.state == KeyState::Active)
            .cloned()
            .ok_or_else(|| CryptoError::KeyNotFound("No active version found".into()))
    }

    /// 检查密钥是否需要轮换
    pub fn needs_rotation(&self, key_id: &str) -> Result<bool> {
        let versions = self
            .key_versions
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        let key_versions = versions
            .get(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))?;

        // 检查活跃版本
        if let Some(active_version) = key_versions.iter().find(|v| v.is_active) {
            let policy = self.get_policy(active_version.algorithm).unwrap_or_default();
            let now = Utc::now();

            // 检查是否过期
            if active_version.expires_at < now {
                return Ok(true);
            }

            // 检查使用次数
            if let Some(max_usage) = policy.max_key_usage {
                if active_version.usage_count >= max_usage {
                    return Ok(true);
                }
            }

            // 检查轮换时间
            let schedule = self
                .rotation_schedule
                .read()
                .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
            if let Some(&rotation_time) = schedule.get(key_id) {
                if now >= rotation_time {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// 执行密钥轮换
    pub fn rotate_key(
        &self,
        key_manager: &dyn KeyManagerOperations,
        key_id: &str,
        algorithm: Algorithm,
    ) -> Result<String> {
        // 检查是否需要轮换
        if !self.needs_rotation(key_id)? {
            return Err(CryptoError::KeyError("Key does not need rotation".into()));
        }

        // 创建新版本
        let new_key_id = self.create_key_version(key_manager, algorithm)?;

        // 更新轮换计划
        let policy = self.get_policy(algorithm).unwrap_or_default();
        if policy.auto_rotation_enabled {
            let mut schedule = self
                .rotation_schedule
                .write()
                .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
            schedule.insert(new_key_id.clone(), Utc::now() + policy.rotation_interval);
        }

        AuditLogger::log("KEY_ROTATED", Some(algorithm), Some(&new_key_id), Ok(()));

        Ok(new_key_id)
    }

    /// 增加密钥使用计数
    pub fn increment_key_usage(&self, key_id: &str) -> Result<()> {
        let mut versions = self
            .key_versions
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        let key_versions = versions
            .get_mut(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))?;

        if let Some(active_version) = key_versions.iter_mut().find(|v| v.is_active) {
            active_version.usage_count += 1;
        }

        Ok(())
    }

    /// 获取密钥轮换警告
    pub fn get_rotation_warning(&self, key_id: &str) -> Result<Option<String>> {
        let versions = self
            .key_versions
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        let key_versions = versions
            .get(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))?;

        let policy = self.get_policy(Algorithm::AES256GCM).unwrap_or_default();
        let now = Utc::now();

        if let Some(active_version) = key_versions.iter().find(|v| v.is_active) {
            // 检查使用次数警告
            if let Some(max_usage) = policy.max_key_usage {
                if active_version.usage_count >= max_usage {
                    return Ok(Some(format!(
                        "Key {} has reached usage limit ({} uses). Consider rotating it.",
                        key_id, active_version.usage_count
                    )));
                }
            }

            // 检查时间过期警告
            let warning_time = active_version.expires_at - policy.rotation_warning_period;

            if now >= warning_time {
                let days_until_expiry = (active_version.expires_at - now).num_days();
                return Ok(Some(format!(
                    "Key {} will expire in {} days. Consider rotating it.",
                    key_id, days_until_expiry
                )));
            }
        }

        Ok(None)
    }

    /// 检查密钥是否存在并获取轮换警告（适用于任何密钥管理器）
    pub fn get_rotation_warning_for_key(
        &self,
        key_manager: &dyn KeyManagerOperations,
        key_id: &str,
    ) -> Result<Option<String>> {
        // 首先检查密钥是否存在
        key_manager.get_key_operation(key_id)?;

        // 如果密钥存在但不在生命周期管理器中，尝试获取密钥信息以确定算法
        // 实际上 key_manager.get_key_operation(key_id) 应该返回 Key 对象，但这里我们无法访问具体类型
        // 假设使用默认策略
        let policy = self.get_policy(Algorithm::AES256GCM).unwrap_or_default();

        // 检查密钥是否接近过期
        // 在实际实现中，我们需要获取密钥的创建时间
        // 由于这里只能确认密钥存在，我们只能返回一般性警告
        if policy.rotation_warning_period > Duration::zero() {
            // 尝试从 schedule 中获取时间信息
            let schedule = self.rotation_schedule.read().map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
            if let Some(next_rotation) = schedule.get(key_id) {
                 let now = Utc::now();
                 let duration = *next_rotation - now;
                 if duration > Duration::zero() {
                     if duration < policy.rotation_warning_period {
                         return Ok(Some(format!(
                            "Key {} is expiring in less than {:?}. Please rotate soon.",
                            key_id, duration
                        )));
                     }
                 } else {
                     // 已经过期
                     return Ok(Some(format!(
                        "Key {} has expired. Please rotate immediately.",
                        key_id
                    )));
                 }
            } else {
                 // 没有轮换计划，可能是新导入的密钥
                 return Ok(Some(format!(
                    "Key {} exists but has no rotation schedule. It may be unmanaged.",
                    key_id
                )));
            }
        }

        Ok(None)
    }

    /// 销毁密钥及其所有版本
    pub fn destroy_key_with_versions(
        &self,
        key_manager: &dyn KeyManagerOperations,
        key_id: &str,
    ) -> Result<()> {
        // 销毁所有版本
        let mut versions = self
            .key_versions
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        if let Some(key_versions) = versions.remove(key_id) {
            for version in key_versions {
                key_manager.destroy_key_operation(&version.key_id)?;
            }
        }

        // 从轮换计划中移除
        let mut schedule = self
            .rotation_schedule
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        schedule.remove(key_id);

        AuditLogger::log("KEY_DESTROYED_WITH_VERSIONS", None, Some(key_id), Ok(()));

        Ok(())
    }

    /// 获取所有需要轮换的密钥
    pub fn get_keys_needing_rotation(&self) -> Result<Vec<String>> {
        let versions = self
            .key_versions
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        let mut keys_needing_rotation = Vec::new();

        for (key_id, _) in versions.iter() {
            if self.needs_rotation(key_id)? {
                keys_needing_rotation.push(key_id.clone());
            }
        }

        Ok(keys_needing_rotation)
    }

    /// 执行批量密钥轮换
    pub fn rotate_all_expired_keys(
        &self,
        key_manager: &dyn KeyManagerOperations,
    ) -> Result<Vec<String>> {
        let keys_needing_rotation = self.get_keys_needing_rotation()?;
        let mut rotated_keys = Vec::new();

        // 获取所有版本信息以查找算法
        let versions = self
            .key_versions
            .read()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;

        // Iterate over a clone of the keys to avoid borrowing issues or use the owned vector
        for key_id in &keys_needing_rotation {
            // We use key_id.as_str() to ensure we are using &str for lookup
            // But versions is HashMap<String, Vec<KeyVersion>>
            // So we can just use key_id directly as it is &String which coerces to &str or &String
            if let Some(key_versions) = versions.get(key_id) {
                if let Some(active_version) = key_versions.iter().find(|v| v.is_active) {
                    // 使用正确的算法进行轮换
                    if let Ok(new_key_id) = self.rotate_key(key_manager, key_id, active_version.algorithm) {
                        rotated_keys.push(new_key_id);
                    }
                }
            }
        }

        Ok(rotated_keys)
    }
}

/// 密钥生命周期管理器扩展 trait
#[allow(dead_code)]
pub trait KeyManagerLifecycleExt: KeyManagerOperations {
    /// 使用生命周期管理创建密钥
    #[allow(dead_code)]
    fn generate_key_with_lifecycle(
        &self,
        algorithm: Algorithm,
        lifecycle_manager: &KeyLifecycleManager,
    ) -> Result<String>;

    /// 轮换密钥
    #[allow(dead_code)]
    fn rotate_key(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        lifecycle_manager: &KeyLifecycleManager,
    ) -> Result<String>;

    /// 获取密钥生命周期状态
    #[allow(dead_code)]
    fn get_key_lifecycle_status(
        &self,
        key_id: &str,
        lifecycle_manager: &KeyLifecycleManager,
    ) -> Result<String>;
}
