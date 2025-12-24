// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

#[cfg(feature = "kdf")]
pub mod derivation;
pub mod lifecycle;
pub mod manager;

#[cfg(test)]
mod tests;

use crate::error::Result;
use crate::memory::{ProtectedKey, SecretBytes};
use crate::types::Algorithm;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// 密钥管理操作trait，用于抽象KeyManager和TenantKeyManager的操作
pub trait KeyManagerOperations {
    /// 生成密钥并返回密钥ID
    fn generate_key_operation(&self, algorithm: Algorithm) -> Result<String>;

    /// 根据密钥ID获取密钥
    fn get_key_operation(&self, key_id: &str) -> Result<Key>;

    /// 销毁密钥
    fn destroy_key_operation(&self, key_id: &str) -> Result<()>;

    /// 获取所有密钥ID
    fn list_keys_operation(&self) -> Result<Vec<String>>;
}

pub use lifecycle::{KeyLifecycleManager, KeyLifecyclePolicy, KeyManagerLifecycleExt};
pub use manager::KeyManager;

/// 密钥状态转换器
pub struct KeyStateManager;

impl KeyStateManager {
    /// 检查状态转换是否有效
    pub fn is_valid_transition(from: KeyState, to: KeyState) -> bool {
        match (from, to) {
            // 从生成状态可以转换到激活状态
            (KeyState::Generated, KeyState::Active) => true,

            // 从激活状态可以转换到暂停或销毁状态
            (KeyState::Active, KeyState::Suspended) => true,
            (KeyState::Active, KeyState::Destroyed) => true,

            // 从暂停状态可以转换回激活状态或销毁状态
            (KeyState::Suspended, KeyState::Active) => true,
            (KeyState::Suspended, KeyState::Destroyed) => true,

            // 销毁状态是最终状态，不能再转换
            (KeyState::Destroyed, _) => false,

            // 其他转换都是无效的
            _ => false,
        }
    }

    /// 获取状态描述
    #[allow(dead_code)]
    pub fn get_state_description(state: KeyState) -> &'static str {
        match state {
            KeyState::Generated => "密钥已生成，等待激活",
            KeyState::Active => "密钥已激活，可以使用",
            KeyState::Suspended => "密钥已暂停，不能使用",
            KeyState::Destroyed => "密钥已销毁，不能再使用",
        }
    }
}

/// 密钥结构，包含完整的生命周期信息
///
/// ## 线程安全说明
///
/// `Key` 类型**不是**线程安全的（`!Send + !Sync`），因为：
/// - `ProtectedKey` 内部包含可变状态，需要外部同步
/// - `usage_count`、`state` 等字段在并发访问时可能导致数据竞争
///
/// 在多线程环境中使用时，必须通过 `Arc<Mutex<Key>>` 或 `Arc<RwLock<Key>>`
/// 进行保护，确保同一时间只有一个线程可以修改密钥状态。
///
/// ## 使用示例
///
/// ```ignore
/// use std::sync::{Arc, Mutex};
/// use crate::key::{Key, KeyManager};
///
/// let key = Arc::new(Mutex::new(Key::new(algorithm, key_data)?));
/// // 在多个线程中使用
/// ```
#[derive(Clone)]
pub struct Key {
    id: String,
    algorithm: Algorithm,
    data: ProtectedKey,
    state: KeyState,
    created_at: DateTime<Utc>,
    activated_at: Option<DateTime<Utc>>,
    suspended_at: Option<DateTime<Utc>>,
    destroyed_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    usage_count: usize,
    max_usage: Option<usize>,
    metadata: std::collections::HashMap<String, String>,
}

impl Key {
    /// 创建新的密钥
    pub fn new(algorithm: Algorithm, data: Vec<u8>) -> Result<Self> {
        let secret = SecretBytes::new(data)?;
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            algorithm,
            data: ProtectedKey::new(secret),
            state: KeyState::Generated,
            created_at: Utc::now(),
            activated_at: None,
            suspended_at: None,
            destroyed_at: None,
            expires_at: None,
            usage_count: 0,
            max_usage: None,
            metadata: std::collections::HashMap::new(),
        })
    }

    /// 创建新的激活状态密钥（用于密钥派生）
    pub fn new_active(algorithm: Algorithm, data: Vec<u8>) -> Result<Self> {
        let secret = SecretBytes::new(data)?;
        let now = Utc::now();
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            algorithm,
            data: ProtectedKey::new(secret),
            state: KeyState::Active,
            created_at: now,
            activated_at: Some(now),
            suspended_at: None,
            destroyed_at: None,
            expires_at: None,
            usage_count: 0,
            max_usage: None,
            metadata: std::collections::HashMap::new(),
        })
    }

    /// 使用指定ID创建新的密钥（用于多租户隔离）
    pub fn new_with_id(algorithm: Algorithm, data: Vec<u8>, id: &str) -> Result<Self> {
        let secret = SecretBytes::new(data)?;
        Ok(Self {
            id: id.to_string(),
            algorithm,
            data: ProtectedKey::new(secret),
            state: KeyState::Generated,
            created_at: Utc::now(),
            activated_at: None,
            suspended_at: None,
            destroyed_at: None,
            expires_at: None,
            usage_count: 0,
            max_usage: None,
            metadata: std::collections::HashMap::new(),
        })
    }

    /// 激活密钥
    pub fn activate(&mut self, tenant_id: Option<&str>) -> Result<()> {
        if !KeyStateManager::is_valid_transition(self.state, KeyState::Active) {
            return Err(crate::error::CryptoError::KeyError(format!(
                "Invalid state transition from {:?} to Active",
                self.state
            )));
        }

        self.state = KeyState::Active;
        self.activated_at = Some(Utc::now());

        if let Some(tenant) = tenant_id {
            crate::audit::AuditLogger::log_with_tenant(
                "KEY_ACTIVATED",
                Some(self.algorithm),
                Some(&self.id),
                Some(tenant),
                Ok(()),
                "authorized",
            );
        } else {
            crate::audit::AuditLogger::log(
                "KEY_ACTIVATED",
                Some(self.algorithm),
                Some(&self.id),
                Ok(()),
            );
        }

        Ok(())
    }

    /// 暂停密钥
    pub fn suspend(&mut self) -> Result<()> {
        if !KeyStateManager::is_valid_transition(self.state, KeyState::Suspended) {
            return Err(crate::error::CryptoError::KeyError(format!(
                "Invalid state transition from {:?} to Suspended",
                self.state
            )));
        }

        self.state = KeyState::Suspended;
        self.suspended_at = Some(Utc::now());

        crate::audit::AuditLogger::log(
            "KEY_SUSPENDED",
            Some(self.algorithm),
            Some(&self.id),
            Ok(()),
        );

        Ok(())
    }

    /// 恢复密钥
    pub fn resume(&mut self) -> Result<()> {
        if !KeyStateManager::is_valid_transition(self.state, KeyState::Active) {
            return Err(crate::error::CryptoError::KeyError(format!(
                "Invalid state transition from {:?} to Active",
                self.state
            )));
        }

        self.state = KeyState::Active;
        self.suspended_at = None;

        crate::audit::AuditLogger::log("KEY_RESUMED", Some(self.algorithm), Some(&self.id), Ok(()));

        Ok(())
    }

    /// 销毁密钥
    pub fn destroy(&mut self) -> Result<()> {
        if !KeyStateManager::is_valid_transition(self.state, KeyState::Destroyed) {
            return Err(crate::error::CryptoError::KeyError(format!(
                "Invalid state transition from {:?} to Destroyed",
                self.state
            )));
        }

        self.state = KeyState::Destroyed;
        self.destroyed_at = Some(Utc::now());

        // 清除密钥数据 - we can't access mutable, so we'll create a new zeroized key
        let zeroized_key =
            crate::memory::SecretBytes::new(vec![0u8; self.data.access()?.as_bytes().len()])?;
        self.data = crate::memory::ProtectedKey::new(zeroized_key);

        crate::audit::AuditLogger::log(
            "KEY_DESTROYED",
            Some(self.algorithm),
            Some(&self.id),
            Ok(()),
        );

        Ok(())
    }

    /// 检查密钥是否过期
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() >= expires_at
        } else {
            false
        }
    }

    /// 检查密钥是否有效
    pub fn is_valid(&self) -> bool {
        self.state == KeyState::Active && !self.is_expired() && !self.is_usage_exceeded()
    }

    /// 检查使用次数是否超限
    pub fn is_usage_exceeded(&self) -> bool {
        if let Some(max_usage) = self.max_usage {
            self.usage_count >= max_usage
        } else {
            false
        }
    }

    /// 增加使用计数
    pub fn increment_usage(&mut self) -> Result<()> {
        if !self.is_valid() {
            return Err(crate::error::CryptoError::KeyError(
                "Key is not valid for use".into(),
            ));
        }

        self.usage_count += 1;
        Ok(())
    }

    /// 设置最大使用次数
    pub(crate) fn set_max_usage(&mut self, max_usage: Option<usize>) {
        self.max_usage = max_usage;
    }

    /// 获取密钥生命周期状态
    pub fn get_lifecycle_status(&self) -> String {
        format!(
            "Key {}: {} (created: {}, state: {:?}, usage: {}, expired: {})",
            self.id,
            if self.is_valid() { "VALID" } else { "INVALID" },
            self.created_at.format("%Y-%m-%d %H:%M:%S"),
            self.state,
            self.usage_count,
            self.is_expired()
        )
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn state(&self) -> KeyState {
        self.state
    }

    pub fn secret_bytes(&self) -> Result<&SecretBytes> {
        if !self.is_valid() {
            return Err(crate::error::CryptoError::KeyError(
                "Key is not valid for use".into(),
            ));
        }

        self.data.access()
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn activated_at(&self) -> Option<DateTime<Utc>> {
        self.activated_at
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    pub fn set_expires_at(&mut self, expires_at: DateTime<Utc>) {
        self.expires_at = Some(expires_at);
    }

    pub fn usage_count(&self) -> usize {
        self.usage_count
    }

    pub fn metadata(&self) -> &std::collections::HashMap<String, String> {
        &self.metadata
    }

    pub fn metadata_mut(&mut self) -> &mut std::collections::HashMap<String, String> {
        &mut self.metadata
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // 确保密钥数据被安全清除 - create a zeroized replacement
        if let Ok(_secret) = self.data.access() {
            if let Ok(zeroized_key) =
                crate::memory::SecretBytes::new(vec![0u8; _secret.as_bytes().len()])
            {
                self.data = crate::memory::ProtectedKey::new(zeroized_key);
            }
        }
    }
}

/// 密钥状态枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Generated,
    Active,
    Suspended,
    Destroyed,
}
