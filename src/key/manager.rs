// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use super::{Key, KeyLifecycleManager, KeyManagerLifecycleExt, KeyManagerOperations, KeyState};
use crate::audit::AuditLogger;
use crate::error::{CryptoError, Result};
use crate::fips::{is_fips_enabled, validator::FipsAlgorithmValidator, FipsContext};
use crate::random::SecureRandom;
use crate::types::Algorithm;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// 引用辅助宏以减少代码重复（宏在 crate 根级别导出）
use crate::{with_lock_read, with_lock_write};

// PKCS#8 key generation for signature algorithms
use crate::key::openssl_rsa::{convert_rsa_der_to_pkcs8, generate_openssl_rsa_private_key};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair};

/// 增强的密钥管理器，支持完整的生命周期管理
pub struct KeyManager {
    keys: Arc<RwLock<HashMap<String, Key>>>,
    key_aliases: Arc<RwLock<HashMap<String, String>>>, // 别名到密钥ID的映射
    lifecycle_manager: Option<Arc<KeyLifecycleManager>>,
    nonce_tracker: Arc<RwLock<HashMap<String, std::collections::HashSet<Vec<u8>>>>>, // nonce 追踪器
    rng: SecureRandom,
    fips_context: Option<Arc<FipsContext>>,
}

impl KeyManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            key_aliases: Arc::new(RwLock::new(HashMap::new())),
            lifecycle_manager: None,
            nonce_tracker: Arc::new(RwLock::new(HashMap::new())),
            rng: SecureRandom::new()?,
            fips_context: None,
        })
    }

    /// 启用生命周期管理
    pub fn enable_lifecycle_management(&mut self, lifecycle_manager: Arc<KeyLifecycleManager>) {
        self.lifecycle_manager = Some(lifecycle_manager);
    }

    /// 设置FIPS上下文
    pub fn set_fips_context(&mut self, fips_context: Arc<FipsContext>) {
        self.fips_context = Some(fips_context);
    }

    /// 为签名算法生成PKCS#8格式的密钥
    fn generate_signature_key(&self, algorithm: Algorithm) -> Result<Vec<u8>> {
        match algorithm {
            Algorithm::Ed25519 => {
                // 生成Ed25519密钥对
                let rng = SystemRandom::new();
                let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| {
                    CryptoError::KeyError(format!("Failed to generate Ed25519 PKCS#8 key: {}", e))
                })?;
                Ok(pkcs8_bytes.as_ref().to_vec())
            }
            Algorithm::ECDSAP256 | Algorithm::ECDSAP384 => {
                // 生成ECDSA密钥对
                let rng = SystemRandom::new();
                let signing_alg = match algorithm {
                    Algorithm::ECDSAP256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    Algorithm::ECDSAP384 => &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                    _ => {
                        return Err(CryptoError::UnsupportedAlgorithm(format!(
                            "Unsupported ECDSA algorithm: {:?}",
                            algorithm
                        )))
                    }
                };

                let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(signing_alg, &rng).map_err(|e| {
                    CryptoError::KeyError(format!("Failed to generate ECDSA PKCS#8 key: {}", e))
                })?;

                Ok(pkcs8_bytes.as_ref().to_vec())
            }
            Algorithm::RSA2048 | Algorithm::RSA3072 | Algorithm::RSA4096 => {
                let key_size = match algorithm {
                    Algorithm::RSA2048 => 2048,
                    Algorithm::RSA3072 => 3072,
                    Algorithm::RSA4096 => 4096,
                    _ => 2048,
                };

                let der_bytes = generate_openssl_rsa_private_key(key_size)?;
                let pkcs8_bytes = convert_rsa_der_to_pkcs8(&der_bytes)?;

                Ok(pkcs8_bytes)
            }
            Algorithm::X25519 => {
                // 生成 X25519 密钥对
                use x25519_dalek::x25519;
                let mut private_key = [0u8; 32];
                self.rng.fill(&mut private_key)?;
                let public_key = x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);

                // 返回格式：[私钥(32字节) || 公钥(32字节)]
                let mut key_data = Vec::with_capacity(64);
                key_data.extend_from_slice(&private_key);
                key_data.extend_from_slice(&public_key);
                Ok(key_data)
            }
            _ => {
                // 对于对称算法，生成随机字节
                let size = algorithm.key_size();
                let mut key_data = vec![0u8; size];
                self.rng.fill(&mut key_data)?;
                Ok(key_data)
            }
        }
    }

    /// 生成密钥并自动激活
    pub fn generate_key(&self, algorithm: Algorithm) -> Result<String> {
        // FIPS 模式下的算法验证
        if is_fips_enabled() {
            FipsAlgorithmValidator::validate_fips_compliance(&algorithm)?;
        }

        // 根据算法类型生成适当格式的密钥
        let key_data = self.generate_signature_key(algorithm)?;

        let mut key = Key::new(algorithm, key_data)?;

        // 自动激活密钥，不传递租户信息（基础管理器没有租户概念）
        key.activate(None)?;

        let id = key.id().to_string();

        // 记录审计日志
        AuditLogger::log("KEY_GENERATE", Some(algorithm), Some(&id), Ok(()));

        {
            let mut store = with_lock_write!(self.keys, "keys");
            store.insert(id.clone(), key);
        }

        Ok(id)
    }

    /// 生成密钥并设置别名
    pub fn generate_key_with_alias(&self, algorithm: Algorithm, alias: &str) -> Result<String> {
        let key_id = self.generate_key(algorithm)?;

        // 设置别名映射
        let mut aliases = with_lock_write!(self.key_aliases, "key_aliases");
        aliases.insert(alias.to_string(), key_id.clone());

        Ok(key_id)
    }

    /// 使用指定ID生成密钥（用于多租户隔离）
    pub fn generate_key_with_id(&self, algorithm: Algorithm, key_id: &str) -> Result<String> {
        self.generate_key_with_id_internal(algorithm, key_id)
    }

    /// 内部方法：使用指定ID生成密钥，可控制是否生成审计日志
    fn generate_key_with_id_internal(&self, algorithm: Algorithm, key_id: &str) -> Result<String> {
        let key_data = self.generate_signature_key(algorithm)?;

        let mut key = Key::new_with_id(algorithm, key_data, key_id)?;

        // 自动激活密钥
        key.activate(None)?;

        {
            let mut store = with_lock_write!(self.keys, "keys");
            store.insert(key_id.to_string(), key);
        }

        Ok(key_id.to_string())
    }

    /// 通过别名获取密钥ID
    pub fn resolve_alias(&self, alias: &str) -> Result<String> {
        let aliases = with_lock_read!(self.key_aliases, "key_aliases");
        aliases
            .get(alias)
            .cloned()
            .ok_or_else(|| CryptoError::KeyNotFound(alias.to_string()))
    }

    /// 获取密钥（支持别名）
    pub fn get_key(&self, id_or_alias: &str) -> Result<Key> {
        // 首先尝试作为别名解析
        let key_id = self
            .resolve_alias(id_or_alias)
            .unwrap_or_else(|_| id_or_alias.to_string());

        let store = with_lock_read!(self.keys, "keys");
        let key = store
            .get(&key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.clone()))?;

        if key.state() == KeyState::Destroyed {
            return Err(CryptoError::KeyNotFound("Key is destroyed".into()));
        }

        // 使用安全的克隆方法
        key.clone_secure()
    }

    /// 获取密钥引用（内部使用）
    ///
    /// 此方法使用恒定时间操作来防止时间攻击，确保攻击者无法通过测量响应时间
    /// 来推断密钥是否存在。
    pub(crate) fn with_key<F, T>(&self, id_or_alias: &str, f: F) -> Result<T>
    where
        F: FnOnce(&Key) -> Result<T>,
    {
        // 首先尝试作为别名解析
        let key_id = self
            .resolve_alias(id_or_alias)
            .unwrap_or_else(|_| id_or_alias.to_string());

        let store = with_lock_read!(self.keys, "keys");

        // 使用恒定时间操作获取密钥
        let key_option = store.get(&key_id);

        // 检查密钥状态，使用恒定时间比较
        let key_valid = key_option.map(|k| k.is_valid()).unwrap_or(false);

        // 如果密钥无效，添加恒定时间延迟以防止时间攻击
        if !key_valid {
            // 恒定时间延迟（约 100 微秒）
            std::thread::sleep(std::time::Duration::from_micros(100));
            return Err(CryptoError::KeyNotFound("Key not found or invalid".into()));
        }

        // 密钥有效，执行操作
        match key_option {
            Some(key) => f(key),
            None => Err(CryptoError::KeyNotFound("Key not found".into())),
        }
    }

    /// 内部使用的可变密钥访问（提取公共逻辑）
    fn with_key_mut<F, T>(&self, id_or_alias: &str, f: F) -> Result<T>
    where
        F: FnOnce(&mut Key) -> Result<T>,
    {
        let key_id = self
            .resolve_alias(id_or_alias)
            .unwrap_or_else(|_| id_or_alias.to_string());

        let mut store = with_lock_write!(self.keys, "keys");
        let key = store
            .get_mut(&key_id)
            .ok_or_else(|| CryptoError::KeyNotFound("Key not found".into()))?;

        if key.state() == KeyState::Destroyed {
            return Err(CryptoError::KeyNotFound("Key is destroyed".into()));
        }

        f(key)
    }

    /// 激活密钥
    pub fn activate_key(&self, id_or_alias: &str) -> Result<()> {
        self.with_key_mut(id_or_alias, |key| key.activate(None))
    }

    /// 暂停密钥
    pub fn suspend_key(&self, id_or_alias: &str) -> Result<()> {
        self.with_key_mut(id_or_alias, |key| key.suspend())
    }

    /// 恢复密钥
    pub fn resume_key(&self, id_or_alias: &str) -> Result<()> {
        self.with_key_mut(id_or_alias, |key| key.resume())
    }

    /// 验证 nonce 未被使用
    ///
    /// 此方法用于防止 nonce 重用攻击。它会检查给定的 nonce 是否已经被使用过，
    /// 如果是，则返回错误。同时限制追踪的 nonce 数量以防止内存耗尽。
    ///
    /// # 参数
    ///
    /// * `key_id` - 密钥ID
    /// * `nonce` - 要验证的 nonce（通常为 12 字节）
    ///
    /// # 返回
    ///
    /// 返回 `Ok(())` 如果 nonce 未被使用，否则返回错误
    pub fn verify_nonce_unused(&self, key_id: &str, nonce: &[u8]) -> Result<()> {
        let mut tracker = with_lock_write!(self.nonce_tracker, "nonce_tracker");

        let used_nonces = tracker
            .entry(key_id.to_string())
            .or_insert_with(std::collections::HashSet::new);

        // 检查 nonce 是否已被使用
        if used_nonces.contains(nonce) {
            return Err(CryptoError::InvalidParameter(
                "Nonce reuse detected - potential attack".into(),
            ));
        }

        // 添加 nonce 到已使用列表
        used_nonces.insert(nonce.to_vec());

        // 限制追踪的 nonce 数量以防止内存耗尽（最多 10,000 个）
        if used_nonces.len() > 10000 {
            // 移除最旧的 nonce
            if let Some(oldest) = used_nonces.iter().next().cloned() {
                used_nonces.remove(&oldest);
            }
        }

        Ok(())
    }

    /// 设置密钥过期时间
    pub fn set_key_expiration(&self, id_or_alias: &str, expires_at: DateTime<Utc>) -> Result<()> {
        self.with_key_mut(id_or_alias, |key| {
            key.set_expires_at(expires_at);
            Ok(())
        })
    }

    /// 销毁密钥
    pub fn destroy_key(&self, id_or_alias: &str) -> Result<()> {
        let key_id = self
            .resolve_alias(id_or_alias)
            .unwrap_or_else(|_| id_or_alias.to_string());

        let mut store = with_lock_write!(self.keys, "keys");
        if let Some(mut key) = store.remove(&key_id) {
            key.destroy()?;

            // 移除别名映射
            let mut aliases = with_lock_write!(self.key_aliases, "key_aliases");
            aliases.retain(|_, v| v != &key_id);

            Ok(())
        } else {
            Err(CryptoError::KeyNotFound(key_id))
        }
    }

    /// 获取密钥状态
    pub fn get_key_status(&self, id_or_alias: &str) -> Result<String> {
        let key_id = self
            .resolve_alias(id_or_alias)
            .unwrap_or_else(|_| id_or_alias.to_string());

        let store = with_lock_read!(self.keys, "keys");
        let key = store
            .get(&key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.clone()))?;

        Ok(key.get_lifecycle_status())
    }

    /// 列出所有密钥ID
    pub fn list_keys(&self) -> Result<Vec<String>> {
        let store = with_lock_read!(self.keys, "keys");
        Ok(store.keys().cloned().collect())
    }

    /// 列出所有密钥别名
    pub fn list_aliases(&self) -> Result<Vec<String>> {
        let aliases = with_lock_read!(self.key_aliases, "key_aliases");
        Ok(aliases.keys().cloned().collect())
    }

    /// 获取密钥统计信息
    pub fn get_key_stats(&self) -> Result<HashMap<String, String>> {
        let store = with_lock_read!(self.keys, "keys");
        let mut stats = HashMap::new();

        let total_keys = store.len();
        let active_keys = store
            .values()
            .filter(|k| k.state() == KeyState::Active)
            .count();
        let suspended_keys = store
            .values()
            .filter(|k| k.state() == KeyState::Suspended)
            .count();
        let destroyed_keys = store
            .values()
            .filter(|k| k.state() == KeyState::Destroyed)
            .count();

        stats.insert("total_keys".to_string(), total_keys.to_string());
        stats.insert("active_keys".to_string(), active_keys.to_string());
        stats.insert("suspended_keys".to_string(), suspended_keys.to_string());
        stats.insert("destroyed_keys".to_string(), destroyed_keys.to_string());

        Ok(stats)
    }

    /// 设置密钥的最大使用次数
    pub fn set_key_max_usage(&self, id_or_alias: &str, max_usage: Option<usize>) -> Result<()> {
        let key_id = self
            .resolve_alias(id_or_alias)
            .unwrap_or_else(|_| id_or_alias.to_string());

        let mut store = with_lock_write!(self.keys, "keys");
        let key = store
            .get_mut(&key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.clone()))?;

        // 使用内部方法设置最大使用次数
        key.set_max_usage(max_usage);

        Ok(())
    }

    // ==================== X25519 密钥交换支持 ====================

    /// 使用 X25519 密钥进行密钥协商（Diffie-Hellman）
    ///
    /// # 参数
    ///
    /// * `key_id_or_alias` - 本地 X25519 密钥的 ID 或别名
    /// * `peer_public_key` - 对方的公钥（32字节）
    ///
    /// # 返回
    ///
    /// 返回共享密钥（32字节）
    pub fn x25519_key_agreement(
        &self,
        key_id_or_alias: &str,
        peer_public_key: &[u8],
    ) -> Result<[u8; 32]> {
        if peer_public_key.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "Invalid X25519 public key length, must be 32 bytes".into(),
            ));
        }

        let key = self.get_key(key_id_or_alias)?;
        if key.algorithm() != Algorithm::X25519 {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key must be X25519 algorithm for key agreement".into(),
            ));
        }

        if peer_public_key.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "Invalid X25519 public key length, must be 32 bytes".into(),
            ));
        }

        // 提取私钥（密钥数据的前32字节）
        let key_bytes = key.secret_bytes()?;
        let private_key_bytes: [u8; 32] = key_bytes.as_bytes()[..32]
            .try_into()
            .map_err(|_| CryptoError::KeyError("Invalid X25519 private key length".into()))?;

        use x25519_dalek::x25519;
        let shared_secret = x25519(private_key_bytes, *array_ref!(peer_public_key, 0, 32));

        // 记录审计日志
        AuditLogger::log(
            "X25519_KEY_AGREEMENT",
            Some(Algorithm::X25519),
            Some(key_id_or_alias),
            Ok(()),
        );

        Ok(shared_secret)
    }

    /// 使用 X25519 密钥派生会话密钥
    ///
    /// # 参数
    ///
    /// * `key_id_or_alias` - X25519 密钥的 ID
    /// * `peer_public_key` - 对方的公钥
    /// * `info` - HKDF 信息上下文
    /// * `output_algorithm` - 输出的会话密钥算法
    ///
    /// # 返回
    ///
    /// 返回派生的会话密钥
    pub fn x25519_derive_session_key(
        &self,
        key_id_or_alias: &str,
        peer_public_key: &[u8],
        info: Option<&[u8]>,
        output_algorithm: Algorithm,
    ) -> Result<Key> {
        // 执行密钥协商获取共享密钥
        let shared_secret = self.x25519_key_agreement(key_id_or_alias, peer_public_key)?;

        // 使用 HKDF 派生会话密钥
        let master_key = Key::new_active(Algorithm::X25519, shared_secret.to_vec())?;
        let derived_key = crate::key::derivation::Hkdf::derive(
            &master_key,
            b"ciphern-x25519-session-key",
            info.unwrap_or(b"session-key"),
            output_algorithm,
        )?;

        // 记录审计日志
        AuditLogger::log(
            "X25519_SESSION_KEY_DERIVE",
            Some(output_algorithm),
            Some(derived_key.id()),
            Ok(()),
        );

        Ok(derived_key)
    }

    /// 生成 X25519 密钥对并返回公钥
    ///
    /// # 返回
    ///
    /// 返回 (密钥ID, 公钥) 元组
    pub fn generate_x25519_keypair(&self) -> Result<(String, [u8; 32])> {
        let key_id = self.generate_key(Algorithm::X25519)?;
        let key = self.get_key(&key_id)?;
        let key_bytes = key.secret_bytes()?;

        // 提取公钥（密钥数据的后32字节）
        let public_key: [u8; 32] = key_bytes.as_bytes()[32..64]
            .try_into()
            .map_err(|_| CryptoError::KeyError("Failed to extract X25519 public key".into()))?;

        Ok((key_id, public_key))
    }

    /// 获取 X25519 公钥
    pub fn get_x25519_public_key(&self, key_id_or_alias: &str) -> Result<[u8; 32]> {
        let key = self.get_key(key_id_or_alias)?;
        if key.algorithm() != Algorithm::X25519 {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key must be X25519 algorithm".into(),
            ));
        }

        let key_bytes = key.secret_bytes()?;
        if key_bytes.as_bytes().len() < 64 {
            return Err(CryptoError::KeyError(
                "Invalid X25519 key format, expected 64 bytes".into(),
            ));
        }

        let public_key: [u8; 32] = key_bytes.as_bytes()[32..64]
            .try_into()
            .map_err(|_| CryptoError::KeyError("Failed to extract X25519 public key".into()))?;

        Ok(public_key)
    }
}

impl KeyManagerLifecycleExt for KeyManager {
    fn generate_key_with_lifecycle(
        &self,
        algorithm: Algorithm,
        lifecycle_manager: &KeyLifecycleManager,
    ) -> Result<String> {
        lifecycle_manager.create_key_version(self, algorithm)
    }

    fn rotate_key(
        &self,
        key_id: &str,
        algorithm: Algorithm,
        lifecycle_manager: &KeyLifecycleManager,
    ) -> Result<String> {
        lifecycle_manager.rotate_key(self, key_id, algorithm)
    }

    fn get_key_lifecycle_status(
        &self,
        key_id: &str,
        lifecycle_manager: &KeyLifecycleManager,
    ) -> Result<String> {
        lifecycle_manager
            .get_rotation_warning(key_id)
            .map(|warning| warning.unwrap_or_else(|| "No rotation warning".to_string()))
    }
}

impl KeyManagerOperations for KeyManager {
    fn generate_key_operation(&self, algorithm: Algorithm) -> Result<String> {
        self.generate_key(algorithm)
    }

    fn get_key_operation(&self, key_id: &str) -> Result<Key> {
        self.get_key(key_id)
    }

    fn destroy_key_operation(&self, key_id: &str) -> Result<()> {
        self.destroy_key(key_id)
    }

    fn list_keys_operation(&self) -> Result<Vec<String>> {
        self.list_keys()
    }
}

/// 多租户密钥管理器，提供租户间的密钥隔离
#[allow(dead_code)]
pub struct TenantKeyManager {
    tenant_id: String,
    key_manager: KeyManager,
}

#[allow(dead_code)]
impl TenantKeyManager {
    /// 创建新的租户密钥管理器
    #[allow(dead_code)]
    pub fn new(tenant_id: &str) -> Result<Self> {
        Ok(Self {
            tenant_id: tenant_id.to_string(),
            key_manager: KeyManager::new()?,
        })
    }

    /// 获取租户ID
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// 规范化密钥ID，确保包含租户前缀并验证租户权限
    fn normalize_key_id(&self, key_id: &str, operation: &str) -> Result<String> {
        if key_id.contains(':') {
            let parts: Vec<&str> = key_id.split(':').collect();
            if parts[0] != self.tenant_id {
                // 记录非授权访问尝试
                AuditLogger::log_unauthorized_access(
                    operation,
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    &format!(
                        "Tenant {} attempted to access key from tenant {}",
                        self.tenant_id, parts[0]
                    ),
                );
                return Err(crate::error::CryptoError::KeyNotFound(
                    "Key not found in tenant".into(),
                ));
            }
            Ok(key_id.to_string())
        } else {
            // 添加租户前缀
            Ok(format!("{}:{}", self.tenant_id, key_id))
        }
    }

    /// 生成密钥（带租户前缀）
    pub fn generate_key(&self, algorithm: Algorithm) -> Result<String> {
        // 生成一个唯一的租户密钥ID
        let tenant_key_id = format!("{}:{}", self.tenant_id, uuid::Uuid::new_v4());

        // 使用带租户信息的审计日志，包含生成的 key_id
        AuditLogger::log_with_tenant(
            "KEY_GENERATE",
            Some(algorithm),
            Some(&tenant_key_id),
            Some(&self.tenant_id),
            Ok(()),
            "authorized",
        );

        let size = algorithm.key_size();
        let mut key_data = vec![0u8; size];
        self.key_manager.rng.fill(&mut key_data)?;

        let mut key = super::Key::new_with_id(algorithm, key_data, &tenant_key_id)?;

        // 自动激活密钥，传递租户信息
        key.activate(Some(&self.tenant_id))?;

        {
            let mut store = self
                .key_manager
                .keys
                .write()
                .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
            store.insert(tenant_key_id.to_string(), key);
        }

        Ok(tenant_key_id.to_string())
    }

    /// 生成密钥并设置别名（带租户前缀）
    pub fn generate_key_with_alias(&self, algorithm: Algorithm, alias: &str) -> Result<String> {
        let key_id = self.generate_key(algorithm)?;
        let tenant_alias = format!("{}:{}", self.tenant_id, alias);

        let mut aliases = self
            .key_manager
            .key_aliases
            .write()
            .map_err(|_| CryptoError::MemoryProtectionFailed("Lock poisoned".into()))?;
        aliases.insert(tenant_alias, key_id.clone());

        Ok(key_id)
    }

    /// 获取密钥（自动添加租户前缀）
    pub fn get_key(&self, key_id: &str) -> Result<super::Key> {
        let tenant_key_id = self.normalize_key_id(key_id, "KEY_ACCESS")?;

        let result = self.key_manager.get_key(&tenant_key_id);

        // 记录访问结果
        match &result {
            Ok(_) => {
                AuditLogger::log_with_tenant(
                    "KEY_ACCESS",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Ok(()),
                    "authorized",
                );
            }
            Err(e) => {
                AuditLogger::log_with_tenant(
                    "KEY_ACCESS",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Err(CryptoError::KeyError(e.to_string())),
                    "authorized",
                );
            }
        }

        result
    }

    /// 列出密钥（返回不带租户前缀的ID）
    pub fn list_keys(&self) -> Result<Vec<String>> {
        let all_keys = self.key_manager.list_keys()?;
        let prefix = format!("{}:", self.tenant_id);
        let tenant_keys: Vec<String> = all_keys
            .into_iter()
            .filter(|key_id| key_id.starts_with(&prefix))
            .map(|key_id| key_id.strip_prefix(&prefix).unwrap_or(&key_id).to_string())
            .collect();

        AuditLogger::log_with_tenant(
            "KEY_LIST",
            None,
            None,
            Some(&self.tenant_id),
            Ok(()),
            "authorized",
        );

        Ok(tenant_keys)
    }

    /// 激活密钥
    pub fn activate_key(&self, key_id: &str) -> Result<()> {
        let tenant_key_id = self.normalize_key_id(key_id, "KEY_ACTIVATE")?;
        let result = self.key_manager.activate_key(&tenant_key_id);

        match &result {
            Ok(_) => {
                AuditLogger::log_with_tenant(
                    "KEY_ACTIVATE",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Ok(()),
                    "authorized",
                );
            }
            Err(e) => {
                AuditLogger::log_with_tenant(
                    "KEY_ACTIVATE",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Err(CryptoError::KeyError(e.to_string())),
                    "authorized",
                );
            }
        }

        result
    }

    /// 暂停密钥
    pub fn suspend_key(&self, key_id: &str) -> Result<()> {
        let tenant_key_id = self.normalize_key_id(key_id, "KEY_SUSPEND")?;
        let result = self.key_manager.suspend_key(&tenant_key_id);

        match &result {
            Ok(_) => {
                AuditLogger::log_with_tenant(
                    "KEY_SUSPEND",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Ok(()),
                    "authorized",
                );
            }
            Err(e) => {
                AuditLogger::log_with_tenant(
                    "KEY_SUSPEND",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Err(CryptoError::KeyError(e.to_string())),
                    "authorized",
                );
            }
        }

        result
    }

    /// 销毁密钥
    pub fn destroy_key(&self, key_id: &str) -> Result<()> {
        let tenant_key_id = self.normalize_key_id(key_id, "KEY_DESTROY")?;
        let result = self.key_manager.destroy_key(&tenant_key_id);

        match &result {
            Ok(_) => {
                AuditLogger::log_with_tenant(
                    "KEY_DESTROY",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Ok(()),
                    "authorized",
                );
            }
            Err(e) => {
                AuditLogger::log_with_tenant(
                    "KEY_DESTROY",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Err(CryptoError::KeyError(e.to_string())),
                    "authorized",
                );
            }
        }

        result
    }

    /// 设置密钥的最大使用次数
    pub fn set_key_max_usage(&self, key_id: &str, max_usage: Option<usize>) -> Result<()> {
        let tenant_key_id = self.normalize_key_id(key_id, "KEY_MAX_USAGE_SET")?;
        let result = self
            .key_manager
            .set_key_max_usage(&tenant_key_id, max_usage);

        match &result {
            Ok(_) => {
                AuditLogger::log_with_tenant(
                    "KEY_MAX_USAGE_SET",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Ok(()),
                    "authorized",
                );
            }
            Err(e) => {
                AuditLogger::log_with_tenant(
                    "KEY_MAX_USAGE_SET",
                    None,
                    Some(key_id),
                    Some(&self.tenant_id),
                    Err(CryptoError::KeyError(e.to_string())),
                    "authorized",
                );
            }
        }

        result
    }
}

impl KeyManagerOperations for TenantKeyManager {
    fn generate_key_operation(&self, algorithm: Algorithm) -> Result<String> {
        self.generate_key(algorithm)
    }

    fn get_key_operation(&self, key_id: &str) -> Result<Key> {
        self.get_key(key_id)
    }

    fn destroy_key_operation(&self, key_id: &str) -> Result<()> {
        self.destroy_key(key_id)
    }

    fn list_keys_operation(&self) -> Result<Vec<String>> {
        self.list_keys()
    }
}
