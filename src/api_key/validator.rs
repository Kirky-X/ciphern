//! API Key 校验器
//!
//! 实现 API Key 的校验逻辑，包括格式验证、哈希验证、权限检查、过期检查等。

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
};

use crate::api_key::cache::Cache;
use crate::api_key::entities::{api_key, rate_limit_block, validation_failure};
use crate::api_key::error::ValidationError;
use crate::api_key::permission::PermissionMatcher;
use crate::api_key::types::{Permission, ValidationResult};
use chrono::{DateTime, FixedOffset, Utc};

/// API Key 校验器
pub struct ApiKeyValidator {
    db: DatabaseConnection,
    cache: Cache,
    permission_matcher: PermissionMatcher,
    /// 失败阈值（默认 5 次）
    failure_threshold: u32,
    /// 失败时间窗口（默认 600 秒 = 10 分钟）
    failure_window_secs: u64,
    /// 封禁时长（默认 3600 秒 = 1 小时）
    block_duration_secs: u64,
}

impl ApiKeyValidator {
    /// 创建新的校验器实例
    pub fn new(db: DatabaseConnection, cache: Cache) -> Self {
        Self {
            db,
            cache,
            permission_matcher: PermissionMatcher::new(),
            failure_threshold: 5,
            failure_window_secs: 600,
            block_duration_secs: 3600,
        }
    }

    /// 获取当前时间（带时区偏移）
    fn now_with_offset() -> DateTime<FixedOffset> {
        Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap())
    }

    /// 校验 API Key
    ///
    /// # 参数
    /// * `key` - API Key 字符串
    /// * `required_permission` - 需要的权限（格式："users:read"）
    pub async fn validate(
        &self,
        key: &str,
        required_permission: &str,
    ) -> Result<ValidationResult, ValidationError> {
        // 1. 验证格式
        if !self.validate_format(key) {
            return Err(ValidationError::InvalidChecksum);
        }

        // 2. 计算密钥哈希
        let key_hash = self.hash_key(key)?;

        // 3. 检查限流
        self.check_rate_limit(&key_hash).await?;

        // 4. 检查缓存
        if let Some(cached) = self.cache.get(&key_hash).await {
            let available_strings: Vec<String> =
                cached.permissions.iter().map(|p| p.to_string()).collect();
            if !self
                .permission_matcher
                .matches(&available_strings, required_permission)
            {
                self.record_failure(&key_hash, "PermissionDenied", None, None)
                    .await;
                return Err(ValidationError::PermissionDenied {
                    required: required_permission.to_string(),
                    available: available_strings,
                });
            }
            return Ok(cached);
        }

        // 5. 查询数据库
        let key_record = api_key::Entity::find()
            .filter(api_key::Column::KeyHash.eq(key_hash.clone()))
            .one(&self.db)
            .await?
            .ok_or_else(|| {
                std::mem::drop(self.record_failure(&key_hash, "KeyNotFound", None, None));
                ValidationError::KeyNotFound
            })?;

        // 6. 检查是否撤销
        if key_record.is_revoked {
            self.record_failure(&key_hash, "KeyRevoked", None, None)
                .await;
            return Err(ValidationError::KeyRevoked);
        }

        // 7. 检查是否过期
        let expires_at_utc = key_record.expires_at.with_timezone(&Utc);
        if expires_at_utc < Utc::now() {
            self.record_failure(&key_hash, "KeyExpired", None, None)
                .await;
            return Err(ValidationError::KeyExpired {
                expired_at: expires_at_utc,
            });
        }

        // 8. 检查权限
        if !self
            .permission_matcher
            .matches(&key_record.permissions, required_permission)
        {
            self.record_failure(&key_hash, "PermissionDenied", None, None)
                .await;
            return Err(ValidationError::PermissionDenied {
                required: required_permission.to_string(),
                available: key_record.permissions.clone(),
            });
        }

        // 9. 更新最后使用时间
        self.update_last_used(&key_hash).await?;

        // 10. 缓存结果
        let result = ValidationResult {
            key_id: key_record.id,
            permissions: key_record
                .permissions
                .iter()
                .map(|p| {
                    Permission::parse_permission(p).unwrap_or_else(|_| {
                        Permission::new(p.to_string(), crate::api_key::types::Action::Read)
                    })
                })
                .collect(),
            expires_at: expires_at_utc,
            last_used_at: key_record
                .last_used_at
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or(Utc::now()),
        };
        self.cache.set(&key_hash, result.clone()).await;

        Ok(result)
    }

    /// 校验多个权限
    pub async fn validate_multi(
        &self,
        key: &str,
        required_permissions: &[String],
    ) -> Result<ValidationResult, ValidationError> {
        // 校验第一个权限（会检查所有权限）
        if required_permissions.is_empty() {
            return self.validate(key, "").await;
        }

        let result = self.validate(key, &required_permissions[0]).await?;
        let available_str: Vec<String> = result.permissions.iter().map(|p| p.to_string()).collect();

        // 检查是否拥有所有要求的权限
        if !self
            .permission_matcher
            .has_all_permissions(&available_str, required_permissions)
        {
            let missing: Vec<String> = required_permissions
                .iter()
                .filter(|req| !self.permission_matcher.matches(&available_str, req))
                .cloned()
                .collect();

            return Err(ValidationError::PermissionDenied {
                required: format!("{:?}", missing),
                available: available_str,
            });
        }

        Ok(result)
    }

    /// 验证 API Key 格式
    fn validate_format(&self, key: &str) -> bool {
        crate::api_key::generator::ApiKeyGenerator::validate_format(key)
    }

    /// 计算密钥哈希
    fn hash_key(&self, key: &str) -> Result<String, ValidationError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize();
        Ok(hex::encode(hash.as_bytes()))
    }

    /// 检查限流
    async fn check_rate_limit(&self, key_hash: &str) -> Result<(), ValidationError> {
        // 检查是否被封禁
        if let Some(block) = rate_limit_block::Entity::find()
            .filter(rate_limit_block::Column::KeyHash.eq(key_hash.to_string()))
            .one(&self.db)
            .await?
        {
            if block.blocked_until.with_timezone(&Utc) > Utc::now() {
                return Err(ValidationError::RateLimitExceeded {
                    blocked_until: block.blocked_until.with_timezone(&Utc),
                });
            }
        }

        Ok(())
    }

    /// 记录校验失败
    async fn record_failure(
        &self,
        key_hash: &str,
        reason: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) {
        let _ = validation_failure::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            key_hash: sea_orm::ActiveValue::Set(key_hash.to_string()),
            failed_at: sea_orm::ActiveValue::Set(Self::now_with_offset()),
            failure_reason: sea_orm::ActiveValue::Set(reason.to_string()),
            ip_address: sea_orm::ActiveValue::Set(ip_address.map(|s| s.to_string())),
            user_agent: sea_orm::ActiveValue::Set(user_agent.map(|s| s.to_string())),
        }
        .insert(&self.db)
        .await;

        // 检查是否需要封禁
        self.check_and_block(key_hash).await;
    }

    /// 检查并触发封禁
    async fn check_and_block(&self, key_hash: &str) {
        let window_start = Utc::now() - chrono::Duration::seconds(self.failure_window_secs as i64);
        let window_start_with_tz = window_start.with_timezone(&FixedOffset::east_opt(0).unwrap());
        let failure_count: u64 = validation_failure::Entity::find()
            .filter(validation_failure::Column::KeyHash.eq(key_hash))
            .filter(validation_failure::Column::FailedAt.gte(window_start_with_tz))
            .count(&self.db)
            .await
            .unwrap_or(0);

        if failure_count >= self.failure_threshold as u64 {
            let blocked_until =
                Utc::now() + chrono::Duration::seconds(self.block_duration_secs as i64);
            let blocked_until_tz = blocked_until.with_timezone(&FixedOffset::east_opt(0).unwrap());
            let _ = rate_limit_block::ActiveModel {
                key_hash: sea_orm::ActiveValue::Set(key_hash.to_string()),
                blocked_until: sea_orm::ActiveValue::Set(blocked_until_tz),
                block_reason: sea_orm::ActiveValue::Set(format!(
                    "Too many failures: {}",
                    failure_count
                )),
            }
            .insert(&self.db)
            .await;

            // 清除失败记录
            let _ = validation_failure::Entity::delete_many()
                .filter(validation_failure::Column::KeyHash.eq(key_hash))
                .exec(&self.db)
                .await;
        }
    }

    /// 更新最后使用时间
    async fn update_last_used(&self, key_hash: &str) -> Result<(), ValidationError> {
        let key = api_key::Entity::find()
            .filter(api_key::Column::KeyHash.eq(key_hash.to_string()))
            .one(&self.db)
            .await?
            .ok_or(ValidationError::KeyNotFound)?;

        let mut active_key: api_key::ActiveModel = key.into();
        active_key.last_used_at = sea_orm::ActiveValue::Set(Some(Self::now_with_offset()));
        active_key.update(&self.db).await?;

        Ok(())
    }

    /// 使缓存失效
    pub async fn invalidate_cache(&self, key_hash: &str) {
        self.cache.remove(key_hash).await;
    }
}
