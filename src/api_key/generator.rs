//! API Key 生成器
//!
//! 实现 API Key 的生成逻辑，包括自定义格式和 JWT Token。

use sea_orm::{DatabaseConnection, EntityTrait, ActiveValue};

use crate::api_key::error::GenerationError;
use crate::api_key::types::{ApiKeyType, Permission, PrefixType, GeneratedKey, JwtClaims};
use crate::api_key::entities::api_key;
use crate::random::SecureRandom;
use chrono::{Duration, Utc, FixedOffset};

/// API Key 生成器
pub struct ApiKeyGenerator {
    db: DatabaseConnection,
    rng: SecureRandom,
    default_expiry_days: u32,
}

impl ApiKeyGenerator {
    /// 创建新的生成器实例
    pub fn new(db: DatabaseConnection) -> Result<Self, GenerationError> {
        Ok(Self {
            db,
            rng: SecureRandom::new()
                .map_err(|e| GenerationError::RandomGenerationFailed(e.to_string()))?,
            default_expiry_days: 90,
        })
    }

    /// 获取当前时间（带时区偏移）
    fn now_with_offset() -> chrono::DateTime<FixedOffset> {
        Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap())
    }

    /// 生成自定义格式 API Key
    ///
    /// 格式: `{prefix}_{random_32chars}_{checksum_4chars}`
    /// 示例: `sk_7Kj9mNpQ2vXwR8tL4hB6nC3fY5gA1sD0_9aE2`
    ///
    /// # 参数
    /// * `prefix` - 前缀类型
    /// * `permissions` - 权限列表（如果为空，使用前缀默认权限）
    /// * `expires_in_days` - 过期天数（默认90天）
    pub async fn generate(
        &self,
        prefix: PrefixType,
        permissions: Option<Vec<Permission>>,
        expires_in_days: Option<u32>,
    ) -> Result<GeneratedKey, GenerationError> {
        // 1. 确定权限
        let final_permissions = if let Some(perms) = permissions {
            if perms.is_empty() {
                prefix.default_permissions()
            } else {
                perms
            }
        } else {
            prefix.default_permissions()
        };

        // 2. 生成随机部分（32字符）
        let random_part = self.generate_random_part()?;

        // 3. 计算校验和（CRC32）
        let checksum = self.calculate_checksum(prefix.as_str(), &random_part)?;

        // 4. 组合完整密钥
        let key = format!("{}{}_{}", prefix.as_str(), random_part, checksum);

        // 5. 计算哈希（Blake3）
        let key_hash = self.hash_key(&key)?;

        // 6. 计算过期时间
        let expires_at = Utc::now() + Duration::days(expires_in_days.unwrap_or(self.default_expiry_days) as i64);
        let expires_at_with_offset = expires_at.with_timezone(&FixedOffset::east_opt(0).unwrap());

        // 7. 保存到数据库
        let new_key = api_key::ActiveModel {
            id: ActiveValue::NotSet,
            key_hash: ActiveValue::Set(key_hash.clone()),
            prefix: ActiveValue::Set(prefix.as_str().to_string()),
            key_type: ActiveValue::Set("ApiKey".to_string()),
            permissions: ActiveValue::Set(final_permissions.iter().map(|p| p.to_string()).collect()),
            created_at: ActiveValue::Set(Self::now_with_offset()),
            expires_at: ActiveValue::Set(expires_at_with_offset),
            last_used_at: ActiveValue::Set(None),
            is_revoked: ActiveValue::Set(false),
            rotation_from: ActiveValue::Set(None),
        };

        let result = api_key::Entity::insert(new_key)
            .exec(&self.db)
            .await?;

        Ok(GeneratedKey {
            key_id: result.last_insert_id,
            key,
            key_hash,
            permissions: final_permissions,
            expires_at,
            key_type: ApiKeyType::ApiKey,
        })
    }

    /// 生成 JWT Token（临时）
    ///
    /// # 参数
    /// * `permissions` - 权限列表
    /// * `expires_in_secs` - 过期秒数（默认3600秒）
    pub async fn generate_jwt(
        &self,
        permissions: Vec<Permission>,
        expires_in_secs: Option<u64>,
    ) -> Result<String, GenerationError> {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let now = Utc::now();
        let exp_secs = expires_in_secs.unwrap_or(3600);
        let exp = now + Duration::seconds(exp_secs as i64);

        let claims = JwtClaims {
            sub: uuid::Uuid::new_v4().to_string(),
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        let secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "default-secret-key-change-in-production".to_string());

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).map_err(|e| GenerationError::JwtSigningFailed(e.to_string()))?;

        // 保存 JWT Token 到数据库
        let token_hash = self.hash_key(&token)?;
        let expires_at = Utc::now() + Duration::seconds(exp_secs as i64);
        let expires_at_with_offset = expires_at.with_timezone(&FixedOffset::east_opt(0).unwrap());

        let new_key = api_key::ActiveModel {
            id: ActiveValue::NotSet,
            key_hash: ActiveValue::Set(token_hash),
            prefix: ActiveValue::Set("jwt_".to_string()),
            key_type: ActiveValue::Set("JwtToken".to_string()),
            permissions: ActiveValue::Set(permissions.iter().map(|p| p.to_string()).collect()),
            created_at: ActiveValue::Set(Self::now_with_offset()),
            expires_at: ActiveValue::Set(expires_at_with_offset),
            last_used_at: ActiveValue::Set(None),
            is_revoked: ActiveValue::Set(false),
            rotation_from: ActiveValue::Set(None),
        };

        api_key::Entity::insert(new_key)
            .exec(&self.db)
            .await?;

        Ok(token)
    }

    /// 生成随机部分（32字符 base62）
    fn generate_random_part(&self) -> Result<String, GenerationError> {
        let mut bytes = [0u8; 16];
        self.rng.fill(&mut bytes)
            .map_err(|e| GenerationError::RandomGenerationFailed(e.to_string()))?;

        // 转换为 base62
        let num = u128::from_be_bytes(bytes);
        Ok(base62::encode(num))
    }

    /// 计算 CRC32 校验和
    fn calculate_checksum(&self, prefix: &str, random_part: &str) -> Result<String, GenerationError> {
        let data = format!("{}{}", prefix, random_part);
        let checksum = crc32fast::hash(data.as_bytes());
        Ok(format!("{:04x}", checksum))
    }

    /// 计算密钥哈希（Blake3）
    fn hash_key(&self, key: &str) -> Result<String, GenerationError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize();
        Ok(hex::encode(hash.as_bytes()))
    }

    /// 验证 API Key 格式
    pub fn validate_format(key: &str) -> bool {
        // 格式: {prefix}_{random_32chars}_{checksum_4chars}
        let parts: Vec<&str> = key.split('_').collect();
        if parts.len() != 3 {
            return false;
        }

        // 检查前缀
        let prefix = parts[0];
        if !prefix.is_empty() && !prefix.ends_with('_') {
            return false;
        }

        // 检查随机部分（32字符）
        if parts[1].len() != 32 {
            return false;
        }

        // 检查校验和（4字符十六进制）
        if parts[2].len() != 4 {
            return false;
        }

        // 验证校验和
        let expected_checksum = crc32fast::hash(format!("{}{}", prefix, parts[1]).as_bytes());
        let actual_checksum = u32::from_str_radix(parts[2], 16).unwrap_or(0);
        expected_checksum == actual_checksum
    }
}
