//! API Key 类型定义
//!
//! 定义 API Key 相关的核心类型，包括权限、密钥类型、前缀等。

use serde::{Deserialize, Serialize};
use std::fmt;

/// API Key 类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiKeyType {
    /// 自定义格式 API Key
    ApiKey,
    /// JWT 临时 Token
    JwtToken,
}

impl fmt::Display for ApiKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiKeyType::ApiKey => write!(f, "ApiKey"),
            ApiKeyType::JwtToken => write!(f, "JwtToken"),
        }
    }
}

/// 权限动作
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Delete,
    Admin,
}

impl Action {
    /// 获取动作的字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Delete => "delete",
            Action::Admin => "admin",
        }
    }

    /// 从字符串解析动作
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "read" => Some(Action::Read),
            "write" => Some(Action::Write),
            "delete" => Some(Action::Delete),
            "admin" => Some(Action::Admin),
            _ => None,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 结构化权限
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    /// 资源名称（如 "users", "orders", "*"）
    pub resource: String,
    /// 动作类型
    pub action: Action,
}

impl Permission {
    /// 创建新权限
    pub fn new(resource: String, action: Action) -> Self {
        Self { resource, action }
    }

    /// 从字符串解析权限（格式："users:read"）
    pub fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid permission format: {}", s));
        }

        let resource = parts[0].to_string();
        let action = Action::from_str(parts[1])
            .ok_or_else(|| format!("Invalid action: {}", parts[1]))?;

        Ok(Self { resource, action })
    }

    /// 转换为字符串（格式："users:read"）
    pub fn to_string(&self) -> String {
        format!("{}:{}", self.resource, self.action.as_str())
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// 预定义前缀类型
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrefixType {
    /// 服务端 key，权限 *:*
    SecretKey,
    /// 公开 key，权限 users:read, orders:read
    PublicKey,
    /// 受限 key，权限自定义
    RestrictedKey,
    /// 自定义前缀
    Custom(String),
}

impl PrefixType {
    /// 获取前缀字符串
    pub fn as_str(&self) -> &str {
        match self {
            PrefixType::SecretKey => "sk_",
            PrefixType::PublicKey => "pk_",
            PrefixType::RestrictedKey => "rk_",
            PrefixType::Custom(prefix) => prefix.as_str(),
        }
    }

    /// 获取默认权限
    pub fn default_permissions(&self) -> Vec<Permission> {
        match self {
            PrefixType::SecretKey => vec![Permission::new("*".to_string(), Action::Admin)],
            PrefixType::PublicKey => vec![
                Permission::new("users".to_string(), Action::Read),
                Permission::new("orders".to_string(), Action::Read),
            ],
            PrefixType::RestrictedKey => vec![],
            PrefixType::Custom(_) => vec![],
        }
    }
}

impl fmt::Display for PrefixType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 生成的密钥信息
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    /// 密钥 ID（数据库自增 ID）
    pub key_id: i64,
    /// 原始密钥（仅生成时可见）
    pub key: String,
    /// 密钥哈希（存储在数据库）
    pub key_hash: String,
    /// 权限列表
    pub permissions: Vec<Permission>,
    /// 过期时间
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// 密钥类型
    pub key_type: ApiKeyType,
}

/// 校验结果
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// 密钥 ID
    pub key_id: i64,
    /// 权限列表
    pub permissions: Vec<Permission>,
    /// 过期时间
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// 最后使用时间
    pub last_used_at: chrono::DateTime<chrono::Utc>,
}

/// 轮换后的密钥对
#[derive(Debug, Clone)]
pub struct RotatedKeyPair {
    /// 旧密钥 ID
    pub old_key_id: i64,
    /// 新密钥
    pub new_key: GeneratedKey,
    /// 宽限期结束时间
    pub grace_period_ends: chrono::DateTime<chrono::Utc>,
}

/// JWT Claims 结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// 主题（临时 token ID）
    pub sub: String,
    /// 权限列表
    pub permissions: Vec<String>,
    /// 过期时间戳
    pub exp: usize,
    /// 签发时间戳
    pub iat: usize,
}

/// 校验失败原因
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureReason {
    Expired,
    Revoked,
    InvalidHash,
    PermissionDenied,
}

/// 通知方式
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationMethod {
    Log,
    Webhook,
    Email,
}

impl fmt::Display for NotificationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotificationMethod::Log => write!(f, "log"),
            NotificationMethod::Webhook => write!(f, "webhook"),
            NotificationMethod::Email => write!(f, "email"),
        }
    }
}
