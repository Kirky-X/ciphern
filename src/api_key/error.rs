//! API Key 错误类型定义
//!
//! 定义 API Key 生成、校验、轮换过程中可能出现的错误类型。

use thiserror::Error;
use chrono::DateTime;
use chrono::Utc;

/// 校验错误
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("API Key not found")]
    KeyNotFound,

    #[error("API Key expired at {expired_at}")]
    KeyExpired { expired_at: DateTime<Utc> },

    #[error("API Key has been revoked")]
    KeyRevoked,

    #[error("Invalid checksum")]
    InvalidChecksum,

    #[error("Permission denied: required {required}, available {available:?}")]
    PermissionDenied {
        required: String,
        available: Vec<String>,
    },

    #[error("Rate limit exceeded, blocked until {blocked_until}")]
    RateLimitExceeded { blocked_until: DateTime<Utc> },

    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),

    #[error("Cache error: {0}")]
    CacheError(String),
}

/// 生成错误
#[derive(Debug, Error)]
pub enum GenerationError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),

    #[error("Duplicate key hash detected")]
    DuplicateKey,

    #[error("Invalid permissions: {0}")]
    InvalidPermissions(String),

    #[error("Invalid prefix: {0}")]
    InvalidPrefix(String),

    #[error("JWT signing failed: {0}")]
    JwtSigningFailed(String),

    #[error("Random generation failed: {0}")]
    RandomGenerationFailed(String),
}

/// 轮换错误
#[derive(Debug, Error)]
pub enum RotationError {
    #[error("API Key not found")]
    KeyNotFound,

    #[error("API Key has already been rotated")]
    KeyAlreadyRotated,

    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),

    #[error("Rotation failed: {0}")]
    RotationFailed(String),
}

/// 缓存错误
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Failed to get from cache: {0}")]
    GetError(String),

    #[error("Failed to set cache: {0}")]
    SetError(String),

    #[error("Cache entry not found")]
    NotFound,
}

/// 通知错误
#[derive(Debug, Error)]
pub enum NotificationError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),

    #[error("Webhook notification failed: {0}")]
    WebhookFailed(String),

    #[error("Email notification failed: {0}")]
    EmailFailed(String),

    #[error("Invalid webhook URL: {0}")]
    InvalidWebhookUrl(String),
}

/// 后台任务错误
#[derive(Debug, Error)]
pub enum BackgroundTaskError {
    #[error("Task execution failed: {0}")]
    TaskFailed(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),
}

/// 权限错误
#[derive(Debug, Error)]
pub enum PermissionError {
    #[error("Invalid permission format: {0}")]
    InvalidFormat(String),

    #[error("Invalid action: {0}")]
    InvalidAction(String),

    #[error("Empty permission list")]
    EmptyPermissionList,
}

/// 结果类型别名
pub type ValidationResult<T> = Result<T, ValidationError>;
pub type GenerationResult<T> = Result<T, GenerationError>;
pub type RotationResult<T> = Result<T, RotationError>;
pub type CacheResult<T> = Result<T, CacheError>;
