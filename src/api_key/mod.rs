//! API Key 管理模块
//!
//! 提供 API Key 的生成、校验、轮换和管理功能。
//!
//! # 功能特性
//!
//! - **密钥生成**: 支持自定义格式 API Key 和 JWT Token
//! - **权限校验**: 支持细粒度权限控制（精确匹配、通配符匹配）
//! - **密钥轮换**: 支持密钥轮换和宽限期管理
//! - **自动过期**: 90 天自动过期
//! - **限流保护**: 失败计数和自动封禁
//! - **缓存优化**: LRU 缓存提升性能
//! - **过期通知**: 支持 webhook、email、日志通知
//! - **后台任务**: 自动清理过期密钥、解封限流、聚合统计
//!
//! # 使用示例
//!
//! ```ignore
//! use ciphern::api_key::{ApiKeyGenerator, ApiKeyValidator, ApiKeyRotation, PrefixType, Permission, Action};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // 初始化
//!     ciphern::init()?;
//!
//!     // 生成 API Key
//!     let generator = ApiKeyGenerator::new(db_pool).await?;
//!     let key = generator.generate(
//!         PrefixType::SecretKey,
//!         Some(vec![
//!             Permission::new("users".to_string(), Action::Read),
//!             Permission::new("orders".to_string(), Action::Write),
//!         ]),
//!         Some(90),
//!     ).await?;
//!     println!("API Key: {}", key.key);
//!
//!     // 校验 API Key
//!     let validator = ApiKeyValidator::new(db_pool, cache);
//!     let result = validator.validate(&key.key, "orders:write").await?;
//!
//!     // 轮换密钥
//!     let rotation = ApiKeyRotation::new(db_pool, 7);
//!     let rotated = rotation.rotate(&key.key, None, Some("安全轮换".to_string())).await?;
//!
//!     // 启动后台任务
//!     let task_manager = TaskManager::new(db_pool, None);
//!     task_manager.start().await;
//!
//!     Ok(())
//! }
//! ```

// Re-exports
pub use types::{
    ApiKeyType, Action, Permission, PrefixType,
    GeneratedKey, ValidationResult, RotatedKeyPair,
    JwtClaims, FailureReason, NotificationMethod,
};

pub use error::{
    ValidationError, GenerationError, RotationError,
    CacheError, NotificationError, BackgroundTaskError,
    PermissionError, ValidationResult as ApiKeyValidationResult,
};

pub use cache::{Cache, CacheConfig};

pub use entities::{
    ApiKeyEntity, ApiKeyModel,
    KeyRotationEntity, KeyRotationModel,
    ValidationFailureEntity, ValidationFailureModel,
    RateLimitBlockEntity, RateLimitBlockModel,
    ExpiryNotificationEntity, ExpiryNotificationModel,
};

pub use notification::{NotificationManager, NotificationConfig, NotificationSender};
pub use task::{TaskManager, TaskConfig, TaskStats};

// Modules
mod types;
mod error;
mod generator;
mod validator;
mod permission;
mod cache;
mod rotation;
mod notification;
mod task;

pub mod entities;
pub mod migration;

// Re-exports from submodules
pub use generator::ApiKeyGenerator;
pub use validator::ApiKeyValidator;
pub use rotation::ApiKeyRotation;
pub use permission::PermissionMatcher;

/// API Key 管理器配置
#[derive(Debug, Clone)]
pub struct ApiKeyConfig {
    /// 默认过期天数
    pub default_expiry_days: u32,
    /// 宽限期天数
    pub grace_period_days: u32,
    /// 失败阈值
    pub failure_threshold: u32,
    /// 失败时间窗口（秒）
    pub failure_window_secs: u64,
    /// 封禁时长（秒）
    pub block_duration_secs: u64,
    /// 缓存 TTL（秒）
    pub cache_ttl_secs: u64,
    /// 缓存最大条目数
    pub cache_max_entries: u64,
    /// 过期通知天数
    pub expiry_notify_days: Vec<u32>,
    /// JWT Secret
    pub jwt_secret: String,
    /// 数据库连接字符串
    pub database_url: String,
    /// 通知配置
    pub notification_config: NotificationConfig,
    /// 任务配置
    pub task_config: TaskConfig,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            default_expiry_days: 90,
            grace_period_days: 7,
            failure_threshold: 5,
            failure_window_secs: 600,
            block_duration_secs: 3600,
            cache_ttl_secs: 600,
            cache_max_entries: 1000,
            expiry_notify_days: vec![14, 7, 3, 1],
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "default-secret-key-change-in-production".to_string()),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/ciphern".to_string()),
            notification_config: NotificationConfig::default(),
            task_config: TaskConfig::default(),
        }
    }
}