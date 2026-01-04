//! Sea-ORM 实体模块
//!
//! 导出所有 API Key 相关的数据库实体。

pub mod api_key;
pub mod expiry_notification;
pub mod key_rotation;
pub mod rate_limit_block;
pub mod validation_failure;

pub use api_key::{Entity as ApiKeyEntity, Model as ApiKeyModel};
pub use expiry_notification::{
    Entity as ExpiryNotificationEntity, Model as ExpiryNotificationModel,
};
pub use key_rotation::{Entity as KeyRotationEntity, Model as KeyRotationModel};
pub use rate_limit_block::{Entity as RateLimitBlockEntity, Model as RateLimitBlockModel};
pub use validation_failure::{Entity as ValidationFailureEntity, Model as ValidationFailureModel};
