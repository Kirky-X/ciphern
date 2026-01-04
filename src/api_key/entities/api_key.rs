//! API Key 数据库实体
//!
//! 定义 api_keys 表的 Sea-ORM 实体模型。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// API Key 实体模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// Blake3 哈希（唯一索引）
    #[sea_orm(unique)]
    pub key_hash: String,
    /// 前缀 (sk_, pk_, rk_)
    pub prefix: String,
    /// 密钥类型
    pub key_type: String,
    /// 权限列表（JSONB）
    pub permissions: Vec<String>,
    /// 创建时间
    pub created_at: DateTimeWithTimeZone,
    /// 过期时间
    pub expires_at: DateTimeWithTimeZone,
    /// 最后使用时间
    pub last_used_at: Option<DateTimeWithTimeZone>,
    /// 是否撤销
    pub is_revoked: bool,
    /// 轮换来源（旧 key ID）
    pub rotation_from: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// 关联到 key_rotations 表（作为旧 key）
    #[sea_orm(has_many = "super::key_rotation::Entity")]
    OldKeyRotations,
    /// 关联到 key_rotations 表（作为新 key）
    #[sea_orm(has_many = "super::key_rotation::Entity")]
    NewKeyRotations,
    /// 关联到 expiry_notifications 表
    #[sea_orm(has_many = "super::expiry_notification::Entity")]
    ExpiryNotifications,
    /// 关联到自身（轮换来源）
    #[sea_orm(
        belongs_to = "Entity",
        from = "Column::RotationFrom",
        to = "Column::Id"
    )]
    RotatedFrom,
}

impl Related<super::key_rotation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::OldKeyRotations.def()
    }
}

impl Related<super::expiry_notification::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ExpiryNotifications.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// 便捷方法
impl Entity {
    /// 根据 key_hash 查找
    pub async fn find_by_key_hash(db: &DbConn, key_hash: &str) -> Result<Option<Model>, DbErr> {
        Self::find()
            .filter(Column::KeyHash.eq(key_hash))
            .one(db)
            .await
    }

    /// 查找有效的密钥
    pub async fn find_valid_keys(db: &DbConn) -> Result<Vec<Model>, DbErr> {
        let now = chrono::Utc::now();
        Self::find()
            .filter(Column::IsRevoked.eq(false))
            .filter(Column::ExpiresAt.gt(now))
            .all(db)
            .await
    }
}
