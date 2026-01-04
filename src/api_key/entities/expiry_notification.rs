//! 过期通知记录实体
//!
//! 定义 key_expiry_notifications 表的 Sea-ORM 实体模型。

use sea_orm::entity::prelude::*;

/// 过期通知记录实体模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "key_expiry_notifications")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 关联的 API Key ID
    pub key_id: i64,
    /// 通知发送时间
    pub notify_at: DateTimeUtc,
    /// 距离过期的天数
    pub days_until_expiry: i32,
    /// 是否已发送
    pub notification_sent: bool,
    /// 通知方式 (log, webhook, email)
    pub notification_method: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// 关联到 api_keys 表
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::KeyId",
        to = "super::api_key::Column::Id"
    )]
    ApiKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}