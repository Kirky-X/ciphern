//! 密钥轮换记录实体
//!
//! 定义 key_rotations 表的 Sea-ORM 实体模型。

use sea_orm::entity::prelude::*;

/// 密钥轮换记录实体模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "key_rotations")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 旧密钥 ID
    pub old_key_id: i64,
    /// 新密钥 ID
    pub new_key_id: i64,
    /// 轮换时间
    pub rotated_at: DateTimeUtc,
    /// 轮换原因
    pub reason: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// 关联到 api_keys 表（旧 key）
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::OldKeyId",
        to = "super::api_key::Column::Id"
    )]
    OldKey,
    /// 关联到 api_keys 表（新 key）
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::NewKeyId",
        to = "super::api_key::Column::Id"
    )]
    NewKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::OldKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}