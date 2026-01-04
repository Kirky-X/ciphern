//! 限流封禁记录实体
//!
//! 定义 rate_limit_blocks 表的 Sea-ORM 实体模型。

use sea_orm::entity::prelude::*;

/// 限流封禁记录实体模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "rate_limit_blocks")]
pub struct Model {
    /// 密钥哈希（主键）
    #[sea_orm(primary_key)]
    pub key_hash: String,
    /// 解封时间
    pub blocked_until: DateTimeWithTimeZone,
    /// 封禁原因
    pub block_reason: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
