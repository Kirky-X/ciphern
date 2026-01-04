//! 校验失败记录实体
//!
//! 定义 validation_failures 表的 Sea-ORM 实体模型。

use sea_orm::entity::prelude::*;

/// 校验失败记录实体模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "validation_failures")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 密钥哈希
    pub key_hash: String,
    /// 失败时间
    pub failed_at: DateTimeWithTimeZone,
    /// 失败原因
    pub failure_reason: String,
    /// 客户端 IP（可选）
    pub ip_address: Option<String>,
    /// User-Agent（可选）
    pub user_agent: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
