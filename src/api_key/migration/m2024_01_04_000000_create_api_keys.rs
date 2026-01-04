//! 创建 API Key 相关表的迁移脚本
//!
//! 此迁移脚本创建以下表：
//! - api_keys: API Key 主表
//! - key_rotations: 密钥轮换记录表
//! - validation_failures: 校验失败记录表
//! - rate_limit_blocks: 限流封禁记录表
//! - key_expiry_notifications: 过期通知记录表

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 创建 api_keys 表
        manager
            .create_table(
                Table::create()
                    .table(ApiKeys::Table)
                    .if_not_exists()
                    .col(pk_auto(ApiKeys::Id))
                    .col(string(ApiKeys::KeyHash).unique_key().not_null())
                    .col(string(ApiKeys::Prefix).not_null())
                    .col(string(ApiKeys::KeyType).not_null())
                    .col(json(ApiKeys::Permissions).not_null())
                    .col(timestamp_with_time_zone(ApiKeys::CreatedAt).not_null())
                    .col(timestamp_with_time_zone(ApiKeys::ExpiresAt).not_null())
                    .col(timestamp_with_time_zone(ApiKeys::LastUsedAt))
                    .col(boolean(ApiKeys::IsRevoked).not_null().default(false))
                    .col(integer(ApiKeys::RotationFrom))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_api_keys_rotation_from")
                            .from(ApiKeys::Table, ApiKeys::RotationFrom)
                            .to(ApiKeys::Table, ApiKeys::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // 创建索引
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_key_hash")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::KeyHash)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_prefix")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::Prefix)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_expiry")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::ExpiresAt)
                    .col(ApiKeys::IsRevoked)
                    .to_owned(),
            )
            .await?;

        // 创建 key_rotations 表
        manager
            .create_table(
                Table::create()
                    .table(KeyRotations::Table)
                    .if_not_exists()
                    .col(pk_auto(KeyRotations::Id))
                    .col(integer(KeyRotations::OldKeyId).not_null())
                    .col(integer(KeyRotations::NewKeyId).not_null())
                    .col(timestamp_with_time_zone(KeyRotations::RotatedAt).not_null())
                    .col(text(KeyRotations::Reason))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_key_rotations_old_key")
                            .from(KeyRotations::Table, KeyRotations::OldKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_key_rotations_new_key")
                            .from(KeyRotations::Table, KeyRotations::NewKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_key_rotations_old_key")
                    .table(KeyRotations::Table)
                    .col(KeyRotations::OldKeyId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_key_rotations_new_key")
                    .table(KeyRotations::Table)
                    .col(KeyRotations::NewKeyId)
                    .to_owned(),
            )
            .await?;

        // 创建 validation_failures 表
        manager
            .create_table(
                Table::create()
                    .table(ValidationFailures::Table)
                    .if_not_exists()
                    .col(pk_auto(ValidationFailures::Id))
                    .col(string(ValidationFailures::KeyHash).not_null())
                    .col(timestamp_with_time_zone(ValidationFailures::FailedAt).not_null())
                    .col(string(ValidationFailures::FailureReason).not_null())
                    .col(string(ValidationFailures::IpAddress))
                    .col(text(ValidationFailures::UserAgent))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_validation_failures_key_hash")
                    .table(ValidationFailures::Table)
                    .col(ValidationFailures::KeyHash)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_validation_failures_failed_at")
                    .table(ValidationFailures::Table)
                    .col(ValidationFailures::FailedAt)
                    .to_owned(),
            )
            .await?;

        // 创建 rate_limit_blocks 表
        manager
            .create_table(
                Table::create()
                    .table(RateLimitBlocks::Table)
                    .if_not_exists()
                    .col(string(RateLimitBlocks::KeyHash).primary_key())
                    .col(timestamp_with_time_zone(RateLimitBlocks::BlockedUntil).not_null())
                    .col(text(RateLimitBlocks::BlockReason).not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_rate_limit_blocks_blocked_until")
                    .table(RateLimitBlocks::Table)
                    .col(RateLimitBlocks::BlockedUntil)
                    .to_owned(),
            )
            .await?;

        // 创建 key_expiry_notifications 表
        manager
            .create_table(
                Table::create()
                    .table(KeyExpiryNotifications::Table)
                    .if_not_exists()
                    .col(pk_auto(KeyExpiryNotifications::Id))
                    .col(integer(KeyExpiryNotifications::KeyId).not_null())
                    .col(timestamp_with_time_zone(KeyExpiryNotifications::NotifyAt).not_null())
                    .col(integer(KeyExpiryNotifications::DaysUntilExpiry).not_null())
                    .col(
                        boolean(KeyExpiryNotifications::NotificationSent)
                            .not_null()
                            .default(false),
                    )
                    .col(string(KeyExpiryNotifications::NotificationMethod).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_key_expiry_notifications_key")
                            .from(KeyExpiryNotifications::Table, KeyExpiryNotifications::KeyId)
                            .to(ApiKeys::Table, ApiKeys::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_key_expiry_notifications_pending")
                    .table(KeyExpiryNotifications::Table)
                    .col(KeyExpiryNotifications::NotificationSent)
                    .col(KeyExpiryNotifications::NotifyAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除表（按依赖顺序）
        manager
            .drop_table(
                Table::drop()
                    .table(KeyExpiryNotifications::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(RateLimitBlocks::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ValidationFailures::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(KeyRotations::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ApiKeys::Table).to_owned())
            .await?;

        Ok(())
    }
}

/// api_keys 表结构
#[derive(Iden)]
enum ApiKeys {
    Table,
    Id,
    KeyHash,
    Prefix,
    KeyType,
    Permissions,
    CreatedAt,
    ExpiresAt,
    LastUsedAt,
    IsRevoked,
    RotationFrom,
}

/// key_rotations 表结构
#[derive(Iden)]
enum KeyRotations {
    Table,
    Id,
    OldKeyId,
    NewKeyId,
    RotatedAt,
    Reason,
}

/// validation_failures 表结构
#[derive(Iden)]
enum ValidationFailures {
    Table,
    Id,
    KeyHash,
    FailedAt,
    FailureReason,
    IpAddress,
    UserAgent,
}

/// rate_limit_blocks 表结构
#[derive(Iden)]
enum RateLimitBlocks {
    Table,
    KeyHash,
    BlockedUntil,
    BlockReason,
}

/// key_expiry_notifications 表结构
#[derive(Iden)]
enum KeyExpiryNotifications {
    Table,
    Id,
    KeyId,
    NotifyAt,
    DaysUntilExpiry,
    NotificationSent,
    NotificationMethod,
}
