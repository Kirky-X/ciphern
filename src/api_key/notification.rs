//!
//! 通知模块
//!
//! 实现 API Key 过期通知，支持日志、webhook 和 email 通知方式。

use chrono::{Duration, Utc};
use sea_orm::{ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Serialize;
use std::fmt::Debug;

use crate::api_key::entities::{api_key, expiry_notification};
use crate::api_key::error::NotificationError;

/// 通知配置
#[derive(Debug, Clone)]
pub struct NotificationConfig {
    /// 通知天数列表
    pub notify_days: Vec<u32>,
    /// Webhook URL
    pub webhook_url: Option<String>,
    /// Webhook 认证令牌
    pub webhook_token: Option<String>,
    /// Email 收件人列表
    pub email_recipients: Vec<String>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            notify_days: vec![14, 7, 3, 1],
            webhook_url: None,
            webhook_token: None,
            email_recipients: Vec::new(),
        }
    }
}

/// 通知发送器
#[derive(Clone)]
pub struct NotificationSender {
    db: DatabaseConnection,
    config: NotificationConfig,
}

impl NotificationSender {
    /// 创建新的通知发送器
    pub fn new(db: DatabaseConnection, config: NotificationConfig) -> Self {
        Self { db, config }
    }

    /// 扫描即将过期的密钥并发送通知
    pub async fn scan_and_notify(&self) -> Result<u64, NotificationError> {
        let mut notified_count = 0u64;

        for days in &self.config.notify_days {
            let target_time = Utc::now() + Duration::days(*days as i64);
            let start_time = Utc::now() + Duration::days((*days + 1) as i64);

            // 查找即将过期的密钥
            let keys_to_notify = api_key::Entity::find()
                .filter(api_key::Column::ExpiresAt.gt(start_time))
                .filter(api_key::Column::ExpiresAt.lte(target_time))
                .filter(api_key::Column::IsRevoked.eq(false))
                .filter(api_key::Column::RotationFrom.is_null())
                .all(&self.db)
                .await?;

            for key_record in keys_to_notify {
                // 检查是否已发送过通知
                let existing_notification = expiry_notification::Entity::find()
                    .filter(expiry_notification::Column::KeyId.eq(key_record.id))
                    .filter(expiry_notification::Column::DaysUntilExpiry.eq(*days as i32))
                    .filter(expiry_notification::Column::NotificationSent.eq(false))
                    .one(&self.db)
                    .await?;

                if existing_notification.is_none() {
                    // 发送通知
                    let method = self.send_notification(&key_record, *days as i32).await?;

                    // 记录通知
                    let notification = expiry_notification::ActiveModel {
                        id: ActiveValue::NotSet,
                        key_id: ActiveValue::Set(key_record.id),
                        notify_at: ActiveValue::Set(Utc::now()),
                        days_until_expiry: ActiveValue::Set(*days as i32),
                        notification_sent: ActiveValue::Set(true),
                        notification_method: ActiveValue::Set(method.as_str().to_string()),
                    };
                    expiry_notification::Entity::insert(notification)
                        .exec(&self.db)
                        .await?;

                    notified_count += 1;
                }
            }
        }

        Ok(notified_count)
    }

    /// 发送单个通知
    async fn send_notification(
        &self,
        key_record: &api_key::Model,
        days_until_expiry: i32,
    ) -> Result<String, NotificationError> {
        let payload = ExpiryNotificationPayload {
            key_id: key_record.id,
            key_hash: key_record.key_hash.clone(),
            prefix: key_record.prefix.clone(),
            expires_at: key_record.expires_at.to_rfc3339(),
            days_until_expiry,
            notification_type: "api_key_expiry_warning",
        };

        // 1. 记录日志（始终执行）
        tracing::info!(
            key_id = %key_record.id,
            days_until_expiry = %days_until_expiry,
            "API Key 即将过期通知"
        );

        // 2. Webhook 通知
        if let Some(webhook_url) = &self.config.webhook_url {
            let client = reqwest::Client::new();
            let mut request = client
                .post(webhook_url)
                .header("Content-Type", "application/json")
                .json(&payload);

            if let Some(token) = &self.config.webhook_token {
                request = request.header("Authorization", format!("Bearer {}", token));
            }

            if let Ok(response) = request.send().await {
                if response.status().is_success() {
                    tracing::info!(url = %webhook_url, "Webhook 通知发送成功");
                } else {
                    tracing::warn!(url = %webhook_url, status = %response.status(), "Webhook 通知发送失败");
                }
            }
        }

        // 3. Email 通知（模拟实现）
        if !self.config.email_recipients.is_empty() {
            let _email_content = format!(
                "您的 API Key 将在 {} 天后过期。\nKey ID: {}\n过期时间: {}",
                days_until_expiry,
                key_record.id,
                key_record.expires_at.to_rfc3339()
            );

            for recipient in &self.config.email_recipients {
                tracing::info!(recipient = %recipient, "Email 通知已排队");
                // 实际项目中这里调用邮件发送服务
            }
        }

        Ok("log".to_string())
    }

    /// 获取待发送的通知统计
    pub async fn get_pending_notifications(
        &self,
    ) -> Result<Vec<expiry_notification::Model>, NotificationError> {
        let notifications = expiry_notification::Entity::find()
            .filter(expiry_notification::Column::NotificationSent.eq(false))
            .all(&self.db)
            .await?;

        Ok(notifications)
    }
}

/// Webhook 通知负载
#[derive(Debug, Serialize)]
pub struct ExpiryNotificationPayload {
    pub key_id: i64,
    pub key_hash: String,
    pub prefix: String,
    pub expires_at: String,
    pub days_until_expiry: i32,
    pub notification_type: &'static str,
}

/// 通知管理器
#[derive(Clone)]
pub struct NotificationManager {
    sender: NotificationSender,
}

impl NotificationManager {
    /// 创建新的通知管理器
    pub fn new(db: DatabaseConnection, config: NotificationConfig) -> Self {
        Self {
            sender: NotificationSender::new(db, config),
        }
    }

    /// 启动通知扫描任务
    pub async fn run_scan(&self) -> Result<u64, NotificationError> {
        self.sender.scan_and_notify().await
    }
}
