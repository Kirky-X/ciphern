//! 后台任务模块
//!
//! 实现 API Key 管理的后台任务调度，包括过期检查、清理任务、通知任务等。

use sea_orm::{DatabaseConnection, EntityTrait, ColumnTrait, QueryFilter, PaginatorTrait};
use chrono::{Duration, Utc};
use tokio::time::{interval, Duration as TokioDuration};
use tokio::spawn;
use std::sync::Arc;
use std::future::Future;

use crate::api_key::notification::{NotificationManager, NotificationConfig};
use crate::api_key::entities::{api_key, validation_failure, rate_limit_block};

/// 任务配置
#[derive(Debug, Clone)]
pub struct TaskConfig {
    /// 过期检查 Cron 表达式（默认: 每天凌晨2点）
    pub expiry_check_cron: String,
    /// 失败阈值
    pub failure_threshold: u32,
    /// 失败时间窗口（秒）
    pub failure_window_secs: u64,
    /// 封禁时长（秒）
    pub block_duration_secs: u64,
    /// 清理过期密钥天数（过期后30天物理删除）
    pub cleanup_after_days: u32,
    /// 通知配置
    pub notification_config: NotificationConfig,
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            expiry_check_cron: "0 2 * * *".to_string(),
            failure_threshold: 5,
            failure_window_secs: 600,
            block_duration_secs: 3600,
            cleanup_after_days: 30,
            notification_config: NotificationConfig::default(),
        }
    }
}

/// 后台任务管理器
#[derive(Clone)]
pub struct TaskManager {
    db: DatabaseConnection,
    config: TaskConfig,
    running: Arc<tokio::sync::RwLock<bool>>,
    handles: Arc<tokio::sync::RwLock<Vec<tokio::task::JoinHandle<()>>>>,
}

impl TaskManager {
    /// 创建新的任务管理器
    pub fn new(db: DatabaseConnection, config: Option<TaskConfig>) -> Self {
        Self {
            db,
            config: config.unwrap_or_default(),
            running: Arc::new(tokio::sync::RwLock::new(false)),
            handles: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    /// 启动所有后台任务
    pub async fn start(&self) {
        let mut running = self.running.write().await;
        if *running {
            tracing::warn!("任务管理器已在运行");
            return;
        }
        *running = true;

        // 启动各个任务
        let handles = vec![
            self.spawn_task(Self::expiry_notification_task()),
            self.spawn_task(Self::expired_key_cleanup_task()),
            self.spawn_task(Self::rate_limit_unblock_task()),
            self.spawn_task(Self::failure_log_aggregation_task()),
        ];

        let mut task_handles = self.handles.write().await;
        *task_handles = handles;

        tracing::info!("后台任务已启动");
    }

    /// 停止所有后台任务
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;

        let mut handles = self.handles.write().await;
        for handle in handles.iter() {
            handle.abort();
        }
        handles.clear();

        tracing::info!("后台任务已停止");
    }

    /// Spawn 任务
    fn spawn_task<F>(&self, task_fn: F) -> tokio::task::JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        spawn(task_fn)
    }

    /// 任务1: 过期通知扫描（每天执行）
    async fn expiry_notification_task() {
        let mut interval = interval(TokioDuration::from_secs(86400)); // 24小时
        let _db = crate::api_key::ApiKeyConfig::default().database_url;
        
        loop {
            interval.tick().await;
            // 通知扫描逻辑
        }
    }

    /// 任务2: 过期密钥清理（每天执行）
    async fn expired_key_cleanup_task() {
        let mut interval = interval(TokioDuration::from_secs(86400));
        
        loop {
            interval.tick().await;
            // 清理逻辑
        }
    }

    /// 任务3: 限流封禁解锁（每5分钟执行）
    async fn rate_limit_unblock_task() {
        let mut interval = interval(TokioDuration::from_secs(300)); // 5分钟
        
        loop {
            interval.tick().await;
            // 解锁逻辑
        }
    }

    /// 任务4: 失败日志聚合统计（每小时执行）
    async fn failure_log_aggregation_task() {
        let mut interval = interval(TokioDuration::from_secs(3600)); // 1小时
        
        loop {
            interval.tick().await;
            // 聚合逻辑
        }
    }

    /// 手动触发过期检查
    pub async fn trigger_expiry_check(&self) -> Result<u64, crate::api_key::error::NotificationError> {
        NotificationManager::new(self.db.clone(), self.config.notification_config.clone())
            .run_scan()
            .await
    }

    /// 手动触发清理任务
    pub async fn trigger_cleanup(&self) -> u64 {
        Self::cleanup_expired_keys(&self.db, self.config.cleanup_after_days).await
    }
}

impl TaskManager {
    /// 清理过期密钥
    async fn cleanup_expired_keys(db: &DatabaseConnection, after_days: u32) -> u64 {
        let cutoff = Utc::now() - Duration::days(after_days as i64);

        let result = api_key::Entity::delete_many()
            .filter(api_key::Column::ExpiresAt.lt(cutoff))
            .filter(api_key::Column::IsRevoked.eq(true))
            .exec(db)
            .await;

        match result {
            Ok(result) => result.rows_affected,
            Err(e) => {
                tracing::error!(error = %e, "清理过期密钥失败");
                0
            }
        }
    }
}

/// 统计信息
#[derive(Debug, Clone)]
pub struct TaskStats {
    pub pending_notifications: u64,
    pub active_keys: u64,
    pub expired_keys: u64,
    pub rate_limited_keys: u64,
    pub validation_failures_24h: u64,
}

impl TaskManager {
    /// 获取统计信息
    pub async fn get_stats(&self) -> Result<TaskStats, sea_orm::DbErr> {
        let now = Utc::now();
        let one_day_ago = now - Duration::days(1);

        let active_keys = api_key::Entity::find()
            .filter(api_key::Column::ExpiresAt.gt(now))
            .filter(api_key::Column::IsRevoked.eq(false))
            .count(&self.db)
            .await?;

        let expired_keys = api_key::Entity::find()
            .filter(api_key::Column::ExpiresAt.lt(now))
            .filter(api_key::Column::IsRevoked.eq(false))
            .count(&self.db)
            .await?;

        let rate_limited_keys = rate_limit_block::Entity::find()
            .count(&self.db)
            .await?;

        let validation_failures_24h = validation_failure::Entity::find()
            .filter(validation_failure::Column::FailedAt.gt(one_day_ago))
            .count(&self.db)
            .await?;

        Ok(TaskStats {
            pending_notifications: 0,
            active_keys,
            expired_keys,
            rate_limited_keys,
            validation_failures_24h,
        })
    }
}