//! LRU 缓存模块
//!
//! 使用 moka crate 实现本地 LRU 缓存，用于缓存校验结果。

use moka::future::Cache as MokaCache;
use std::sync::Arc;
use std::time::Duration;

use crate::api_key::types::ValidationResult;

/// 缓存配置
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// TTL（秒）
    pub ttl_secs: u64,
    /// 最大条目数
    pub max_entries: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_secs: 600,      // 10 分钟
            max_entries: 1000,  // 1000 个条目
        }
    }
}

/// API Key 缓存
#[derive(Clone)]
pub struct Cache {
    inner: Arc<MokaCache<String, ValidationResult>>,
}

impl Cache {
    /// 创建新缓存
    pub fn new(config: CacheConfig) -> Self {
        let cache = MokaCache::builder()
            .time_to_live(Duration::from_secs(config.ttl_secs))
            .max_capacity(config.max_entries)
            .build();

        Self {
            inner: Arc::new(cache),
        }
    }

    /// 获取缓存值
    pub async fn get(&self, key: &str) -> Option<ValidationResult> {
        self.inner.get(key).await
    }

    /// 设置缓存值
    pub async fn set(&self, key: &str, value: ValidationResult) {
        self.inner.insert(key.to_string(), value).await;
    }

    /// 移除缓存值
    pub async fn remove(&self, key: &str) {
        self.inner.remove(key).await;
    }

    /// 清空缓存
    pub async fn clear(&self) {
        self.inner.invalidate_all();
    }

    /// 获取当前条目数
    pub async fn len(&self) -> usize {
        self.inner.entry_count() as usize
    }

    /// 检查是否为空
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}