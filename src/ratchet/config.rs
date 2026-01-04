// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Double Ratchet 协议配置
//!
//! 提供 Double Ratchet 会话的配置选项，包括签名验证、跳过消息处理、安全参数等。

use serde::{Deserialize, Serialize};

/// Double Ratchet 协议配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetConfig {
    /// 是否启用签名验证
    pub enable_signature_verification: bool,

    /// 跳过消息最大数量
    pub max_skip_messages: usize,

    /// 跳过消息密钥最大内存使用（字节）
    pub max_skipped_keys_memory: usize,

    /// 是否启用弱密钥检测
    pub enable_weak_key_detection: bool,

    /// 最小熵阈值
    pub min_entropy_threshold: f64,

    /// 是否启用并行密钥派生
    pub enable_parallel_key_derivation: bool,

    /// 是否启用审计日志
    pub enable_audit_logging: bool,

    /// 会话过期时间（秒）
    pub session_ttl_seconds: u64,

    /// 链密钥派生信息
    pub chain_key_info: Vec<u8>,

    /// 消息密钥派生信息
    pub message_key_info: Vec<u8>,

    /// 根密钥派生信息
    pub root_key_info: Vec<u8>,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            enable_signature_verification: false,
            max_skip_messages: 1000,
            max_skipped_keys_memory: 1024 * 1024, // 1MB
            enable_weak_key_detection: true,
            min_entropy_threshold: 3.0,
            enable_parallel_key_derivation: true,
            enable_audit_logging: true,
            session_ttl_seconds: 86400, // 24小时
            chain_key_info: b"ChainKey".to_vec(),
            message_key_info: b"MessageKey".to_vec(),
            root_key_info: b"RootKey".to_vec(),
        }
    }
}

impl RatchetConfig {
    /// 创建新的配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置签名验证
    pub fn with_signature_verification(mut self, enabled: bool) -> Self {
        self.enable_signature_verification = enabled;
        self
    }

    /// 设置最大跳过消息数
    pub fn with_max_skip_messages(mut self, max: usize) -> Self {
        self.max_skip_messages = max;
        self
    }

    /// 设置会话 TTL
    pub fn with_session_ttl(mut self, seconds: u64) -> Self {
        self.session_ttl_seconds = seconds;
        self
    }

    /// 启用审计日志
    pub fn with_audit_logging(mut self, enabled: bool) -> Self {
        self.enable_audit_logging = enabled;
        self
    }

    /// 验证配置是否有效
    pub fn validate(&self) -> bool {
        if self.max_skip_messages == 0 {
            return false;
        }
        if self.max_skipped_keys_memory == 0 {
            return false;
        }
        if self.session_ttl_seconds == 0 {
            return false;
        }
        if self.min_entropy_threshold <= 0.0 {
            return false;
        }
        true
    }
}
