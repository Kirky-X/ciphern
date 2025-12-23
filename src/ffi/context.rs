// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! FFI Context Management
//!
//! Centralized context management for FFI operations

use crate::ffi::CiphernError;
use crate::fips::{FipsContext, FipsMode};
use crate::key::{KeyLifecycleManager, KeyManager};
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex, RwLock};

/// FFI 上下文状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextState {
    Uninitialized,
    Initializing,
    Ready,
    ShuttingDown,
    Error,
}

/// FFI 上下文配置
#[derive(Debug, Clone)]
pub struct ContextConfig {
    pub enable_fips: bool,
    /// 最大密钥数量
    #[allow(dead_code)]
    pub max_keys: usize,
    /// 密钥生命周期策略
    #[allow(dead_code)]
    pub key_lifecycle_policy: crate::key::KeyLifecyclePolicy,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            enable_fips: false,
            max_keys: 1000,
            key_lifecycle_policy: crate::key::KeyLifecyclePolicy::default(),
        }
    }
}

/// 内部上下文状态
struct InnerContext {
    state: ContextState,
    key_manager: Option<Arc<KeyManager>>,
    lifecycle_manager: Option<Arc<KeyLifecycleManager>>,
    fips_context: Option<Arc<FipsContext>>,
}

/// FFI 上下文管理器
pub struct FfiContext {
    inner: RwLock<InnerContext>,
    config: ContextConfig,
}

impl FfiContext {
    /// 创建新的上下文
    pub fn new(config: ContextConfig) -> Self {
        Self {
            inner: RwLock::new(InnerContext {
                state: ContextState::Uninitialized,
                key_manager: None,
                lifecycle_manager: None,
                fips_context: None,
            }),
            config,
        }
    }

    /// 初始化上下文
    pub fn initialize(&self) -> std::result::Result<(), CiphernError> {
        // 检查当前状态 (读锁)
        {
            let inner = self.inner.read().unwrap();
            match inner.state {
                ContextState::Ready => return Ok(()),
                ContextState::Initializing => return Err(CiphernError::UnknownError),
                ContextState::ShuttingDown | ContextState::Error => {
                    return Err(CiphernError::UnknownError)
                }
                _ => {}
            }
        }

        // 设置初始化状态 (写锁)
        {
            let mut inner = self.inner.write().unwrap();
            if inner.state == ContextState::Ready {
                return Ok(());
            }
            if inner.state == ContextState::Initializing {
                return Err(CiphernError::UnknownError);
            }
            inner.state = ContextState::Initializing;
        }

        // 执行初始化 (不持有锁)
        let result = self.do_initialize_resources();

        // 更新状态 (写锁)
        let mut inner = self.inner.write().unwrap();
        match result {
            Ok((km, lm, fc)) => {
                inner.key_manager = Some(km);
                inner.lifecycle_manager = Some(lm);
                inner.fips_context = fc;
                inner.state = ContextState::Ready;
                Ok(())
            }
            Err(e) => {
                inner.state = ContextState::Error;
                Err(e)
            }
        }
    }

    /// 准备资源
    #[allow(clippy::type_complexity)]
    fn do_initialize_resources(
        &self,
    ) -> std::result::Result<
        (
            Arc<KeyManager>,
            Arc<KeyLifecycleManager>,
            Option<Arc<FipsContext>>,
        ),
        CiphernError,
    > {
        // 初始化核心库
        crate::init().map_err(|_| CiphernError::UnknownError)?;

        // 创建密钥管理器
        let key_manager = KeyManager::new().map_err(|_| CiphernError::MemoryAllocationFailed)?;
        let key_manager = Arc::new(key_manager);

        // 创建生命周期管理器
        let lifecycle_manager =
            KeyLifecycleManager::new().map_err(|_| CiphernError::MemoryAllocationFailed)?;
        let lifecycle_manager = Arc::new(lifecycle_manager);

        // 如果需要，初始化 FIPS 上下文
        let fips_context = if self.config.enable_fips {
            // 启用 FIPS 模式
            FipsContext::enable().map_err(|_| CiphernError::FipsError)?;

            // 创建 FIPS 上下文
            let ctx = FipsContext::new(FipsMode::Enabled).map_err(|_| CiphernError::FipsError)?;
            Some(Arc::new(ctx))
        } else {
            None
        };

        Ok((key_manager, lifecycle_manager, fips_context))
    }

    /// 清理上下文
    pub fn cleanup(&self) {
        let mut inner = self.inner.write().unwrap();

        inner.state = ContextState::ShuttingDown;

        // 清理资源
        inner.key_manager = None;
        inner.lifecycle_manager = None;
        inner.fips_context = None;

        inner.state = ContextState::Uninitialized;
    }

    /// 获取密钥管理器
    pub fn key_manager(&self) -> std::result::Result<Arc<KeyManager>, CiphernError> {
        let inner = self.inner.read().unwrap();
        if inner.state != ContextState::Ready {
            return Err(CiphernError::UnknownError);
        }
        inner.key_manager.clone().ok_or(CiphernError::UnknownError)
    }

    /// 获取生命周期管理器
    #[allow(dead_code)]
    pub fn lifecycle_manager(&self) -> std::result::Result<Arc<KeyLifecycleManager>, CiphernError> {
        let inner = self.inner.read().unwrap();
        if inner.state != ContextState::Ready {
            return Err(CiphernError::UnknownError);
        }
        inner
            .lifecycle_manager
            .clone()
            .ok_or(CiphernError::UnknownError)
    }

    /// 获取 FIPS 上下文
    #[allow(dead_code)]
    pub fn fips_context(&self) -> Option<Arc<FipsContext>> {
        let inner = self.inner.read().unwrap();
        inner.fips_context.clone()
    }

    /// 检查 FIPS 是否启用
    pub fn is_fips_enabled(&self) -> bool {
        let inner = self.inner.read().unwrap();
        inner.fips_context.is_some() && crate::fips::is_fips_enabled()
    }

    /// 设置 FIPS 启用状态
    pub fn set_fips_enabled(&self, enabled: bool) {
        let mut inner = self.inner.write().unwrap();

        if enabled && inner.fips_context.is_none() {
            // 如果启用且当前没有FIPS上下文，尝试初始化
            if let Ok(fips_context) = FipsContext::new(FipsMode::Enabled) {
                inner.fips_context = Some(Arc::new(fips_context));
            }
        } else if !enabled {
            // 如果禁用，清除FIPS上下文
            inner.fips_context = None;
        }
    }

    /// 获取状态
    #[allow(dead_code)]
    pub fn state(&self) -> ContextState {
        self.inner.read().unwrap().state
    }
}

/// 全局 FFI 上下文
static GLOBAL_CONTEXT: Lazy<Arc<Mutex<Option<Arc<FfiContext>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));

/// 获取或创建全局上下文
pub fn get_context() -> std::result::Result<Arc<FfiContext>, CiphernError> {
    let mut global = GLOBAL_CONTEXT.lock().unwrap();

    if let Some(ref context) = *global {
        return Ok(context.clone());
    }

    // 创建新上下文
    let config = ContextConfig::default();
    let context = Arc::new(FfiContext::new(config));
    *global = Some(context.clone());

    Ok(context)
}

/// 初始化全局上下文
pub fn initialize_context() -> std::result::Result<(), CiphernError> {
    let context = get_context()?;
    context.initialize()
}

/// 清理全局上下文
pub fn cleanup_context() {
    if let Ok(context) = get_context() {
        context.cleanup();
    }

    // 清除全局引用
    let mut global = GLOBAL_CONTEXT.lock().unwrap();
    *global = None;
}

/// 检查上下文是否就绪
#[allow(dead_code)]
pub fn is_context_ready() -> bool {
    if let Ok(global) = GLOBAL_CONTEXT.lock() {
        if let Some(ref context) = *global {
            return context.state() == ContextState::Ready;
        }
    }
    false
}

/// 安全的上下文操作包装器
pub fn with_context<F, R>(f: F) -> std::result::Result<R, CiphernError>
where
    F: FnOnce(&Arc<FfiContext>) -> std::result::Result<R, CiphernError>,
{
    let context = get_context()?;
    f(&context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_lifecycle() {
        // 注意：这个测试需要小心处理全局状态
        // 在实际测试中，可能需要使用测试专用的上下文管理

        let config = ContextConfig::default();
        let context = Arc::new(FfiContext::new(config));

        assert_eq!(context.state(), ContextState::Uninitialized);

        // 测试初始化
        assert!(context.initialize().is_ok());
        assert_eq!(context.state(), ContextState::Ready);

        // 测试清理
        context.cleanup();
        assert_eq!(context.state(), ContextState::Uninitialized);
    }

    #[test]
    fn test_context_config() {
        let config = ContextConfig {
            enable_fips: true,
            max_keys: 500,
            key_lifecycle_policy: crate::key::KeyLifecyclePolicy::default(),
        };

        let context = FfiContext::new(config);
        assert_eq!(context.state(), ContextState::Uninitialized);
    }
}
