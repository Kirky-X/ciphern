// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! FFI Context Management
//! 
//! Centralized context management for FFI operations

use std::sync::{Arc, Mutex, RwLock};
use once_cell::sync::Lazy;
use crate::{fips::{FipsContext, FipsMode}, key::{KeyLifecycleManager, KeyManager}, CryptoError, Result};
use super::interface::CiphernError;

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
    pub max_keys: usize,
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

/// FFI 上下文管理器
pub struct FfiContext {
    state: RwLock<ContextState>,
    config: ContextConfig,
    key_manager: Option<Arc<KeyManager>>,
    lifecycle_manager: Option<Arc<KeyLifecycleManager>>,
    fips_context: Option<Arc<FipsContext>>,
}

impl FfiContext {
    /// 创建新的上下文
    pub fn new(config: ContextConfig) -> Self {
        Self {
            state: RwLock::new(ContextState::Uninitialized),
            config,
            key_manager: None,
            lifecycle_manager: None,
            fips_context: None,
        }
    }

    /// 初始化上下文
    pub fn initialize(&self) -> Result<(), CiphernError> {
        // 检查当前状态
        {
            let state = self.state.read().unwrap();
            match *state {
                ContextState::Ready => return Ok(()),
                ContextState::Initializing => {
                    return Err(CiphernError::UnknownError);
                }
                ContextState::ShuttingDown | ContextState::Error => {
                    return Err(CiphernError::UnknownError);
                }
                _ => {}
            }
        }

        // 设置初始化状态
        {
            let mut state = self.state.write().unwrap();
            *state = ContextState::Initializing;
        }

        // 执行初始化
        let result = self.do_initialize();

        // 更新状态
        {
            let mut state = self.state.write().unwrap();
            *state = match result {
                Ok(_) => ContextState::Ready,
                Err(_) => ContextState::Error,
            };
        }

        result
    }

    /// 实际初始化逻辑
    fn do_initialize(&self) -> Result<(), CiphernError> {
        // 初始化核心库
        crate::init().map_err(|_| CiphernError::UnknownError)?;

        // 创建密钥管理器
        let key_manager = KeyManager::new()
            .map_err(|_| CiphernError::MemoryAllocationFailed)?;
        self.key_manager = Some(Arc::new(key_manager));

        // 创建生命周期管理器
        let lifecycle_manager = KeyLifecycleManager::new()
            .map_err(|_| CiphernError::MemoryAllocationFailed)?;
        self.lifecycle_manager = Some(Arc::new(lifecycle_manager));

        // 如果需要，初始化 FIPS 上下文
        if self.config.enable_fips {
            self.initialize_fips()?;
        }

        Ok(())
    }

    /// 初始化 FIPS 上下文
    fn initialize_fips(&self) -> Result<(), CiphernError> {
        // 启用 FIPS 模式
        FipsContext::enable()
            .map_err(|_| CiphernError::FipsError)?;

        // 创建 FIPS 上下文
        let fips_context = FipsContext::new(FipsMode::Enabled)
            .map_err(|_| CiphernError::FipsError)?;
        self.fips_context = Some(Arc::new(fips_context));

        Ok(())
    }

    /// 清理上下文
    pub fn cleanup(&self) {
        // 设置关闭状态
        {
            let mut state = self.state.write().unwrap();
            *state = ContextState::ShuttingDown;
        }

        // 清理资源
        self.key_manager = None;
        self.lifecycle_manager = None;
        self.fips_context = None;

        // 重置状态
        {
            let mut state = self.state.write().unwrap();
            *state = ContextState::Uninitialized;
        }
    }

    /// 获取密钥管理器
    pub fn key_manager(&self) -> Result<Arc<KeyManager>, CiphernError> {
        self.check_ready()?;
        self.key_manager.clone()
            .ok_or(CiphernError::UnknownError)
    }

    /// 获取生命周期管理器
    pub fn lifecycle_manager(&self) -> Result<Arc<KeyLifecycleManager>, CiphernError> {
        self.check_ready()?;
        self.lifecycle_manager.clone()
            .ok_or(CiphernError::UnknownError)
    }

    /// 获取 FIPS 上下文
    pub fn fips_context(&self) -> Option<Arc<FipsContext>> {
        self.fips_context.clone()
    }

    /// 检查是否就绪
    fn check_ready(&self) -> Result<(), CiphernError> {
        let state = self.state.read().unwrap();
        match *state {
            ContextState::Ready => Ok(()),
            ContextState::Uninitialized => Err(CiphernError::UnknownError),
            ContextState::Initializing => Err(CiphernError::UnknownError),
            ContextState::ShuttingDown => Err(CiphernError::UnknownError),
            ContextState::Error => Err(CiphernError::UnknownError),
        }
    }

    /// 检查 FIPS 是否启用
    pub fn is_fips_enabled(&self) -> bool {
        self.fips_context.is_some() && crate::fips::is_fips_enabled()
    }

    /// 设置 FIPS 启用状态
    pub fn set_fips_enabled(&self, enabled: bool) {
        if enabled && self.fips_context.is_none() {
            // 如果启用且当前没有FIPS上下文，尝试初始化
            if let Ok(fips_context) = FipsContext::new(FipsMode::Enabled) {
                self.fips_context = Some(Arc::new(fips_context));
            }
        } else if !enabled {
            // 如果禁用，清除FIPS上下文
            self.fips_context = None;
        }
    }

    /// 获取状态
    pub fn state(&self) -> ContextState {
        *self.state.read().unwrap()
    }
}

/// 全局 FFI 上下文
static GLOBAL_CONTEXT: Lazy<Arc<Mutex<Option<Arc<FfiContext>>>>> = Lazy::new(|| {
    Arc::new(Mutex::new(None))
});

/// 获取或创建全局上下文
pub fn get_context() -> Result<Arc<FfiContext>, CiphernError> {
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
pub fn initialize_context() -> Result<(), CiphernError> {
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
pub fn is_context_ready() -> bool {
    if let Ok(context) = get_context() {
        context.state() == ContextState::Ready
    } else {
        false
    }
}

/// 安全的上下文操作包装器
pub fn with_context<F, R>(f: F) -> Result<R, CiphernError>
where
    F: FnOnce(&Arc<FfiContext>) -> Result<R, CiphernError>,
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
        
        let context = Arc::new(FfiContext::new(config.clone()));
        assert!(context.config.enable_fips);
        assert_eq!(context.config.max_keys, 500);
    }
}