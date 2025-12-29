// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::provider::SymmetricCipher;
use crate::error::CryptoError;
use crate::i18n::translate;
use crate::plugin::{CipherPlugin, Plugin};
use crate::types::Algorithm;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub struct PluginManager {
    plugins: Arc<RwLock<HashMap<String, Arc<dyn Plugin>>>>,
    cipher_plugins: Arc<RwLock<HashMap<Algorithm, Arc<dyn CipherPlugin>>>>,
    health_check_interval: Duration,
    max_failures: u32,
    #[allow(dead_code)]
    max_plugins: usize,
    #[allow(dead_code)]
    max_memory_mb: u64,
}

#[allow(dead_code)]
impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            cipher_plugins: Arc::new(RwLock::new(HashMap::new())),
            health_check_interval: Duration::from_secs(30),
            max_failures: 3,
            max_plugins: 16,
            max_memory_mb: 256,
        }
    }

    pub fn with_limits(max_plugins: usize, max_memory_mb: u64) -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            cipher_plugins: Arc::new(RwLock::new(HashMap::new())),
            health_check_interval: Duration::from_secs(30),
            max_failures: 3,
            max_plugins,
            max_memory_mb,
        }
    }

    pub fn register_plugin(&self, plugin: Arc<dyn Plugin>) -> Result<(), CryptoError> {
        self.check_plugin_limits()?;

        let mut plugins = self
            .plugins
            .write()
            .map_err(|_| CryptoError::PluginError(translate("plugin.registry_lock_failed")))?;

        if plugins.len() >= self.max_plugins {
            return Err(CryptoError::PluginError(format!(
                "已达到最大插件数量限制 {}，无法注册更多插件",
                self.max_plugins
            )));
        }

        plugins.insert(plugin.name().to_string(), plugin.clone());
        Ok(())
    }

    pub fn register_cipher_plugin(&self, plugin: Arc<dyn CipherPlugin>) -> Result<(), CryptoError> {
        let mut cipher_plugins = self.cipher_plugins.write().map_err(|_| {
            CryptoError::PluginError(translate("plugin.cipher_registry_lock_failed"))
        })?;

        for algo in plugin.supported_algorithms() {
            cipher_plugins.insert(algo, plugin.clone());
        }
        Ok(())
    }

    pub fn get_plugin(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.read().ok()?.get(name).cloned()
    }

    pub fn get_cipher_provider(&self, algo: Algorithm) -> Option<Arc<dyn SymmetricCipher>> {
        let cipher_plugins = self.cipher_plugins.read().ok()?;
        cipher_plugins.get(&algo).map(|p| p.as_symmetric_cipher())
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.plugins
            .read()
            .map(|plugins| plugins.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn health_check_all(&self) -> HashMap<String, bool> {
        let mut results = HashMap::new();

        if let Ok(plugins) = self.plugins.read() {
            for (name, plugin) in plugins.iter() {
                let health = plugin.health_check().unwrap_or(false);
                results.insert(name.clone(), health);
            }
        }

        results
    }

    pub fn monitor_plugins(&self) -> Result<(), CryptoError> {
        let start_time = Instant::now();
        let mut failure_counts: HashMap<String, u32> = HashMap::new();

        loop {
            std::thread::sleep(self.health_check_interval);

            let health_results = self.health_check_all();

            for (name, is_healthy) in health_results {
                if !is_healthy {
                    *failure_counts.entry(name.clone()).or_insert(0) += 1;

                    if failure_counts[&name] >= self.max_failures {
                        self.handle_plugin_failure(&name)?;
                        failure_counts.remove(&name);
                    }
                } else {
                    failure_counts.remove(&name);
                }
            }

            // 出于测试目的，在合理时间后停止监控
            if start_time.elapsed() > Duration::from_secs(300) {
                break;
            }
        }

        Ok(())
    }

    fn check_plugin_limits(&self) -> Result<(), CryptoError> {
        let current_count = self.plugins.read().map(|p| p.len()).unwrap_or(0);
        if current_count >= self.max_plugins {
            return Err(CryptoError::PluginError(format!(
                "插件数量 {} 已达到上限 {}",
                current_count, self.max_plugins
            )));
        }
        Ok(())
    }

    fn handle_plugin_failure(&self, plugin_name: &str) -> Result<(), CryptoError> {
        eprintln!("插件 '{}' 健康检查失败 - 正在卸载", plugin_name);

        // 从注册表中移除
        if let Ok(mut plugins) = self.plugins.write() {
            plugins.remove(plugin_name);
        }

        // 移除关联的密码插件
        if let Ok(mut cipher_plugins) = self.cipher_plugins.write() {
            cipher_plugins.retain(|_, plugin| plugin.name() != plugin_name);
        }

        Ok(())
    }

    pub fn graceful_shutdown(&self) -> Result<(), CryptoError> {
        let plugins = self
            .plugins
            .read()
            .map_err(|_| CryptoError::PluginError("获取关闭插件注册表锁失败".into()))?;

        for (name, _plugin) in plugins.iter() {
            println!("正在卸载插件: {}", name);
            // 在实际实现中，我们会调用插件的清理方法
        }

        Ok(())
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}
