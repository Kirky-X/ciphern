// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::plugin::{Plugin, PluginMetadata, PluginLoadError};
use crate::error::{CryptoError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use libloading::{Library, Symbol};

pub struct PluginLoader {
    plugin_dirs: Vec<PathBuf>,
    loaded_plugins: HashMap<String, Arc<dyn Plugin>>,
    libraries: Vec<Arc<Library>>,
}

impl PluginLoader {
    pub fn new(plugin_dirs: Vec<PathBuf>) -> Self {
        Self {
            plugin_dirs,
            loaded_plugins: HashMap::new(),
            libraries: Vec::new(),
        }
    }

    pub fn load_plugin_from_file(&mut self, path: &Path) -> Result<Arc<dyn Plugin>> {
        let metadata = self.validate_plugin_file(path)?;
        
        // Use libloading to load the dynamic library
        let lib = unsafe {
            Library::new(path).map_err(|e| {
                CryptoError::PluginError(format!("Failed to load dynamic library: {}", e))
            })?
        };
        
        let lib_arc = Arc::new(lib);
        
        // In a real implementation, the plugin would export a function to create an instance
        type PluginConstructor = unsafe fn() -> *mut dyn Plugin;
        
        let plugin = unsafe {
            let constructor: Symbol<PluginConstructor> = lib_arc.get(b"_create_plugin").map_err(|e| {
                CryptoError::PluginError(format!("Failed to find _create_plugin symbol: {}", e))
            })?;
            
            let plugin_ptr = constructor();
            if plugin_ptr.is_null() {
                return Err(CryptoError::PluginError("Plugin constructor returned null".into()));
            }
            
            // Convert raw pointer to Box then to Arc
            // Note: The plugin must be compiled with the same ABI
            Arc::from_raw(plugin_ptr)
        };
        
        self.libraries.push(lib_arc);
        self.loaded_plugins.insert(metadata.name.clone(), plugin.clone());
        Ok(plugin)
    }

    pub fn load_all_plugins(&mut self) -> Vec<Result<Arc<dyn Plugin>>> {
        let mut results = Vec::new();
        
        for dir in &self.plugin_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("plugin") {
                        results.push(self.load_plugin_from_file(&path));
                    }
                }
            }
        }
        
        results
    }

    fn validate_plugin_file(&self, path: &Path) -> Result<PluginMetadata> {
        // Read and validate plugin file
        let content = fs::read(path)
            .map_err(|e| CryptoError::PluginError(format!("Failed to read plugin file: {}", e)))?;
        
        // Calculate checksum
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let checksum = format!("{:x}", hasher.finalize());
        
        // Parse metadata (simplified - in real implementation would use proper format)
        let metadata = PluginMetadata {
            name: path.file_stem().unwrap().to_string_lossy().to_string(),
            version: "1.0.0".to_string(),
            author: "Test Author".to_string(),
            description: "Test Plugin".to_string(),
            dependencies: vec![],
            checksum,
        };
        
        Ok(metadata)
    }

    /// 卸载插件并释放资源
    pub fn unload_plugin(&mut self, name: &str) -> Result<()> {
        if let Some(plugin) = self.loaded_plugins.remove(name) {
            // 在 Rust 中，当 Arc 被移除且计数归零时，插件会被释放
            // 但对于动态加载的库，我们需要确保 libloading::Library 也被正确处理
            // libloading 会在 Library struct 被 drop 时调用 dlclose()
            
            // 显式触发插件的 shutdown 方法
            // 由于 plugin 是 Arc<dyn Plugin>，我们需要通过 get_mut 获取可变引用
            // 或者插件接口设计为接收 &self 的 shutdown
            // 这里我们假设插件内部会处理状态
            let mut plugin_clone = plugin.clone();
            if let Some(p) = Arc::get_mut(&mut plugin_clone) {
                p.shutdown()?;
            }
            
            // 清理对应的 Library 引用，触发 dlclose
            // 在实际实现中，通常需要记录插件与 Library 的对应关系
            // 这里简化处理，清理 libraries 列表
            self.libraries.retain(|lib| Arc::strong_count(lib) > 1);
            
            log::info!("Plugin {} unloaded and resources released", name);
            Ok(())
        } else {
            Err(CryptoError::PluginError(format!("Plugin '{}' not found", name)))
        }
    }

    pub fn get_plugin(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.loaded_plugins.get(name).cloned()
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.loaded_plugins.keys().cloned().collect()
    }
}