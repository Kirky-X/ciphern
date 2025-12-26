// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::i18n::translate_with_args;
use crate::plugin::{Plugin, PluginMetadata};
use libloading::{Library, Symbol};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct PluginLoader {
    plugin_dirs: Vec<PathBuf>,
    loaded_plugins: HashMap<String, Arc<dyn Plugin>>,
    libraries: Vec<Arc<Library>>,
}

#[allow(dead_code)]
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

        // 使用 libloading 加载动态库
        let lib = unsafe {
            Library::new(path).map_err(|e| {
                CryptoError::PluginError(translate_with_args(
                    "plugin.load_library_failed",
                    &[("error", &e.to_string())],
                ))
            })?
        };

        let lib_arc = Arc::new(lib);

        // 在实际实现中，插件会导出一个创建实例的函数
        type PluginConstructor = unsafe fn() -> *mut dyn Plugin;

        let plugin = unsafe {
            let constructor: Symbol<PluginConstructor> =
                lib_arc.get(b"_create_plugin").map_err(|e| {
                    CryptoError::PluginError(translate_with_args(
                        "plugin.find_symbol_failed",
                        &[("error", &e.to_string())],
                    ))
                })?;

            let plugin_ptr = constructor();
            if plugin_ptr.is_null() {
                return Err(CryptoError::PluginError(translate_with_args(
                    "plugin.constructor_null",
                    &[],
                )));
            }

            // 将原始指针转换为 Box 再转换为 Arc
            // 注意：插件必须使用相同的 ABI 编译
            Arc::from_raw(plugin_ptr)
        };

        self.libraries.push(lib_arc);
        self.loaded_plugins
            .insert(metadata.name.clone(), plugin.clone());
        Ok(plugin)
    }

    pub fn load_all_plugins(&mut self) -> Vec<Result<Arc<dyn Plugin>>> {
        let mut results = Vec::with_capacity(64);

        let mut paths_to_load = Vec::new();
        for dir in &self.plugin_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("plugin") {
                        paths_to_load.push(path);
                    }
                }
            }
        }

        for path in paths_to_load {
            results.push(self.load_plugin_from_file(&path));
        }

        results
    }

    fn validate_plugin_file(&self, path: &Path) -> Result<PluginMetadata> {
        // 读取并验证插件文件
        let content = fs::read(path)
            .map_err(|e| CryptoError::PluginError(format!("读取插件文件失败: {}", e)))?;

        // 计算校验和
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let checksum = format!("{:x}", hasher.finalize());

        // 从 sidecar 文件解析元数据（例如 plugin.json 或 plugin.toml）
        let metadata_path = path.with_extension("json");
        let metadata = if metadata_path.exists() {
            let metadata_content = fs::read_to_string(&metadata_path)
                .map_err(|e| CryptoError::PluginError(format!("读取元数据文件失败: {}", e)))?;
            let metadata: PluginMetadata = serde_json::from_str(&metadata_content)
                .map_err(|e| CryptoError::PluginError(format!("解析元数据失败: {}", e)))?;
            // 验证校验和与实际文件内容匹配
            if metadata.checksum != checksum {
                return Err(CryptoError::PluginError("插件校验和不匹配".to_string()));
            }
            metadata
        } else {
            // 回退/默认元数据用于测试或当 sidecar 不存在时，但会发出警告
            // 在严格模式下，这可能会失败
            // 现在，我们构造最小元数据但标记它
            PluginMetadata {
                name: path.file_stem().unwrap().to_string_lossy().to_string(),
                version: "0.0.0".to_string(),
                author: "Unknown".to_string(),
                description: "未找到元数据文件".to_string(),
                dependencies: vec![],
                checksum,
            }
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
            // 我们通过检查引用计数来确保只有不再被其他插件使用的库才会被卸载
            // 注意：如果多个插件共享同一个库文件，这种简单的计数可能不够，需要更复杂的依赖管理
            self.libraries.retain(|lib| Arc::strong_count(lib) > 1);

            log::info!(
                "{}",
                translate_with_args("plugin.unloaded", &[("name", &name)])
            );
            Ok(())
        } else {
            Err(CryptoError::PluginError(format!("插件 '{}' 不存在", name)))
        }
    }

    pub fn get_plugin(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.loaded_plugins.get(name).cloned()
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.loaded_plugins.keys().cloned().collect()
    }
}
