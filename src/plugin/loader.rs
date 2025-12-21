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

    pub fn unload_plugin(&mut self, name: &str) -> Result<()> {
        self.loaded_plugins.remove(name)
            .ok_or_else(|| CryptoError::PluginError(format!("Plugin '{}' not found", name)))?;
        
        // In a real implementation, we would need to handle library unloading carefully
        // because the plugin instance (Arc<dyn Plugin>) might still be in use.
        // For simplicity, we keep the library loaded for now.
        
        Ok(())
    }

    pub fn get_plugin(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.loaded_plugins.get(name).cloned()
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.loaded_plugins.keys().cloned().collect()
    }
}