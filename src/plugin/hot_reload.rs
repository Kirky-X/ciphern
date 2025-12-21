// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full information.

use crate::plugin::{Plugin, PluginMetadata};
use crate::error::{CryptoError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::SystemTime;

pub struct HotReloadWatcher {
    watched_files: Arc<Mutex<HashMap<PathBuf, SystemTime>>>,
    reload_handlers: Arc<Mutex<HashMap<String, Box<dyn Fn(&str) + Send + Sync>>>>,
}

impl HotReloadWatcher {
    pub fn new() -> Self {
        Self {
            watched_files: Arc::new(Mutex::new(HashMap::new())),
            reload_handlers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn watch_plugin(&self, plugin_path: &Path, plugin_name: &str) -> Result<()> {
        let metadata = fs::metadata(plugin_path)
            .map_err(|e| CryptoError::PluginError(format!("Failed to read plugin metadata: {}", e)))?;
        
        let modified_time = metadata.modified()
            .map_err(|e| CryptoError::PluginError(format!("Failed to get modification time: {}", e)))?;
        
        let mut watched_files = self.watched_files.lock().unwrap();
        watched_files.insert(plugin_path.to_path_buf(), modified_time);
        
        Ok(())
    }

    pub fn register_reload_handler<F>(&self, plugin_name: &str, handler: F) -> Result<()>
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let mut handlers = self.reload_handlers.lock().unwrap();
        handlers.insert(plugin_name.to_string(), Box::new(handler));
        Ok(())
    }

    pub fn check_for_changes(&self) -> Result<Vec<HotReloadEvent>> {
        let mut events = Vec::new();
        let watched_files = self.watched_files.lock().unwrap();
        
        for (path, last_modified) in watched_files.iter() {
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(current_modified) = metadata.modified() {
                    if current_modified > *last_modified {
                        let plugin_name = path.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        
                        events.push(HotReloadEvent {
                            plugin_name: plugin_name.clone(),
                            plugin_path: path.clone(),
                            event_type: HotReloadEventType::FileChanged,
                        });
                    }
                }
            }
        }
        
        Ok(events)
    }

    pub fn process_reload_events(&self, events: Vec<HotReloadEvent>) -> Result<()> {
        for event in events {
            let handlers = self.reload_handlers.lock().unwrap();
            
            if let Some(handler) = handlers.get(&event.plugin_name) {
                handler(&event.plugin_name);
            }
            
            // Update the watched file timestamp
            if let Ok(metadata) = fs::metadata(&event.plugin_path) {
                if let Ok(new_time) = metadata.modified() {
                    let mut watched_files = self.watched_files.lock().unwrap();
                    watched_files.insert(event.plugin_path.clone(), new_time);
                }
            }
        }
        
        Ok(())
    }

    pub fn start_monitoring(&self, interval_ms: u64) -> Result<()> {
        let watcher = Arc::new(self.clone());
        
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(interval_ms));
                
                if let Ok(events) = watcher.check_for_changes() {
                    if !events.is_empty() {
                        if let Err(e) = watcher.process_reload_events(events) {
                            eprintln!("Error processing reload events: {:?}", e);
                        }
                    }
                }
            }
        });
        
        Ok(())
    }

    pub fn stop_watching(&self, plugin_path: &Path) -> Result<()> {
        let mut watched_files = self.watched_files.lock().unwrap();
        watched_files.remove(plugin_path);
        Ok(())
    }
}

impl Clone for HotReloadWatcher {
    fn clone(&self) -> Self {
        Self {
            watched_files: Arc::clone(&self.watched_files),
            reload_handlers: Arc::clone(&self.reload_handlers),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HotReloadEvent {
    pub plugin_name: String,
    pub plugin_path: PathBuf,
    pub event_type: HotReloadEventType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HotReloadEventType {
    FileChanged,
    FileDeleted,
    FileCreated,
}

pub struct SafeReloadManager {
    active_plugins: Arc<Mutex<HashMap<String, Arc<dyn Plugin>>>>,
    staging_plugins: Arc<Mutex<HashMap<String, Arc<dyn Plugin>>>>,
    rollback_timeout: std::time::Duration,
}

impl SafeReloadManager {
    pub fn new() -> Self {
        Self {
            active_plugins: Arc::new(Mutex::new(HashMap::new())),
            staging_plugins: Arc::new(Mutex::new(HashMap::new())),
            rollback_timeout: std::time::Duration::from_secs(30),
        }
    }

    pub fn stage_plugin(&self, plugin: Arc<dyn Plugin>) -> Result<()> {
        let mut staging = self.staging_plugins.lock().unwrap();
        staging.insert(plugin.name().to_string(), plugin);
        Ok(())
    }

    pub fn commit_plugin(&self, plugin_name: &str) -> Result<()> {
        let mut staging = self.staging_plugins.lock().unwrap();
        let mut active = self.active_plugins.lock().unwrap();
        
        if let Some(plugin) = staging.remove(plugin_name) {
            active.insert(plugin_name.to_string(), plugin);
            Ok(())
        } else {
            Err(CryptoError::PluginError(format!("Plugin '{}' not found in staging", plugin_name)))
        }
    }

    pub fn rollback_plugin(&self, plugin_name: &str) -> Result<()> {
        let mut staging = self.staging_plugins.lock().unwrap();
        staging.remove(plugin_name);
        Ok(())
    }

    pub fn get_active_plugin(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.active_plugins.lock().unwrap().get(name).cloned()
    }

    pub fn perform_health_check(&self, plugin_name: &str) -> Result<bool> {
        let staging = self.staging_plugins.lock().unwrap();
        
        if let Some(plugin) = staging.get(plugin_name) {
            plugin.health_check()
        } else {
            Err(CryptoError::PluginError(format!("Plugin '{}' not found in staging", plugin_name)))
        }
    }

    pub fn wait_for_stability(&self, plugin_name: &str, checks: u32, interval_ms: u64) -> Result<bool> {
        for i in 0..checks {
            match self.perform_health_check(plugin_name) {
                Ok(true) => {
                    if i == checks - 1 {
                        return Ok(true);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(interval_ms));
                }
                Ok(false) | Err(_) => return Ok(false),
            }
        }
        Ok(false)
    }
}

impl Default for SafeReloadManager {
    fn default() -> Self {
        Self::new()
    }
}