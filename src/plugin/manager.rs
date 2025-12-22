// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::plugin::{CipherPlugin, Plugin, PluginMetadata};
use crate::provider::{ProviderRegistry, SymmetricCipher};
use crate::types::Algorithm;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub struct PluginManager {
    plugins: Arc<RwLock<HashMap<String, Arc<dyn Plugin>>>>,
    cipher_plugins: Arc<RwLock<HashMap<Algorithm, Arc<dyn CipherPlugin>>>>,
    health_check_interval: Duration,
    max_failures: u32,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            cipher_plugins: Arc::new(RwLock::new(HashMap::new())),
            health_check_interval: Duration::from_secs(30),
            max_failures: 3,
        }
    }

    pub fn register_plugin(&self, plugin: Arc<dyn Plugin>) -> Result<()> {
        let mut plugins = self.plugins.write().map_err(|_| {
            CryptoError::PluginError("Failed to acquire plugin registry lock".into())
        })?;
        
        plugins.insert(plugin.name().to_string(), plugin.clone());
        Ok(())
    }

    pub fn register_cipher_plugin(&self, plugin: Arc<dyn CipherPlugin>) -> Result<()> {
        let mut cipher_plugins = self.cipher_plugins.write().map_err(|_| {
            CryptoError::PluginError("Failed to acquire cipher plugin registry lock".into())
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
        self.plugins.read()
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

    pub fn monitor_plugins(&self) -> Result<()> {
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
            
            // Stop monitoring after reasonable time for testing
            if start_time.elapsed() > Duration::from_secs(300) {
                break;
            }
        }
        
        Ok(())
    }

    fn handle_plugin_failure(&self, plugin_name: &str) -> Result<()> {
        eprintln!("Plugin '{}' failed health check - unloading", plugin_name);
        
        // Remove from registries
        if let Ok(mut plugins) = self.plugins.write() {
            plugins.remove(plugin_name);
        }
        
        // Remove associated cipher plugins
        if let Ok(mut cipher_plugins) = self.cipher_plugins.write() {
            cipher_plugins.retain(|_, plugin| plugin.name() != plugin_name);
        }
        
        Ok(())
    }

    pub fn graceful_shutdown(&self) -> Result<()> {
        let plugins = self.plugins.read().map_err(|_| {
            CryptoError::PluginError("Failed to acquire plugin registry lock for shutdown".into())
        })?;
        
        for (name, plugin) in plugins.iter() {
            if let Err(e) = plugin.as_ref().as_any().downcast_ref::<std::sync::Arc<dyn Plugin>>()
                .and_then(|p| p.as_ref().as_any().downcast_ref::<&mut dyn Plugin>())
                .map(|p| p.shutdown()) {
                eprintln!("Failed to shutdown plugin '{}': {:?}", name, e);
            }
        }
        
        Ok(())
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}