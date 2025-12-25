// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

pub mod loader;
pub mod manager;
// pub mod hot_reload; // Removed as it is unused and causes warnings

use crate::error::Result;
use crate::plugin::manager::PluginManager;
use crate::provider::SymmetricCipher;
use crate::types::Algorithm;
use lazy_static::lazy_static;
use std::any::Any;
use std::sync::Arc;

lazy_static! {
    pub static ref PLUGIN_MANAGER: PluginManager = PluginManager::new();
}
#[allow(dead_code)]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    #[allow(dead_code)]
    fn version(&self) -> &str;
    #[allow(dead_code)]
    fn initialize(&mut self) -> Result<()>;
    fn shutdown(&mut self) -> Result<()>;
    fn health_check(&self) -> Result<bool>;
    #[allow(dead_code)]
    fn as_any(&self) -> &dyn Any;
}

pub trait CipherPlugin: Plugin {
    fn as_symmetric_cipher(&self) -> Arc<dyn SymmetricCipher>;
    fn supported_algorithms(&self) -> Vec<Algorithm>;
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub dependencies: Vec<String>,
    pub checksum: String,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct PluginLoadError {
    pub plugin_name: String,
    pub reason: String,
    pub recoverable: bool,
}

impl std::fmt::Display for PluginLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Plugin '{}' load error: {} (recoverable: {})",
            self.plugin_name, self.reason, self.recoverable
        )
    }
}

impl std::error::Error for PluginLoadError {}
