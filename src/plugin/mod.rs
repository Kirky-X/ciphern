// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Plugin system for ciphern library.
//!
//! This module provides plugin loading and management capabilities.
//! Plugins can extend ciphern with custom cipher implementations.
//!
//! # Example
//!
//! ```ignore
//! use ciphern::plugin::{PluginManager, PluginMetadata};
//!
//! let manager = PluginManager::new();
//! let plugins = manager.list_plugins();
//! ```

#[cfg(feature = "plugin")]
pub mod loader;

#[cfg(feature = "plugin")]
pub use manager::PluginManager;

pub mod manager;

use crate::cipher::provider::SymmetricCipher;
use crate::error::Result;
use crate::types::Algorithm;
use lazy_static::lazy_static;
use std::any::Any;
use std::sync::Arc;

lazy_static! {
    pub static ref PLUGIN_MANAGER: PluginManager = PluginManager::new();
}

/// Plugin trait that all plugins must implement.
///
/// This trait defines the core interface for plugins.
/// Implement this trait to create custom plugins for ciphern.
#[cfg(feature = "plugin")]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn initialize(&mut self) -> Result<()>;
    fn shutdown(&mut self) -> Result<()>;
    fn health_check(&self) -> Result<bool>;
    fn as_any(&self) -> &dyn Any;
}

/// Cipher plugin trait for custom cipher implementations.
///
/// Plugins implementing this trait can provide custom cipher algorithms
/// that integrate with ciphern's plugin system.
#[cfg(feature = "plugin")]
pub trait CipherPlugin: Plugin {
    fn as_symmetric_cipher(&self) -> Arc<dyn SymmetricCipher>;
    fn supported_algorithms(&self) -> Vec<Algorithm>;
}

use serde::{Deserialize, Serialize};

/// Metadata describing a plugin.
///
/// This struct contains information about a plugin loaded from disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(feature = "plugin")]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub dependencies: Vec<String>,
    pub checksum: String,
}

/// Error that can occur when loading a plugin.
#[derive(Debug)]
#[cfg(feature = "plugin")]
pub struct PluginLoadError {
    pub plugin_name: String,
    pub reason: String,
    pub recoverable: bool,
}

impl std::fmt::Display for PluginLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Plugin load error: {} - {}",
            self.plugin_name, self.reason
        )
    }
}

impl std::error::Error for PluginLoadError {}
