// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::plugin::hot_reload::HotReloadEventType;
use ciphern::plugin::{HotReloadWatcher, PluginLoader, PluginManager, SafeReloadManager};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_plugin_hot_reload_basic() {
    // Create temporary plugin directory
    let temp_dir = tempfile::tempdir().unwrap();
    let plugin_dir = temp_dir.path().join("plugins");
    fs::create_dir(&plugin_dir).unwrap();
    
    // Create test plugin file
    let plugin_path = plugin_dir.join("test_plugin.plugin");
    fs::write(&plugin_path, b"test plugin content").unwrap();
    
    // Test hot reload watcher
    let watcher = HotReloadWatcher::new();
    watcher.watch_plugin(&plugin_path, "test_plugin").unwrap();
    
    // Register reload handler
    let reload_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reload_called_clone = Arc::clone(&reload_called);
    
    watcher.register_reload_handler("test_plugin", move |_| {
        reload_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
    }).unwrap();
    
    // Simulate file change
    thread::sleep(Duration::from_millis(100));
    fs::write(&plugin_path, b"updated plugin content").unwrap();
    
    // Check for changes
    thread::sleep(Duration::from_millis(200));
    let events = watcher.check_for_changes().unwrap();
    
    assert!(!events.is_empty(), "Should detect file change");
    assert_eq!(events[0].plugin_name, "test_plugin");
    assert_eq!(events[0].event_type, HotReloadEventType::FileChanged);
    
    // Process events
    watcher.process_reload_events(events).unwrap();
    
    // Verify reload handler was called
    thread::sleep(Duration::from_millis(100));
    assert!(reload_called.load(std::sync::atomic::Ordering::SeqCst), "Reload handler should be called");
}

#[test]
fn test_plugin_fault_isolation() {
    let manager = PluginManager::new();
    
    // Create test plugin that fails health check
    struct FailingPlugin {
        name: String,
        fail_count: std::sync::atomic::AtomicU32,
    }
    
    impl ciphern::plugin::Plugin for FailingPlugin {
        fn name(&self) -> &str {
            &self.name
        }
        
        fn version(&self) -> &str {
            "1.0.0"
        }
        
        fn initialize(&mut self) -> ciphern::error::Result<()> {
            Ok(())
        }
        
        fn shutdown(&mut self) -> ciphern::error::Result<()> {
            Ok(())
        }
        
        fn health_check(&self) -> ciphern::error::Result<bool> {
            let count = self.fail_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(count < 3) // Fail after 3 checks
        }
        
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
    
    let failing_plugin = Arc::new(FailingPlugin {
        name: "failing_plugin".to_string(),
        fail_count: std::sync::atomic::AtomicU32::new(0),
    });
    
    manager.register_plugin(failing_plugin.clone()).unwrap();
    
    // Initial health check should pass
    let health_results = manager.health_check_all();
    assert_eq!(health_results.len(), 1);
    assert!(*health_results.get("failing_plugin").unwrap(), "Initial health check should pass");
    
    // Multiple health checks should eventually fail
    for _ in 0..5 {
        let _results = manager.health_check_all();
        thread::sleep(Duration::from_millis(10));
    }
    
    // Plugin should be removed after max failures
    let final_health = manager.health_check_all();
    assert!(final_health.is_empty() || !final_health.contains_key("failing_plugin"), 
            "Failing plugin should be removed");
}

#[test]
fn test_safe_reload_manager() {
    let safe_manager = SafeReloadManager::new();
    
    // Create a test plugin stub for lifecycle testing
    struct TestPlugin {
        name: String,
        stable: std::sync::atomic::AtomicBool,
    }
    
    impl ciphern::plugin::Plugin for TestPlugin {
        fn name(&self) -> &str {
            &self.name
        }
        
        fn version(&self) -> &str {
            "1.0.0"
        }
        
        fn initialize(&mut self) -> ciphern::error::Result<()> {
            Ok(())
        }
        
        fn shutdown(&mut self) -> ciphern::error::Result<()> {
            Ok(())
        }
        
        fn health_check(&self) -> ciphern::error::Result<bool> {
            Ok(self.stable.load(std::sync::atomic::Ordering::SeqCst))
        }
        
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
    
    let plugin = Arc::new(TestPlugin {
        name: "test_plugin".to_string(),
        stable: std::sync::atomic::AtomicBool::new(true),
    });
    
    // Stage the plugin
    safe_manager.stage_plugin(plugin.clone()).unwrap();
    
    // Perform health checks
    let stable = safe_manager.wait_for_stability("test_plugin", 3, 100).unwrap();
    assert!(stable, "Plugin should be stable");
    
    // Commit the plugin
    safe_manager.commit_plugin("test_plugin").unwrap();
    
    // Verify plugin is active
    let active_plugin = safe_manager.get_active_plugin("test_plugin");
    assert!(active_plugin.is_some(), "Plugin should be active after commit");
}

#[test]
fn test_plugin_loader_functionality() {
    let temp_dir = tempfile::tempdir().unwrap();
    let plugin_dir = temp_dir.path().join("plugins");
    fs::create_dir(&plugin_dir).unwrap();
    
    // Create multiple plugin files
    for i in 0..3 {
        let plugin_path = plugin_dir.join(format!("plugin_{}.plugin", i));
        fs::write(&plugin_path, format!("plugin content {}", i)).unwrap();
    }
    
    let mut loader = PluginLoader::new(vec![plugin_dir]);
    
    // Load all plugins
    let results = loader.load_all_plugins();
    assert_eq!(results.len(), 3, "Should load all 3 plugins");
    
    // Verify plugins are loaded
    let plugin_names = loader.list_plugins();
    assert_eq!(plugin_names.len(), 3);
    
    // Test plugin retrieval
    for name in &plugin_names {
        let plugin = loader.get_plugin(name);
        assert!(plugin.is_some(), "Should retrieve plugin by name");
        
        if let Some(plugin) = plugin {
            assert_eq!(plugin.name(), name);
            assert_eq!(plugin.version(), "1.0.0");
        }
    }
    
    // Test plugin unloading
    let first_plugin = plugin_names[0].clone();
    loader.unload_plugin(&first_plugin).unwrap();
    
    let remaining_plugins = loader.list_plugins();
    assert_eq!(remaining_plugins.len(), 2);
    assert!(!remaining_plugins.contains(&first_plugin), "Plugin should be unloaded");
}

#[test]
fn test_plugin_manager_integration() {
    let manager = PluginManager::new();
    
    // Create and register multiple plugins
    for i in 0..5 {
        struct TestPlugin {
            name: String,
        }
        
        impl ciphern::plugin::Plugin for TestPlugin {
            fn name(&self) -> &str {
                &self.name
            }
            
            fn version(&self) -> &str {
                "1.0.0"
            }
            
            fn initialize(&mut self) -> ciphern::error::Result<()> {
                Ok(())
            }
            
            fn shutdown(&mut self) -> ciphern::error::Result<()> {
                Ok(())
            }
            
            fn health_check(&self) -> ciphern::error::Result<bool> {
                Ok(true)
            }
            
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
        
        let plugin = Arc::new(TestPlugin {
            name: format!("test_plugin_{}", i),
        });
        
        manager.register_plugin(plugin).unwrap();
    }
    
    // List all plugins
    let plugin_names = manager.list_plugins();
    assert_eq!(plugin_names.len(), 5, "Should have 5 registered plugins");
    
    // Health check all plugins
    let health_results = manager.health_check_all();
    assert_eq!(health_results.len(), 5);
    
    for (name, is_healthy) in health_results {
        assert!(is_healthy, "Plugin {} should be healthy", name);
    }
    
    // Test graceful shutdown
    manager.graceful_shutdown().unwrap();
}