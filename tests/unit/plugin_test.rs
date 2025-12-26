// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

#[cfg(test)]
#[cfg(feature = "plugin")]
mod plugin_manager_tests {
    use ciphern::plugin::{Plugin, PluginManager, CipherPlugin, PluginMetadata};
    use ciphern::types::Algorithm;
    use std::sync::Arc;
    use std::any::Any;

    mod test_plugin {
        use super::*;

        pub struct TestPlugin {
            name: String,
            version: String,
            init_count: u32,
            shutdown_count: u32,
            healthy: bool,
        }

        impl TestPlugin {
            pub fn new(name: &str, version: &str, healthy: bool) -> Self {
                Self {
                    name: name.to_string(),
                    version: version.to_string(),
                    init_count: 0,
                    shutdown_count: 0,
                    healthy,
                }
            }
        }

        impl Plugin for TestPlugin {
            fn name(&self) -> &str {
                &self.name
            }

            fn version(&self) -> &str {
                &self.version
            }

            fn initialize(&mut self) -> ciphern::Result<()> {
                self.init_count += 1;
                Ok(())
            }

            fn shutdown(&mut self) -> ciphern::Result<()> {
                self.shutdown_count += 1;
                Ok(())
            }

            fn health_check(&self) -> ciphern::Result<bool> {
                Ok(self.healthy)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        pub struct TestCipherPlugin {
            name: String,
            version: String,
            algorithms: Vec<Algorithm>,
        }

        impl TestCipherPlugin {
            pub fn new(name: &str, algorithms: Vec<Algorithm>) -> Self {
                Self {
                    name: name.to_string(),
                    version: "1.0.0".to_string(),
                    algorithms,
                }
            }
        }

        impl Plugin for TestCipherPlugin {
            fn name(&self) -> &str {
                &self.name
            }

            fn version(&self) -> &str {
                &self.version
            }

            fn initialize(&mut self) -> ciphern::Result<()> {
                Ok(())
            }

            fn shutdown(&mut self) -> ciphern::Result<()> {
                Ok(())
            }

            fn health_check(&self) -> ciphern::Result<bool> {
                Ok(true)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        impl CipherPlugin for TestCipherPlugin {
            fn as_symmetric_cipher(&self) -> Arc<dyn ciphern::cipher::provider::SymmetricCipher> {
                Arc::new(TestCipher::new())
            }

            fn supported_algorithms(&self) -> Vec<Algorithm> {
                self.algorithms.clone()
            }
        }

        pub struct TestCipher;

        impl TestCipher {
            pub fn new() -> Self {
                Self
            }
        }

        impl ciphern::cipher::provider::SymmetricCipher for TestCipher {
            fn encrypt(
                &self,
                _key: &ciphern::key::Key,
                _plaintext: &[u8],
                _iv: Option<&[u8]>,
            ) -> ciphern::Result<Vec<u8>> {
                Ok(vec![])
            }

            fn decrypt(
                &self,
                _key: &ciphern::key::Key,
                _ciphertext: &[u8],
                _iv: Option<&[u8]>,
            ) -> ciphern::Result<Vec<u8>> {
                Ok(vec![])
            }

            fn algorithm(&self) -> Algorithm {
                Algorithm::Aes256Gcm
            }
        }
    }

    use self::test_plugin::{TestCipher, TestCipherPlugin, TestPlugin};

    #[test]
    fn test_plugin_manager_new() {
        let manager = PluginManager::new();
        let plugins = manager.list_plugins();
        assert!(plugins.is_empty());
    }

    #[test]
    fn test_register_plugin() {
        let manager = PluginManager::new();
        let plugin = Arc::new(TestPlugin::new("test_plugin", "1.0.0", true));

        let result = manager.register_plugin(plugin.clone());
        assert!(result.is_ok());

        let plugins = manager.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert!(plugins.contains(&"test_plugin".to_string()));
    }

    #[test]
    fn test_get_plugin() {
        let manager = PluginManager::new();
        let plugin = Arc::new(TestPlugin::new("get_test", "2.0.0", true));
        manager.register_plugin(plugin.clone()).unwrap();

        let retrieved = manager.get_plugin("get_test");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name(), "get_test");
    }

    #[test]
    fn test_get_nonexistent_plugin() {
        let manager = PluginManager::new();
        let retrieved = manager.get_plugin("nonexistent");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_register_multiple_plugins() {
        let manager = PluginManager::new();

        let plugin1 = Arc::new(TestPlugin::new("plugin1", "1.0.0", true));
        let plugin2 = Arc::new(TestPlugin::new("plugin2", "1.0.0", true));
        let plugin3 = Arc::new(TestPlugin::new("plugin3", "1.0.0", true));

        manager.register_plugin(plugin1).unwrap();
        manager.register_plugin(plugin2).unwrap();
        manager.register_plugin(plugin3).unwrap();

        let plugins = manager.list_plugins();
        assert_eq!(plugins.len(), 3);
    }

    #[test]
    fn test_health_check_all() {
        let manager = PluginManager::new();

        let healthy_plugin = Arc::new(TestPlugin::new("healthy", "1.0.0", true));
        let unhealthy_plugin = Arc::new(TestPlugin::new("unhealthy", "1.0.0", false));

        manager.register_plugin(healthy_plugin).unwrap();
        manager.register_plugin(unhealthy_plugin).unwrap();

        let health_results = manager.health_check_all();

        assert_eq!(health_results.get("healthy"), Some(&true));
        assert_eq!(health_results.get("unhealthy"), Some(&false));
    }

    #[test]
    fn test_register_cipher_plugin() {
        let manager = PluginManager::new();
        let algorithms = vec![Algorithm::Aes256Gcm, Algorithm::Sm4Gcm];
        let cipher_plugin = Arc::new(TestCipherPlugin::new("cipher_plugin", algorithms));

        let result = manager.register_cipher_plugin(cipher_plugin.clone());
        assert!(result.is_ok());

        let provider = manager.get_cipher_provider(Algorithm::Aes256Gcm);
        assert!(provider.is_some());
    }

    #[test]
    fn test_graceful_shutdown() {
        let manager = PluginManager::new();
        let plugin = Arc::new(TestPlugin::new("shutdown_test", "1.0.0", true));
        manager.register_plugin(plugin).unwrap();

        let result = manager.graceful_shutdown();
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_trait_object_safety() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<dyn Plugin>>();
        assert_send_sync::<Arc<dyn CipherPlugin>>();
    }
}

#[cfg(test)]
#[cfg(feature = "plugin")]
mod plugin_metadata_tests {
    use ciphern::plugin::PluginMetadata;
    use serde_json;

    #[test]
    fn test_plugin_metadata_serialization() {
        let metadata = PluginMetadata {
            name: "test_plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "Test Author".to_string(),
            description: "A test plugin".to_string(),
            dependencies: vec!["dependency1".to_string()],
            checksum: "abc123".to_string(),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("test_plugin"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn test_plugin_metadata_deserialization() {
        let json = r#"{
            "name": "deser_test",
            "version": "2.0.0",
            "author": "Test Author",
            "description": "A deserialization test",
            "dependencies": ["dep1", "dep2"],
            "checksum": "xyz789"
        }"#;

        let metadata: PluginMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.name, "deser_test");
        assert_eq!(metadata.version, "2.0.0");
        assert_eq!(metadata.author, "Test Author");
        assert_eq!(metadata.dependencies.len(), 2);
    }

    #[test]
    fn test_plugin_metadata_clone() {
        let original = PluginMetadata {
            name: "clone_test".to_string(),
            version: "1.0.0".to_string(),
            author: "Author".to_string(),
            description: "Description".to_string(),
            dependencies: vec![],
            checksum: "checksum".to_string(),
        };

        let cloned = original.clone();
        assert_eq!(cloned.name, original.name);
        assert_eq!(cloned.version, original.version);
    }

    #[test]
    fn test_plugin_metadata_debug() {
        let metadata = PluginMetadata {
            name: "debug_test".to_string(),
            version: "1.0.0".to_string(),
            author: "Author".to_string(),
            description: "Description".to_string(),
            dependencies: vec![],
            checksum: "checksum".to_string(),
        };

        let debug_format = format!("{:?}", metadata);
        assert!(debug_format.contains("debug_test"));
    }
}

#[cfg(test)]
#[cfg(feature = "plugin")]
mod plugin_load_error_tests {
    use ciphern::plugin::PluginLoadError;

    #[test]
    fn test_plugin_load_error_display() {
        let error = PluginLoadError {
            plugin_name: "test_plugin".to_string(),
            reason: "Failed to load".to_string(),
            recoverable: false,
        };

        let display = format!("{}", error);
        assert!(display.contains("test_plugin"));
        assert!(display.contains("Failed to load"));
    }

    #[test]
    fn test_plugin_load_error_debug() {
        let error = PluginLoadError {
            plugin_name: "debug_plugin".to_string(),
            reason: "Debug reason".to_string(),
            recoverable: true,
        };

        let debug_format = format!("{:?}", error);
        assert!(debug_format.contains("debug_plugin"));
        assert!(debug_format.contains("true"));
    }

    #[test]
    fn test_plugin_load_error_recoverable() {
        let recoverable_error = PluginLoadError {
            plugin_name: "recoverable".to_string(),
            reason: "Temporary failure".to_string(),
            recoverable: true,
        };

        let unrecoverable_error = PluginLoadError {
            plugin_name: "unrecoverable".to_string(),
            reason: "Permanent failure".to_string(),
            recoverable: false,
        };

        assert!(recoverable_error.recoverable);
        assert!(!unrecoverable_error.recoverable);
    }
}

#[cfg(test)]
#[cfg(feature = "plugin")]
mod plugin_integration_tests {
    use ciphern::plugin::{PluginManager, Plugin, CipherPlugin, PluginMetadata};
    use ciphern::types::Algorithm;
    use std::sync::Arc;
    use std::any::Any;

    struct IntegrationTestPlugin {
        name: String,
        initialized: bool,
        shutdown: bool,
    }

    impl IntegrationTestPlugin {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                initialized: false,
                shutdown: false,
            }
        }
    }

    impl Plugin for IntegrationTestPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn version(&self) -> &str {
            "1.0.0"
        }

        fn initialize(&mut self) -> ciphern::Result<()> {
            self.initialized = true;
            Ok(())
        }

        fn shutdown(&mut self) -> ciphern::Result<()> {
            self.shutdown = true;
            Ok(())
        }

        fn health_check(&self) -> ciphern::Result<bool> {
            Ok(self.initialized && !self.shutdown)
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_plugin_lifecycle() {
        let manager = PluginManager::new();

        let mut plugin = IntegrationTestPlugin::new("lifecycle_test");
        assert!(!plugin.initialized);

        let plugin_arc = Arc::new(plugin);
        let plugin_for_init = plugin_arc.clone();

        manager.register_plugin(plugin_arc).unwrap();

        let retrieved = manager.get_plugin("lifecycle_test").unwrap();

        assert_eq!(retrieved.name(), "lifecycle_test");
    }

    #[test]
    fn test_health_check_with_plugin_state() {
        let manager = PluginManager::new();

        let plugin = Arc::new(IntegrationTestPlugin::new("state_test"));
        manager.register_plugin(plugin.clone()).unwrap();

        let health = manager.health_check_all();
        assert_eq!(health.get("state_test"), Some(&true));

        assert!(plugin.initialized);
    }

    #[test]
    fn test_duplicate_plugin_registration() {
        let manager = PluginManager::new();

        let plugin1 = Arc::new(IntegrationTestPlugin::new("duplicate"));
        let plugin2 = Arc::new(IntegrationTestPlugin::new("duplicate"));

        manager.register_plugin(plugin1).unwrap();
        manager.register_plugin(plugin2).unwrap();

        let plugins = manager.list_plugins();
        assert_eq!(plugins.len(), 1);
    }

    #[test]
    fn test_empty_plugin_list() {
        let manager = PluginManager::new();
        let plugins = manager.list_plugins();
        assert!(plugins.is_empty());
    }
}

#[cfg(test)]
#[cfg(feature = "plugin")]
mod plugin_edge_case_tests {
    use ciphern::plugin::{PluginManager, Plugin};
    use ciphern::types::Algorithm;
    use std::sync::Arc;
    use std::any::Any;

    struct EdgeCasePlugin {
        name: String,
        health_check_returns: bool,
    }

    impl Plugin for EdgeCasePlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn version(&self) -> &str {
            "0.0.1-alpha"
        }

        fn initialize(&mut self) -> ciphern::Result<()> {
            Ok(())
        }

        fn shutdown(&mut self) -> ciphern::Result<()> {
            Ok(())
        }

        fn health_check(&self) -> ciphern::Result<bool> {
            Ok(self.health_check_returns)
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_plugin_name_with_special_chars() {
        let manager = PluginManager::new();
        let plugin = Arc::new(EdgeCasePlugin {
            name: "plugin-with-special.name_v1".to_string(),
            health_check_returns: true,
        });

        let result = manager.register_plugin(plugin);
        assert!(result.is_ok());

        let retrieved = manager.get_plugin("plugin-with-special.name_v1");
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_health_check_all_empty() {
        let manager = PluginManager::new();
        let results = manager.health_check_all();
        assert!(results.is_empty());
    }

    #[test]
    fn test_get_cipher_provider_empty() {
        let manager = PluginManager::new();
        let provider = manager.get_cipher_provider(Algorithm::Aes256Gcm);
        assert!(provider.is_none());
    }

    #[test]
    fn test_very_long_plugin_name() {
        let manager = PluginManager::new();
        let long_name = "a".repeat(1000);
        let plugin = Arc::new(EdgeCasePlugin {
            name: long_name.clone(),
            health_check_returns: true,
        });

        let result = manager.register_plugin(plugin);
        assert!(result.is_ok());

        let retrieved = manager.get_plugin(&long_name);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_unicode_plugin_name() {
        let manager = PluginManager::new();
        let plugin = Arc::new(EdgeCasePlugin {
            name: "插件_テスト_플러그인".to_string(),
            health_check_returns: true,
        });

        let result = manager.register_plugin(plugin);
        assert!(result.is_ok());
    }
}
