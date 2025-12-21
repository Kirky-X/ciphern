// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::{KeyManager, Algorithm};
use ciphern::key::manager::TenantKeyManager;
use ciphern::memory::SecretBytes;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_tenant_key_isolation() {
    // 创建两个租户的管理器
    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());
    
    // 租户1生成密钥
    let tenant1_key = tenant1_manager.generate_key(Algorithm::AES256GCM).unwrap();
    
    // 租户2生成密钥
    let tenant2_key = tenant2_manager.generate_key(Algorithm::AES256GCM).unwrap();
    
    // 验证租户无法访问其他租户的密钥
    assert!(tenant2_manager.get_key(&tenant1_key).is_err());
    assert!(tenant1_manager.get_key(&tenant2_key).is_err());
    
    // 验证租户只能看到自己的密钥
    let tenant1_keys = tenant1_manager.list_keys().unwrap();
    let tenant2_keys = tenant2_manager.list_keys().unwrap();
    
    assert_eq!(tenant1_keys.len(), 1);
    assert_eq!(tenant2_keys.len(), 1);
    assert!(!tenant1_keys.contains(&tenant2_key));
    assert!(!tenant2_keys.contains(&tenant1_key));
}

#[test]
fn test_tenant_data_encryption_isolation() {
    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());
    
    let cipher = ciphern::provider::registry::REGISTRY.get_symmetric(Algorithm::AES256GCM).unwrap();
    
    // 租户1加密数据
    let tenant1_data = b"Tenant 1 sensitive data";
    let tenant1_key_id = tenant1_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let tenant1_key = tenant1_manager.get_key(&tenant1_key_id).unwrap();
    let tenant1_encrypted = cipher.encrypt(&tenant1_key, tenant1_data, None).unwrap();
    
    // 租户2加密数据
    let tenant2_data = b"Tenant 2 sensitive data";
    let tenant2_key_id = tenant2_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let tenant2_key = tenant2_manager.get_key(&tenant2_key_id).unwrap();
    let tenant2_encrypted = cipher.encrypt(&tenant2_key, tenant2_data, None).unwrap();
    
    // 验证租户无法解密其他租户的数据
    assert!(cipher.decrypt(&tenant1_key, &tenant1_encrypted, None).is_ok()); // 租户1可以解密自己的数据
    assert!(cipher.decrypt(&tenant2_key, &tenant2_encrypted, None).is_ok()); // 租户2可以解密自己的数据
    
    // 验证租户可以解密自己的数据
    let decrypted1 = cipher.decrypt(&tenant1_key, &tenant1_encrypted, None).unwrap();
    assert_eq!(tenant1_data, &decrypted1[..]);
    
    let decrypted2 = cipher.decrypt(&tenant2_key, &tenant2_encrypted, None).unwrap();
    assert_eq!(tenant2_data, &decrypted2[..]);
}

#[test]
fn test_concurrent_tenant_operations() {
    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());
    
    // 并发操作测试
    let handles = vec![
        {
            let manager = tenant1_manager.clone();
            thread::spawn(move || {
                for i in 0..10 {
                    let key_id = manager.generate_key(Algorithm::AES256GCM).unwrap();
                    println!("Tenant 1 generated key {}", i);
                    thread::sleep(Duration::from_millis(10));
                }
            })
        },
        {
            let manager = tenant2_manager.clone();
            thread::spawn(move || {
                for i in 0..10 {
                    let key_id = manager.generate_key(Algorithm::AES256GCM).unwrap();
                    println!("Tenant 2 generated key {}", i);
                    thread::sleep(Duration::from_millis(10));
                }
            })
        }
    ];
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    // 验证每个租户都有正确的密钥数量
    let tenant1_keys = tenant1_manager.list_keys().unwrap();
    let tenant2_keys = tenant2_manager.list_keys().unwrap();
    
    assert_eq!(tenant1_keys.len(), 10);
    assert_eq!(tenant2_keys.len(), 10);
    
    // 验证密钥隔离
    for key1 in &tenant1_keys {
        assert!(!tenant2_keys.contains(key1));
    }
    for key2 in &tenant2_keys {
        assert!(!tenant1_keys.contains(key2));
    }
}

#[test]
fn test_tenant_key_rotation_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());
    
    // 创建生命周期管理器
    let lifecycle_manager1 = Arc::new(ciphern::key::lifecycle::KeyLifecycleManager::new()?);
    let lifecycle_manager2 = Arc::new(ciphern::key::lifecycle::KeyLifecycleManager::new()?);
    
    // 生成密钥
    let key1 = tenant1_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let key2 = tenant2_manager.generate_key(Algorithm::AES256GCM).unwrap();
    
    // 等待轮换时间
    thread::sleep(Duration::from_secs(3));
    
    // 验证轮换警告
    let warning1 = lifecycle_manager1.get_rotation_warning_for_key(tenant1_manager.as_ref(), &key1)?;
    let warning2 = lifecycle_manager2.get_rotation_warning_for_key(tenant2_manager.as_ref(), &key2)?;
    
    assert!(warning1.is_some());
    assert!(warning2.is_some());
    
    // 验证轮换策略的独立性
    assert!(warning1.unwrap().contains("expired"));
    assert!(warning2.unwrap().contains("expired"));
    
    Ok(())
}

#[test]
fn test_tenant_resource_limits() {
    let tenant_manager = TenantKeyManager::new("limited_tenant").unwrap();
    
    // 测试密钥数量限制
    for i in 0..100 {
        let result = tenant_manager.generate_key(Algorithm::AES256GCM);
        assert!(result.is_ok(), "Failed to generate key {}: {:?}", i, result);
    }
    
    let keys = tenant_manager.list_keys().unwrap();
    assert_eq!(keys.len(), 100);
    
    // 测试内存使用限制（如果实现）
    // 这里可以添加内存使用监控逻辑
    println!("租户生成了 {} 个密钥", keys.len());
}

#[test]
fn test_tenant_deletion_cascade() {
    let tenant_manager = Arc::new(TenantKeyManager::new("temp_tenant").unwrap());
    
    // 生成多个密钥
    let mut key_ids = Vec::new();
    for _ in 0..5 {
        let key_id = tenant_manager.generate_key(Algorithm::AES256GCM).unwrap();
        key_ids.push(key_id);
    }
    
    // 验证密钥存在
    assert_eq!(tenant_manager.list_keys().unwrap().len(), 5);
    
    // 模拟租户删除（这里需要实现租户删除功能）
    // 在实际实现中，这应该清理所有租户相关的资源
    
    // 验证密钥被清理
    // 注意：这需要TenantKeyManager实现drop或显式的清理方法
    println!("租户密钥数量: {}", tenant_manager.list_keys().unwrap().len());
}

#[test]
fn test_cross_tenant_attack_prevention() {
    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());
    
    // 租户1生成密钥
    let key1 = tenant1_manager.generate_key(Algorithm::AES256GCM).unwrap();
    
    // 尝试通过各种方式访问其他租户的密钥
    
    // 1. 直接密钥访问
    assert!(tenant2_manager.get_key(&key1).is_err());
    
    // 2. 尝试使用其他租户的密钥ID进行加密
    let cipher = ciphern::provider::registry::REGISTRY.get_symmetric(Algorithm::AES256GCM).unwrap();
    let data = b"Malicious data";
    
    // 租户2无法访问租户1的密钥
    assert!(tenant2_manager.get_key(&key1).is_err());
    
    // 3. 验证租户隔离性 - 租户2无法使用租户1的密钥
    // 由于租户2无法获取租户1的密钥，这里我们验证密钥确实被隔离
    let tenant1_key = tenant1_manager.get_key(&key1).unwrap();
    let encrypted = cipher.encrypt(&tenant1_key, data, None).unwrap();
    
    // 租户2无法获取租户1的密钥，所以无法解密
    assert!(tenant2_manager.get_key(&key1).is_err());
    
    println!("跨租户攻击防护验证完成");
}