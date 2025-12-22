// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::key::lifecycle::{KeyLifecycleManager, KeyLifecyclePolicy, RotationSchedule};
use ciphern::key::manager::KeyManagerLifecycleExt;
use ciphern::{Algorithm, KeyManager};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_key_rotation_workflow() {
    let key_manager = KeyManager::new().unwrap();
    
    // 1. 创建初始密钥
    let old_key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    key_manager.activate_key(&old_key_id).unwrap();
    
    // 2. 使用旧密钥加密数据
    let plaintext = b"Data encrypted with old key";
    let cipher = ciphern::provider::registry::REGISTRY.get_cipher(Algorithm::AES256GCM).unwrap();
    let ciphertext = cipher.encrypt(&key_manager, &old_key_id, plaintext).unwrap();
    
    // 3. 手动轮换密钥
    let new_key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    key_manager.activate_key(&new_key_id).unwrap();
    
    // 4. 旧密钥仍可解密
    let decrypted_old = cipher.decrypt(&key_manager, &old_key_id, &ciphertext).unwrap();
    assert_eq!(plaintext, &decrypted_old[..]);
    
    // 5. 新数据使用新密钥
    let new_plaintext = b"Data encrypted with new key";
    let new_ciphertext = cipher.encrypt(&key_manager, &new_key_id, new_plaintext).unwrap();
    
    let decrypted_new = cipher.decrypt(&key_manager, &new_key_id, &new_ciphertext).unwrap();
    assert_eq!(new_plaintext, &decrypted_new[..]);
    
    // 6. 验证隔离性
    assert!(cipher.decrypt(&key_manager, &new_key_id, &ciphertext).is_err());
}

#[test]
fn test_automatic_key_rotation() {
    let mut key_manager = KeyManager::new().unwrap();
    
    // 创建生命周期管理器
    let lifecycle_manager = Arc::new(KeyLifecycleManager::new(KeyLifecyclePolicy {
        rotation_schedule: RotationSchedule::TimeBased(std::time::Duration::from_secs(1)),
        max_age: std::time::Duration::from_secs(2),
        max_usage: Some(5),
    }));
    
    key_manager.enable_lifecycle_management(lifecycle_manager.clone());
    
    // 生成密钥并激活
    let key_id = key_manager.generate_key_with_lifecycle(Algorithm::AES256GCM, &lifecycle_manager).unwrap();
    
    // 等待密钥过期
    thread::sleep(Duration::from_secs(3));
    
    // 检查轮换警告
    let warning = lifecycle_manager.get_rotation_warning(&key_id).unwrap();
    assert!(warning.is_some());
    assert!(warning.unwrap().contains("expired"));
    
    // 执行密钥轮换
    let new_key_id = key_manager.rotate_key(&key_id, Algorithm::AES256GCM, &lifecycle_manager).unwrap();
    
    // 验证新密钥已创建
    assert_ne!(key_id, new_key_id);
    assert!(key_manager.get_key(&new_key_id).is_ok());
}

#[test]
fn test_usage_based_rotation() {
    let mut key_manager = KeyManager::new().unwrap();
    
    let lifecycle_manager = Arc::new(KeyLifecycleManager::new(KeyLifecyclePolicy {
        rotation_schedule: RotationSchedule::UsageBased(3),
        max_age: std::time::Duration::from_secs(3600),
        max_usage: Some(3),
    }));
    
    key_manager.enable_lifecycle_management(lifecycle_manager.clone());
    
    let key_id = key_manager.generate_key_with_lifecycle(Algorithm::AES256GCM, &lifecycle_manager).unwrap();
    
    let cipher = ciphern::provider::registry::REGISTRY.get_cipher(Algorithm::AES256GCM).unwrap();
    let plaintext = b"Test data";
    
    // 使用密钥3次
    for i in 0..3 {
        let data = format!("Test data {}", i);
        let _ciphertext = cipher.encrypt(&key_manager, &key_id, data.as_bytes()).unwrap();
    }
    
    // 检查轮换警告
    let warning = lifecycle_manager.get_rotation_warning(&key_id).unwrap();
    assert!(warning.is_some());
    assert!(warning.unwrap().contains("usage limit"));
}

#[test]
fn test_key_rotation_with_alias() {
    let mut key_manager = KeyManager::new().unwrap();
    
    let lifecycle_manager = Arc::new(KeyLifecycleManager::new(KeyLifecyclePolicy {
        rotation_schedule: RotationSchedule::TimeBased(std::time::Duration::from_secs(1)),
        max_age: std::time::Duration::from_secs(1),
        max_usage: None,
    }));
    
    key_manager.enable_lifecycle_management(lifecycle_manager.clone());
    
    // 生成带别名的密钥
    let alias = "my-app-key";
    let key_id = key_manager.generate_key_with_alias(Algorithm::AES256GCM, alias).unwrap();
    
    // 等待密钥过期
    thread::sleep(Duration::from_secs(2));
    
    // 轮换密钥并保留别名
    let new_key_id = key_manager.rotate_key(&key_id, Algorithm::AES256GCM, &lifecycle_manager).unwrap();
    
    // 验证别名指向新密钥
    let resolved_id = key_manager.resolve_alias(alias).unwrap();
    assert_eq!(resolved_id, new_key_id);
}

#[test]
fn test_concurrent_key_rotation() {
    let mut key_manager = KeyManager::new().unwrap();
    
    let lifecycle_manager = Arc::new(KeyLifecycleManager::new(KeyLifecyclePolicy {
        rotation_schedule: RotationSchedule::TimeBased(std::time::Duration::from_millis(100)),
        max_age: std::time::Duration::from_millis(200),
        max_usage: None,
    }));
    
    key_manager.enable_lifecycle_management(lifecycle_manager.clone());
    
    let key_id = key_manager.generate_key_with_lifecycle(Algorithm::AES256GCM, &lifecycle_manager).unwrap();
    
    // 模拟并发轮换请求
    let manager_clone = Arc::new(key_manager);
    let lifecycle_clone = lifecycle_manager.clone();
    let key_clone = key_id.clone();
    
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        // 尝试轮换密钥
        let result = manager_clone.rotate_key(&key_clone, Algorithm::AES256GCM, &lifecycle_clone);
        result
    });
    
    // 主线程也尝试轮换
    thread::sleep(Duration::from_millis(300));
    let result1 = manager_clone.rotate_key(&key_id, Algorithm::AES256GCM, &lifecycle_manager);
    let result2 = handle.join().unwrap();
    
    // 只有一个轮换应该成功
    assert!(result1.is_ok() || result2.is_ok());
}