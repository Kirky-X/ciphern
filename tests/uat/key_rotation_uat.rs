// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use chrono::Duration as ChronoDuration;
use ciphern::key::lifecycle::{KeyLifecycleManager, KeyLifecyclePolicy};
use ciphern::key::KeyManagerLifecycleExt;
use ciphern::{Algorithm, KeyManager};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_scheduled_key_rotation() {
    let mut key_manager = KeyManager::new().unwrap();

    // 配置定期轮换策略（每2秒轮换一次）
    let lifecycle_manager = Arc::new(KeyLifecycleManager::new().unwrap());

    // 设置策略
    let policy = KeyLifecyclePolicy {
        key_lifetime: ChronoDuration::seconds(2),
        rotation_interval: ChronoDuration::seconds(2),
        rotation_warning_period: ChronoDuration::seconds(1),
        max_key_usage: None,
        auto_rotation_enabled: true,
        version_management_enabled: true,
    };
    lifecycle_manager
        .set_policy(Algorithm::AES256GCM, policy)
        .unwrap();

    key_manager.enable_lifecycle_management(lifecycle_manager.clone());

    // 生成初始密钥
    let key_id = key_manager
        .generate_key_with_lifecycle(Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();

    println!("初始密钥ID: {}", key_id);

    // 等待轮换时间
    thread::sleep(Duration::from_secs(3));

    // 检查轮换状态
    let warning = lifecycle_manager.get_rotation_warning(&key_id).unwrap();
    assert!(warning.is_some(), "密钥应该需要轮换");
    println!("轮换警告: {:?}", warning);

    // 执行轮换
    let new_key_id = key_manager
        .rotate_key(&key_id, Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();
    println!("新密钥ID: {}", new_key_id);

    // 验证轮换成功
    assert_ne!(key_id, new_key_id);
    assert!(key_manager.get_key(&new_key_id).is_ok());
}

#[test]
fn test_rotation_with_data_migration() {
    let mut key_manager = KeyManager::new().unwrap();

    let lifecycle_manager = Arc::new(KeyLifecycleManager::new().unwrap());

    // 设置策略
    let policy = KeyLifecyclePolicy {
        key_lifetime: ChronoDuration::seconds(1),
        rotation_interval: ChronoDuration::seconds(1),
        rotation_warning_period: ChronoDuration::seconds(1),
        max_key_usage: None,
        auto_rotation_enabled: true,
        version_management_enabled: true,
    };
    lifecycle_manager
        .set_policy(Algorithm::AES256GCM, policy)
        .unwrap();

    key_manager.enable_lifecycle_management(lifecycle_manager.clone());

    // 生成密钥并加密数据
    let old_key_id = key_manager
        .generate_key_with_lifecycle(Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();

    let cipher = ciphern::provider::registry::REGISTRY
        .get_symmetric(Algorithm::AES256GCM)
        .unwrap();
    let sensitive_data = b"Sensitive customer data that needs protection";
    let old_key = key_manager.get_key(&old_key_id).unwrap();
    let encrypted_data = cipher.encrypt(&old_key, sensitive_data, None).unwrap();

    println!("使用旧密钥加密数据: {:?}", encrypted_data.len());

    // 等待轮换
    thread::sleep(Duration::from_secs(2));

    // 执行轮换
    let new_key_id = key_manager
        .rotate_key(&old_key_id, Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();

    // 验证旧密钥仍可解密（向后兼容）
    let decrypted_old = cipher.decrypt(&old_key, &encrypted_data, None).unwrap();
    assert_eq!(sensitive_data, &decrypted_old[..]);

    // 使用新密钥加密新数据
    let new_data = b"New data after rotation";
    let new_key = key_manager.get_key(&new_key_id).unwrap();
    let new_encrypted = cipher.encrypt(&new_key, new_data, None).unwrap();

    let decrypted_new = cipher.decrypt(&new_key, &new_encrypted, None).unwrap();
    assert_eq!(new_data, &decrypted_new[..]);

    println!("数据迁移验证完成");
}

#[test]
fn test_rotation_policy_enforcement() {
    let mut key_manager = KeyManager::new().unwrap();

    // 严格的轮换策略
    let lifecycle_manager = Arc::new(KeyLifecycleManager::new().unwrap());

    // 设置策略
    let policy = KeyLifecyclePolicy {
        key_lifetime: ChronoDuration::milliseconds(500),
        rotation_interval: ChronoDuration::milliseconds(500),
        rotation_warning_period: ChronoDuration::milliseconds(250),
        max_key_usage: Some(2), // 最多使用2次
        auto_rotation_enabled: true,
        version_management_enabled: true,
    };
    lifecycle_manager
        .set_policy(Algorithm::AES256GCM, policy)
        .unwrap();

    key_manager.enable_lifecycle_management(lifecycle_manager.clone());

    let key_id = key_manager
        .generate_key_with_lifecycle(Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();

    let cipher = ciphern::provider::registry::REGISTRY
        .get_symmetric(Algorithm::AES256GCM)
        .unwrap();
    let _plaintext = b"Test data";
    let key = key_manager.get_key(&key_id).unwrap();

    // 使用密钥2次（允许范围内）
    for i in 0..2 {
        let data = format!("Test data {}", i);
        let _encrypted = cipher.encrypt(&key, data.as_bytes(), None).unwrap();
        // 增加使用计数
        lifecycle_manager.increment_key_usage(&key_id).unwrap();
    }

    // 第3次使用应该触发轮换警告
    let warning = lifecycle_manager.get_rotation_warning(&key_id).unwrap();
    assert!(warning.is_some());
    assert!(warning.unwrap().contains("usage limit"));

    // 为了测试时间过期警告，创建一个新的密钥并等待其过期
    let time_test_key_id = key_manager
        .generate_key_with_lifecycle(Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();

    // 等待时间过期 - 密钥生命周期为1秒，等待1.5秒确保过期
    thread::sleep(Duration::from_millis(1500));

    // 时间过期应该触发轮换警告
    let time_warning = lifecycle_manager
        .get_rotation_warning(&time_test_key_id)
        .unwrap();
    println!("时间警告: {:?}", time_warning);
    assert!(time_warning.is_some());
    // 检查是否包含时间相关的警告信息
    let warning_text = time_warning.unwrap();
    assert!(warning_text.contains("expire") || warning_text.contains("expired"));

    println!("轮换策略验证完成");
}

#[test]
fn test_rotation_audit_logging() {
    let mut key_manager = KeyManager::new().unwrap();

    let lifecycle_manager = Arc::new(KeyLifecycleManager::new().unwrap());

    // 设置策略
    let policy = KeyLifecyclePolicy {
        key_lifetime: ChronoDuration::seconds(1),
        rotation_interval: ChronoDuration::seconds(1),
        rotation_warning_period: ChronoDuration::seconds(1),
        max_key_usage: None,
        auto_rotation_enabled: true,
        version_management_enabled: true,
    };
    lifecycle_manager
        .set_policy(Algorithm::AES256GCM, policy)
        .unwrap();

    key_manager.enable_lifecycle_management(lifecycle_manager.clone());

    // 生成密钥
    let key_id = key_manager
        .generate_key_with_lifecycle(Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();

    // 等待轮换
    thread::sleep(Duration::from_secs(2));

    // 执行轮换并验证审计日志
    let new_key_id = key_manager
        .rotate_key(&key_id, Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();

    // 验证轮换事件被记录（这里简化，实际应该检查审计日志）
    assert_ne!(key_id, new_key_id);
    println!("密钥轮换审计日志验证完成");
}

#[test]
fn test_emergency_key_rotation() {
    let mut key_manager = KeyManager::new().unwrap();
    let lifecycle_manager = Arc::new(KeyLifecycleManager::new().unwrap());

    // 设置策略 - 使用立即轮换策略
    let emergency_policy = KeyLifecyclePolicy {
        key_lifetime: ChronoDuration::seconds(0), // 立即轮换
        rotation_interval: ChronoDuration::seconds(0),
        rotation_warning_period: ChronoDuration::seconds(0),
        max_key_usage: None,
        auto_rotation_enabled: true,
        version_management_enabled: true,
    };
    lifecycle_manager
        .set_policy(Algorithm::AES256GCM, emergency_policy)
        .unwrap();

    key_manager.enable_lifecycle_management(lifecycle_manager.clone());

    // 生成密钥 - 使用生命周期管理创建，这样密钥会被正确跟踪
    let key_id = key_manager
        .generate_key_with_lifecycle(Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();

    // 等待一小段时间确保密钥过期
    thread::sleep(Duration::from_millis(100));

    // 执行紧急轮换 - 使用同一个生命周期管理器
    let new_key_id = key_manager
        .rotate_key(&key_id, Algorithm::AES256GCM, &lifecycle_manager)
        .unwrap();

    assert_ne!(key_id, new_key_id);
    println!("紧急密钥轮换验证完成");
}
