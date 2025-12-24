// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::key::derivation::Hkdf;
use crate::{Algorithm, KeyManager};

#[test]
fn test_key_lifecycle() {
    let manager = KeyManager::new().unwrap();

    // Generate
    let key_id = manager.generate_key(Algorithm::AES256GCM).unwrap();

    // Suspend key
    manager.suspend_key(&key_id).unwrap();

    // Resume key
    manager.resume_key(&key_id).unwrap();

    // Destroy
    manager.destroy_key(&key_id).unwrap();

    // Verify destruction
    assert!(manager.get_key(&key_id).is_err());
}

#[test]
fn test_key_derivation_hkdf() {
    let manager = KeyManager::new().unwrap();
    let master_id = manager.generate_key(Algorithm::AES256GCM).unwrap();

    // 获取主密钥
    let master_key = manager.get_key(&master_id).unwrap();

    // 派生不同上下文的密钥
    let derived1 = Hkdf::derive(&master_key, b"", b"context1", Algorithm::AES256GCM).unwrap();
    let derived2 = Hkdf::derive(&master_key, b"", b"context2", Algorithm::AES256GCM).unwrap();

    // 不同上下文应该产生不同密钥
    assert_ne!(
        derived1.secret_bytes().unwrap().as_bytes(),
        derived2.secret_bytes().unwrap().as_bytes()
    );

    // 相同上下文应该产生相同密钥 (确定性)
    let derived1_again = Hkdf::derive(&master_key, b"", b"context1", Algorithm::AES256GCM).unwrap();
    assert_eq!(
        derived1.secret_bytes().unwrap().as_bytes(),
        derived1_again.secret_bytes().unwrap().as_bytes()
    );
}

#[test]
fn test_key_derivation_with_salt() {
    let manager = KeyManager::new().unwrap();
    let master_id = manager.generate_key(Algorithm::AES256GCM).unwrap();
    let master_key = manager.get_key(&master_id).unwrap();

    // 使用不同盐值派生
    let derived1 = Hkdf::derive(&master_key, b"salt1", b"context", Algorithm::AES256GCM).unwrap();
    let derived2 = Hkdf::derive(&master_key, b"salt2", b"context", Algorithm::AES256GCM).unwrap();

    // 不同盐值应该产生不同密钥
    assert_ne!(
        derived1.secret_bytes().unwrap().as_bytes(),
        derived2.secret_bytes().unwrap().as_bytes()
    );
}

#[test]
fn test_key_derivation_different_algorithms() {
    let manager = KeyManager::new().unwrap();
    // 使用ECDSAP384作为主密钥（与UAT测试相同）
    let master_id = manager.generate_key(Algorithm::ECDSAP384).unwrap();
    let master_key = manager.get_key(&master_id).unwrap();

    println!("Master key is_valid: {}", master_key.is_valid());

    // 派生不同算法的密钥 - 使用固定盐值避免超过128字节限制
    let salt = b"test-salt-for-derivation"; // 使用固定盐值

    // 测试所有对称加密算法的密钥派生
    // 现在支持所有密钥长度：16字节、24字节、32字节

    // AES-256 (32字节)
    let derived_aes256 = Hkdf::derive(
        &master_key,
        salt,
        b"aes256-derivation",
        Algorithm::AES256GCM,
    )
    .unwrap();
    assert_eq!(derived_aes256.secret_bytes().unwrap().as_bytes().len(), 32);
    assert!(derived_aes256.is_valid());

    // SM4 (16字节)
    let derived_sm4 =
        Hkdf::derive(&master_key, salt, b"sm4-derivation", Algorithm::SM4GCM).unwrap();
    assert_eq!(derived_sm4.secret_bytes().unwrap().as_bytes().len(), 16);
    assert!(derived_sm4.is_valid());

    // AES-128 (16字节)
    let derived_aes128 = Hkdf::derive(
        &master_key,
        salt,
        b"aes128-derivation",
        Algorithm::AES128GCM,
    )
    .unwrap();
    assert_eq!(derived_aes128.secret_bytes().unwrap().as_bytes().len(), 16);
    assert!(derived_aes128.is_valid());

    // AES-192 (24字节)
    let derived_aes192 = Hkdf::derive(
        &master_key,
        salt,
        b"aes192-derivation",
        Algorithm::AES192GCM,
    )
    .unwrap();
    assert_eq!(derived_aes192.secret_bytes().unwrap().as_bytes().len(), 24);
    assert!(derived_aes192.is_valid());

    // 验证不同算法派生的密钥是不同的
    assert_ne!(
        derived_aes256.secret_bytes().unwrap().as_bytes(),
        derived_aes128.secret_bytes().unwrap().as_bytes()
    );
    assert_ne!(
        derived_aes256.secret_bytes().unwrap().as_bytes(),
        derived_aes192.secret_bytes().unwrap().as_bytes()
    );
    assert_ne!(
        derived_aes128.secret_bytes().unwrap().as_bytes(),
        derived_sm4.secret_bytes().unwrap().as_bytes()
    );
}

#[test]
fn test_key_derivation_deterministic() {
    let manager = KeyManager::new().unwrap();
    let master_id = manager.generate_key(Algorithm::AES256GCM).unwrap();
    let master_key = manager.get_key(&master_id).unwrap();

    // 多次使用相同参数派生应该产生相同结果
    let mut derived_keys = Vec::new();
    for _ in 0..5 {
        let derived = Hkdf::derive(
            &master_key,
            b"test_salt",
            b"test_context",
            Algorithm::AES256GCM,
        )
        .unwrap();
        derived_keys.push(derived.secret_bytes().unwrap().as_bytes().to_vec());
    }

    // 所有派生密钥应该相同
    for i in 1..derived_keys.len() {
        assert_eq!(derived_keys[0], derived_keys[i]);
    }
}

#[test]
fn test_key_derivation_edge_cases() {
    let manager = KeyManager::new().unwrap();
    let master_id = manager.generate_key(Algorithm::AES256GCM).unwrap();
    let master_key = manager.get_key(&master_id).unwrap();

    // 测试空盐值
    let derived_empty_salt =
        Hkdf::derive(&master_key, b"", b"context", Algorithm::AES256GCM).unwrap();
    assert!(!derived_empty_salt
        .secret_bytes()
        .unwrap()
        .as_bytes()
        .is_empty());

    // 测试空上下文
    let derived_empty_context =
        Hkdf::derive(&master_key, b"salt", b"", Algorithm::AES256GCM).unwrap();
    assert!(!derived_empty_context
        .secret_bytes()
        .unwrap()
        .as_bytes()
        .is_empty());

    // 测试长上下文
    let long_context = vec![b'A'; 1000];
    let derived_long_context =
        Hkdf::derive(&master_key, b"salt", &long_context, Algorithm::AES256GCM).unwrap();
    assert!(!derived_long_context
        .secret_bytes()
        .unwrap()
        .as_bytes()
        .is_empty());

    // 测试不同结果
    assert_ne!(
        derived_empty_salt.secret_bytes().unwrap().as_bytes(),
        derived_empty_context.secret_bytes().unwrap().as_bytes()
    );
}

#[test]
fn test_key_derivation_security_properties() {
    let manager = KeyManager::new().unwrap();
    let master_id = manager.generate_key(Algorithm::AES256GCM).unwrap();
    let master_key = manager.get_key(&master_id).unwrap();

    // 测试密钥派生的雪崩效应 - 微小变化应该产生完全不同的结果
    let derived1 = Hkdf::derive(&master_key, b"salt", b"context1", Algorithm::AES256GCM).unwrap();
    let derived2 = Hkdf::derive(&master_key, b"salt", b"context2", Algorithm::AES256GCM).unwrap();

    // 只改变一个字符，结果应该完全不同
    let derived1_bytes = derived1.secret_bytes().unwrap().as_bytes();
    let derived2_bytes = derived2.secret_bytes().unwrap().as_bytes();

    assert_ne!(derived1_bytes, derived2_bytes);

    // 计算不同字节数，应该接近50%（雪崩效应）
    let mut differences = 0;
    for i in 0..derived1_bytes.len().min(derived2_bytes.len()) {
        if derived1_bytes[i] != derived2_bytes[i] {
            differences += 1;
        }
    }

    // 应该至少有75%的字节不同（强雪崩效应）
    let difference_ratio = differences as f64 / derived1_bytes.len() as f64;
    assert!(
        difference_ratio > 0.75,
        "Key derivation should have strong avalanche effect"
    );
}

#[test]
fn test_key_expiration() {
    let manager = KeyManager::new().unwrap();
    let key_id = manager.generate_key(Algorithm::AES256GCM).unwrap();

    // 设置过期时间为未来1小时
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    manager.set_key_expiration(&key_id, expires_at).unwrap();

    let key = manager.get_key(&key_id).unwrap();
    assert!(!key.is_expired());

    // 设置过期时间为过去1小时
    let expires_at = chrono::Utc::now() - chrono::Duration::hours(1);
    manager.set_key_expiration(&key_id, expires_at).unwrap();

    let key = manager.get_key(&key_id).unwrap();
    assert!(key.is_expired());
    assert!(!key.is_valid());
}

#[test]
fn test_key_usage_limit() {
    let manager = KeyManager::new().unwrap();
    let key_id = manager.generate_key(Algorithm::AES256GCM).unwrap();

    // 设置密钥的最大使用次数为3
    manager.set_key_max_usage(&key_id, Some(3)).unwrap();

    // 获取密钥并模拟使用3次
    let mut key = manager.get_key(&key_id).unwrap();
    for _ in 0..3 {
        assert!(key.increment_usage().is_ok());
    }

    // 第4次使用应该失败
    assert!(key.increment_usage().is_err());
    assert!(key.is_usage_exceeded());
}
