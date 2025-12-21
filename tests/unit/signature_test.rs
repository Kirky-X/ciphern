// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::key::KeyManager;
use ciphern::types::Algorithm;

#[test]
fn test_ecdsa_p384_key_generation() {
    // 测试ECDSA P384密钥生成
    let key_manager = KeyManager::new().unwrap();
    let private_key_id = key_manager.generate_key(Algorithm::ECDSAP384).unwrap();
    
    // 验证密钥存在且状态正确
    let key = key_manager.get_key(&private_key_id).unwrap();
    assert_eq!(key.algorithm(), Algorithm::ECDSAP384);
    assert_eq!(key.state(), ciphern::key::KeyState::Active);
}

#[test]
fn test_sm2_key_generation() {
    // 测试SM2密钥生成
    let key_manager = KeyManager::new().unwrap();
    let private_key_id = key_manager.generate_key(Algorithm::SM2).unwrap();
    
    // 验证密钥存在且状态正确
    let key = key_manager.get_key(&private_key_id).unwrap();
    assert_eq!(key.algorithm(), Algorithm::SM2);
    assert_eq!(key.state(), ciphern::key::KeyState::Active);
}

#[test]
fn test_signature_key_validation() {
    // 测试密钥验证逻辑
    let key_manager = KeyManager::new().unwrap();
    let private_key_id = key_manager.generate_key(Algorithm::ECDSAP384).unwrap();
    
    // 验证密钥存在
    assert!(key_manager.get_key(&private_key_id).is_ok());
    
    // 验证不存在的密钥会失败
    assert!(key_manager.get_key("nonexistent_key").is_err());
}

#[test]
fn test_signature_key_state_transitions() {
    // 测试密钥状态转换
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::ECDSAP384).unwrap();
    
    let key = key_manager.get_key(&key_id).unwrap();
    assert_eq!(key.state(), ciphern::key::KeyState::Active);
    
    // 验证密钥的基本属性
    assert_eq!(key.algorithm(), Algorithm::ECDSAP384);
    assert!(!key.id().is_empty());
}

#[test]
fn test_signature_key_uniqueness() {
    // 测试密钥唯一性
    let key_manager = KeyManager::new().unwrap();
    
    // 生成两个不同的密钥
    let key_id1 = key_manager.generate_key(Algorithm::ECDSAP384).unwrap();
    let key_id2 = key_manager.generate_key(Algorithm::ECDSAP384).unwrap();
    
    // 验证密钥ID不同
    assert_ne!(key_id1, key_id2);
    
    // 验证两个密钥都是有效的
    assert!(key_manager.get_key(&key_id1).is_ok());
    assert!(key_manager.get_key(&key_id2).is_ok());
}

#[test]
fn test_signature_key_algorithm_compatibility() {
    // 测试不同算法的密钥生成
    let key_manager = KeyManager::new().unwrap();
    
    let ecdsa_key = key_manager.generate_key(Algorithm::ECDSAP384).unwrap();
    let sm2_key = key_manager.generate_key(Algorithm::SM2).unwrap();
    
    // 验证不同算法的密钥可以共存
    let ecdsa_key_obj = key_manager.get_key(&ecdsa_key).unwrap();
    let sm2_key_obj = key_manager.get_key(&sm2_key).unwrap();
    
    assert_eq!(ecdsa_key_obj.algorithm(), Algorithm::ECDSAP384);
    assert_eq!(sm2_key_obj.algorithm(), Algorithm::SM2);
}

#[test]
fn test_signature_key_generation_performance() {
    // 测试密钥生成性能
    let key_manager = KeyManager::new().unwrap();
    
    // 生成多个密钥测试性能
    let start = std::time::Instant::now();
    for _ in 0..10 {
        let _key_id = key_manager.generate_key(Algorithm::ECDSAP384).unwrap();
    }
    let duration = start.elapsed();
    
    // 验证所有密钥生成在合理时间内完成
    assert!(duration.as_millis() < 1000); // 应该在1秒内完成
}

#[test]
fn test_signature_key_lifecycle() {
    // 测试密钥生命周期管理
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::ECDSAP384).unwrap();
    
    let key = key_manager.get_key(&key_id).unwrap();
    
    // 验证密钥生命周期状态
    assert!(key.is_valid());
}