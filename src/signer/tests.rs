// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::provider::REGISTRY;
use crate::key::KeyState;
use crate::{key::KeyManager, Algorithm};

#[test]
fn test_sm2_key_generation() {
    // 测试SM2密钥生成
    let key_manager = KeyManager::new().unwrap();
    let private_key_id = key_manager.generate_key(Algorithm::SM2).unwrap();

    // 验证密钥存在且状态正确
    let key = key_manager.get_key(&private_key_id).unwrap();
    assert_eq!(key.algorithm(), Algorithm::SM2);
    assert_eq!(key.state(), KeyState::Active);
}

#[test]
fn test_sm2_signature_and_verification() {
    // 测试SM2签名和验证
    let key_manager = KeyManager::new().unwrap();
    let private_key_id = key_manager.generate_key(Algorithm::SM2).unwrap();
    let key = key_manager.get_key(&private_key_id).unwrap();

    // 测试消息
    let message = b"Hello, SM2 signature!";

    // 获取签名器
    let signer = REGISTRY.get_signer(Algorithm::SM2).unwrap();

    // 签名
    let signature = signer.sign(&key, message).unwrap();

    // 验证签名长度 (64字节 = 32字节r + 32字节s)
    assert_eq!(signature.len(), 64);

    // 验证签名
    let is_valid = signer.verify(&key, message, &signature).unwrap();
    assert!(is_valid);

    // 验证修改后的消息签名失败
    let modified_message = b"Hello, modified message!";
    let is_invalid = signer.verify(&key, modified_message, &signature).unwrap();
    assert!(!is_invalid);
}

#[test]
fn test_sm2_signature_with_different_messages() {
    // 测试SM2对不同消息的签名
    let key_manager = KeyManager::new().unwrap();
    let private_key_id = key_manager.generate_key(Algorithm::SM2).unwrap();
    let key = key_manager.get_key(&private_key_id).unwrap();

    let signer = REGISTRY.get_signer(Algorithm::SM2).unwrap();

    // 测试不同长度的消息
    let messages: Vec<&[u8]> = vec![
        b"Short message".as_ref(),
        b"This is a longer message for SM2 signature testing".as_ref(),
        b"A very long message that contains many characters and should test the robustness of the SM2 signature implementation with various input sizes".as_ref(),
    ];

    for message in messages {
        let signature = signer.sign(&key, message).unwrap();
        assert_eq!(signature.len(), 64);

        let is_valid = signer.verify(&key, message, &signature).unwrap();
        assert!(
            is_valid,
            "Signature verification failed for message: {:?}",
            message
        );
    }
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
    assert_eq!(key.state(), KeyState::Active);

    // 验证密钥的基本属性
    assert_eq!(key.algorithm(), Algorithm::ECDSAP384);
    assert!(!key.id().is_empty());
}

#[test]
fn test_algorithm_key_compatibility() {
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
