//! Double Ratchet Protocol Integration Tests
//!
//! 测试 Double Ratchet 协议的端到端功能，包括：
//! - 完整的加密/解密流程
//! - 状态持久化和恢复
//! - 大消息加密
//! - 状态信息查询

use ciphern::ratchet::{DoubleRatchetState, RatchetConfig};

/// 测试完整的 Double Ratchet 加密会话
///
/// 验证 Alice 和 Bob 之间能够正确进行消息交换，
/// 包括 DH Ratchet 和对称密钥 Ratchet 的完整流程。
#[test]
fn test_complete_session() {
    let config = RatchetConfig::default();
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    // Alice 生成密钥对
    let alice_public = alice.generate_dh_keypair().unwrap();

    // Bob 初始化会话（使用 Alice 的公钥）
    bob.initialize(&alice_public, None, true).unwrap();

    // Bob 生成自己的密钥对
    let bob_public = bob.generate_dh_keypair().unwrap();

    // Alice 初始化响应（使用 Bob 的公钥）
    alice.initialize(&bob_public, None, false).unwrap();

    // 准备发送第一条消息
    alice.prepare_first_message().unwrap();

    // Alice 发送消息给 Bob
    let msg1 = b"Hello, Bob! This is Alice.";
    let encrypted1 = alice.encrypt(msg1).unwrap();
    let decrypted1 = bob.decrypt(&encrypted1).unwrap();
    assert_eq!(&decrypted1, msg1);

    // Bob 回复消息给 Alice
    let msg2 = b"Hi Alice! I received your message.";
    let encrypted2 = bob.encrypt(msg2).unwrap();
    let decrypted2 = alice.decrypt(&encrypted2).unwrap();
    assert_eq!(&decrypted2, msg2);

    // 多轮消息交换
    for i in 0..10 {
        let msg = format!("Message {} from Alice", i + 1);
        let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, msg.as_bytes());

        let reply = format!("Ack {} from Bob", i + 1);
        let encrypted_reply = bob.encrypt(reply.as_bytes()).unwrap();
        let decrypted_reply = alice.decrypt(&encrypted_reply).unwrap();
        assert_eq!(&decrypted_reply, reply.as_bytes());
    }
}

/// 测试状态持久化和恢复
///
/// 验证状态能够正确序列化和反序列化。
#[test]
fn test_state_persistence() {
    let config = RatchetConfig::default();
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    // 初始化会话
    let alice_public = alice.generate_dh_keypair().unwrap();
    bob.initialize(&alice_public, None, true).unwrap();
    let bob_public = bob.generate_dh_keypair().unwrap();
    alice.initialize(&bob_public, None, false).unwrap();
    alice.prepare_first_message().unwrap();

    // 发送一些消息建立会话历史
    for i in 0..3 {
        let msg = format!("Message {}", i);
        let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
        bob.decrypt(&encrypted).unwrap();
    }

    // 保存 Alice 状态
    let alice_state_json = alice.save_state().unwrap();
    let alice_state_binary = alice.save_state_binary().unwrap();

    // 从 JSON 恢复
    let alice_restored = DoubleRatchetState::load_state(&alice_state_json, None).unwrap();

    // 从二进制恢复
    let alice_restored2 = DoubleRatchetState::load_state_binary(&alice_state_binary, None).unwrap();

    // 验证恢复后的状态信息正确
    let info = alice_restored.state_info();
    assert!(info.is_initialized);
    assert!(info.send_message_number > 0);

    // 验证两个恢复的实例状态一致
    let info2 = alice_restored2.state_info();
    assert_eq!(info.send_message_number, info2.send_message_number);
}

/// 测试大消息加密
///
/// 验证能够正确处理较大的消息。
#[test]
fn test_large_message() {
    let config = RatchetConfig::default();
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    // 初始化会话
    let alice_public = alice.generate_dh_keypair().unwrap();
    bob.initialize(&alice_public, None, true).unwrap();
    let bob_public = bob.generate_dh_keypair().unwrap();
    alice.initialize(&bob_public, None, false).unwrap();
    alice.prepare_first_message().unwrap();

    // 1MB 的消息
    let large_msg = vec![0x42u8; 1024 * 1024];
    let encrypted = alice.encrypt(&large_msg).unwrap();
    let decrypted = bob.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted.len(), large_msg.len());
    assert_eq!(&decrypted, &large_msg);
}

/// 测试空消息
///
/// 验证能够正确处理空消息。
#[test]
fn test_empty_message() {
    let config = RatchetConfig::default();
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    // 初始化会话
    let alice_public = alice.generate_dh_keypair().unwrap();
    bob.initialize(&alice_public, None, true).unwrap();
    let bob_public = bob.generate_dh_keypair().unwrap();
    alice.initialize(&bob_public, None, false).unwrap();
    alice.prepare_first_message().unwrap();

    let empty_msg: &[u8] = b"";
    let encrypted = alice.encrypt(empty_msg).unwrap();
    let decrypted = bob.decrypt(&encrypted).unwrap();
    assert!(decrypted.is_empty());
}

/// 测试错误消息解密
///
/// 验证解密错误能够被正确处理。
#[test]
fn test_invalid_message() {
    let config = RatchetConfig::default();
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    // 初始化会话
    let alice_public = alice.generate_dh_keypair().unwrap();
    bob.initialize(&alice_public, None, true).unwrap();
    let bob_public = bob.generate_dh_keypair().unwrap();
    alice.initialize(&bob_public, None, false).unwrap();
    alice.prepare_first_message().unwrap();

    // 创建无效消息（修改密文）
    let mut invalid_message = alice.encrypt(b"valid").unwrap();
    invalid_message.ciphertext[0] ^= 0xFF;

    let result = bob.decrypt(&invalid_message);
    assert!(result.is_err());
}

/// 测试状态信息查询
///
/// 验证能够正确获取状态信息。
#[test]
fn test_state_info() {
    let config = RatchetConfig::default();
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    // 初始化前
    let info_before = alice.state_info();
    assert_eq!(info_before.send_message_number, 0);
    assert!(!info_before.is_initialized);

    // 初始化会话
    let alice_public = alice.generate_dh_keypair().unwrap();
    bob.initialize(&alice_public, None, true).unwrap();
    let bob_public = bob.generate_dh_keypair().unwrap();
    alice.initialize(&bob_public, None, false).unwrap();
    alice.prepare_first_message().unwrap();

    let info_alice = alice.state_info();
    let info_bob = bob.state_info();
    assert!(info_alice.is_initialized);
    assert!(info_bob.is_initialized);

    // Alice 发送消息后
    alice.encrypt(b"test").unwrap();
    let info_after = alice.state_info();
    assert_eq!(info_after.send_message_number, 1);
}

/// 测试多轮消息交换
///
/// 验证长时间会话的正确性。
#[test]
fn test_multiple_message_rounds() {
    let config = RatchetConfig::default();
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    // 初始化会话
    let alice_public = alice.generate_dh_keypair().unwrap();
    bob.initialize(&alice_public, None, true).unwrap();
    let bob_public = bob.generate_dh_keypair().unwrap();
    alice.initialize(&bob_public, None, false).unwrap();
    alice.prepare_first_message().unwrap();

    // 发送 50 条消息
    for i in 0..50 {
        let msg = format!("Round {} - Message from Alice", i);
        let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, msg.as_bytes());
    }
}
