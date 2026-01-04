//! Double Ratchet Protocol Demo
//!
//! 此示例演示如何使用 ciphern 库实现 Double Ratchet 协议。
//! Double Ratchet（双棘轮）协议是 Signal Protocol 的核心组件，
//! 提供前向安全（forward secrecy）和后向安全（future secrecy）的消息加密。
//!
//! 运行方式:
//! ```bash
//! cargo run --example double_ratchet_demo
//! ```

use ciphern::ratchet::{DoubleRatchetState, RatchetConfig};

fn main() {
    println!("=== Double Ratchet Protocol Demo ===\n");

    // 创建配置
    let config = RatchetConfig::default();

    // 创建通信双方
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    println!("1. 初始化会话");

    // Alice 生成密钥对
    let alice_public = alice.generate_dh_keypair().unwrap();
    println!("   Alice 生成密钥对: {:?}", &alice_public[0..8]);

    // Bob 初始化会话（使用 Alice 的公钥）
    bob.initialize(&alice_public, None, true).unwrap();
    println!("   Bob 使用 Alice 的公钥初始化");

    // Bob 生成自己的密钥对
    let bob_public = bob.generate_dh_keypair().unwrap();
    println!("   Bob 生成密钥对: {:?}", &bob_public[0..8]);

    // Alice 初始化响应（使用 Bob 的公钥）
    alice.initialize(&bob_public, None, false).unwrap();
    println!("   Alice 使用 Bob 的公钥初始化");

    // 准备发送第一条消息
    alice.prepare_first_message().unwrap();
    println!("   ✓ 会话已建立");

    println!("\n2. 发送和接收消息");
    println!("   ─────────────────────────────────────");

    // 发送消息
    let messages = [
        "你好，Bob！这是加密消息。",
        "这条消息使用 Double Ratchet 协议加密。",
        "即使有人截获了之前的密钥，也无法解密这条消息。",
        "每条消息都使用不同的密钥加密。",
        "这就是前向安全（Forward Secrecy）。",
    ];

    for (i, msg) in messages.iter().enumerate() {
        // Alice 加密
        let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
        println!(
            "   [Alice -> Bob] 消息 {}: {} 字节",
            i + 1,
            encrypted.ciphertext.len()
        );

        // Bob 解密
        let decrypted = bob.decrypt(&encrypted).unwrap();
        println!("   [Bob 收到] {}", String::from_utf8_lossy(&decrypted));

        // Bob 回复
        let reply = format!("已收到消息 {}", i + 1);
        let reply_encrypted = bob.encrypt(reply.as_bytes()).unwrap();
        let reply_decrypted = alice.decrypt(&reply_encrypted).unwrap();
        println!(
            "   [Bob -> Alice] {}",
            String::from_utf8_lossy(&reply_decrypted)
        );
    }

    println!("\n3. 状态持久化");
    println!("   ─────────────────────────────────────");

    // 保存状态
    let state_json = alice.save_state().unwrap();
    let state_binary = alice.save_state_binary().unwrap();
    println!("   JSON 状态大小: {} 字节", state_json.len());
    println!("   二进制状态大小: {} 字节", state_binary.len());

    // 恢复状态
    let mut alice_restored = DoubleRatchetState::load_state(&state_json, None).unwrap();
    let mut bob_restored = DoubleRatchetState::load_state_binary(&state_binary, None).unwrap();

    println!("   ✓ 状态已保存并恢复");

    // 使用恢复的状态继续通信
    let msg = "这是状态恢复后发送的消息。";
    let encrypted = alice_restored.encrypt(msg.as_bytes()).unwrap();
    let decrypted = bob_restored.decrypt(&encrypted).unwrap();
    println!(
        "   ✓ 恢复后通信正常: {}",
        String::from_utf8_lossy(&decrypted)
    );

    println!("\n4. 安全特性演示");
    println!("   ─────────────────────────────────────");
    println!("   ✓ 前向安全 (Forward Secrecy): 旧密钥泄露不影响新消息");
    println!("   ✓ 后向安全 (Future Secrecy): 定期更新密钥");
    println!("   ✓ 唯一密钥: 每条消息使用独立的加密密钥");
    println!("   ✓ 消息认证: 防止消息篡改");

    println!("\n=== 演示完成 ===");
}

/// 运行同步通信示例
///
/// 展示 Alice 和 Bob 之间同步发送消息的场景。
pub fn run_synchronous_example() {
    println!("\n--- 同步通信示例 ---\n");

    let config = RatchetConfig::default();
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    // 初始化会话
    let alice_public = alice.generate_dh_keypair().unwrap();
    bob.initialize(&alice_public, None, true).unwrap();
    let bob_public = bob.generate_dh_keypair().unwrap();
    alice.initialize(&bob_public, None, false).unwrap();
    alice.prepare_first_message().unwrap();

    // 同步消息交换
    for i in 1..=5 {
        let msg = format!("同步消息 #{}", i);
        let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();

        let reply = format!("回复 #{}", i);
        let reply_encrypted = bob.encrypt(reply.as_bytes()).unwrap();
        let reply_decrypted = alice.decrypt(&reply_encrypted).unwrap();

        println!("   {} -> {}", msg, String::from_utf8_lossy(&decrypted));
        println!(
            "   {} -> {}",
            reply,
            String::from_utf8_lossy(&reply_decrypted)
        );
    }
}

/// 运行异步消息示例
///
/// 展示处理乱序到达消息的场景。
pub fn run_asynchronous_example() {
    println!("\n--- 异步消息示例 ---\n");

    let config = RatchetConfig::default();
    let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
    let mut bob = DoubleRatchetState::new(config, None).unwrap();

    // 初始化会话
    let alice_public = alice.generate_dh_keypair().unwrap();
    bob.initialize(&alice_public, None, true).unwrap();
    let bob_public = bob.generate_dh_keypair().unwrap();
    alice.initialize(&bob_public, None, false).unwrap();
    alice.prepare_first_message().unwrap();

    // Alice 连续发送 3 条消息
    let messages = ["消息 A", "消息 B", "消息 C"];
    let mut encrypted_messages = Vec::new();

    for msg in &messages {
        let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
        encrypted_messages.push(encrypted);
    }

    // Bob 乱序接收
    println!("   Bob 接收顺序: 消息 B, 消息 C, 消息 A");

    // 先接收第 2 条
    let decrypted = bob.decrypt(&encrypted_messages[1]).unwrap();
    println!("   解密: {}", String::from_utf8_lossy(&decrypted));

    // 再接收第 3 条
    let decrypted = bob.decrypt(&encrypted_messages[2]).unwrap();
    println!("   解密: {}", String::from_utf8_lossy(&decrypted));

    // 最后接收第 1 条
    let decrypted = bob.decrypt(&encrypted_messages[0]).unwrap();
    println!("   解密: {}", String::from_utf8_lossy(&decrypted));

    println!("   ✓ 乱序消息处理成功");
}
