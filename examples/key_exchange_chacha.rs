// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! X25519 密钥交换和 ChaCha20-Poly1305 加密示例
//!
//! 本示例演示如何使用 ciphern 库进行：
//! 1. X25519 密钥协商（ECDH）
//! 2. 使用协商的密钥进行 ChaCha20-Poly1305 加密

use ciphern::{Cipher, KeyManager, X25519KeyManager, X25519Session};

fn main() {
    println!("=== X25519 密钥交换示例 ===\n");

    // 1. 创建密钥管理器
    let key_manager = KeyManager::new().expect("创建密钥管理器失败");
    let x25519_manager = X25519KeyManager::new().expect("创建 X25519 密钥管理器失败");

    // 2. Alice 和 Bob 生成各自的 X25519 密钥对
    println!("1. 生成密钥对...");
    let (alice_key, alice_public) = x25519_manager
        .generate_keypair()
        .expect("生成 Alice 密钥对失败");
    let (bob_key, bob_public) = x25519_manager
        .generate_keypair()
        .expect("生成 Bob 密钥对失败");

    println!("   Alice 公钥: {}", hex::encode(alice_public));
    println!("   Bob 公钥:   {}\n", hex::encode(bob_public));

    // 3. 执行密钥协商
    println!("2. 执行密钥协商...");
    let alice_shared = x25519_manager
        .key_agreement(&alice_key, &bob_public)
        .expect("Alice 密钥协商失败");
    let bob_shared = x25519_manager
        .key_agreement(&bob_key, &alice_public)
        .expect("Bob 密钥协商失败");

    assert_eq!(alice_shared, bob_shared, "共享密钥应该匹配");
    println!("   ✓ 密钥协商成功!");
    println!("   共享密钥: {}\n", hex::encode(alice_shared));

    // 4. 使用会话进行密钥交换
    println!("3. 使用 X25519Session 进行密钥交换...");
    let mut alice_session = X25519Session::new(&x25519_manager).expect("创建 Alice 会话失败");
    let mut bob_session = X25519Session::new(&x25519_manager).expect("创建 Bob 会话失败");

    let alice_pub = *alice_session.local_public();
    let bob_pub = *bob_session.local_public();

    alice_session
        .set_peer_public(&bob_pub, &x25519_manager)
        .expect("Alice 设置对等公钥失败");
    bob_session
        .set_peer_public(&alice_pub, &x25519_manager)
        .expect("Bob 设置对等公钥失败");

    assert!(alice_session.is_established(), "Alice 会话应该已建立");
    assert!(bob_session.is_established(), "Bob 会话应该已建立");
    assert_eq!(
        alice_session.shared_secret().unwrap(),
        bob_session.shared_secret().unwrap(),
        "会话共享密钥应该匹配"
    );
    println!("   ✓ X25519Session 密钥交换成功!\n");

    // 5. 使用 KeyManager API 进行密钥协商
    println!("4. 使用 KeyManager API 进行密钥协商...");
    let key_id = key_manager
        .generate_key(ciphern::Algorithm::X25519)
        .expect("生成 X25519 密钥失败");
    let peer_public = x25519_manager
        .generate_keypair()
        .expect("生成对等密钥对失败")
        .1;

    let shared_secret = key_manager
        .x25519_key_agreement(&key_id, &peer_public)
        .expect("KeyManager 密钥协商失败");
    println!("   ✓ KeyManager API 密钥协商成功!");
    println!("   共享密钥: {}\n", hex::encode(shared_secret));

    println!("=== ChaCha20-Poly1305 加密示例 ===\n");

    // 6. ChaCha20-Poly1305 加密演示
    println!("5. ChaCha20-Poly1305 加密...");
    let cipher = Cipher::new(ciphern::Algorithm::ChaCha20Poly1305).expect("创建加密器失败");
    let key_id = key_manager
        .generate_key(ciphern::Algorithm::ChaCha20Poly1305)
        .expect("生成 ChaCha20 密钥失败");

    let plaintext = b"This is a test message encrypted with ChaCha20-Poly1305! Hello, World!";
    let ciphertext = cipher
        .encrypt(&key_manager, &key_id, plaintext)
        .expect("加密失败");

    println!("   原始消息: {}", String::from_utf8_lossy(plaintext));
    println!("   密文长度: {} 字节", ciphertext.len());
    println!("   ✓ 加密成功!\n");

    // 7. 解密
    println!("6. ChaCha20-Poly1305 解密...");
    let decrypted = cipher
        .decrypt(&key_manager, &key_id, &ciphertext)
        .expect("解密失败");
    assert_eq!(
        &decrypted, plaintext,
        "Decrypted message should match original"
    );

    println!("   解密消息: {}", String::from_utf8_lossy(&decrypted));
    println!("   ✓ 解密成功!\n");

    // 8. 使用 AAD（附加认证数据）进行加密
    println!("7. 使用 AAD 进行加密...");
    let aad = b"Additional Authentication Data";
    let ciphertext_aad = cipher
        .encrypt_aad(&key_manager, &key_id, plaintext, aad)
        .expect("带 AAD 的加密失败");
    let decrypted_aad = cipher
        .decrypt_aad(&key_manager, &key_id, &ciphertext_aad, aad)
        .expect("带 AAD 的解密失败");

    assert_eq!(
        &decrypted_aad, plaintext,
        "Decryption with AAD should succeed"
    );
    println!("   ✓ 带 AAD 的加密和解密成功!\n");

    println!("=== 所有示例完成 ===");
}
