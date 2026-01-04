// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! 模糊测试：加密和解密功能
//!
//! 此测试通过向加密/解密函数输入随机数据来发现潜在的漏洞。

#[cfg(feature = "encrypt")]
use ciphern::{Algorithm, Cipher, KeyManager};
use ciphern::CryptoError;

/// 模糊测试：AES-GCM 加密/解密
#[cfg(feature = "encrypt")]
#[test]
fn fuzz_aes_gcm_encrypt_decrypt() {
    let key_manager = KeyManager::new();
    let key_id = key_manager.generate_key(Algorithm::Aes256Gcm).unwrap();
    let cipher = Cipher::new(Algorithm::Aes256Gcm).unwrap();

    // 测试各种大小的输入
    for size in [0, 1, 16, 31, 32, 33, 64, 128, 256, 512, 1024, 2048, 4096] {
        let mut plaintext = vec![0u8; size];
        // 使用随机数据填充
        getrandom::getrandom(&mut plaintext).unwrap();

        // 加密
        let ciphertext = cipher.encrypt(&key_manager, &key_id, &plaintext);

        // 验证加密成功
        assert!(ciphertext.is_ok(), "Encryption failed for size {}", size);

        let ciphertext = ciphertext.unwrap();

        // 解密
        let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext);

        // 验证解密成功
        assert!(decrypted.is_ok(), "Decryption failed for size {}", size);

        let decrypted = decrypted.unwrap();

        // 验证数据一致性
        assert_eq!(plaintext, decrypted, "Data mismatch for size {}", size);
    }
}

/// 模糊测试：ChaCha20-Poly1305 加密/解密
#[cfg(feature = "encrypt")]
#[test]
fn fuzz_chacha20poly1305_encrypt_decrypt() {
    let key_manager = KeyManager::new();
    let key_id = key_manager.generate_key(Algorithm::ChaCha20Poly1305).unwrap();
    let cipher = Cipher::new(Algorithm::ChaCha20Poly1305).unwrap();

    // 测试各种大小的输入
    for size in [0, 1, 16, 31, 32, 33, 64, 128, 256, 512, 1024, 2048, 4096] {
        let mut plaintext = vec![0u8; size];
        getrandom::getrandom(&mut plaintext).unwrap();

        let ciphertext = cipher.encrypt(&key_manager, &key_id, &plaintext);
        assert!(ciphertext.is_ok());

        let ciphertext = ciphertext.unwrap();
        let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext);
        assert!(decrypted.is_ok());

        let decrypted = decrypted.unwrap();
        assert_eq!(plaintext, decrypted);
    }
}

/// 模糊测试：SM4-GCM 加密/解密
#[cfg(feature = "encrypt")]
#[test]
fn fuzz_sm4gcm_encrypt_decrypt() {
    let key_manager = KeyManager::new();
    let key_id = key_manager.generate_key(Algorithm::Sm4Gcm).unwrap();
    let cipher = Cipher::new(Algorithm::Sm4Gcm).unwrap();

    // 测试各种大小的输入
    for size in [0, 1, 16, 31, 32, 33, 64, 128, 256, 512, 1024, 2048, 4096] {
        let mut plaintext = vec![0u8; size];
        getrandom::getrandom(&mut plaintext).unwrap();

        let ciphertext = cipher.encrypt(&key_manager, &key_id, &plaintext);
        assert!(ciphertext.is_ok());

        let ciphertext = ciphertext.unwrap();
        let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext);
        assert!(decrypted.is_ok());

        let decrypted = decrypted.unwrap();
        assert_eq!(plaintext, decrypted);
    }
}

/// 模糊测试：使用损坏的密文进行解密
#[cfg(feature = "encrypt")]
#[test]
fn fuzz_decrypt_with_corrupted_ciphertext() {
    let key_manager = KeyManager::new();
    let key_id = key_manager.generate_key(Algorithm::Aes256Gcm).unwrap();
    let cipher = Cipher::new(Algorithm::Aes256Gcm).unwrap();

    let plaintext = b"test data";
    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();

    // 测试损坏的密文
    for i in 0..ciphertext.len().min(10) {
        let mut corrupted = ciphertext.clone();
        corrupted[i] ^= 0xFF; // 翻转字节

        let result = cipher.decrypt(&key_manager, &key_id, &corrupted);
        // 应该失败，因为 authentication tag 不匹配
        assert!(result.is_err(), "Decryption should fail for corrupted ciphertext at position {}", i);
    }
}

/// 模糊测试：使用错误的密钥进行解密
#[cfg(feature = "encrypt")]
#[test]
fn fuzz_decrypt_with_wrong_key() {
    let key_manager = KeyManager::new();
    let key_id1 = key_manager.generate_key(Algorithm::Aes256Gcm).unwrap();
    let key_id2 = key_manager.generate_key(Algorithm::Aes256Gcm).unwrap();
    let cipher = Cipher::new(Algorithm::Aes256Gcm).unwrap();

    let plaintext = b"test data";
    let ciphertext = cipher.encrypt(&key_manager, &key_id1, plaintext).unwrap();

    // 使用不同的密钥解密
    let result = cipher.decrypt(&key_manager, &key_id2, &ciphertext);
    // 应该失败
    assert!(result.is_err(), "Decryption should fail with wrong key");
}

/// 模糊测试：使用空密文进行解密
#[cfg(feature = "encrypt")]
#[test]
fn fuzz_decrypt_with_empty_ciphertext() {
    let key_manager = KeyManager::new();
    let key_id = key_manager.generate_key(Algorithm::Aes256Gcm).unwrap();
    let cipher = Cipher::new(Algorithm::Aes256Gcm).unwrap();

    let result = cipher.decrypt(&key_manager, &key_id, &[]);
    // 应该失败，因为密文太短（缺少 nonce 和 tag）
    assert!(result.is_err(), "Decryption should fail with empty ciphertext");
}

/// 模糊测试：使用过短的密文进行解密
#[cfg(feature = "encrypt")]
#[test]
fn fuzz_decrypt_with_short_ciphertext() {
    let key_manager = KeyManager::new();
    let key_id = key_manager.generate_key(Algorithm::Aes256Gcm).unwrap();
    let cipher = Cipher::new(Algorithm::Aes256Gcm).unwrap();

    // 测试各种长度的短密文
    for size in 0..28 {
        let ciphertext = vec![0u8; size];
        let result = cipher.decrypt(&key_manager, &key_id, &ciphertext);
        // 应该失败，因为密文太短
        assert!(result.is_err(), "Decryption should fail with short ciphertext of size {}", size);
    }
}