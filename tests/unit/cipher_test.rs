// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use securevault::{Cipher, Algorithm, KeyManager};

#[test]
fn test_aes256_encrypt_decrypt() {
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();
    
    let plaintext = b"Hello, SecureVault!";
    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();
    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext).unwrap();
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_aes256_wrong_key_fails() {
    let key_manager = KeyManager::new().unwrap();
    let key1_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let key2_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();
    
    let plaintext = b"Secret message";
    let ciphertext = cipher.encrypt(&key_manager, &key1_id, plaintext).unwrap();
    
    // Attempt to decrypt with wrong key ID
    assert!(cipher.decrypt(&key_manager, &key2_id, &ciphertext).is_err());
}

#[test]
fn test_sm4_encrypt_decrypt() {
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::SM4GCM).unwrap();
    let cipher = Cipher::new(Algorithm::SM4GCM).unwrap();
    
    let plaintext = b"Chinese cryptography standard";
    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();
    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext).unwrap();
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_empty_plaintext() {
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();
    
    let plaintext = b"";
    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();
    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext).unwrap();
    
    assert_eq!(plaintext, &decrypted[..]);
}