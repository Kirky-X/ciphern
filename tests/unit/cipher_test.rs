// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::{Algorithm, Cipher, key::Key};
use securevault::KeyManager;

#[test]
fn test_aes_gcm_vectors() {
    // Vector 1 (AES-128-GCM)
    let key_bytes = hex::decode("00000000000000000000000000000000").unwrap();
    let iv_bytes = hex::decode("000000000000000000000000").unwrap();
    let plaintext = hex::decode("00000000000000000000000000000000").unwrap();
    let expected_ct = hex::decode("0388dace60b6a392f328c2b971b2fe78").unwrap();
    let expected_tag = hex::decode("ab6e47d42cec13bdf53a67b21257bdcc").unwrap();

    let key = Key::new_active(Algorithm::AES128GCM, key_bytes).unwrap();
    let cipher = Cipher::new(Algorithm::AES128GCM).unwrap();
    let cipher_impl = cipher.get_implementation();

    let result = cipher_impl.encrypt_with_nonce(&key, &plaintext, &iv_bytes, None).unwrap();
    let (ct, tag) = result.split_at(plaintext.len());
    assert_eq!(ct, expected_ct);
    assert_eq!(tag, expected_tag);

    // Vector 4 (AES-192-GCM)
    let key_bytes = hex::decode("000000000000000000000000000000000000000000000000").unwrap();
    let expected_ct = hex::decode("98e7247c07f0fe411c267e4384b0f600").unwrap();
    let expected_tag = hex::decode("2ff58d80033927ab8ef4d4587514f0fb").unwrap();

    let key = Key::new_active(Algorithm::AES192GCM, key_bytes).unwrap();
    let cipher = Cipher::new(Algorithm::AES192GCM).unwrap();
    let cipher_impl = cipher.get_implementation();

    let result = cipher_impl.encrypt_with_nonce(&key, &plaintext, &iv_bytes, None).unwrap();
    let (ct, tag) = result.split_at(plaintext.len());
    assert_eq!(ct, expected_ct);
    assert_eq!(tag, expected_tag);
}

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