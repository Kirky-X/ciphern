// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::key::Key;
use ciphern::{Algorithm, Cipher};

mod cavp;
use cavp::run_aes_gcm_cavp_tests;

#[test]
fn test_nist_cavp_aes_gcm_vectors() {
    let test_vector_path = "tests/fips/cavp/test_vectors.json";

    match run_aes_gcm_cavp_tests(test_vector_path) {
        Ok(_) => println!("All CAVP tests passed successfully!"),
        Err(e) => panic!("CAVP tests failed: {}", e),
    }
}

#[test]
fn test_aes_gcm_encryption_decryption() {
    // Basic functionality test for AES-128-GCM
    let key_bytes = vec![0x00; 16]; // 128-bit key
    let iv_bytes = vec![0x00; 12]; // 96-bit IV
    let plaintext = b"Hello, World!";
    let aad = b"additional data";

    let key = Key::new_active(Algorithm::AES128GCM, key_bytes).expect("Failed to create key");
    let cipher = Cipher::new(Algorithm::AES128GCM).expect("Failed to create cipher");
    let cipher_impl = cipher.get_implementation();

    // Test encryption
    let ciphertext = cipher_impl
        .encrypt_with_nonce(&key, plaintext, &iv_bytes, Some(aad))
        .expect("Encryption failed");

    // Verify ciphertext is different from plaintext
    assert_ne!(&ciphertext[..plaintext.len()], plaintext);

    // Test decryption
    let mut decrypt_input = iv_bytes.to_vec();
    decrypt_input.extend_from_slice(&ciphertext);
    let decrypted = cipher_impl
        .decrypt(&key, &decrypt_input, Some(aad))
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_256_gcm_encryption_decryption() {
    // Test AES-256-GCM with different key sizes
    let key_bytes = vec![0x01; 32]; // 256-bit key
    let iv_bytes = vec![0x02; 12]; // 96-bit IV
    let plaintext = b"Testing AES-256-GCM encryption";
    let aad = b"authenticated data";

    let key = Key::new_active(Algorithm::AES256GCM, key_bytes).expect("Failed to create key");
    let cipher = Cipher::new(Algorithm::AES256GCM).expect("Failed to create cipher");
    let cipher_impl = cipher.get_implementation();

    // Test encryption
    let ciphertext = cipher_impl
        .encrypt_with_nonce(&key, plaintext, &iv_bytes, Some(aad))
        .expect("Encryption failed");

    // Test decryption
    let mut decrypt_input = iv_bytes.to_vec();
    decrypt_input.extend_from_slice(&ciphertext);
    let decrypted = cipher_impl
        .decrypt(&key, &decrypt_input, Some(aad))
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_invalid_tag_detection() {
    // Test that decryption fails with invalid authentication tag
    let key_bytes = vec![0x00; 16];
    let iv_bytes = vec![0x00; 12];
    let plaintext = b"Test message";
    let aad = b"additional data";

    let key = Key::new_active(Algorithm::AES128GCM, key_bytes).expect("Failed to create key");
    let cipher = Cipher::new(Algorithm::AES128GCM).expect("Failed to create cipher");
    let cipher_impl = cipher.get_implementation();

    // Encrypt
    let mut ciphertext = cipher_impl
        .encrypt_with_nonce(&key, plaintext, &iv_bytes, Some(aad))
        .expect("Encryption failed");

    // Corrupt the authentication tag (last 16 bytes)
    let tag_start = ciphertext.len() - 16;
    ciphertext[tag_start] ^= 0xFF;

    // Decryption should fail
    let mut decrypt_input = iv_bytes.to_vec();
    decrypt_input.extend_from_slice(&ciphertext);
    let result = cipher_impl.decrypt(&key, &decrypt_input, Some(aad));
    assert!(result.is_err(), "Decryption should fail with corrupted tag");
}
