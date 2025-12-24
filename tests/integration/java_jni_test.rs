// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Java JNI Integration Tests
//!
//! Tests for the Java Native Interface (JNI) bindings
//! These tests validate the JNI functionality through the public API

#[cfg(test)]
mod tests {
    #[cfg(feature = "encrypt")]
    mod encrypt_tests {
        use ciphern::{init, Algorithm, Cipher, KeyManager};

        #[test]
        fn test_aes256_gcm_encrypt_decrypt() {
            let _ = init();

            let key_manager = KeyManager::new().unwrap();
            let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();

            let plaintext = b"Hello, World! This is a test message for JNI encryption.";

            let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();
            let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();

            let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext);

            key_manager.destroy_key(&key_id).ok();
        }

        #[cfg(all(feature = "encrypt", not(feature = "fips")))]
        mod non_fips_tests {
            use ciphern::{init, Algorithm, Cipher, KeyManager};

            #[test]
            fn test_sm4_gcm_encrypt_decrypt() {
                let _ = init();

                let key_manager = KeyManager::new().unwrap();
                let key_id = key_manager.generate_key(Algorithm::SM4GCM).unwrap();

                let plaintext = b"Test message for SM4 encryption via JNI API.";

                let cipher = Cipher::new(Algorithm::SM4GCM).unwrap();
                let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();

                let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext).unwrap();
                assert_eq!(decrypted, plaintext);

                key_manager.destroy_key(&key_id).ok();
            }

            #[test]
            fn test_encrypt_decrypt_different_sizes() {
                let _ = init();

                let key_manager = KeyManager::new().unwrap();

                let test_cases: Vec<(&[u8], Algorithm)> = vec![
                    (b"Short", Algorithm::AES256GCM),
                    (b"This is a medium length test message for encryption.", Algorithm::AES256GCM),
                    (b"Hello, World! This is a test message for JNI encryption. Testing various message lengths.", Algorithm::SM4GCM),
                ];

                for (plaintext, algorithm) in test_cases {
                    let key_id = key_manager.generate_key(algorithm).unwrap();
                    let cipher = Cipher::new(algorithm).unwrap();

                    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();
                    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext).unwrap();

                    assert_eq!(
                        decrypted, plaintext,
                        "Decryption failed for algorithm {:?}",
                        algorithm
                    );

                    key_manager.destroy_key(&key_id).ok();
                }
            }
        }

        #[cfg(all(feature = "encrypt", feature = "fips"))]
        mod fips_only_tests {
            use ciphern::{init, Algorithm, Cipher, KeyManager};

            #[test]
            fn test_sm4_not_available_in_fips_mode() {
                let _ = init();

                let key_manager = KeyManager::new().unwrap();
                let result = key_manager.generate_key(Algorithm::SM4GCM);
                assert!(result.is_err());
            }

            #[test]
            fn test_encrypt_decrypt_different_sizes_fips() {
                let _ = init();

                let key_manager = KeyManager::new().unwrap();

                let test_cases: Vec<(&[u8], Algorithm)> = vec![
                    (b"Short", Algorithm::AES256GCM),
                    (
                        b"This is a medium length test message for encryption.",
                        Algorithm::AES256GCM,
                    ),
                ];

                for (plaintext, algorithm) in test_cases {
                    let key_id = key_manager.generate_key(algorithm).unwrap();
                    let cipher = Cipher::new(algorithm).unwrap();

                    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();
                    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext).unwrap();

                    assert_eq!(
                        decrypted, plaintext,
                        "Decryption failed for algorithm {:?}",
                        algorithm
                    );

                    key_manager.destroy_key(&key_id).ok();
                }
            }
        }
    }

    mod error_handling_tests {
        use ciphern::{init, Algorithm, Cipher, CryptoError, KeyManager};

        #[test]
        fn test_invalid_key_id() {
            let _ = init();
            let key_manager = KeyManager::new().unwrap();
            let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();

            let result = cipher.encrypt(&key_manager, "invalid-key-id", b"test");
            assert!(matches!(result, Err(CryptoError::KeyNotFound(_))));
        }

        #[test]
        fn test_destroy_nonexistent_key() {
            let _ = init();
            let key_manager = KeyManager::new().unwrap();

            let result = key_manager.destroy_key("nonexistent-key-id");
            assert!(matches!(result, Err(CryptoError::KeyNotFound(_))));
        }
    }
}
