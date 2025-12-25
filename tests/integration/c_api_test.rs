// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! C API Integration Tests
//!
//! Tests for the C-compatible Foreign Function Interface (FFI)

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

            let plaintext = b"Hello, World! This is a test message for C FFI encryption.";

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

                let plaintext = b"Test message for SM4 encryption via FFI API.";

                let cipher = Cipher::new(Algorithm::SM4GCM).unwrap();
                let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();

                let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext).unwrap();
                assert_eq!(decrypted, plaintext);

                key_manager.destroy_key(&key_id).ok();
            }
        }

        #[cfg(all(feature = "encrypt", feature = "fips"))]
        mod fips_only_tests {
            use ciphern::{init, Algorithm, KeyManager};

            #[test]
            fn test_sm4_not_available_in_fips_mode() {
                let _ = init();

                let key_manager = KeyManager::new().unwrap();
                let result = key_manager.generate_key(Algorithm::SM4GCM);
                assert!(result.is_err());
            }
        }
    }

    mod error_handling_tests {
        use ciphern::{Algorithm, Cipher, CryptoError};

        #[test]
        fn test_invalid_key_id() {
            use ciphern::{init, KeyManager};
            let _ = init();
            let key_manager = KeyManager::new().unwrap();
            let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();

            let result = cipher.encrypt(&key_manager, "invalid-key-id", b"test");
            assert!(matches!(result, Err(CryptoError::EncryptionFailed(_))));
        }
    }

    #[cfg(feature = "fips")]
    mod fips_mode_tests {
        use ciphern::is_fips_enabled;

        #[test]
        fn test_fips_mode_status() {
            use ciphern::init;
            let _ = init();
            assert!(is_fips_enabled());
        }
    }
}
