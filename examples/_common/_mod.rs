// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Ciphern Crypto Library - Complete Usage Examples
//!
//! This module demonstrates how to use all major features of Ciphern.
//!
//! # Examples
//!
//! - Symmetric encryption with AES and SM4
//! - Digital signatures with ECDSA, SM2, Ed25519, and RSA
//! - Key management and lifecycle
//! - Key derivation functions
//! - Hash operations
//! - Secure random number generation
//! - Streaming encryption for large files
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ciphern::{Cipher, Algorithm, KeyManager, init};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize the library
//!     init()?;
//!
//!     // Create a key manager
//!     let key_manager = KeyManager::new()?;
//!
//!     // Generate a key
//!     let key_id = key_manager.generate_key(Algorithm::AES256GCM)?;
//!
//!     // Create a cipher and encrypt data
//!     let cipher = Cipher::new(Algorithm::AES256GCM)?;
//!     let plaintext = b"Hello, Ciphern!";
//!     let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
//!
//!     // Decrypt the data
//!     let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
//!
//!     assert_eq!(plaintext, decrypted.as_slice());
//!     println!("Encryption/decryption successful!");
//!
//!     Ok(())
//! }
//! ```

mod common;

pub mod symmetric_encryption;
pub mod digital_signatures;
pub mod key_management;
pub mod key_derivation;
pub mod hashing;
pub mod random_generation;
pub mod streaming_encryption;
pub mod fips_compliance;
pub mod python_api;
pub mod java_api;

#[cfg(test)]
mod tests {
    use crate::common::setup;
    use crate::{symmetric_encryption, digital_signatures, key_management, key_derivation, hashing, random_generation, streaming_encryption, fips_compliance};
    use std::path::Path;

    #[test]
    fn test_symmetric_encryption_examples() {
        println!("\n=== Testing Symmetric Encryption Examples ===");
        symmetric_encryption::run_all().expect("Symmetric encryption examples failed");
    }

    #[test]
    fn test_key_derivation_examples() {
        println!("\n=== Testing Key Derivation Examples ===");
        key_derivation::run_all().expect("Key derivation examples failed");
    }

    #[test]
    fn test_random_generation_examples() {
        println!("\n=== Testing Random Generation Examples ===");
        random_generation::run_all().expect("Random generation examples failed");
    }
}
