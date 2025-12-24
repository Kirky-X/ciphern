// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Symmetric Encryption Examples
//!
//! This module demonstrates symmetric encryption using AES and SM4 algorithms.
//!
//! # AES-256-GCM
//!
//! AES (Advanced Encryption Standard) is the international standard for symmetric encryption.
//! GCM (Galois/Counter Mode) provides both confidentiality and authenticity.
//!
//! # SM4-GCM
//!
//! SM4 is the Chinese national standard for symmetric encryption, required for use
//! in government and financial applications in China.

#[path = "_common/mod.rs"]
mod common;

use common::{print_result, print_section, print_string, setup};

/// Run all symmetric encryption examples
pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    run_aes_example()?;
    run_sm4_example()?;
    Ok(())
}

/// AES-256-GCM Encryption Example
///
/// This example demonstrates:
/// - Generating an AES-256-GCM key
/// - Encrypting data
/// - Decrypting the data
/// - Verifying the result
pub fn run_aes_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("AES-256-GCM Encryption Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    print_string("Generated Key ID", &key_id);

    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES256GCM)?;
    print_string("Algorithm", "AES-256-GCM");

    let plaintext = b"Hello, this is a secret message for AES encryption!";
    print_string("Plaintext", std::str::from_utf8(plaintext).unwrap());

    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
    print_result("Ciphertext", &ciphertext);
    println!("  Ciphertext length: {} bytes", ciphertext.len());

    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
    print_string("Decrypted", std::str::from_utf8(&decrypted).unwrap());

    assert_eq!(plaintext, decrypted.as_slice());
    println!("  ✓ AES-256-GCM encryption/decryption verified!");

    Ok(())
}

/// AES-128-GCM Encryption Example
///
/// Demonstrates AES-128 for scenarios with less strict key size requirements.
pub fn run_aes128_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("AES-128-GCM Encryption Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES128GCM)?;
    print_string("Generated Key ID", &key_id);

    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES128GCM)?;
    let plaintext = b"AES-128 encryption example";
    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;

    assert_eq!(plaintext, decrypted.as_slice());
    println!("  ✓ AES-128-GCM encryption/decryption verified!");

    Ok(())
}

/// AES-192-GCM Encryption Example
///
/// Demonstrates AES-192 for balanced security requirements.
pub fn run_aes192_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("AES-192-GCM Encryption Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES192GCM)?;
    print_string("Generated Key ID", &key_id);

    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES192GCM)?;
    let plaintext = b"AES-192 encryption example";
    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;

    assert_eq!(plaintext, decrypted.as_slice());
    println!("  ✓ AES-192-GCM encryption/decryption verified!");

    Ok(())
}

/// SM4-GCM Encryption Example
///
/// SM4 is the Chinese national standard symmetric encryption algorithm.
/// It's mandatory for use in government and financial applications in China.
///
/// This example demonstrates:
/// - Generating an SM4-GCM key
/// - Encrypting data using the Chinese national standard
/// - Decrypting and verifying the result
pub fn run_sm4_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("SM4-GCM Encryption Example (Chinese National Standard)");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::SM4GCM)?;
    print_string("Generated Key ID", &key_id);

    let cipher = ciphern::Cipher::new(ciphern::Algorithm::SM4GCM)?;
    print_string("Algorithm", "SM4-GCM");

    let plaintext = b"Hello, this is a message encrypted with SM4-GCM!";
    print_string("Plaintext", std::str::from_utf8(plaintext).unwrap());

    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
    print_result("Ciphertext", &ciphertext);
    println!("  Ciphertext length: {} bytes", ciphertext.len());

    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
    print_string("Decrypted", std::str::from_utf8(&decrypted).unwrap());

    assert_eq!(plaintext, decrypted.as_slice());
    println!("  ✓ SM4-GCM encryption/decryption verified!");

    Ok(())
}

/// Multiple Encryption Example
///
/// Demonstrates encrypting multiple messages with the same key.
pub fn run_multiple_encryption() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Multiple Messages Encryption Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES256GCM)?;

    let messages: Vec<&[u8]> = vec![b"First message", b"Second msg...", b"Third msg......"];

    let mut ciphertexts = Vec::new();
    for (i, message) in messages.iter().enumerate() {
        let ciphertext = cipher.encrypt(&key_manager, &key_id, message)?;
        println!(
            "  Message {}: {} bytes -> {} bytes",
            i + 1,
            message.len(),
            ciphertext.len()
        );
        ciphertexts.push(ciphertext);
    }

    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        let decrypted = cipher.decrypt(&key_manager, &key_id, ciphertext)?;
        assert_eq!(&decrypted, messages[i]);
        println!("  Message {} decrypted successfully", i + 1);
    }

    println!("  ✓ Multiple message encryption/decryption verified!");

    Ok(())
}

/// Large Data Encryption Example
///
/// Demonstrates encrypting larger amounts of data.
pub fn run_large_data_encryption() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Large Data Encryption Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES256GCM)?;

    let size = 1024 * 1024; // 1 MB
    let plaintext: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
    println!(
        "  Plaintext size: {} bytes ({:.2} MB)",
        plaintext.len(),
        plaintext.len() as f64 / 1024.0 / 1024.0
    );

    let start = std::time::Instant::now();
    let ciphertext = cipher.encrypt(&key_manager, &key_id, &plaintext)?;
    let encrypt_time = start.elapsed();
    println!("  Encryption time: {:?}", encrypt_time);
    println!(
        "  Ciphertext size: {} bytes ({:.2} MB)",
        ciphertext.len(),
        ciphertext.len() as f64 / 1024.0 / 1024.0
    );

    let start = std::time::Instant::now();
    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
    let decrypt_time = start.elapsed();
    println!("  Decryption time: {:?}", decrypt_time);

    assert_eq!(plaintext, decrypted);
    println!("  ✓ Large data encryption/decryption verified!");
    println!(
        "  Throughput: {:.2} MB/s",
        (size as f64 / 1024.0 / 1024.0) / decrypt_time.as_secs_f64()
    );

    Ok(())
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
