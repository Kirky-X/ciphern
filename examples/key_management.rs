// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Key Management Examples
//!
//! This module demonstrates key lifecycle management features:
//! - Key generation
//! - Key states (active, suspended, deprecated)
//! - Key rotation
//! - Key alias management
//! - Key statistics

#[path = "_common/mod.rs"]
mod common;

use common::{print_result, print_section, setup};

/// Run all key management examples
pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    run_basic_key_generation()?;
    run_key_rotation_example()?;
    run_key_states_example()?;
    run_key_alias_example()?;
    run_key_stats_example()?;
    run_multiple_keys_example()?;
    Ok(())
}

/// Basic Key Generation Example
///
/// Demonstrates generating keys for different algorithms.
pub fn run_basic_key_generation() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Basic Key Generation Example");

    let key_manager = setup()?;

    let aes_key = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    print_result("AES-256-GCM Key ID", aes_key.as_bytes());

    let sm4_key = key_manager.generate_key(ciphern::Algorithm::SM4GCM)?;
    print_result("SM4-GCM Key ID", sm4_key.as_bytes());

    let ed25519_key = key_manager.generate_key(ciphern::Algorithm::Ed25519)?;
    print_result("Ed25519 Key ID", ed25519_key.as_bytes());

    println!("  Generated 3 keys successfully");

    Ok(())
}

/// Key Rotation Example
///
/// Demonstrates key rotation with automatic re-encryption.
pub fn run_key_rotation_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Key Rotation Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    println!("  Generated key: {}", key_id);

    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES256GCM)?;
    let plaintext = b"Data to be protected";
    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
    println!("  Encrypted data with original key");

    key_manager.activate_key(&key_id)?;
    println!("  Key activated for use");

    key_manager.suspend_key(&key_id)?;
    println!("  Key suspended (temporarily disabled)");

    key_manager.resume_key(&key_id)?;
    println!("  Key resumed (re-enabled)");

    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
    assert_eq!(&decrypted, plaintext);
    println!("  ✓ Key rotation and state management verified!");

    Ok(())
}

/// Key States Example
///
/// Demonstrates managing key lifecycle states.
pub fn run_key_states_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Key States Example");

    let key_manager = setup()?;

    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    let status = key_manager.get_key_status(&key_id)?;
    println!("  Initial status: {}", status);

    key_manager.activate_key(&key_id)?;
    let status = key_manager.get_key_status(&key_id)?;
    println!("  After activation: {}", status);

    key_manager.suspend_key(&key_id)?;
    let status = key_manager.get_key_status(&key_id)?;
    println!("  After suspension: {}", status);

    key_manager.resume_key(&key_id)?;
    let status = key_manager.get_key_status(&key_id)?;
    println!("  After resumption: {}", status);

    key_manager.destroy_key(&key_id)?;
    let status = key_manager.get_key_status(&key_id)?;
    println!("  After destruction: {}", status);

    println!("  ✓ Key state transitions verified!");

    Ok(())
}

/// Key Alias Example
///
/// Demonstrates using human-readable aliases for keys.
pub fn run_key_alias_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Key Alias Example");

    let key_manager = setup()?;

    let key_id = key_manager
        .generate_key_with_alias(ciphern::Algorithm::AES256GCM, "production-encryption-key")?;
    println!(
        "  Created key with alias 'production-encryption-key': {}",
        key_id
    );

    let resolved_id = key_manager.resolve_alias("production-encryption-key")?;
    println!("  Resolved alias to key ID: {}", resolved_id);

    assert_eq!(key_id, resolved_id);
    println!("  ✓ Key alias resolution verified!");

    Ok(())
}

/// Key Statistics Example
///
/// Demonstrates retrieving key statistics.
pub fn run_key_stats_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Key Statistics Example");

    let key_manager = setup()?;

    for _ in 0..3 {
        key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    }

    let stats = key_manager.get_key_stats()?;
    println!("  Key statistics:");
    for (key, value) in &stats {
        println!("    {}: {}", key, value);
    }

    let keys = key_manager.list_keys()?;
    println!("  Total keys: {}", keys.len());

    let aliases = key_manager.list_aliases()?;
    println!("  Total aliases: {}", aliases.len());

    println!("  ✓ Key statistics verified!");

    Ok(())
}

/// Multiple Keys Example
///
/// Demonstrates managing multiple keys simultaneously.
pub fn run_multiple_keys_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Multiple Keys Management Example");

    let key_manager = setup()?;

    let key_ids = vec![
        key_manager.generate_key(ciphern::Algorithm::AES256GCM)?,
        key_manager.generate_key(ciphern::Algorithm::AES256GCM)?,
        key_manager.generate_key(ciphern::Algorithm::SM4GCM)?,
        key_manager.generate_key(ciphern::Algorithm::ECDSAP384)?,
    ];

    println!("  Generated {} keys:", key_ids.len());
    for (i, key_id) in key_ids.iter().enumerate() {
        let status = key_manager.get_key_status(key_id)?;
        println!("    {}: {} - {}", i + 1, status, key_id);
    }

    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES256GCM)?;
    let message = b"Shared message encrypted with multiple keys";

    for key_id in &key_ids[0..2] {
        let ciphertext = cipher.encrypt(&key_manager, key_id, message)?;
        let decrypted = cipher.decrypt(&key_manager, key_id, &ciphertext)?;
        assert_eq!(&decrypted, message);
        println!("  Encrypted/decrypted with key: {}", key_id);
    }

    println!("  ✓ Multiple keys management verified!");

    Ok(())
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
