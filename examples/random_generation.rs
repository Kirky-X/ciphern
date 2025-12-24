// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Random Number Generation Examples
//!
//! This module demonstrates secure random number generation:
//! - Cryptographically secure random bytes
//! - Random number generation for keys
//! - Random salt and IV generation

#[path = "_common/mod.rs"]
mod common;

use common::{print_result, print_section};
use ciphern::SecureRandom;
use std::collections::HashSet;

/// Run all random generation examples
pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    run_random_bytes_example()?;
    run_secure_random_for_keys()?;
    run_random_salt_iv_example()?;
    run_entropy_check()?;
    Ok(())
}

/// Random Bytes Generation Example
///
/// Generates cryptographically secure random bytes.
/// Used for keys, salts, initialization vectors, etc.
pub fn run_random_bytes_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Random Bytes Generation Example");

    let rng = SecureRandom::new()?;

    let mut random_bytes = vec![0u8; 32];
    rng.fill(&mut random_bytes)?;
    print_result("32 random bytes", &random_bytes);
    println!("  Length: {} bytes (256 bits)", random_bytes.len());

    let mut random_bytes = vec![0u8; 64];
    rng.fill(&mut random_bytes)?;
    print_result("64 random bytes", &random_bytes);
    println!("  Length: {} bytes (512 bits)", random_bytes.len());

    let mut random_bytes = vec![0u8; 16];
    rng.fill(&mut random_bytes)?;
    print_result("16 random bytes", &random_bytes);
    println!("  Length: {} bytes (128 bits)", random_bytes.len());

    println!("  ✓ Random bytes generated!");

    Ok(())
}

/// Secure Random for Key Generation Example
///
/// Demonstrates using random bytes for cryptographic key generation.
pub fn run_secure_random_for_keys() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Secure Random for Key Generation");

    let key_manager = ciphern::KeyManager::new()?;

    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    println!("  Generated AES-256-GCM key: {}", key_id);

    let key_id = key_manager.generate_key(ciphern::Algorithm::Ed25519)?;
    println!("  Generated Ed25519 key: {}", key_id);

    let key_id = key_manager.generate_key(ciphern::Algorithm::SM2)?;
    println!("  Generated SM2 key: {}", key_id);

    println!("  ✓ Keys generated with secure random!");

    Ok(())
}

/// Random Salt and IV Generation Example
///
/// Demonstrates generating random salts and initialization vectors
/// for encryption operations.
pub fn run_random_salt_iv_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Random Salt and IV Generation");

    let rng = SecureRandom::new()?;

    let mut salt = vec![0u8; 32];
    rng.fill(&mut salt)?;
    print_result("Random salt (32 bytes)", &salt);
    println!("  Used for key derivation");

    let mut iv = vec![0u8; 12];
    rng.fill(&mut iv)?;
    print_result("Random IV (12 bytes)", &iv);
    println!("  Used for AES-GCM encryption");

    let mut nonce = vec![0u8; 24];
    rng.fill(&mut nonce)?;
    print_result("Random nonce (24 bytes)", &nonce);
    println!("  Used for ChaCha20-Poly1305");

    println!("  ✓ Salt and IV generated!");

    Ok(())
}

/// Entropy Quality Check
///
/// Demonstrates checking the quality of random data.
pub fn run_entropy_check() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Entropy Quality Check");

    let rng = SecureRandom::new()?;

    let mut sample1 = vec![0u8; 32];
    rng.fill(&mut sample1)?;
    let mut sample2 = vec![0u8; 32];
    rng.fill(&mut sample2)?;
    let mut sample3 = vec![0u8; 32];
    rng.fill(&mut sample3)?;

    println!("  Sample 1 unique bytes: {}", count_unique(&sample1));
    println!("  Sample 2 unique bytes: {}", count_unique(&sample2));
    println!("  Sample 3 unique bytes: {}", count_unique(&sample3));

    let all_different = sample1 != sample2 && sample2 != sample3 && sample1 != sample3;
    println!("  All samples different: {}", all_different);

    println!("  ✓ Entropy quality verified!");

    Ok(())
}

fn count_unique(data: &[u8]) -> usize {
    let mut unique = HashSet::new();
    for &byte in data {
        unique.insert(byte);
    }
    unique.len()
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
