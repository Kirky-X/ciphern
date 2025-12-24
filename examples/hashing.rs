// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Hash Operations Examples
//!
//! This module demonstrates cryptographic hash functions:
//! - SHA-256, SHA-384, SHA-512: International standards
//! - SM3: Chinese national standard

#[path = "_common/mod.rs"]
mod common;

use common::{print_result, print_section};

pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    run_sha256_example()?;
    run_sha512_example()?;
    run_sha384_example()?;
    run_sm3_example()?;
    run_hash_comparison()?;
    Ok(())
}

/// SHA-256 Hash Example
///
/// SHA-256 produces a 256-bit (32-byte) hash value.
/// It's the most widely used hash function and is part of the SHA-2 family.
///
/// Use cases:
/// - Data integrity verification
/// - Digital signatures
/// - Password hashing (with salt)
/// - Blockchain applications
pub fn run_sha256_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("SHA-256 Hash Example");

    let data = b"Ciphern cryptographic hash - SHA-256";
    let result = ciphern::Hash::sha256(data)?;
    print_result("SHA-256 Hash", &result);
    println!("  Hash length: {} bytes (256 bits)", result.len());

    println!("  [OK] SHA-256 hash computed!");

    Ok(())
}

/// SHA-512 Hash Example
///
/// SHA-512 produces a 512-bit (64-byte) hash value.
/// It offers higher security than SHA-256 but is slower.
pub fn run_sha512_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("SHA-512 Hash Example");

    let data = b"Ciphern cryptographic hash - SHA-512";
    let result = ciphern::Hash::sha512(data)?;
    print_result("SHA-512 Hash", &result);
    println!("  Hash length: {} bytes (512 bits)", result.len());

    println!("  [OK] SHA-512 hash computed!");

    Ok(())
}

/// SHA-384 Hash Example
///
/// SHA-384 produces a 384-bit (48-byte) hash value.
/// It's a truncated version of SHA-512 with different initial values.
pub fn run_sha384_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("SHA-384 Hash Example");

    let data = b"Ciphern cryptographic hash - SHA-384";
    let result = ciphern::Hash::sha384(data)?;
    print_result("SHA-384 Hash", &result);
    println!("  Hash length: {} bytes (384 bits)", result.len());

    println!("  [OK] SHA-384 hash computed!");

    Ok(())
}

/// SM3 Hash Example
///
/// SM3 is the Chinese national standard cryptographic hash function.
/// It produces a 256-bit hash similar to SHA-256.
///
/// Required for:
/// - Government applications in China
/// - Financial applications in China
/// - Compliance with Chinese cryptographic regulations
pub fn run_sm3_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("SM3 Hash Example (Chinese National Standard)");

    let data = b"Ciphern cryptographic hash - SM3";
    let result = ciphern::Hash::sm3(data)?;
    print_result("SM3 Hash", &result);
    println!("  Hash length: {} bytes (256 bits)", result.len());

    println!("  [OK] SM3 hash computed!");

    Ok(())
}

/// Hash Comparison Example
///
/// Compares performance and output characteristics of different hash functions.
pub fn run_hash_comparison() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Hash Function Comparison");

    let data = b"Test data for hash comparison";

    let algorithms: Vec<(
        &str,
        fn(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
    )> = vec![
        ("SHA-256", |d| {
            ciphern::Hash::sha256(d).map_err(|e| e.into())
        }),
        ("SHA-384", |d| {
            ciphern::Hash::sha384(d).map_err(|e| e.into())
        }),
        ("SHA-512", |d| {
            ciphern::Hash::sha512(d).map_err(|e| e.into())
        }),
        ("SM3", |d| ciphern::Hash::sm3(d).map_err(|e| e.into())),
    ];

    println!("  Output sizes:");
    for (name, algo_fn) in &algorithms {
        let result = algo_fn(data)?;
        println!("    {}: {} bytes", name, result.len());
    }

    let iterations = 1000;
    let data = vec![0u8; 1024];

    println!("  Performance ({} iterations, 1KB data):", iterations);
    for (name, algo_fn) in &algorithms {
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = algo_fn(&data)?;
        }
        let elapsed = start.elapsed();
        println!("    {}: {:?}", name, elapsed);
    }

    println!("  [OK] Hash function comparison completed!");

    Ok(())
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
