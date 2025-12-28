// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Hashing examples for ciphern cryptographic library

use ciphern::{Hasher, Result};

fn run_all() -> Result<()> {
    println!("=== Hash Function Examples ===\n");

    example_sha256()?;
    example_sha512()?;
    example_multi_hash()?;
    example_sm3()?;

    Ok(())
}

fn example_sha256() -> Result<()> {
    println!("[1] SHA-256 Example");

    let data = b"Hello, World!";
    let hasher = Hasher::new(ciphern::Algorithm::SHA256)?;
    let hash = hasher.hash(data);

    println!("  Input: \"Hello, World!\"");
    println!("  SHA-256: {}", hex::encode(&hash));
    println!("  Length: {} bytes", hash.len());

    println!("  [OK] SHA-256 example completed!\n");
    Ok(())
}

fn example_sha512() -> Result<()> {
    println!("[2] SHA-512 Example");

    let data = b"Hello, World!";
    let hasher = Hasher::new(ciphern::Algorithm::SHA512)?;
    let hash = hasher.hash(data);

    println!("  Input: \"Hello, World!\"");
    println!("  SHA-512: {}", hex::encode(&hash));
    println!("  Length: {} bytes", hash.len());

    println!("  [OK] SHA-512 example completed!\n");
    Ok(())
}

type HashFn = fn(&[u8]) -> Result<Vec<u8>>;

fn example_multi_hash() -> Result<()> {
    println!("[3] Multiple Hash Algorithms Comparison");

    let data = b"Test data for hash comparison";

    let algorithms: Vec<(String, HashFn)> = vec![
        ("SHA-256".to_string(), |d| {
            let hasher = Hasher::new(ciphern::Algorithm::SHA256)?;
            Ok(hasher.hash(d))
        }),
        ("SHA-384".to_string(), |d| {
            let hasher = Hasher::new(ciphern::Algorithm::SHA384)?;
            Ok(hasher.hash(d))
        }),
        ("SHA-512".to_string(), |d| {
            let hasher = Hasher::new(ciphern::Algorithm::SHA512)?;
            Ok(hasher.hash(d))
        }),
        ("SM3".to_string(), |d| {
            let hasher = Hasher::new(ciphern::Algorithm::SM3)?;
            Ok(hasher.hash(d))
        }),
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

fn example_sm3() -> Result<()> {
    println!("\n[4] SM3 Example (Chinese National Standard)");

    let data = b"Hello, World!";
    let hasher = Hasher::new(ciphern::Algorithm::SM3)?;
    let hash = hasher.hash(data);

    println!("  Input: \"Hello, World!\"");
    println!("  SM3: {}", hex::encode(&hash));
    println!("  Length: {} bytes", hash.len());

    println!("  [OK] SM3 example completed!\n");
    Ok(())
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
