// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Digital Signatures Examples
//!
//! This module demonstrates digital signature operations using various algorithms:
//! - ECDSA (P-256, P-384): International standard
//! - SM2: Chinese national standard
//! - Ed25519: High-performance curve-based signature
//! - RSA: Traditional public-key cryptography

#[path = "_common/mod.rs"]
mod common;

use common::{print_result, print_section, print_string, setup};

/// Run all digital signature examples
pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    run_ecdsa_example()?;
    run_sm2_example()?;
    run_ed25519_example()?;
    run_rsa_example()?;
    Ok(())
}

/// ECDSA P-384 Digital Signature Example
///
/// ECDSA (Elliptic Curve Digital Signature Algorithm) is widely used for
/// digital signatures. P-384 provides a good balance of security and performance.
///
/// This example demonstrates:
/// - Generating an ECDSA P-384 key pair
/// - Signing a message
/// - Verifying the signature
/// - Detecting tampered messages
pub fn run_ecdsa_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("ECDSA P-384 Digital Signature Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::ECDSAP384)?;
    print_string("Generated Key ID", &key_id);

    let signer = ciphern::Signer::new(ciphern::Algorithm::ECDSAP384)?;
    print_string("Algorithm", "ECDSA P-384");

    let message = b"This message needs to be signed with ECDSA P-384";
    print_string("Message", std::str::from_utf8(message).unwrap());

    let signature = signer.sign(&key_manager, &key_id, message)?;
    print_result("Signature", &signature);
    println!("  Signature length: {} bytes", signature.len());

    let is_valid = signer.verify(&key_manager, &key_id, message, &signature)?;
    println!("  Signature verification result: {}", is_valid);
    assert!(is_valid, "ECDSA signature verification failed!");
    println!("  ✓ ECDSA P-384 signature verified!");

    let invalid_message = b"Tampered message";
    let is_invalid = signer.verify(&key_manager, &key_id, invalid_message, &signature)?;
    assert!(!is_invalid, "Should detect tampered message!");
    println!("  ✓ Tampered message correctly rejected!");

    Ok(())
}

/// ECDSA P-256 Digital Signature Example
///
/// ECDSA P-256 is widely used and provides sufficient security for most applications.
pub fn run_ecdsa_p256_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("ECDSA P-256 Digital Signature Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::ECDSAP256)?;
    let signer = ciphern::Signer::new(ciphern::Algorithm::ECDSAP256)?;

    let message = b"ECDSA P-256 signature example";
    let signature = signer.sign(&key_manager, &key_id, message)?;
    let is_valid = signer.verify(&key_manager, &key_id, message, &signature)?;

    assert!(is_valid);
    println!("  ✓ ECDSA P-256 signature verified!");

    Ok(())
}

/// SM2 Digital Signature Example
///
/// SM2 is the Chinese national standard for digital signatures.
/// It's required for use in government and financial applications in China.
///
/// The SM2 signature is 64 bytes (r || s, each 32 bytes).
pub fn run_sm2_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("SM2 Digital Signature Example (Chinese National Standard)");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::SM2)?;
    print_string("Generated Key ID", &key_id);

    let signer = ciphern::Signer::new(ciphern::Algorithm::SM2)?;
    print_string("Algorithm", "SM2");

    let message = b"This message needs to be signed with SM2";
    print_string("Message", std::str::from_utf8(message).unwrap());

    let signature = signer.sign(&key_manager, &key_id, message)?;
    print_result("Signature", &signature);
    println!("  Signature length: {} bytes", signature.len());
    println!("  (SM2 signature is 64 bytes: r || s, each 32 bytes)");

    let is_valid = signer.verify(&key_manager, &key_id, message, &signature)?;
    println!("  Signature verification result: {}", is_valid);
    assert!(is_valid, "SM2 signature verification failed!");
    println!("  ✓ SM2 signature verified!");

    Ok(())
}

/// Ed25519 Digital Signature Example
///
/// Ed25519 is a high-performance digital signature algorithm based on
/// the Curve25519 elliptic curve. It's known for its speed and small
/// signature sizes (64 bytes).
///
/// Advantages:
/// - Very fast signing and verification
/// - Small key and signature sizes
/// - Resistant to implementation errors
pub fn run_ed25519_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Ed25519 Digital Signature Example (High Performance)");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::Ed25519)?;
    print_string("Generated Key ID", &key_id);

    let signer = ciphern::Signer::new(ciphern::Algorithm::Ed25519)?;
    print_string("Algorithm", "Ed25519");

    let message = b"High-performance digital signature with Ed25519";
    print_string("Message", std::str::from_utf8(message).unwrap());

    let signature = signer.sign(&key_manager, &key_id, message)?;
    print_result("Signature", &signature);
    println!("  Signature length: {} bytes", signature.len());

    let is_valid = signer.verify(&key_manager, &key_id, message, &signature)?;
    println!("  Signature verification result: {}", is_valid);
    assert!(is_valid, "Ed25519 signature verification failed!");
    println!("  ✓ Ed25519 signature verified!");

    Ok(())
}

/// RSA-4096 Digital Signature Example
///
/// RSA is a traditional public-key cryptosystem that can be used for
/// digital signatures. RSA-4096 provides a high level of security.
///
/// Use cases:
/// - Legacy system compatibility
/// - Certificate signing
/// - Non-repudiation requirements
pub fn run_rsa_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("RSA-4096 Digital Signature Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::RSA4096)?;
    print_string("Generated Key ID", &key_id);

    let signer = ciphern::Signer::new(ciphern::Algorithm::RSA4096)?;
    print_string("Algorithm", "RSA-4096");

    let message = b"This message needs to be signed with RSA-4096";
    print_string("Message", std::str::from_utf8(message).unwrap());

    let signature = signer.sign(&key_manager, &key_id, message)?;
    print_result("Signature", &signature);
    println!("  Signature length: {} bytes", signature.len());

    let is_valid = signer.verify(&key_manager, &key_id, message, &signature)?;
    println!("  Signature verification result: {}", is_valid);
    assert!(is_valid, "RSA signature verification failed!");
    println!("  ✓ RSA-4096 signature verified!");

    Ok(())
}

/// RSA-2048 Digital Signature Example
///
/// RSA-2048 provides a good balance of security and performance for
/// most applications.
pub fn run_rsa_2048_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("RSA-2048 Digital Signature Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::RSA2048)?;
    let signer = ciphern::Signer::new(ciphern::Algorithm::RSA2048)?;

    let message = b"RSA-2048 signature example";
    let signature = signer.sign(&key_manager, &key_id, message)?;
    let is_valid = signer.verify(&key_manager, &key_id, message, &signature)?;

    assert!(is_valid);
    println!("  ✓ RSA-2048 signature verified!");

    Ok(())
}

/// RSA-3072 Digital Signature Example
///
/// RSA-3072 provides security between RSA-2048 and RSA-4096.
pub fn run_rsa_3072_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("RSA-3072 Digital Signature Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::RSA3072)?;
    let signer = ciphern::Signer::new(ciphern::Algorithm::RSA3072)?;

    let message = b"RSA-3072 signature example";
    let signature = signer.sign(&key_manager, &key_id, message)?;
    let is_valid = signer.verify(&key_manager, &key_id, message, &signature)?;

    assert!(is_valid);
    println!("  ✓ RSA-3072 signature verified!");

    Ok(())
}

/// Signature Performance Comparison Example
///
/// Demonstrates the performance differences between signature algorithms.
pub fn run_signature_performance() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Signature Performance Comparison");

    let key_manager = setup()?;
    let algorithms = vec![
        ciphern::Algorithm::Ed25519,
        ciphern::Algorithm::ECDSAP256,
        ciphern::Algorithm::ECDSAP384,
        ciphern::Algorithm::RSA2048,
    ];

    let message = b"Performance test message for digital signatures";

    for algo in algorithms {
        let key_id = key_manager.generate_key(algo)?;
        let signer = ciphern::Signer::new(algo)?;

        let iterations = 10;
        let mut sign_times = Vec::new();
        let mut verify_times = Vec::new();

        for _ in 0..iterations {
            let signature = signer.sign(&key_manager, &key_id, message)?;

            let start = std::time::Instant::now();
            let _ = signer.verify(&key_manager, &key_id, message, &signature)?;
            verify_times.push(start.elapsed());

            sign_times.push(start.elapsed());
        }

        let avg_sign: std::time::Duration = sign_times.iter().sum();
        let avg_verify: std::time::Duration = verify_times.iter().sum();

        println!("  {:?}", algo);
        println!("    Average sign time: {:?}", avg_sign / iterations as u32);
        println!("    Average verify time: {:?}", avg_verify / iterations as u32);
    }

    println!("  ✓ Performance comparison completed!");

    Ok(())
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
