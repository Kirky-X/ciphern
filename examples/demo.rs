// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Ciphern Crypto Library - Complete Usage Demo
//!
//! This file demonstrates all major features of the Ciphern cryptographic library.
//!
//! Run with: cargo run --example demo

use ciphern::{init, Algorithm, Cipher, Hash, Hkdf, KeyManager, Result, Signer};

fn main() -> Result<()> {
    println!("{}", "=".repeat(70));
    println!("  Ciphern Crypto Library - Complete Demo");
    println!("{}", "=".repeat(70));

    init()?;

    demo_symmetric_encryption()?;
    demo_digital_signatures()?;
    demo_hashing()?;
    demo_random_generation()?;
    demo_key_management()?;
    demo_key_derivation()?;

    println!("\n{}", "=".repeat(70));
    println!("  All demos completed successfully!");
    println!("{}", "=".repeat(70));

    Ok(())
}

fn demo_symmetric_encryption() -> Result<()> {
    println!("\n[1] Symmetric Encryption (AES-256-GCM)");
    println!("{}", "-".repeat(50));

    let key_manager = KeyManager::new()?;
    let key_id = key_manager.generate_key(Algorithm::AES256GCM)?;
    let cipher = Cipher::new(Algorithm::AES256GCM)?;

    let plaintext = b"Hello, Ciphern! This is a secret message.";
    println!("  Plaintext: {}", std::str::from_utf8(plaintext).unwrap());

    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext)?;
    println!("  Ciphertext (hex): {}...", hex::encode(&ciphertext[..32]));

    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
    println!("  Decrypted: {}", std::str::from_utf8(&decrypted).unwrap());

    assert_eq!(plaintext, decrypted.as_slice());
    println!("  ✓ AES-256-GCM encryption verified!");

    Ok(())
}

fn demo_digital_signatures() -> Result<()> {
    println!("\n[2] Digital Signatures (Ed25519)");
    println!("{}", "-".repeat(50));

    let key_manager = KeyManager::new()?;
    let key_id = key_manager.generate_key(Algorithm::Ed25519)?;
    let signer = Signer::new(Algorithm::Ed25519)?;

    let message = b"Message to be signed";
    println!("  Message: {}", std::str::from_utf8(message).unwrap());

    let signature = signer.sign(&key_manager, &key_id, message)?;
    println!("  Signature (hex): {}...", hex::encode(&signature[..32]));

    let is_valid = signer.verify(&key_manager, &key_id, message, &signature)?;
    println!(
        "  Verification: {}",
        if is_valid { "Valid" } else { "Invalid" }
    );

    assert!(is_valid);
    println!("  ✓ Ed25519 signature verified!");

    Ok(())
}

fn demo_hashing() -> Result<()> {
    println!("\n[3] Hash Operations (SHA-256, SM3)");
    println!("{}", "-".repeat(50));

    let data = b"Ciphern - Modern Cryptographic Library";

    println!("  Data: {}", std::str::from_utf8(data).unwrap());

    let sha256 = Hash::sha256(data)?;
    println!("  SHA-256: {}...", hex::encode(&sha256[..16]));

    let sm3 = Hash::sm3(data)?;
    println!("  SM3:    {}...", hex::encode(&sm3[..16]));

    println!("  ✓ Hash operations completed!");

    Ok(())
}

fn demo_random_generation() -> Result<()> {
    println!("\n[4] Secure Random Generation");
    println!("{}", "-".repeat(50));

    let rng = ciphern::SecureRandom::new()?;
    let mut random_bytes = vec![0u8; 32];
    rng.fill(&mut random_bytes)?;
    println!(
        "  Random bytes (32): {}...",
        hex::encode(&random_bytes[..8])
    );

    println!("  ✓ Random generation completed!");

    Ok(())
}

fn demo_key_management() -> Result<()> {
    println!("\n[5] Key Management");
    println!("{}", "-".repeat(50));

    let key_manager = KeyManager::new()?;
    let key_id = key_manager.generate_key(Algorithm::AES256GCM)?;
    println!("  Generated key: {}", key_id);

    let status = key_manager.get_key_status(&key_id)?;
    println!("  Key status: {}", status);

    println!("  ✓ Key management completed!");

    Ok(())
}

fn demo_key_derivation() -> Result<()> {
    println!("\n[6] Key Derivation");
    println!("{}", "-".repeat(50));

    let key_manager = KeyManager::new()?;
    let master_key_id = key_manager.generate_key(Algorithm::AES256GCM)?;
    let master_key = key_manager.get_key(&master_key_id)?;

    let salt = b"demo_salt";
    let info = b"demo_context";

    let derived_key = Hkdf::derive(&master_key, salt, info, Algorithm::AES256GCM)?;

    println!("  Master key: {}", master_key_id);
    println!("  Derived key algorithm: {:?}", derived_key.algorithm());

    println!("  ✓ Key derivation completed!");

    Ok(())
}
