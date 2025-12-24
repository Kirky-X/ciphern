// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Key Derivation Examples
//!
//! This module demonstrates key derivation functions (KDF):
//! - HKDF: HMAC-based Key Derivation Function
//! - PBKDF2: Password-Based Key Derivation Function 2
//! - Scrypt: Memory-hard key derivation function
//! - Argon2id: Modern memory-hard KDF
//! - SM3-KDF: SM3-based key derivation (国密标准)

#[path = "_common/mod.rs"]
mod common;

use ciphern::{Argon2id, Hkdf, Pbkdf2, Sm3Kdf};
use common::{print_result, print_section, print_string, setup};

/// Run all key derivation examples
pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    run_hkdf_example()?;
    run_pbkdf2_example()?;
    run_argon2id_example()?;
    run_sm3_kdf_example()?;
    run_key_derivation_example()?;
    run_derivation_best_practices()?;
    Ok(())
}

/// HKDF Example
///
/// HKDF (HMAC-based Key Derivation Function) is used to derive keys
/// from a master key or password.
///
/// Use cases:
/// - Deriving multiple keys from a master key
/// - Expanding key material
/// - Key separation
pub fn run_hkdf_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("HKDF Key Derivation Example");

    let key_manager = setup()?;
    let master_key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    print_string("Master Key ID", &master_key_id);

    let master_key = key_manager.get_key(&master_key_id)?;
    let salt = b"hkdf_salt_for_this_derivation";
    let info = b"app_key_derivation_context";

    let derived_key = Hkdf::derive(&master_key, salt, info, ciphern::Algorithm::AES256GCM)?;
    print_result(
        "Derived Key (first 16 bytes)",
        derived_key.secret_bytes()?.as_bytes(),
    );

    println!("  [OK] HKDF key derivation completed!");

    Ok(())
}

/// PBKDF2 Example
///
/// PBKDF2 (Password-Based Key Derivation Function 2) derives keys
/// from passwords using a pseudorandom function (HMAC-SHA256).
///
/// Parameters:
/// - Iterations: Number of iterations (higher = more secure, slower)
/// - Salt: Random salt to prevent rainbow table attacks
/// - Output length: Length of derived key
pub fn run_pbkdf2_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("PBKDF2 Key Derivation Example");

    let password = b"my_secure_password_for_derivation";
    let salt = b"unique_random_salt_for_pbkdf2";

    let iterations = 100000;
    println!("  Using {} iterations for PBKDF2", iterations);

    let derived_key = Pbkdf2::derive(password, salt, iterations, ciphern::Algorithm::AES256GCM)?;
    print_result(
        "Derived Key (first 16 bytes)",
        derived_key.secret_bytes()?.as_bytes(),
    );

    println!("  [OK] PBKDF2 key derivation completed!");

    Ok(())
}

/// Argon2id Example
///
/// Argon2id is the winner of the Password Hashing Competition and provides
/// excellent resistance against GPU and ASIC attacks.
pub fn run_argon2id_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Argon2id Key Derivation Example");

    let password = b"secure_password_for_argon2id";
    let salt = b"argon2id_salt_value_16";

    let derived_key = Argon2id::derive(password, salt, ciphern::Algorithm::AES256GCM)?;
    print_result(
        "Derived Key (first 16 bytes)",
        derived_key.secret_bytes()?.as_bytes(),
    );

    println!("  [OK] Argon2id key derivation completed!");

    Ok(())
}

/// SM3-KDF Example
///
/// SM3-KDF is a key derivation function based on the SM3 hash algorithm,
/// part of the Chinese National Standard (GM/T 32918.4-2016).
pub fn run_sm3_kdf_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("SM3-KDF Key Derivation Example");

    let key_manager = setup()?;
    let master_key_id = key_manager.generate_key(ciphern::Algorithm::SM4GCM)?;
    print_string("Master Key ID", &master_key_id);

    let master_key = key_manager.get_key(&master_key_id)?;
    let data = b"sm3_kdf_derivation_data";

    let derived_key = Sm3Kdf::derive(&master_key, data, 16, ciphern::Algorithm::SM4GCM)?;
    print_result("Derived Key", derived_key.secret_bytes()?.as_bytes());

    println!("  [OK] SM3-KDF key derivation completed!");

    Ok(())
}

/// Key Derivation with Context Example
///
/// Demonstrates deriving different keys from the same master key
/// using different contexts.
pub fn run_key_derivation_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Key Derivation with Context Example");

    let key_manager = setup()?;
    let master_key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    print_string("Master Key ID", &master_key_id);

    let master_key = key_manager.get_key(&master_key_id)?;
    let salt = b"common_salt_for_all_derivations";

    let contexts = vec![
        ("encryption", b"encryption_key_ctxt"),
        ("signature", b"signature_key_ctxt_"),
        ("authentication", b"auth_key_context___"),
    ];

    let mut derived_keys = Vec::new();
    for (name, context) in &contexts {
        let derived_key = Hkdf::derive(&master_key, salt, *context, ciphern::Algorithm::AES256GCM)?;
        let key_bytes = derived_key.secret_bytes()?;
        derived_keys.push(key_bytes.clone());
        print_result(&format!("Derived Key for {}", name), key_bytes.as_bytes());
    }

    println!("  [OK] Multiple keys derived from master key!");

    Ok(())
}

/// Derivation Security Best Practices
///
/// Demonstrates best practices for key derivation.
pub fn run_derivation_best_practices() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Key Derivation Best Practices");

    println!("  1. Use unique salt for each derivation");
    let password = b"shared_password";
    let salt1 = b"unique_salt_for_user_1";
    let salt2 = b"unique_salt_for_user_2";

    let key1 = Pbkdf2::derive(password, salt1, 100000, ciphern::Algorithm::AES256GCM)?;
    let key2 = Pbkdf2::derive(password, salt2, 100000, ciphern::Algorithm::AES256GCM)?;

    let key1_bytes = key1.secret_bytes()?;
    let key2_bytes = key2.secret_bytes()?;

    println!(
        "    Different salts produce different keys: {}",
        key1_bytes.as_bytes() != key2_bytes.as_bytes()
    );

    println!("  2. Use appropriate iteration count for PBKDF2");
    println!("    Recommended: 600,000+ for PBKDF2-HMAC-SHA256");
    println!("    Using 100,000 for this example (increase for production)");

    println!("  3. Use appropriate parameters for scrypt/Argon2id");
    println!("    Argon2id: memory=64MB, iterations=3, parallelism=4");

    println!("  4. Include context/labels for key separation");
    let key_manager = setup()?;
    let master_key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    let master_key = key_manager.get_key(&master_key_id)?;
    let _payment_key = Hkdf::derive(
        &master_key,
        b"payment_salt",
        b"payment_system_key",
        ciphern::Algorithm::AES256GCM,
    )?;
    let _auth_key = Hkdf::derive(
        &master_key,
        b"auth_salt",
        b"auth_system_key",
        ciphern::Algorithm::AES256GCM,
    )?;
    println!("    Derived separate keys for payment and auth systems");

    println!("  [OK] Key derivation best practices demonstrated!");

    Ok(())
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
