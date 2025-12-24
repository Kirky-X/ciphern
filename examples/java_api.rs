// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Ciphern Crypto Library - Java FFI Examples
//!
//! This module provides examples of using Ciphern from Java via JNI.

#[path = "_common/mod.rs"]
mod common;

use common::print_section;

/// Run all Java API examples
pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    java_aes_example();
    java_signature_example();
    java_key_management_example();
    java_hash_example();
    java_complete_example();
    Ok(())
}

/// Java AES-256-GCM Encryption Example
///
/// Demonstrates using Ciphern from Java with AES-256-GCM encryption.
pub fn java_aes_example() {
    print_section("Java AES-256-GCM Example");

    println!(
        r#"
Java AES-256-GCM Example
========================

// Initialize the library
Ciphern.init();

// Create a key manager
KeyManager keyManager = new KeyManager();

// Generate a key
String keyId = keyManager.generateKey(Algorithm.AES_256_GCM);
System.out.println("Generated Key ID: " + keyId);

// Create a cipher
Cipher cipher = new Cipher(Algorithm.AES_256_GCM);

// Encrypt data
byte[] plaintext = "Hello, Ciphern from Java!".getBytes();
byte[] ciphertext = cipher.encrypt(keyManager, keyId, plaintext);
System.out.println("Ciphertext length: " + ciphertext.length + " bytes");

// Decrypt data
byte[] decrypted = cipher.decrypt(keyManager, keyId, ciphertext);
System.out.println("Decrypted: " + new String(decrypted));

// Verify
assert Arrays.equals(plaintext, decrypted);
System.out.println("Java AES-256-GCM encryption successful!");
"#
    );
}

/// Java Digital Signature Example
///
/// Demonstrates digital signatures from Java.
pub fn java_signature_example() {
    print_section("Java Digital Signature Example");

    println!(
        r#"
Java Digital Signature Example
==============================

// Initialize the library
Ciphern.init();

// Create a key manager
KeyManager keyManager = new KeyManager();

// Generate an Ed25519 key pair
String keyId = keyManager.generateKey(Algorithm.ED_25519);
System.out.println("Generated Key ID: " + keyId);

// Create a signer
Signer signer = new Signer(Algorithm.ED_25519);

// Sign a message
byte[] message = "Message to sign".getBytes();
byte[] signature = signer.sign(keyManager, keyId, message);
System.out.println("Signature length: " + signature.length + " bytes");

// Verify the signature
boolean isValid = signer.verify(keyManager, keyId, message, signature);
System.out.println("Signature valid: " + isValid);

assert isValid;
System.out.println("Java digital signature successful!");
"#
    );
}

/// Java Key Management Example
///
/// Demonstrates key management from Java.
pub fn java_key_management_example() {
    print_section("Java Key Management Example");

    println!(
        r#"
Java Key Management Example
===========================

// Initialize the library
Ciphern.init();

// Create a key manager
KeyManager keyManager = new KeyManager();

// Generate multiple keys
String keyId1 = keyManager.generateKey(Algorithm.AES_256_GCM);
String keyId2 = keyManager.generateKey(Algorithm.SM4_GCM);
String keyId3 = keyManager.generateKey(Algorithm.ED_25519);

System.out.println("Generated 3 keys:");
System.out.println("  1. " + keyId1);
System.out.println("  2. " + keyId2);
System.out.println("  3. " + keyId3);

// Get key state
KeyState state = keyManager.getKeyState(keyId1);
System.out.println("Key 1 state: " + state);

// Rotate key
keyManager.rotateKey(keyId1);
System.out.println("Key 1 rotated successfully");

// Deprecate key
keyManager.deprecateKey(keyId2);
System.out.println("Key 2 deprecated successfully");

// Destroy key
keyManager.destroyKey(keyId3);
System.out.println("Key 3 destroyed successfully");

System.out.println("Java key management successful!");
"#
    );
}

/// Java Hash Operations Example
///
/// Demonstrates hash operations from Java.
pub fn java_hash_example() {
    print_section("Java Hash Operations Example");

    println!(
        r#"
Java Hash Operations Example
============================

// Initialize the library
Ciphern.init();

// Data to hash
byte[] data = "Hello, Ciphern!".getBytes();

// Compute SHA-256 hash
byte[] sha256 = Hash.sha256(data);
System.out.println("SHA-256: " + bytesToHex(sha256));

// Compute SHA-512 hash
byte[] sha512 = Hash.sha512(data);
System.out.println("SHA-512: " + bytesToHex(sha512));

// Compute SM3 hash (Chinese national standard)
byte[] sm3 = Hash.sm3(data);
System.out.println("SM3: " + bytesToHex(sm3));

// Compute BLAKE3 hash (high performance)
byte[] blake3 = Hash.blake3(data);
System.out.println("BLAKE3: " + bytesToHex(blake3));

System.out.println("Java hash operations successful!");
"#
    );
}

/// Java Complete Example
///
/// A complete Java example demonstrating multiple features.
pub fn java_complete_example() {
    print_section("Java Complete Example");

    println!(
        r#"
Java Complete Example
=====================

import com.ciphern.*;

public class CiphernExample {{
    public static void main(String[] args) {{
        try {{
            // Initialize
            Ciphern.init();
            System.out.println("Ciphern initialized");

            // Key management
            KeyManager keyManager = new KeyManager();
            String aesKey = keyManager.generateKey(Algorithm.AES_256_GCM);
            String signKey = keyManager.generateKey(Algorithm.ED_25519);
            System.out.println("Keys generated");

            // Encryption
            Cipher cipher = new Cipher(Algorithm.AES_256_GCM);
            byte[] plaintext = "Secret message from Java!".getBytes();
            byte[] ciphertext = cipher.encrypt(keyManager, aesKey, plaintext);
            System.out.println("Data encrypted: " + ciphertext.length + " bytes");

            // Decryption
            byte[] decrypted = cipher.decrypt(keyManager, aesKey, ciphertext);
            System.out.println("Data decrypted: " + new String(decrypted));

            // Digital signature
            Signer signer = new Signer(Algorithm.ED_25519);
            byte[] message = "Message to sign".getBytes();
            byte[] signature = signer.sign(keyManager, signKey, message);
            System.out.println("Message signed: " + signature.length + " bytes");

            // Verify signature
            boolean valid = signer.verify(keyManager, signKey, message, signature);
            System.out.println("Signature valid: " + valid);

            // Hash operations
            byte[] hash = Hash.sha256(plaintext);
            System.out.println("SHA-256: " + bytesToHex(hash));

            // Key lifecycle
            keyManager.rotateKey(aesKey);
            System.out.println("Key rotated");

            keyManager.deprecateKey(aesKey);
            System.out.println("Key deprecated");

            keyManager.destroyKey(aesKey);
            System.out.println("Key destroyed");

            System.out.println("\nAll operations completed successfully!");

        }} catch (CiphernException e) {{
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }}
    }}

    private static String bytesToHex(byte[] bytes) {{
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {{
            sb.append(String.format("%02x", b));
        }}
        return sb.toString();
    }}
}}
}}
"#
    );
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
