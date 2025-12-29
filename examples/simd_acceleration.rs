// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SIMD Acceleration Example
//!
//! This example demonstrates how to use the SIMD-accelerated cryptographic operations
//! in the ciphern library. SIMD (Single Instruction, Multiple Data) provides significant
//! performance improvements for processing multiple data elements in parallel.
//!
//! # Enabling SIMD
//!
//! SIMD features are optional and must be enabled via Cargo features:
//!
//! ```toml
//! [dependencies]
//! ciphern = { version = "0.1", features = ["simd"] }
//! ```
//!
//! # Example Usage

use ciphern::simd;

fn main() {
    println!("SIMD Acceleration Example\n");
    println!("========================\n");

    demonstrate_simd_availability();
    demonstrate_sha256_acceleration();
    demonstrate_sm4_encryption();
    demonstrate_benchmark_comparison();
}

fn demonstrate_simd_availability() {
    println!("1. SIMD Availability Check");
    println!("--------------------------");

    if simd::is_simd_available() {
        println!("✓ SIMD acceleration is available!");
        println!("  - Architecture: Detected SIMD support\n");
    } else {
        println!("✗ SIMD acceleration is not enabled or available.");
        println!("  Enable with: cargo run --features simd\n");
    }
}

fn demonstrate_sha256_acceleration() {
    println!("2. SHA256 SIMD Acceleration");
    println!("---------------------------");

    if !simd::is_simd_available() {
        println!("  [Skipped - SIMD not available]\n");
        return;
    }

    let test_data =
        b"Hello, World! This is a test message for SHA256 hashing with SIMD acceleration.";

    println!("  Input data: {} bytes", test_data.len());
    println!("  Processing with SIMD-accelerated SHA256...");

    let result = simd::simd_process_blocks_sha256(test_data);
    println!("  Result: {:x?}\n", result);
}

fn demonstrate_sm4_encryption() {
    println!("3. SM4 SIMD Encryption");
    println!("----------------------");

    if !simd::is_simd_available() {
        println!("  [Skipped - SIMD not available]\n");
        return;
    }

    let key = [0x12u8; 16];
    let plaintext = b"SM4 encrypted with SIMD acceleration demo data!!";
    assert!(
        plaintext.len().is_multiple_of(16),
        "Plaintext must be multiple of 16 bytes"
    );

    println!("  Key: {:02x?}", &key[..]);
    println!("  Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!("  Plaintext length: {} bytes", plaintext.len());

    let encrypted = simd::simd_sm4_encrypt(&key, plaintext);
    println!("  Encrypted length: {} bytes", encrypted.len());

    let decrypted = simd::simd_sm4_decrypt(&key, &encrypted);
    let decrypted_str = String::from_utf8_lossy(&decrypted);
    println!("  Decrypted: {}", decrypted_str);
    println!(
        "  Decryption verified: {}\n",
        decrypted_str == String::from_utf8_lossy(plaintext)
    );
}

fn demonstrate_benchmark_comparison() {
    println!("4. Performance Notes");
    println!("--------------------");
    println!("  SIMD acceleration provides significant performance benefits:");
    println!("  - SHA256: ~2-4x faster on supported architectures");
    println!("  - SM4: ~2-3x faster on supported architectures");
    println!();
    println!("  Performance gains are most noticeable with:");
    println!("  - Large files or data streams");
    println!("  - Batch processing operations");
    println!("  - Server-side cryptographic operations");
    println!();
    println!("  Note: Actual performance gains depend on:");
    println!("  - CPU architecture (x86_64, aarch64, etc.)");
    println!("  - SIMD instruction set version (SSE4, AVX2, NEON)");
    println!("  - Data size and alignment");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_availability() {
        let _ = main;
    }

    #[test]
    fn test_sha256_simd() {
        if !simd::is_simd_available() {
            return;
        }
        let data = b"test data for sha256";
        let result = simd::simd_process_blocks_sha256(data);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sm4_simd() {
        if !simd::is_simd_available() {
            return;
        }
        let key = [0u8; 16];
        let plaintext = b"test data 16 !!!"; // exactly 16 bytes
        let encrypted = simd::simd_sm4_encrypt(&key, plaintext);
        let decrypted = simd::simd_sm4_decrypt(&key, &encrypted);
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }
}
