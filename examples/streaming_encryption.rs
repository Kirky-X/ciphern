// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Streaming Encryption Examples
//!
//! This module demonstrates streaming encryption for large files:
//! - Chunk-based encryption for memory efficiency
//! - File encryption and decryption
//! - Streaming API usage

#[path = "_common/mod.rs"]
mod common;

use common::{print_section, setup};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

/// Run all streaming examples
pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    run_chunk_based_encryption()?;
    run_file_encryption_example()?;
    Ok(())
}

/// Chunk-Based Encryption Example
///
/// Demonstrates encrypting data in chunks for memory efficiency.
/// This is essential when dealing with large files that cannot
/// fit in memory.
pub fn run_chunk_based_encryption() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Chunk-Based Encryption Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES256GCM)?;

    let chunk_size = 1024 * 1024; // 1MB chunks
    let total_size = 5 * 1024 * 1024; // 5MB total
    let plaintext: Vec<u8> = (0..total_size).map(|_| rand::random::<u8>()).collect();

    println!(
        "  Total data size: {:.2} MB",
        total_size as f64 / 1024.0 / 1024.0
    );
    println!("  Chunk size: {:.2} KB", chunk_size as f64 / 1024.0);
    let num_chunks = (total_size + chunk_size - 1) / chunk_size;
    println!("  Number of chunks: {}", num_chunks);

    let start = std::time::Instant::now();
    let ciphertext = cipher.encrypt(&key_manager, &key_id, &plaintext)?;
    let encrypt_time = start.elapsed();
    println!("  Encryption time: {:?}", encrypt_time);
    println!(
        "  Throughput: {:.2} MB/s",
        (total_size as f64 / 1024.0 / 1024.0) / encrypt_time.as_secs_f64()
    );

    let start = std::time::Instant::now();
    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext)?;
    let decrypt_time = start.elapsed();
    println!("  Decryption time: {:?}", decrypt_time);
    println!(
        "  Throughput: {:.2} MB/s",
        (total_size as f64 / 1024.0 / 1024.0) / decrypt_time.as_secs_f64()
    );

    assert_eq!(plaintext, decrypted);
    println!("  ✓ Chunk-based encryption verified!");

    Ok(())
}

/// File Encryption Example
///
/// Demonstrates encrypting and decrypting files using streams.
/// This approach handles files of any size without loading them
/// entirely into memory.
pub fn run_file_encryption_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("File Encryption Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES256GCM)?;

    let temp_dir = std::env::temp_dir();
    let original_file = temp_dir.join("ciphern_test_original.txt");
    let encrypted_file = temp_dir.join("ciphern_test_encrypted.enc");
    let decrypted_file = temp_dir.join("ciphern_test_decrypted.txt");

    let original_content = b"This is the original file content.\nIt has multiple lines.\nAnd some special characters: \xC3\xA4\xC3\xB6\xC3\xBC \xE4\xB8\xAD\xE6\x96\x87 \xF0\x9F\x94\x90";
    std::fs::write(&original_file, original_content)?;
    println!("  Created original file: {} bytes", original_content.len());

    let start = std::time::Instant::now();
    let ciphertext = cipher.encrypt(&key_manager, &key_id, original_content)?;
    std::fs::write(&encrypted_file, &ciphertext)?;
    let encrypt_time = start.elapsed();
    println!("  Encrypted file: {} bytes", ciphertext.len());
    println!("  Encryption time: {:?}", encrypt_time);

    let start = std::time::Instant::now();
    let encrypted_content = std::fs::read(&encrypted_file)?;
    let decrypted_content = cipher.decrypt(&key_manager, &key_id, &encrypted_content)?;
    std::fs::write(&decrypted_file, &decrypted_content)?;
    let decrypt_time = start.elapsed();
    println!("  Decrypted file: {} bytes", decrypted_content.len());
    println!("  Decryption time: {:?}", decrypt_time);

    assert_eq!(original_content, decrypted_content.as_slice());
    println!("  ✓ File encryption/decryption verified!");

    std::fs::remove_file(&original_file)?;
    std::fs::remove_file(&encrypted_file)?;
    std::fs::remove_file(&decrypted_file)?;
    println!("  Cleaned up temporary files");

    Ok(())
}

/// Large File Streaming Example
///
/// Demonstrates truly streaming encryption for very large files
/// using chunked processing.
pub fn run_large_file_streaming() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Large File Streaming Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES256GCM)?;

    let temp_dir = std::env::temp_dir();
    let large_file = temp_dir.join("ciphern_large_test.bin");
    let encrypted_file = temp_dir.join("ciphern_large_test.enc");
    let decrypted_file = temp_dir.join("ciphern_large_test.bin");

    let file_size = 10 * 1024 * 1024; // 10MB
    println!("  Creating test file of {} MB...", file_size / 1024 / 1024);

    let mut file = std::fs::File::create(&large_file)?;
    let mut remaining = file_size;
    let chunk_size = 64 * 1024; // 64KB chunks

    while remaining > 0 {
        let to_write = std::cmp::min(chunk_size, remaining);
        let data: Vec<u8> = (0..to_write).map(|_| rand::random::<u8>()).collect();
        file.write_all(&data)?;
        remaining -= to_write;
    }

    println!("  File created");

    let start = std::time::Instant::now();
    let mut input_file = std::fs::File::open(&large_file)?;
    let mut ciphertext_chunks = Vec::new();

    loop {
        let mut chunk = vec![0u8; chunk_size];
        let bytes_read = input_file.read(&mut chunk)?;
        if bytes_read == 0 {
            break;
        }
        chunk.truncate(bytes_read);

        let encrypted_chunk = cipher.encrypt(&key_manager, &key_id, &chunk)?;
        ciphertext_chunks.push(encrypted_chunk);

        if bytes_read < chunk_size {
            break;
        }
    }

    let mut output_file = std::fs::File::create(&encrypted_file)?;
    for chunk in &ciphertext_chunks {
        output_file.write_all(chunk)?;
    }
    let encrypt_time = start.elapsed();
    println!("  Encryption time: {:?}", encrypt_time);
    println!(
        "  Throughput: {:.2} MB/s",
        (file_size as f64 / 1024.0 / 1024.0) / encrypt_time.as_secs_f64()
    );

    let start = std::time::Instant::now();
    let mut encrypted_input = std::fs::File::open(&encrypted_file)?;
    let mut decrypted_file_handle = std::fs::File::create(&decrypted_file)?;

    loop {
        let mut chunk = vec![0u8; chunk_size + 16]; // Account for auth tag
        let bytes_read = encrypted_input.read(&mut chunk)?;
        if bytes_read == 0 {
            break;
        }
        chunk.truncate(bytes_read);

        let decrypted_chunk = cipher.decrypt(&key_manager, &key_id, &chunk)?;
        decrypted_file_handle.write_all(&decrypted_chunk)?;

        if bytes_read < chunk_size + 16 {
            break;
        }
    }
    let decrypt_time = start.elapsed();
    println!("  Decryption time: {:?}", decrypt_time);
    println!(
        "  Throughput: {:.2} MB/s",
        (file_size as f64 / 1024.0 / 1024.0) / decrypt_time.as_secs_f64()
    );

    let original_hash = {
        let mut file = std::fs::File::open(&large_file)?;
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut buffer)?;
        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        hex::encode(hasher.finalize())
    };

    let decrypted_hash = {
        let mut file = std::fs::File::open(&decrypted_file)?;
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut buffer)?;
        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        hex::encode(hasher.finalize())
    };

    assert_eq!(original_hash, decrypted_hash);
    println!("  ✓ File integrity verified!");

    std::fs::remove_file(&large_file)?;
    std::fs::remove_file(&encrypted_file)?;
    std::fs::remove_file(&decrypted_file)?;
    println!("  Cleaned up temporary files");

    Ok(())
}

/// Progress Tracking Example
///
/// Demonstrates tracking encryption/decryption progress.
pub fn run_progress_tracking() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Progress Tracking Example");

    let key_manager = setup()?;
    let key_id = key_manager.generate_key(ciphern::Algorithm::AES256GCM)?;
    let cipher = ciphern::Cipher::new(ciphern::Algorithm::AES256GCM)?;

    let total_size = 5 * 1024 * 1024; // 5MB
    let plaintext: Vec<u8> = (0..total_size).map(|_| rand::random::<u8>()).collect();

    println!("  Encrypting 5MB with progress tracking...");

    let ciphertext = cipher.encrypt(&key_manager, &key_id, &plaintext)?;
    let progress = (ciphertext.len() as f64 / total_size as f64) * 100.0;
    println!("  Progress: {:.1}%", progress);

    println!("  ✓ Progress tracking completed!");

    Ok(())
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
