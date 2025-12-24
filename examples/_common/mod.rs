// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Common utilities for examples

use ciphern::Result;
use hex::encode;

#[allow(dead_code)]
pub fn setup() -> Result<ciphern::KeyManager> {
    ciphern::init()?;
    let key_manager = ciphern::KeyManager::new()?;
    Ok(key_manager)
}

#[allow(dead_code)]
pub fn print_section(title: &str) {
    println!("\n{}", "=".repeat(60));
    println!("  {}", title);
    println!("{}\n", "=".repeat(60));
}

#[allow(dead_code)]
pub fn print_result(label: &str, data: &[u8]) {
    println!("  {}: {}", label, encode(data));
}

#[allow(dead_code)]
pub fn print_string(label: &str, data: &str) {
    println!("  {}: {}", label, data);
}
