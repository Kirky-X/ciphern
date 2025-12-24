// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! FIPS Compliance Examples
//!
//! This module demonstrates FIPS compliance features and best practices
//! when using Ciphern in regulated environments.

#[path = "_common/mod.rs"]
mod common;

use common::print_section;

/// Run all FIPS compliance examples
pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    run_fips_mode_example()?;
    run_algorithm_validation_example()?;
    run_self_test_example()?;
    Ok(())
}

/// FIPS Mode Example
///
/// Demonstrates enabling and using FIPS 140-2 compliant mode.
pub fn run_fips_mode_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("FIPS 140-2 Compliant Mode Example");

    println!("  Checking FIPS mode status...");

    let is_enabled = ciphern::is_fips_enabled();
    println!("  FIPS mode enabled: {}", is_enabled);

    let algorithms = ciphern::get_fips_approved_algorithms();
    println!("  Approved algorithms count: {}", algorithms.len());
    for algo in &algorithms {
        println!("    - {:?}", algo);
    }

    println!("  ✓ FIPS mode example completed!");

    Ok(())
}

/// Algorithm Validation Example
///
/// Demonstrates validating algorithms for FIPS compliance.
pub fn run_algorithm_validation_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Algorithm Validation Example");

    println!("  FIPS approved algorithms:\n");

    let algorithms = vec![
        ciphern::Algorithm::AES256GCM,
        ciphern::Algorithm::ECDSAP384,
        ciphern::Algorithm::Ed25519,
        ciphern::Algorithm::RSA3072,
    ];

    for algo in &algorithms {
        let is_approved = ciphern::get_fips_approved_algorithms().contains(algo);
        println!(
            "  {:?}: {}",
            algo,
            if is_approved {
                "Approved"
            } else {
                "Not approved"
            }
        );
    }

    println!("  ✓ Algorithm validation example completed!");

    Ok(())
}

/// Self-Test Example
///
/// Demonstrates FIPS-required self-tests.
pub fn run_self_test_example() -> Result<(), Box<dyn std::error::Error>> {
    print_section("Self-Tests Example");

    println!("  Note: FIPS self-tests run automatically on library initialization\n");

    let is_enabled = ciphern::is_fips_enabled();
    println!(
        "  FIPS mode: {}",
        if is_enabled { "Enabled" } else { "Disabled" }
    );

    let algorithms = ciphern::get_fips_approved_algorithms();
    println!("  Approved algorithms: {}", algorithms.len());

    if is_enabled {
        println!("  ✓ FIPS self-tests passed during initialization");
    } else {
        println!("  Note: Run with --features fips to enable FIPS self-tests");
    }

    println!("  [OK] Self-test example completed!");

    Ok(())
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
