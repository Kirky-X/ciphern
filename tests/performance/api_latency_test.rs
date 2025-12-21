// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::{Algorithm, Cipher, KeyManager};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const TEST_ITERATIONS: usize = 1000;
const P99_THRESHOLD_MS: f64 = 50.0;

#[derive(Debug, Clone)]
struct LatencyStats {
    min: Duration,
    max: Duration,
    mean: Duration,
    p50: Duration,
    p90: Duration,
    p99: Duration,
    p999: Duration,
}

fn calculate_latency_stats(latencies: &mut Vec<Duration>) -> LatencyStats {
    latencies.sort_unstable();

    let min = latencies[0];
    let max = latencies[latencies.len() - 1];

    let sum: Duration = latencies.iter().sum();
    let mean = sum / latencies.len() as u32;

    let p50_idx = (latencies.len() - 1) * 50 / 100;
    let p90_idx = (latencies.len() - 1) * 90 / 100;
    let p99_idx = (latencies.len() - 1) * 99 / 100;
    let p999_idx = (latencies.len() - 1) * 999 / 1000;

    LatencyStats {
        min,
        max,
        mean,
        p50: latencies[p50_idx],
        p90: latencies[p90_idx],
        p99: latencies[p99_idx],
        p999: latencies[p999_idx],
    }
}

fn measure_encryption_latency(
    cipher: &Cipher,
    key_manager: &KeyManager,
    key_id: &str,
    payload: &[u8],
) -> Duration {
    let start = Instant::now();
    let _encrypted = cipher.encrypt(key_manager, key_id, payload).unwrap();
    start.elapsed()
}

fn measure_decryption_latency(
    cipher: &Cipher,
    key_manager: &KeyManager,
    key_id: &str,
    encrypted: &[u8],
) -> Duration {
    let start = Instant::now();
    let _decrypted = cipher.decrypt(key_manager, key_id, encrypted).unwrap();
    start.elapsed()
}

fn run_latency_test(
    algorithm: Algorithm,
    payload_sizes: &[usize],
) -> HashMap<String, LatencyStats> {
    let mut results = HashMap::new();
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(algorithm).unwrap();
    let cipher = Cipher::new(algorithm).unwrap();

    for &size in payload_sizes {
        let mut encryption_latencies = Vec::with_capacity(TEST_ITERATIONS);
        let mut decryption_latencies = Vec::with_capacity(TEST_ITERATIONS);

        // Pre-generate payloads to avoid allocation overhead in measurement
        let payload = vec![0u8; size];

        // Warm up
        for _ in 0..100 {
            let encrypted = cipher.encrypt(&key_manager, &key_id, &payload).unwrap();
            let _decrypted = cipher.decrypt(&key_manager, &key_id, &encrypted).unwrap();
        }

        // Measure encryption latency
        for _ in 0..TEST_ITERATIONS {
            let latency = measure_encryption_latency(&cipher, &key_manager, &key_id, &payload);
            encryption_latencies.push(latency);
        }

        // Measure decryption latency
        let encrypted_payload = cipher.encrypt(&key_manager, &key_id, &payload).unwrap();
        for _ in 0..TEST_ITERATIONS {
            let latency =
                measure_decryption_latency(&cipher, &key_manager, &key_id, &encrypted_payload);
            decryption_latencies.push(latency);
        }

        let encrypt_stats = calculate_latency_stats(&mut encryption_latencies);
        let decrypt_stats = calculate_latency_stats(&mut decryption_latencies);

        results.insert(format!("encrypt_{}_bytes", size), encrypt_stats);
        results.insert(format!("decrypt_{}_bytes", size), decrypt_stats);
    }

    results
}

#[test]
fn test_api_communication_latency_aes256() {
    println!("\n=== API Communication Latency Test - AES256GCM ===");

    let payload_sizes = vec![128, 1024, 4096, 16384]; // Typical API payload sizes
    let results = run_latency_test(Algorithm::AES256GCM, &payload_sizes);

    let mut all_tests_passed = true;

    for (operation, stats) in &results {
        let p99_ms = stats.p99.as_secs_f64() * 1000.0;
        let passed = p99_ms < P99_THRESHOLD_MS;
        all_tests_passed &= passed;

        println!("\n{}:", operation);
        println!(
            "  P99: {:.3}ms (threshold: {:.1}ms) - {}",
            p99_ms,
            P99_THRESHOLD_MS,
            if passed { "✅ PASS" } else { "❌ FAIL" }
        );
        println!(
            "  Min: {:.3}ms, Max: {:.3}ms, Mean: {:.3}ms",
            stats.min.as_secs_f64() * 1000.0,
            stats.max.as_secs_f64() * 1000.0,
            stats.mean.as_secs_f64() * 1000.0
        );
        println!(
            "  P50: {:.3}ms, P90: {:.3}ms, P999: {:.3}ms",
            stats.p50.as_secs_f64() * 1000.0,
            stats.p90.as_secs_f64() * 1000.0,
            stats.p999.as_secs_f64() * 1000.0
        );
    }

    assert!(
        all_tests_passed,
        "Some latency tests failed P99 threshold of {}ms",
        P99_THRESHOLD_MS
    );
}

#[test]
fn test_api_communication_latency_sm4() {
    println!("\n=== API Communication Latency Test - SM4GCM ===");

    let payload_sizes = vec![128, 1024, 4096, 16384]; // Typical API payload sizes
    let results = run_latency_test(Algorithm::SM4GCM, &payload_sizes);

    let mut all_tests_passed = true;

    for (operation, stats) in &results {
        let p99_ms = stats.p99.as_secs_f64() * 1000.0;
        let passed = p99_ms < P99_THRESHOLD_MS;
        all_tests_passed &= passed;

        println!("\n{}:", operation);
        println!(
            "  P99: {:.3}ms (threshold: {:.1}ms) - {}",
            p99_ms,
            P99_THRESHOLD_MS,
            if passed { "✅ PASS" } else { "❌ FAIL" }
        );
        println!(
            "  Min: {:.3}ms, Max: {:.3}ms, Mean: {:.3}ms",
            stats.min.as_secs_f64() * 1000.0,
            stats.max.as_secs_f64() * 1000.0,
            stats.mean.as_secs_f64() * 1000.0
        );
        println!(
            "  P50: {:.3}ms, P90: {:.3}ms, P999: {:.3}ms",
            stats.p50.as_secs_f64() * 1000.0,
            stats.p90.as_secs_f64() * 1000.0,
            stats.p999.as_secs_f64() * 1000.0
        );
    }

    assert!(
        all_tests_passed,
        "Some latency tests failed P99 threshold of {}ms",
        P99_THRESHOLD_MS
    );
}

#[test]
fn test_end_to_end_api_latency() {
    println!("\n=== End-to-End API Communication Latency Test ===");

    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();

    let mut e2e_latencies = Vec::with_capacity(TEST_ITERATIONS);

    // Simulate typical API request/response cycle
    let request =
        b"{\"action\":\"transfer\",\"amount\":1000,\"from\":\"user123\",\"to\":\"user456\"}";
    let response = b"{\"status\":\"success\",\"transaction_id\":\"tx789\",\"timestamp\":\"2025-01-01T12:00:00Z\"}";

    // Warm up
    for _ in 0..100 {
        let encrypted_req = cipher.encrypt(&key_manager, &key_id, request).unwrap();
        let _decrypted_req = cipher
            .decrypt(&key_manager, &key_id, &encrypted_req)
            .unwrap();
        let encrypted_res = cipher.encrypt(&key_manager, &key_id, response).unwrap();
        let _decrypted_res = cipher
            .decrypt(&key_manager, &key_id, &encrypted_res)
            .unwrap();
    }

    // Measure end-to-end latency
    for _ in 0..TEST_ITERATIONS {
        let start = Instant::now();

        // Client encrypts request
        let encrypted_req = cipher.encrypt(&key_manager, &key_id, request).unwrap();

        // Server decrypts request
        let decrypted_req = cipher
            .decrypt(&key_manager, &key_id, &encrypted_req)
            .unwrap();

        // Server processes request (simulated)
        assert_eq!(request, &decrypted_req[..]);

        // Server encrypts response
        let encrypted_res = cipher.encrypt(&key_manager, &key_id, response).unwrap();

        // Client decrypts response
        let decrypted_res = cipher
            .decrypt(&key_manager, &key_id, &encrypted_res)
            .unwrap();
        assert_eq!(response, &decrypted_res[..]);

        e2e_latencies.push(start.elapsed());
    }

    let stats = calculate_latency_stats(&mut e2e_latencies);
    let p99_ms = stats.p99.as_secs_f64() * 1000.0;
    let passed = p99_ms < P99_THRESHOLD_MS;

    println!("\nEnd-to-End API Communication:");
    println!(
        "  P99: {:.3}ms (threshold: {:.1}ms) - {}",
        p99_ms,
        P99_THRESHOLD_MS,
        if passed { "✅ PASS" } else { "❌ FAIL" }
    );
    println!(
        "  Min: {:.3}ms, Max: {:.3}ms, Mean: {:.3}ms",
        stats.min.as_secs_f64() * 1000.0,
        stats.max.as_secs_f64() * 1000.0,
        stats.mean.as_secs_f64() * 1000.0
    );
    println!(
        "  P50: {:.3}ms, P90: {:.3}ms, P999: {:.3}ms",
        stats.p50.as_secs_f64() * 1000.0,
        stats.p90.as_secs_f64() * 1000.0,
        stats.p999.as_secs_f64() * 1000.0
    );

    assert!(
        passed,
        "End-to-end API latency test failed P99 threshold of {}ms",
        P99_THRESHOLD_MS
    );
}
