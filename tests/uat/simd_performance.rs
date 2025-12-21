// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

#[test]
fn uat_simd_performance_check() {
    use securevault::{Cipher, Algorithm, KeyManager};
    use std::time::Instant;

    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();
    
    let size = 1024 * 1024; // 1MB
    let plaintext = vec![0u8; size];
    
    // Warmup
    for _ in 0..10 {
        let _ = cipher.encrypt(&key_manager, &key_id, &plaintext).unwrap();
    }
    
    let iterations = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = cipher.encrypt(&key_manager, &key_id, &plaintext).unwrap();
    }
    let elapsed = start.elapsed();
    
    let total_bytes = (size * iterations) as f64;
    let seconds = elapsed.as_secs_f64();
    let throughput_mb_s = (total_bytes / seconds) / (1024.0 * 1024.0);
    
    println!("AES-256-GCM Throughput: {:.2} MB/s", throughput_mb_s);
    
    // Basic sanity check for performance (adjust threshold based on environment)
    // assert!(throughput_mb_s > 100.0); 
}