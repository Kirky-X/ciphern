// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! 模糊测试：随机数生成器
//!
//! 此测试通过向随机数生成器输入各种参数来发现潜在的问题。

use ciphern::SecureRandom;

/// 模糊测试：生成各种大小的随机数
#[test]
fn fuzz_random_generation_various_sizes() {
    let rng = SecureRandom::new().unwrap();

    // 测试各种大小的缓冲区
    for size in [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
                 255, 256, 511, 512, 1023, 1024, 2047, 2048, 4095, 4096,
                 8191, 8192, 16383, 16384, 32767, 32768, 65535, 65536] {
        let mut buf = vec![0u8; size];
        rng.fill(&mut buf).unwrap();

        // 验证生成的随机数不是全零
        if size > 0 {
            let all_zeros = buf.iter().all(|&b| b == 0);
            assert!(!all_zeros, "Generated all zeros for size {}", size);

            // 验证生成的随机数不是全相同
            let all_same = buf.iter().all(|&b| b == buf[0]);
            assert!(!all_same, "Generated all same bytes for size {}", size);
        }
    }
}

/// 模糊测试：生成多个随机数并验证唯一性
#[test]
fn fuzz_random_generation_uniqueness() {
    let rng = SecureRandom::new().unwrap();
    const NUM_GENERATIONS: usize = 100;
    const BUFFER_SIZE: usize = 32;

    let mut generated_values = Vec::new();

    for _ in 0..NUM_GENERATIONS {
        let mut buf = [0u8; BUFFER_SIZE];
        rng.fill(&mut buf).unwrap();

        // 验证这个值之前没有生成过（对于 32 字节的缓冲区，重复的概率极低）
        assert!(!generated_values.contains(&buf), "Generated duplicate random value");
        generated_values.push(buf);
    }
}

/// 模糊测试：连续生成随机数并验证统计特性
#[test]
fn fuzz_random_generation_statistics() {
    let rng = SecureRandom::new().unwrap();
    const NUM_SAMPLES: usize = 10000;
    const BUFFER_SIZE: usize = 1;

    let mut byte_counts = [0usize; 256];

    for _ in 0..NUM_SAMPLES {
        let mut buf = [0u8; BUFFER_SIZE];
        rng.fill(&mut buf).unwrap();
        byte_counts[buf[0] as usize] += 1;
    }

    // 验证每个字节值至少出现一次（对于 10000 个样本，这是合理的）
    for i in 0..256 {
        assert!(byte_counts[i] > 0, "Byte value {} never appeared", i);
    }

    // 验证分布大致均匀（每个字节值应该出现约 40 次）
    let expected = NUM_SAMPLES / 256;
    let tolerance = expected / 2; // 允许 50% 的偏差

    for i in 0..256 {
        let count = byte_counts[i];
        assert!(
            count >= expected - tolerance && count <= expected + tolerance,
            "Byte value {} appeared {} times, expected around {}",
            i, count, expected
        );
    }
}

/// 模糊测试：使用多个随机数生成器实例
#[test]
fn fuzz_multiple_rng_instances() {
    const NUM_INSTANCES: usize = 10;
    const BUFFER_SIZE: usize = 32;

    let mut instances = Vec::new();
    for _ in 0..NUM_INSTANCES {
        instances.push(SecureRandom::new().unwrap());
    }

    // 从每个实例生成随机数
    let mut generated_values = Vec::new();
    for rng in &instances {
        let mut buf = [0u8; BUFFER_SIZE];
        rng.fill(&mut buf).unwrap();
        generated_values.push(buf);
    }

    // 验证所有生成的值都不相同（概率极低）
    for i in 0..NUM_INSTANCES {
        for j in (i + 1)..NUM_INSTANCES {
            assert_ne!(
                generated_values[i], generated_values[j],
                "RNG instances {} and {} generated the same value",
                i, j
            );
        }
    }
}

/// 模糊测试：随机数生成的性能
#[test]
fn fuzz_random_generation_performance() {
    let rng = SecureRandom::new().unwrap();
    const NUM_ITERATIONS: usize = 1000;
    const BUFFER_SIZE: usize = 1024;

    let start = std::time::Instant::now();

    for _ in 0..NUM_ITERATIONS {
        let mut buf = [0u8; BUFFER_SIZE];
        rng.fill(&mut buf).unwrap();
    }

    let duration = start.elapsed();

    // 验证性能合理（应该在几秒内完成）
    assert!(
        duration.as_secs() < 10,
        "Random generation took too long: {:?}",
        duration
    );

    println!("Generated {} KB of random data in {:?}", NUM_ITERATIONS * BUFFER_SIZE / 1024, duration);
}