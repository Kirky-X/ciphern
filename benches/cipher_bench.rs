// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::random::{is_hardware_rng_available, BulkHardwareRng, HardwareRng};
use ciphern::{Algorithm, Cipher, KeyManager};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

fn bench_aes256_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes256_encrypt");
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();

    for size in [1024, 10240, 102400, 1048576].iter() {
        group.throughput(criterion::Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let plaintext = vec![0u8; size];
            b.iter(|| {
                cipher
                    .encrypt(&key_manager, &key_id, black_box(&plaintext))
                    .unwrap()
            });
        });
    }

    group.finish();
}

fn bench_sm4_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm4_encrypt");
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::SM4GCM).unwrap();
    let cipher = Cipher::new(Algorithm::SM4GCM).unwrap();

    for size in [1024, 10240, 102400, 1048576].iter() {
        group.throughput(criterion::Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let plaintext = vec![0u8; size];
            b.iter(|| {
                cipher
                    .encrypt(&key_manager, &key_id, black_box(&plaintext))
                    .unwrap()
            });
        });
    }

    group.finish();
}

fn bench_hardware_rng(c: &mut Criterion) {
    let mut group = c.benchmark_group("hardware_rng");

    if !is_hardware_rng_available() {
        // Skip if hardware RNG is not available
        group.bench_function("software_fallback", |b| {
            b.iter(|| {
                let mut rng = HardwareRng::new().unwrap();
                let mut buf = [0u8; 32];
                rng.fill_bytes(&mut buf);
            });
        });
        group.finish();
        return;
    }

    // Benchmark single u64 generation
    group.bench_function("next_u64", |b| {
        let mut rng = HardwareRng::new().unwrap();
        b.iter(|| {
            let _ = rng.next_u64();
        });
    });

    // Benchmark fill_bytes for different sizes
    for size in [32, 64, 128, 256, 512, 1024].iter() {
        group.throughput(criterion::Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut rng = HardwareRng::new().unwrap();
            b.iter(|| {
                let mut buf = vec![0u8; size];
                rng.fill_bytes(&mut buf);
            });
        });
    }

    // Benchmark raw hardware_fill_bytes
    for size in [32, 64, 128, 256, 512, 1024].iter() {
        group.throughput(criterion::Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("raw_{}", size)),
            size,
            |b, &size| {
                b.iter(|| {
                    let mut buf = vec![0u8; size];
                    ciphern::hardware_fill_bytes(&mut buf).unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_bulk_hardware_rng(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_hardware_rng");

    if !is_hardware_rng_available() {
        return;
    }

    for buffer_size in [256, 512, 1024, 2048, 4096].iter() {
        group.throughput(criterion::Throughput::Bytes(*buffer_size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(buffer_size),
            buffer_size,
            |b, &buffer_size| {
                let mut rng = BulkHardwareRng::new(buffer_size).unwrap();
                b.iter(|| {
                    let mut dest = vec![0u8; 4096];
                    rng.fill(&mut dest).unwrap();
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_aes256_encrypt,
    bench_sm4_encrypt,
    bench_hardware_rng,
    bench_bulk_hardware_rng
);
criterion_main!(benches);
