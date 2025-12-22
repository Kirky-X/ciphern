// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::{Algorithm, Cipher, KeyManager};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

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

criterion_group!(benches, bench_aes256_encrypt, bench_sm4_encrypt);
criterion_main!(benches);
