// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! GPU 设备检测和实际使用测试
//!
//! 验证CUDA设备枚举、初始化和实际GPU计算功能

#[cfg(feature = "gpu")]
use ciphern::hardware::gpu::device::{XpuManager, XpuType};
#[cfg(feature = "gpu")]
use ciphern::hardware::gpu::{init_gpu, is_gpu_enabled, is_gpu_initialized};
#[cfg(feature = "gpu")]
use ciphern::Algorithm;

#[test]
#[cfg(all(feature = "gpu", feature = "gpu-cuda"))]
fn test_cuda_device_detection() {
    let manager = XpuManager::new();

    match manager {
        Ok(m) => {
            let device_count = m.get_device_count();
            println!("Detected {} GPU device(s)", device_count);
            assert!(device_count > 0, "Expected at least one GPU device");

            let device_type = m.default_device_type();
            println!("Primary device type: {}", device_type);
            assert_eq!(device_type, XpuType::NvidiaCuda);

            let primary_device = m.get_primary_device();
            assert!(primary_device.is_ok(), "Failed to get primary device");
            let device = primary_device.unwrap();
            println!("Primary device: {}", device.device_name());
            assert!(!device.device_name().is_empty());
        }
        Err(e) => {
            println!("No GPU devices available: {:?}", e);
        }
    }
}

#[test]
#[cfg(all(feature = "gpu", feature = "gpu-cuda"))]
fn test_gpu_initialization() {
    let result = init_gpu();
    println!("GPU init result: {:?}", result);

    match result {
        Ok(()) => {
            assert!(is_gpu_enabled(), "GPU should be enabled after init");
            assert!(is_gpu_initialized(), "GPU should be initialized after init");
        }
        Err(e) => {
            println!("GPU init failed (expected if no CUDA driver): {:?}", e);
        }
    }
}

#[test]
#[cfg(all(feature = "gpu", feature = "gpu-cuda"))]
fn test_device_enumeration_detailed() {
    let manager_result = XpuManager::new();

    if let Ok(manager) = manager_result {
        let devices = manager.get_all_devices();
        println!("Total devices found: {}", devices.len());

        for (index, device) in devices.iter().enumerate() {
            println!(
                "Device {}: {} (type: {:?})",
                index,
                device.device_name(),
                device.device_type()
            );

            let caps = device.capabilities();
            println!("  - Compute units: {}", caps.compute_units);
            println!(
                "  - Global memory: {} MB",
                caps.global_memory / (1024 * 1024)
            );
            println!("  - Max work group: {}", caps.max_work_group_size);
            println!("  - ECC supported: {}", caps.ecc_supported);
            println!("  - Algorithms: {:?}", caps.supported_algorithms);
        }

        assert!(!devices.is_empty(), "Should have at least one device");
    } else {
        println!("No devices found (no CUDA driver or no GPU)");
    }
}

#[test]
#[cfg(all(feature = "gpu", feature = "gpu-cuda"))]
fn test_actual_gpu_kernel_usage() {
    let manager_result = XpuManager::new();

    if let Ok(manager) = manager_result {
        let primary_device = manager.get_primary_device();
        assert!(primary_device.is_ok(), "Should have primary device");

        let device = primary_device.unwrap();
        println!("Testing kernel access for: {}", device.device_name());

        // 测试获取各算法的kernel
        let algorithms = [
            Algorithm::SHA256,
            Algorithm::SHA512,
            Algorithm::AES256GCM,
            Algorithm::ECDSAP256,
            Algorithm::Ed25519,
        ];

        for algo in &algorithms {
            match device.get_kernel(*algo) {
                Ok(_kernel) => {
                    println!("  ✓ {} kernel: Available", algo);
                }
                Err(e) => {
                    println!("  ✗ {} kernel: {} (not implemented yet)", algo, e);
                }
            }
        }

        // 验证设备状态
        let health = device.check_health();
        match health {
            Ok(h) => {
                println!(
                    "Device health: healthy={}, memory={}/{} MB",
                    h.is_healthy,
                    h.memory_used / (1024 * 1024),
                    h.memory_total / (1024 * 1024)
                );
            }
            Err(e) => {
                println!("Health check failed: {:?}", e);
            }
        }
    } else {
        println!("No GPU devices available");
    }
}

#[test]
#[cfg(all(feature = "gpu", feature = "gpu-cuda"))]
fn test_gpu_memory_operations() {
    let manager_result = XpuManager::new();

    if let Ok(manager) = manager_result {
        let primary_device = manager.get_primary_device();
        assert!(primary_device.is_ok());

        let device = primary_device.unwrap();

        // 测试内存分配
        let alloc_result = device.allocate_device_buffer(1024 * 1024); // 1MB
        println!("Device buffer allocation (1MB): {:?}", alloc_result);

        // 测试主机缓冲区分配
        let host_buffer = device.allocate_host_buffer(4096);
        println!(
            "Host buffer allocation (4KB): {} bytes",
            host_buffer.unwrap().len()
        );

        // 测试数据复制到设备
        let test_data = vec![0x42u8; 1024];
        let copy_result = device.copy_to_device(&test_data, 0);
        println!("Copy to device: {:?}", copy_result);

        // 测试从设备复制数据
        let read_result = device.copy_from_device(0, 1024);
        match read_result {
            Ok(data) => println!("Copy from device: {} bytes", data.len()),
            Err(e) => println!("Copy from device failed: {:?}", e),
        }
    }
}

#[test]
#[cfg(all(feature = "gpu", feature = "gpu-cuda"))]
fn test_gpu_sha256_computation() {
    use ciphern::Hasher;

    let manager_result = XpuManager::new();

    if let Ok(manager) = manager_result {
        let primary_device = manager.get_primary_device();
        assert!(primary_device.is_ok(), "Should have primary device");

        let device = primary_device.unwrap();
        let kernel = device.get_kernel(Algorithm::SHA256);
        assert!(kernel.is_ok(), "Should get SHA256 kernel");

        let kernel = kernel.unwrap();
        println!("Testing SHA256 GPU computation");

        let test_data = b"Hello, GPU Accelerated Cryptography! This is a test message for SHA256 hashing on GPU.";

        let gpu_result = kernel.hash(test_data, Algorithm::SHA256);
        assert!(gpu_result.is_ok(), "GPU SHA256 computation should succeed");
        let gpu_hash = gpu_result.unwrap();
        println!("GPU SHA256 hash: {:02x?}", gpu_hash);
        assert_eq!(gpu_hash.len(), 32, "SHA256 should produce 32 bytes");

        let cpu_hasher = Hasher::new(Algorithm::SHA256).unwrap();
        let cpu_hash = cpu_hasher.hash(test_data);
        println!("CPU SHA256 hash: {:02x?}", cpu_hash);
        assert_eq!(
            gpu_hash, cpu_hash,
            "GPU and CPU SHA256 results should match"
        );

        println!("✓ GPU SHA256 computation verified - results match CPU implementation");
    }
}

#[test]
#[cfg(feature = "gpu-cuda")]
fn test_gpu_sha512_computation() {
    use ciphern::Hasher;

    let manager_result = XpuManager::new();

    if let Ok(manager) = manager_result {
        let primary_device = manager.get_primary_device();
        assert!(primary_device.is_ok(), "Should have primary device");

        let device = primary_device.unwrap();
        let kernel = device.get_kernel(Algorithm::SHA512);
        assert!(kernel.is_ok(), "Should get SHA512 kernel");

        let kernel = kernel.unwrap();
        println!("Testing SHA512 GPU computation");

        let test_data = b"GPU accelerated SHA512 hashing test with a longer message to ensure proper block processing.";

        let gpu_result = kernel.hash(test_data, Algorithm::SHA512);
        assert!(gpu_result.is_ok(), "GPU SHA512 computation should succeed");
        let gpu_hash = gpu_result.unwrap();
        println!("GPU SHA512 hash: {:02x?}", gpu_hash);
        assert_eq!(gpu_hash.len(), 64, "SHA512 should produce 64 bytes");

        let cpu_hasher = Hasher::new(Algorithm::SHA512).unwrap();
        let cpu_hash = cpu_hasher.hash(test_data);
        println!("CPU SHA512 hash: {:02x?}", cpu_hash);
        assert_eq!(
            gpu_hash, cpu_hash,
            "GPU and CPU SHA512 results should match"
        );

        println!("✓ GPU SHA512 computation verified - results match CPU implementation");
    }
}

#[test]
#[cfg(feature = "gpu-cuda")]
fn test_gpu_aes_gcm_encryption() {
    use aes_gcm::aead::Aead;
    use aes_gcm::KeyInit;

    let manager_result = XpuManager::new();

    if let Ok(manager) = manager_result {
        let primary_device = manager.get_primary_device();
        assert!(primary_device.is_ok(), "Should have primary device");

        let device = primary_device.unwrap();
        let kernel = device.get_kernel(Algorithm::AES256GCM);
        assert!(kernel.is_ok(), "Should get AES256GCM kernel");

        let kernel = kernel.unwrap();
        println!("Testing AES256-GCM GPU encryption");

        let key_data = vec![0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"Secret message encrypted on GPU with AES-256-GCM! This ensures confidentiality and authenticity.";

        let gpu_result = kernel.aes_gcm_encrypt(&key_data, &nonce, plaintext);
        assert!(gpu_result.is_ok(), "GPU AES-GCM encryption should succeed");
        let ciphertext = gpu_result.unwrap();
        println!(
            "GPU encrypted {} bytes -> {} bytes",
            plaintext.len(),
            ciphertext.len()
        );
        assert!(
            ciphertext.len() >= plaintext.len() + 16,
            "GCM adds 16-byte auth tag"
        );

        let cpu_aead = aes_gcm::Aes256Gcm::new_from_slice(&key_data).unwrap();
        let cpu_ciphertext = cpu_aead
            .encrypt(aes_gcm::Nonce::from_slice(&nonce), plaintext.as_slice())
            .unwrap();
        println!(
            "CPU encrypted {} bytes -> {} bytes",
            plaintext.len(),
            cpu_ciphertext.len()
        );
        assert_eq!(
            ciphertext, cpu_ciphertext,
            "GPU and CPU encryption results should match"
        );

        let gpu_decrypt_result = kernel.aes_gcm_decrypt(&key_data, &nonce, &ciphertext);
        assert!(
            gpu_decrypt_result.is_ok(),
            "GPU AES-GCM decryption should succeed"
        );
        let gpu_plaintext = gpu_decrypt_result.unwrap();
        assert_eq!(
            gpu_plaintext, plaintext,
            "Decrypted plaintext should match original"
        );

        println!(
            "✓ GPU AES256-GCM encryption/decryption verified - results match CPU implementation"
        );
    }
}

#[test]
#[cfg(feature = "gpu-cuda")]
fn test_gpu_batch_hashing() {
    use ciphern::Hasher;

    let manager_result = XpuManager::new();

    if let Ok(manager) = manager_result {
        let primary_device = manager.get_primary_device();
        assert!(primary_device.is_ok(), "Should have primary device");

        let device = primary_device.unwrap();
        let kernel = device.get_kernel(Algorithm::SHA256);
        assert!(kernel.is_ok(), "Should get SHA256 kernel");

        let kernel = kernel.unwrap();
        println!("Testing SHA256 GPU batch computation");

        let test_data: Vec<Vec<u8>> = vec![
            b"Message 1 for batch processing".to_vec(),
            b"Message 2 with different content".to_vec(),
            b"Third message in the batch test".to_vec(),
            b"Final message number four".to_vec(),
        ];

        let gpu_result = kernel.hash_batch(&test_data, Algorithm::SHA256);
        assert!(gpu_result.is_ok(), "GPU batch hashing should succeed");
        let gpu_hashes = gpu_result.unwrap();
        assert_eq!(
            gpu_hashes.len(),
            test_data.len(),
            "Should get same number of hashes"
        );

        println!("GPU batch processed {} messages", test_data.len());

        let cpu_hasher = Hasher::new(Algorithm::SHA256).unwrap();
        let mut cpu_hashes = Vec::new();
        for data in &test_data {
            let hash = cpu_hasher.hash(data);
            cpu_hashes.push(hash);
        }

        for (i, (gpu_hash, cpu_hash)) in gpu_hashes.iter().zip(cpu_hashes.iter()).enumerate() {
            assert_eq!(gpu_hash, cpu_hash, "Hash {} should match", i);
            println!("  Message {}: {:02x?} ✓", i + 1, &gpu_hash[..8]);
        }

        println!(
            "✓ GPU batch SHA256 computation verified - all {} results match CPU",
            test_data.len()
        );
    }
}
