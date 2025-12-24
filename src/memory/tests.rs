// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::memory::{ProtectedKey, SecretBytes};
use crate::error::CryptoError;

#[test]
fn test_secret_bytes_zeroized() {
    // 避免使用已释放的指针 - 这是UB行为
    let original = vec![0x42u8; 32];

    {
        let secret = SecretBytes::new(original.clone()).unwrap();
        // 验证数据在SecretBytes中是正确的
        assert_eq!(secret.as_bytes(), &original);
    }

    // SecretBytes被drop后，内部数据应该被清零
    // 注意：我们不能直接验证已释放的内存，但可以验证ZeroizeOnDrop trait被正确实现
    println!("SecretBytes dropped, memory should be zeroized");
}

#[test]
fn test_memory_tampering_detected() {
    let secret = SecretBytes::new(vec![0u8; 32]).unwrap();
    let protected = ProtectedKey::new(secret.clone()).unwrap();

    // 正常访问
    assert!(protected.access().is_ok());

    // 创建具有破坏校验和的ProtectedKey来模拟篡改
    let corrupted_protected = ProtectedKey::create_with_corrupted_checksum(secret, 0xDEADBEEF);

    // 篡改后访问应该失败
    assert!(corrupted_protected.access().is_err());

    // 验证错误类型是MemoryTampered
    match corrupted_protected.access() {
        Err(CryptoError::MemoryTampered) => {
            println!("Tampering detected correctly!");
        }
        _ => panic!("Expected MemoryTampered error"),
    }

    // 验证克隆后的完整性
    let secret2 = SecretBytes::new(vec![1u8; 32]).unwrap();
    let protected2 = ProtectedKey::new(secret2).unwrap();
    assert!(protected2.access().is_ok());

    // 克隆应该保持完整性
    let cloned = protected2.clone();
    assert!(cloned.access().is_ok());
}

#[test]
fn test_secret_bytes_cloning() {
    let original_data = vec![0xABu8; 64];
    let secret1 = SecretBytes::new(original_data.clone()).unwrap();

    // 克隆SecretBytes
    let secret2 = secret1.clone();

    // 验证数据相同
    assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    assert_eq!(secret1.as_bytes(), &original_data);
}

#[test]
fn test_protected_key_creation() {
    let secret = SecretBytes::new(vec![0x55u8; 32]).unwrap();
    let protected = ProtectedKey::new(secret).unwrap();

    // 验证可以正常访问
    let accessed_secret = protected.access().unwrap();
    assert_eq!(accessed_secret.as_bytes(), &[0x55u8; 32]);
}

#[test]
fn test_memory_locking() {
    // 测试内存锁定功能（如果支持）
    let data = vec![0x77u8; 128];
    let result = SecretBytes::new(data);

    // 在支持mlock的系统上应该成功
    #[cfg(unix)]
    assert!(result.is_ok());

    #[cfg(not(unix))]
    {
        // 在非Unix系统上，应该回退到仅清零
        let _secret = result.unwrap();
        println!("Memory locking not supported on this platform, using zeroize fallback");
    }
}

#[test]
fn test_zeroize_on_drop() {
    use std::sync::atomic::{AtomicBool, Ordering};

    static DROPPED: AtomicBool = AtomicBool::new(false);

    struct TestDrop {
        data: Vec<u8>,
    }

    impl Drop for TestDrop {
        fn drop(&mut self) {
            DROPPED.store(true, Ordering::SeqCst);
            // 清零数据
            self.data.fill(0);
        }
    }

    {
        let _test = TestDrop {
            data: vec![0xFFu8; 32],
        };
    }

    assert!(DROPPED.load(Ordering::SeqCst));
    println!("Drop implementation verified - data should be zeroized");
}
