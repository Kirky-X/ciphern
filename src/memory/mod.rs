// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(unix)]
use libc::{c_void, mlock};

#[cfg(test)]
mod tests;

#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub struct SecretBytes {
    inner: Vec<u8>,
    locked: bool,
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        let cloned_inner = self.inner.clone();
        let mut cloned = Self {
            inner: cloned_inner,
            locked: false,
        };

        if let Err(e) = cloned.lock_memory() {
            cloned.inner.zeroize();
            panic!("Failed to clone SecretBytes with memory lock: {}", e);
        }

        cloned
    }
}

impl SecretBytes {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        // 运行时检查：数据不能为空
        if data.is_empty() {
            return Err(CryptoError::InvalidParameter(
                "SecretBytes should not be created with empty data".into(),
            ));
        }

        // 运行时检查：数据长度不能超过 1MB（出于内存锁定效率考虑）
        const MAX_SECRET_SIZE: usize = 1024 * 1024; // 1MB
        if data.len() > MAX_SECRET_SIZE {
            return Err(CryptoError::InvalidParameter(format!(
                "SecretBytes data should not exceed {} bytes for memory locking efficiency",
                MAX_SECRET_SIZE
            )));
        }

        let mut secret = Self {
            inner: data,
            locked: false,
        };
        secret.lock_memory()?;
        Ok(secret)
    }

    #[cfg(unix)]
    fn lock_memory(&mut self) -> Result<()> {
        if self.inner.is_empty() {
            return Ok(());
        }
        let ptr = self.inner.as_mut_ptr() as *mut c_void;
        let len = self.inner.len();

        let ret = unsafe { mlock(ptr, len) };
        if ret != 0 {
            return Err(CryptoError::MemoryProtectionFailed("mlock failed".into()));
        }
        self.locked = true;
        Ok(())
    }

    #[cfg(not(unix))]
    fn lock_memory(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        debug_assert!(
            !self.inner.is_empty(),
            "SecretBytes should not contain empty data"
        );
        &self.inner
    }
}

#[derive(Clone, Debug)]
pub struct ProtectedKey {
    key: SecretBytes,
    canary: [u8; 16],
    checksum: u64,
}

impl ProtectedKey {
    pub fn new(key: SecretBytes) -> Result<Self> {
        let mut canary = [0u8; 16];

        // 确保生成有效的随机 canary（不是全零）
        let mut attempts = 0;
        while canary.iter().all(|&b| b == 0) && attempts < 10 {
            getrandom::getrandom(&mut canary).map_err(|_| CryptoError::InsufficientEntropy)?;
            attempts += 1;
        }

        // 如果仍然生成全零，使用固定值
        if canary.iter().all(|&b| b == 0) {
            canary.copy_from_slice(&[1u8; 16]);
        }

        let checksum = Self::compute_checksum(key.as_bytes(), &canary);

        Ok(Self {
            key,
            canary,
            checksum,
        })
    }

    pub fn access(&self) -> Result<&SecretBytes> {
        debug_assert!(
            !self.canary.iter().all(|&b| b == 0),
            "Canary should not be all zeros"
        );

        let current_checksum = Self::compute_checksum(self.key.as_bytes(), &self.canary);
        if current_checksum != self.checksum {
            return Err(CryptoError::MemoryTampered);
        }
        Ok(&self.key)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn create_with_corrupted_checksum(key: SecretBytes, corrupted_checksum: u64) -> Self {
        let mut canary = [0u8; 16];

        // 确保生成有效的随机 canary（不是全零）
        // 如果 getrandom 失败，使用固定值
        if getrandom::getrandom(&mut canary).is_err() {
            // 使用非零的固定值
            canary.copy_from_slice(&[1u8; 16]);
        }

        Self {
            key,
            canary,
            checksum: corrupted_checksum,
        }
    }

    fn compute_checksum(data: &[u8], canary: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        canary.hash(&mut hasher);
        hasher.finish()
    }

    /// 安全地清零密钥数据
    ///
    /// 此方法会清零密钥数据、canary 和 checksum，确保敏感信息不会残留在内存中。
    /// 此操作是不可逆的。
    pub fn zeroize_secure(&mut self) -> Result<()> {
        // 清零密钥数据
        self.key.inner.zeroize();

        // 清零 canary
        self.canary.zeroize();

        // 清零 checksum
        self.checksum = 0;

        Ok(())
    }
}
