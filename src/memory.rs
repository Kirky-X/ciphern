// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[cfg(unix)]
use libc::{mlock, c_void};

/// Secure container for sensitive data with auto-zeroize and mlock
#[derive(Zeroize, ZeroizeOnDrop)]
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
        let _ = cloned.lock_memory();
        cloned
    }
}

impl SecretBytes {
    pub fn new(data: Vec<u8>) -> Result<Self> {
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
        unsafe {
            let ptr = self.inner.as_ptr() as *const c_void;
            let len = self.inner.len();
            if mlock(ptr, len) != 0 {
                return Err(CryptoError::MemoryProtectionFailed("mlock failed".into()));
            }
        }
        self.locked = true;
        Ok(())
    }

    #[cfg(not(unix))]
    fn lock_memory(&mut self) -> Result<()> {
        // Windows/Other implementation omitted for brevity, fallback to just zeroize
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

// ZeroizeOnDrop handles automatic cleanup, so we don't need manual Drop

/// Wrapper that adds integrity checks (canary + checksum)
#[derive(Clone)]
pub struct ProtectedKey {
    key: SecretBytes,
    canary: [u8; 16],
    checksum: u64,
}

impl ProtectedKey {
    pub fn new(key: SecretBytes) -> Self {
        let mut canary = [0u8; 16];
        // In real code, use SecureRandom. Here using simple fill for structure
        getrandom::getrandom(&mut canary).unwrap_or_default();
        
        let checksum = Self::compute_checksum(key.as_bytes(), &canary);
        
        Self { key, canary, checksum }
    }

    pub fn access(&self) -> Result<&SecretBytes> {
        let current_checksum = Self::compute_checksum(self.key.as_bytes(), &self.canary);
        if current_checksum != self.checksum {
            return Err(CryptoError::MemoryTampered);
        }
        Ok(&self.key)
    }

    /// 测试用的方法：通过创建具有不同数据的ProtectedKey来验证篡改检测
    pub fn create_with_corrupted_checksum(key: SecretBytes, corrupted_checksum: u64) -> Self {
        let mut canary = [0u8; 16];
        getrandom::getrandom(&mut canary).unwrap_or_default();
        
        Self { key, canary, checksum: corrupted_checksum }
    }

    fn compute_checksum(data: &[u8], canary: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        canary.hash(&mut hasher);
        hasher.finish()
    }
}