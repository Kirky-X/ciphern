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

        if let Err(e) = cloned.lock_memory() {
            cloned.inner.zeroize();
            panic!("Failed to clone SecretBytes with memory lock: {}", e);
        }

        cloned
    }
}

impl SecretBytes {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        debug_assert!(
            !data.is_empty(),
            "SecretBytes should not be created with empty data"
        );
        debug_assert!(
            data.len() <= 1024 * 1024,
            "SecretBytes data should not exceed 1MB for memory locking efficiency"
        );

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

#[derive(Clone)]
pub struct ProtectedKey {
    key: SecretBytes,
    canary: [u8; 16],
    checksum: u64,
}

impl ProtectedKey {
    pub fn new(key: SecretBytes) -> Result<Self> {
        let mut canary = [0u8; 16];
        getrandom::getrandom(&mut canary).map_err(|_| CryptoError::InsufficientEntropy)?;

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
        getrandom::getrandom(&mut canary).unwrap_or_default();

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
}
