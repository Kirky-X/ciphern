// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use rand::{RngCore, SeedableRng, CryptoRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};

pub trait EntropySource: Send + Sync {
    fn get_bytes(&self, buf: &mut [u8]) -> Result<()>;
}

struct OsEntropy;

impl EntropySource for OsEntropy {
    fn get_bytes(&self, buf: &mut [u8]) -> Result<()> {
        getrandom::getrandom(buf).map_err(|_| CryptoError::InsufficientEntropy)
    }
}

pub struct SecureRandom {
    csprng: Arc<Mutex<ChaCha20Rng>>,
}

impl SecureRandom {
    pub fn new() -> Result<Self> {
        let mut seed = [0u8; 32];
        OsEntropy.get_bytes(&mut seed)?;
        let rng = ChaCha20Rng::from_seed(seed);
        Ok(Self {
            csprng: Arc::new(Mutex::new(rng)),
        })
    }

    pub fn fill(&self, dest: &mut [u8]) -> Result<()> {
        let mut rng = self.csprng.lock().map_err(|_| CryptoError::MemoryProtectionFailed("RNG Lock Poisoned".into()))?;
        
        // Reseed periodically logic would go here
        
        rng.fill_bytes(dest);
        Ok(())
    }
}

impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        let mut rng = self.csprng.lock().unwrap();
        rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        let mut rng = self.csprng.lock().unwrap();
        rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut rng = self.csprng.lock().unwrap();
        rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        let mut rng = self.csprng.lock().unwrap();
        rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureRandom {}