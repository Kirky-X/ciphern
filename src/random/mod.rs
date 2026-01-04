// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::audit::AuditLogger;
use crate::error::{CryptoError, Result};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroize;

mod monitor;

use monitor::{RngMonitor, RngMonitorConfig, RngMonitorManager};

mod hardware;

pub use hardware::{
    detect_hardware_rng, hardware_fill_bytes, is_hardware_rng_available, is_rdseed_available,
    rdseed_fill_bytes, BulkHardwareRng, HardwareRng, SeedGenerator,
};

static RNG_MONITOR_MANAGER: OnceLock<Arc<RngMonitorManager>> = OnceLock::new();

pub fn get_rng_monitor_manager() -> Arc<RngMonitorManager> {
    RNG_MONITOR_MANAGER
        .get_or_init(|| {
            let manager = Arc::new(RngMonitorManager::new());
            let config = RngMonitorConfig::default();
            let monitor = Arc::new(RngMonitor::new(config));
            manager.add_monitor(monitor.clone());
            monitor.start_real_time_monitoring();
            manager
        })
        .clone()
}

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
        seed.zeroize();

        Ok(Self {
            csprng: Arc::new(Mutex::new(rng)),
        })
    }

    pub fn fill(&self, dest: &mut [u8]) -> Result<()> {
        let mut rng = self
            .csprng
            .lock()
            .map_err(|_| CryptoError::MemoryProtectionFailed("RNG Lock Poisoned".into()))?;

        rng.fill_bytes(dest);

        if dest.len() >= 16 {
            let mut all_same = true;
            for i in 1..dest.len() {
                if dest[i] != dest[0] {
                    all_same = false;
                    break;
                }
            }
            if all_same {
                let manager = get_rng_monitor_manager();
                if let Some(monitor) = manager.get_first_monitor() {
                    monitor.record_external_test_result(false, "continuous_test");
                }

                AuditLogger::log(
                    "RNG_CONTINUOUS_TEST_FAILURE",
                    None,
                    None,
                    Err(CryptoError::FipsError(
                        "Continuous RNG test failed: all bytes are identical".into(),
                    )),
                );
                return Err(CryptoError::FipsError("Continuous RNG test failed".into()));
            }
        }

        Ok(())
    }
}

impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        self.csprng.lock().expect("RNG lock poisoned").next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.csprng.lock().expect("RNG lock poisoned").next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.csprng
            .lock()
            .expect("RNG lock poisoned")
            .fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.csprng
            .lock()
            .map_err(|_| rand::Error::new("Lock poisoned"))?
            .try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureRandom {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_generation() {
        let rng = SecureRandom::new().unwrap();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf).unwrap();

        // 确保生成的随机数不是全零
        assert_ne!(buf, [0u8; 32]);

        // 确保生成的随机数不是全相同
        let mut buf2 = [0u8; 32];
        rng.fill(&mut buf2).unwrap();
        assert_ne!(buf, buf2);
    }

    #[test]
    fn test_secure_random_different_sizes() {
        let rng = SecureRandom::new().unwrap();

        // 测试不同大小的缓冲区
        let sizes = [1, 16, 32, 64, 128, 256, 512, 1024];
        for size in sizes {
            let mut buf = vec![0u8; size];
            rng.fill(&mut buf).unwrap();
            assert_ne!(buf, vec![0u8; size]);
        }
    }

    #[test]
    fn test_entropy_source() {
        let entropy = OsEntropy;
        let mut buf = [0u8; 32];
        entropy.get_bytes(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn test_rng_monitor_manager() {
        let manager = get_rng_monitor_manager();
        let metrics = manager.get_first_monitor().unwrap().get_health_metrics();
        assert!(metrics.health_score >= 0.0 && metrics.health_score <= 1.0);
    }

    #[test]
    fn test_rng_monitor_sampling_rate() {
        let config = RngMonitorConfig {
            sampling_rate: 0.5, // 50% 采样率
            ..Default::default()
        };
        let monitor = RngMonitor::new(config);

        // 执行多次健康检查，应该有部分跳过完整检查
        for _ in 0..10 {
            let _ = monitor.perform_health_check();
        }

        let metrics = monitor.get_health_metrics();
        assert!(metrics.total_tests > 0);
    }
}
