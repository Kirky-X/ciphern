// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroize;

pub mod monitor;

use monitor::{RngMonitor, RngMonitorConfig, RngMonitorManager};

/// 全局 RNG 监控管理器
static RNG_MONITOR_MANAGER: OnceLock<Arc<RngMonitorManager>> = OnceLock::new();

/// 获取全局 RNG 监控管理器
pub fn get_rng_monitor_manager() -> Arc<RngMonitorManager> {
    RNG_MONITOR_MANAGER
        .get_or_init(|| {
            let manager = Arc::new(RngMonitorManager::new());

            // 创建默认监控器配置
            let config = RngMonitorConfig::default();
            let monitor = Arc::new(RngMonitor::new(config));

            // 添加监控器到管理器
            manager.add_monitor(monitor.clone());

            // 启动实时监控
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

        // 清零种子数据，防止敏感信息残留
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

        // Reseed periodically logic would go here

        rng.fill_bytes(dest);

        // 运行时健康检查 (FIPS 140-3 连续随机数生成器测试)
        if dest.len() >= 16 {
            // 简单的重复性检查
            let mut all_same = true;
            for i in 1..dest.len() {
                if dest[i] != dest[0] {
                    all_same = false;
                    break;
                }
            }
            if all_same {
                // 记录到 RNG 监控器
                let manager = get_rng_monitor_manager();
                if let Some(monitor) = manager.get_first_monitor() {
                    monitor.record_external_test_result(false, "continuous_test");
                }

                crate::audit::AuditLogger::log(
                    "RNG_CONTINUOUS_TEST_FAILURE",
                    None,
                    None,
                    Err("Continuous RNG test failed: all bytes are identical"),
                );
                return Err(CryptoError::FipsError("Continuous RNG test failed".into()));
            }
        }

        Ok(())
    }
}

impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        if let Ok(mut rng) = self.csprng.lock() {
            rng.next_u32()
        } else {
            0
        }
    }

    fn next_u64(&mut self) -> u64 {
        if let Ok(mut rng) = self.csprng.lock() {
            rng.next_u64()
        } else {
            0
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Ok(mut rng) = self.csprng.lock() {
            rng.fill_bytes(dest)
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        let mut rng = self
            .csprng
            .lock()
            .map_err(|_| rand::Error::new("Lock poisoned"))?;
        rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureRandom {}
