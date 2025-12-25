// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use super::KeyManagerOperations;
use crate::audit::AuditLogger;
use crate::error::{CryptoError, Result};
use crate::types::Algorithm;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RotationTrigger {
    TimeBased,
    UsageBased,
    Manual,
    Emergency,
    WarningThreshold,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RotationConfig {
    pub enable_auto_rotation: bool,
    pub enable_usage_limit_rotation: bool,
    pub warning_threshold_percent: f64,
    pub min_rotation_interval: Duration,
    pub emergency_rotation_on_compromise: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enable_auto_rotation: true,
            enable_usage_limit_rotation: true,
            warning_threshold_percent: 0.8,
            min_rotation_interval: Duration::days(1),
            emergency_rotation_on_compromise: true,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RotationEvent {
    pub trigger: RotationTrigger,
    pub old_key_id: String,
    pub new_key_id: String,
    pub timestamp: DateTime<Utc>,
    pub reason: String,
    pub automatic: bool,
}

#[allow(dead_code)]
impl RotationEvent {
    pub fn new(
        trigger: RotationTrigger,
        old_key_id: String,
        new_key_id: String,
        reason: String,
        automatic: bool,
    ) -> Self {
        Self {
            trigger,
            old_key_id,
            new_key_id,
            timestamp: Utc::now(),
            reason,
            automatic,
        }
    }
}

#[derive(Clone, Default)]
pub struct KeyRotationConfig {
    pub config: RotationConfig,
    pub rotation_callbacks: Vec<Arc<dyn KeyRotationCallback + Send + Sync>>,
}

impl fmt::Debug for KeyRotationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRotationConfig")
            .field("config", &self.config)
            .field("rotation_callbacks", &self.rotation_callbacks.len())
            .finish()
    }
}

impl KeyRotationConfig {
    pub fn new() -> Self {
        Self::default()
    }
}

#[allow(dead_code)]
pub trait KeyRotationCallback: Send + Sync {
    fn before_rotation(&self, key_id: &str, reason: &str) -> Result<()>;
    fn after_rotation(&self, old_key_id: &str, new_key_id: &str) -> Result<()>;
    fn on_rotation_failure(&self, key_id: &str, error: &str) -> Result<()>;
}

struct DefaultRotationCallback;

impl KeyRotationCallback for DefaultRotationCallback {
    fn before_rotation(&self, _key_id: &str, _reason: &str) -> Result<()> {
        AuditLogger::log("ROTATION_BEFORE", None, Some(_key_id), Ok(()));
        Ok(())
    }

    fn after_rotation(&self, _old_key_id: &str, new_key_id: &str) -> Result<()> {
        AuditLogger::log("ROTATION_AFTER", None, Some(new_key_id), Ok(()));
        Ok(())
    }

    fn on_rotation_failure(&self, key_id: &str, error: &str) -> Result<()> {
        AuditLogger::log(
            "ROTATION_FAILURE",
            None,
            Some(key_id),
            Err(CryptoError::KeyError(error.to_string())),
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KeyRotationManager {
    config: Arc<RwLock<KeyRotationConfig>>,
    rotation_history: Arc<RwLock<Vec<RotationEvent>>>,
    pending_rotations: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

#[allow(dead_code)]
impl KeyRotationManager {
    pub fn new() -> Result<Self> {
        let mut config = KeyRotationConfig::new();
        config
            .rotation_callbacks
            .push(Arc::new(DefaultRotationCallback));

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            rotation_history: Arc::new(RwLock::new(Vec::new())),
            pending_rotations: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn set_config(&self, config: RotationConfig) {
        let mut write_config = self.config.write().unwrap();
        write_config.config = config;
    }

    pub fn get_config(&self) -> RotationConfig {
        let read_config = self.config.read().unwrap();
        read_config.config.clone()
    }

    pub fn add_callback(&self, callback: Arc<dyn KeyRotationCallback + Send + Sync>) {
        let mut write_config = self.config.write().unwrap();
        write_config.rotation_callbacks.push(callback);
    }

    pub fn get_rotation_history(&self, key_id: Option<&str>, limit: usize) -> Vec<RotationEvent> {
        let history = self.rotation_history.read().unwrap();
        let mut events: Vec<RotationEvent> = if let Some(key_id) = key_id {
            history
                .iter()
                .filter(|e| e.old_key_id == key_id || e.new_key_id == key_id)
                .cloned()
                .collect()
        } else {
            history.clone()
        };

        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events.into_iter().take(limit).collect()
    }

    pub fn check_rotation_needed(
        &self,
        _key_id: &str,
        _algorithm: Algorithm,
        current_usage: usize,
        max_usage: Option<usize>,
        expires_at: Option<DateTime<Utc>>,
        last_rotation: Option<DateTime<Utc>>,
    ) -> (bool, Option<RotationTrigger>, Option<String>) {
        let config = {
            let read_config = self.config.read().unwrap();
            read_config.config.clone()
        };

        let now = Utc::now();

        if let Some(expires_at) = expires_at {
            if now >= expires_at {
                return (
                    true,
                    Some(RotationTrigger::Emergency),
                    Some("Key has expired".to_string()),
                );
            }

            let warning_threshold =
                Duration::seconds((expires_at.timestamp() - now.timestamp()) / 5);
            if now >= expires_at - warning_threshold {
                return (
                    true,
                    Some(RotationTrigger::WarningThreshold),
                    Some("Key is approaching expiration".to_string()),
                );
            }
        }

        if config.enable_usage_limit_rotation {
            if let Some(max) = max_usage {
                let threshold = (max as f64 * config.warning_threshold_percent) as usize;
                if current_usage >= threshold {
                    return (
                        true,
                        Some(RotationTrigger::UsageBased),
                        Some(format!(
                            "Key usage {} approaching limit {} ({:.0}%)",
                            current_usage,
                            max,
                            config.warning_threshold_percent * 100.0
                        )),
                    );
                }

                if current_usage >= max {
                    return (
                        true,
                        Some(RotationTrigger::UsageBased),
                        Some(format!("Key usage {} reached limit {}", current_usage, max)),
                    );
                }
            }
        }

        if config.enable_auto_rotation {
            if let Some(last_rot) = last_rotation {
                if now - last_rot >= config.min_rotation_interval {
                    return (
                        true,
                        Some(RotationTrigger::TimeBased),
                        Some("Scheduled rotation interval reached".to_string()),
                    );
                }
            }
        }

        (false, None, None)
    }

    pub fn execute_rotation<F>(
        &self,
        _key_manager: &dyn KeyManagerOperations,
        key_id: &str,
        algorithm: Algorithm,
        trigger: RotationTrigger,
        reason: String,
        create_new_key: F,
    ) -> Result<String>
    where
        F: FnOnce(Algorithm) -> Result<String>,
    {
        let callbacks: Vec<Arc<dyn KeyRotationCallback + Send + Sync>> = {
            let read_config = self.config.read().unwrap();
            read_config.rotation_callbacks.clone()
        };

        for callback in &callbacks {
            if let Err(e) = callback.before_rotation(key_id, &reason) {
                for cb in &callbacks {
                    let _ =
                        cb.on_rotation_failure(key_id, &format!("Before callback failed: {}", e));
                }
                return Err(e);
            }
        }

        let new_key_id = create_new_key(algorithm)?;

        let event = RotationEvent::new(
            trigger,
            key_id.to_string(),
            new_key_id.clone(),
            reason.clone(),
            false,
        );

        {
            let mut history = self.rotation_history.write().unwrap();
            history.push(event);
            if history.len() > 1000 {
                history.truncate(500);
            }
        }

        for callback in &callbacks {
            if let Err(e) = callback.after_rotation(key_id, &new_key_id) {
                for cb in &callbacks {
                    let _ =
                        cb.on_rotation_failure(key_id, &format!("After callback failed: {}", e));
                }
            }
        }

        AuditLogger::log("KEY_ROTATED", Some(algorithm), Some(&new_key_id), Ok(()));

        Ok(new_key_id)
    }

    pub fn get_next_scheduled_rotation(&self, key_id: &str) -> Option<DateTime<Utc>> {
        let pending = self.pending_rotations.read().unwrap();
        pending.get(key_id).cloned()
    }

    pub fn schedule_rotation(&self, key_id: &str, when: DateTime<Utc>) {
        let mut pending = self.pending_rotations.write().unwrap();
        pending.insert(key_id.to_string(), when);
    }

    pub fn cancel_scheduled_rotation(&self, key_id: &str) {
        let mut pending = self.pending_rotations.write().unwrap();
        pending.remove(key_id);
    }

    pub fn get_rotation_stats(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();
        let history = self.rotation_history.read().unwrap();

        let total_rotations = history.len();
        let auto_rotations = history.iter().filter(|e| e.automatic).count();
        let manual_rotations = total_rotations - auto_rotations;

        stats.insert("total_rotations".to_string(), total_rotations.to_string());
        stats.insert(
            "automatic_rotations".to_string(),
            auto_rotations.to_string(),
        );
        stats.insert("manual_rotations".to_string(), manual_rotations.to_string());

        let trigger_counts: HashMap<String, usize> =
            history
                .iter()
                .filter(|e| !e.automatic)
                .fold(HashMap::new(), |mut acc, e| {
                    *acc.entry(format!("{:?}", e.trigger)).or_insert(0) += 1;
                    acc
                });

        for (trigger, count) in trigger_counts {
            stats.insert(
                format!("trigger_{}", trigger.to_lowercase()),
                count.to_string(),
            );
        }

        stats
    }
}

impl Default for KeyRotationManager {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
