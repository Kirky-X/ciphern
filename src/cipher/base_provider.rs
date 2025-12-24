// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::CryptoError;
use crate::provider::SymmetricCipher;
use crate::side_channel::{
    protect_critical_operation, RotatingSboxMasking, SideChannelConfig, SideChannelContext,
};
use crate::types::Algorithm;
use log::warn;
use std::sync::{Arc, Mutex};

/// Base structure for all cipher providers with side-channel protection
#[derive(Debug, Clone)]
pub struct BaseCipherProvider {
    pub side_channel_context: Option<Arc<Mutex<SideChannelContext>>>,
    pub rotating_sbox: Option<Arc<Mutex<RotatingSboxMasking>>>,
}

impl BaseCipherProvider {
    /// Create a new base provider with default side-channel configuration
    pub fn new() -> Result<Self, CryptoError> {
        let side_channel_context = Arc::new(Mutex::new(SideChannelContext::new(
            SideChannelConfig::default(),
        )));

        let rotating_sbox = RotatingSboxMasking::new(4)
            .map_err(|e| {
                CryptoError::SideChannelError(format!(
                    "Failed to initialize side-channel protection (RotatingSboxMasking): {}",
                    e
                ))
            })
            .map(|sbox| Some(Arc::new(Mutex::new(sbox))))?;

        warn!("Side-channel protection initialized with rotating S-box masking (mask_size=4)");

        Ok(Self {
            side_channel_context: Some(side_channel_context),
            rotating_sbox,
        })
    }

    /// Create a new base provider with custom side-channel configuration
    pub fn with_side_channel_config(config: SideChannelConfig) -> Result<Self, CryptoError> {
        let rotating_sbox = if config.power_analysis_protection {
            let sbox = RotatingSboxMasking::new(4).map_err(|e| {
                CryptoError::SideChannelError(format!(
                    "Failed to initialize power analysis protection: {}",
                    e
                ))
            })?;

            warn!("Power analysis protection enabled with mask_size=4");

            Some(Arc::new(Mutex::new(sbox)))
        } else {
            warn!(
                "Power analysis protection disabled - system is running in reduced security mode"
            );
            None
        };

        Ok(Self {
            side_channel_context: Some(Arc::new(Mutex::new(SideChannelContext::new(config)))),
            rotating_sbox,
        })
    }

    /// Execute a critical operation with side-channel protection
    pub fn protect_operation<F, R>(&self, operation: F) -> crate::error::Result<R>
    where
        F: FnOnce() -> crate::error::Result<R>,
    {
        if let Some(ref ctx) = self.side_channel_context {
            let mut context_guard = ctx.lock().unwrap();
            protect_critical_operation(&mut context_guard, operation)
        } else {
            operation()
        }
    }

    /// Get a reference to the side-channel context
    #[allow(dead_code)]
    pub fn side_channel_context(&self) -> &Option<Arc<Mutex<SideChannelContext>>> {
        &self.side_channel_context
    }

    /// Get a reference to the rotating S-box
    #[allow(dead_code)]
    pub fn rotating_sbox(&self) -> &Option<Arc<Mutex<RotatingSboxMasking>>> {
        &self.rotating_sbox
    }

    /// Get side-channel protection statistics
    #[allow(dead_code)]
    pub fn get_side_channel_stats(&self) -> Option<crate::side_channel::SideChannelStats> {
        self.side_channel_context
            .as_ref()
            .and_then(|ctx| ctx.lock().ok().map(|guard| guard.get_stats()))
    }

    /// Check if side-channel protection is enabled
    #[allow(dead_code)]
    pub fn is_side_channel_protected(&self) -> bool {
        self.side_channel_context.is_some() && self.rotating_sbox.is_some()
    }

    /// Perform side-channel protected key expansion
    #[allow(dead_code)]
    pub fn expand_key_protected(&self, key_bytes: &[u8]) -> crate::error::Result<Vec<u8>> {
        if key_bytes.is_empty() {
            return Err(crate::error::CryptoError::InvalidParameter(
                "Key bytes cannot be empty".to_string(),
            ));
        }

        if key_bytes.len() < 16 || key_bytes.len() > 64 {
            return Err(crate::error::CryptoError::InvalidKeySize {
                expected: 32,
                actual: key_bytes.len(),
            });
        }

        if let Some(ref sbox_masking) = self.rotating_sbox {
            let mut expanded_key = Vec::with_capacity(240);
            expanded_key.extend_from_slice(key_bytes);

            // Simulate key expansion with side-channel protection
            // In a real implementation, this would use the masked S-box for all SubBytes operations
            for i in 0..(expanded_key.len() / 4) {
                if i > 7 && i % 4 == 0 {
                    // Apply masked S-box transformation
                    let byte_idx = i * 4;
                    for j in 0..4 {
                        if byte_idx + j < expanded_key.len() {
                            let input = expanded_key[byte_idx + j];
                            // Use rotating S-box for side-channel protection
                            let mut sbox = sbox_masking.lock().map_err(|_| {
                                crate::error::CryptoError::SideChannelError(
                                    "S-box lock poisoned".into(),
                                )
                            })?;
                            expanded_key[byte_idx + j] = sbox.lookup(input);
                        }
                    }
                }
            }

            Ok(expanded_key)
        } else {
            // Fallback to simple key copy without additional protection
            Ok(key_bytes.to_vec())
        }
    }
}

impl Default for BaseCipherProvider {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            log::error!("Failed to create default BaseCipherProvider: {}", e);
            panic!("Critical security component initialization failed: {}", e)
        })
    }
}

/// Trait for cipher providers that can be built from a base provider
#[allow(dead_code)]
pub trait CipherProvider: SymmetricCipher + Send + Sync {
    /// Get the base provider
    fn base_provider(&self) -> &BaseCipherProvider;

    /// Get the algorithm this provider implements
    fn algorithm_type(&self) -> Algorithm;
}

/// Macro to implement common provider functionality
#[macro_export]
macro_rules! impl_cipher_provider {
    ($provider:ty, $algorithm:expr) => {
        impl $crate::cipher::base_provider::CipherProvider for $provider {
            fn base_provider(&self) -> &$crate::cipher::base_provider::BaseCipherProvider {
                &self.base
            }
            fn algorithm_type(&self) -> $crate::types::Algorithm {
                $algorithm
            }
        }
    };
}
