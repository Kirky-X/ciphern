// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

mod r#impl;
mod r#struct;

pub use self::r#struct::{
    EmbeddedPowerConfig, EmbeddedPowerProtector, EmbeddedPowerProtectorBuilder, EmbeddedPowerStats,
};

// === Tests ===

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CryptoError;

    #[test]
    fn test_embedded_power_protector_creation() {
        let protector = EmbeddedPowerProtector::new(EmbeddedPowerConfig::default());
        let stats = protector.stats();

        assert_eq!(stats.total_operations, 0);
        assert!(stats.last_operation_time.is_none());
    }

    #[test]
    fn test_embedded_power_protector_builder() {
        let protector = EmbeddedPowerProtectorBuilder::new()
            .cortex_m_optimization(true)
            .power_masking_strength(0.9)
            .random_delay_range(20, 80)
            .clock_jitter(true, 0.4)
            .power_noise(true, 0.6)
            .build();

        let stats = protector.stats();
        assert_eq!(stats.power_masking_strength, 0.9);
        assert!(stats.cortex_m_optimization_enabled);
    }

    #[test]
    fn test_protect_operation() {
        let protector = EmbeddedPowerProtector::new(EmbeddedPowerConfig::default());

        let result = protector.protect_operation(|| Ok::<_, CryptoError>(42));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);

        let stats = protector.stats();
        assert_eq!(stats.total_operations, 1);
        assert!(stats.last_operation_time.is_some());
    }

    #[test]
    fn test_multiple_operations() {
        let protector = EmbeddedPowerProtector::new(EmbeddedPowerConfig::default());

        for i in 0..5 {
            let result = protector.protect_operation(|| Ok::<_, CryptoError>(i));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), i);
        }

        let stats = protector.stats();
        assert_eq!(stats.total_operations, 5);
    }
}
