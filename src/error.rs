// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use thiserror::Error;

#[cfg(feature = "python_ffi")]
#[allow(unused_imports)]
use pyo3::exceptions::PyRuntimeError;

#[derive(Debug, Error, Clone)]
pub enum CryptoError {
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Not initialized")]
    NotInitialized,

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key error: {0}")]
    KeyError(String),

    #[error("Key usage limit exceeded: key_id={key_id}, type={limit_type}, current={current_count}, max={max_count}")]
    KeyUsageLimitExceeded {
        key_id: String,
        limit_type: String,
        current_count: usize,
        max_count: usize,
    },

    #[error("Algorithm not supported: {0:?}")]
    UnsupportedAlgorithm(String),

    #[error("Insufficient entropy")]
    InsufficientEntropy,

    #[error("Memory protection failed: {0}")]
    MemoryProtectionFailed(String),

    #[error("Memory allocation failed: {0}")]
    MemoryAllocationFailed(String),

    #[error("Memory transfer failed: {0}")]
    MemoryTransferFailed(String),

    #[error("Memory tampering detected")]
    MemoryTampered,

    #[error("FIPS mode violation: {0}")]
    FipsError(String),

    #[error("Side-channel error: {0}")]
    SideChannelError(String),

    #[error("Security error: {0}")]
    SecurityError(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("IO Error: {0}")]
    IoError(String),

    #[error("System time error")]
    TimeError,

    #[error("Plugin error: {0}")]
    PluginError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Unknown error")]
    UnknownError,

    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),

    #[error("Hardware acceleration unavailable: {0}")]
    HardwareAccelerationUnavailable(String),

    #[error("Async operation failed: {0}")]
    AsyncOperationFailed(String),

    #[error("Hardware initialization failed: {0}")]
    HardwareInitializationFailed(String),
}

#[cfg(feature = "gpu")]
impl From<ecdsa::Error> for CryptoError {
    fn from(error: ecdsa::Error) -> Self {
        CryptoError::SigningFailed(error.to_string())
    }
}

#[cfg(feature = "i18n")]
mod i18n_error_impl {
    use super::*;

    pub trait LocalizedError {
        fn get_translation_key(&self) -> &'static str;
        fn get_message_key(&self) -> &'static str;
    }

    impl LocalizedError for CryptoError {
        fn get_translation_key(&self) -> &'static str {
            match self {
                CryptoError::InvalidKeySize { .. } => "crypto_error.invalid_key_size",
                CryptoError::InvalidParameter(_) => "crypto_error.invalid_parameter",
                CryptoError::InvalidInput(_) => "crypto_error.invalid_input",
                CryptoError::NotInitialized => "crypto_error.not_initialized",
                CryptoError::InvalidState(_) => "crypto_error.invalid_state",
                CryptoError::DecryptionFailed(_) => "crypto_error.decryption_failed",
                CryptoError::EncryptionFailed(_) => "crypto_error.encryption_failed",
                CryptoError::KeyNotFound(_) => "crypto_error.key_not_found",
                CryptoError::KeyError(_) => "crypto_error.key_error",
                CryptoError::KeyUsageLimitExceeded { .. } => {
                    "crypto_error.key_usage_limit_exceeded"
                }
                CryptoError::UnsupportedAlgorithm(_) => "crypto_error.unsupported_algorithm",
                CryptoError::InsufficientEntropy => "crypto_error.insufficient_entropy",
                CryptoError::MemoryProtectionFailed(_) => "crypto_error.memory_protection_failed",
                CryptoError::MemoryAllocationFailed(_) => "crypto_error.memory_allocation_failed",
                CryptoError::MemoryTransferFailed(_) => "crypto_error.memory_transfer_failed",
                CryptoError::MemoryTampered => "crypto_error.memory_tampered_message",
                CryptoError::FipsError(_) => "crypto_error.fips_error",
                CryptoError::SideChannelError(_) => "crypto_error.side_channel_error",
                CryptoError::SecurityError(_) => "crypto_error.security_error",
                CryptoError::NotImplemented(_) => "crypto_error.not_implemented",
                CryptoError::IoError(_) => "crypto_error.io_error",
                CryptoError::TimeError => "crypto_error.time_error",
                CryptoError::PluginError(_) => "crypto_error.plugin_error",
                CryptoError::InternalError(_) => "crypto_error.internal_error",
                CryptoError::SigningFailed(_) => "crypto_error.signing_failed",
                CryptoError::VerificationFailed(_) => "crypto_error.verification_failed",
                CryptoError::UnknownError => "crypto_error.unknown_error",
                CryptoError::InvalidKeyLength(_) => "crypto_error.invalid_key_length",
                CryptoError::HardwareAccelerationUnavailable(_) => {
                    "crypto_error.hardware_acceleration_unavailable"
                }
                CryptoError::AsyncOperationFailed(_) => "crypto_error.async_operation_failed",
                CryptoError::HardwareInitializationFailed(_) => {
                    "crypto_error.hardware_initialization_failed"
                }
            }
        }

        fn get_message_key(&self) -> &'static str {
            match self {
                CryptoError::InvalidKeySize { .. } => "crypto_error.invalid_key_size_message",
                CryptoError::InvalidParameter(_) => "crypto_error.invalid_parameter_message",
                CryptoError::InvalidInput(_) => "crypto_error.invalid_input_message",
                CryptoError::NotInitialized => "crypto_error.not_initialized_message",
                CryptoError::InvalidState(_) => "crypto_error.invalid_state_message",
                CryptoError::DecryptionFailed(_) => "crypto_error.decryption_failed_message",
                CryptoError::EncryptionFailed(_) => "crypto_error.encryption_failed_message",
                CryptoError::KeyNotFound(_) => "crypto_error.key_not_found_message",
                CryptoError::KeyError(_) => "crypto_error.key_error_message",
                CryptoError::KeyUsageLimitExceeded { .. } => {
                    "crypto_error.key_usage_limit_exceeded_message"
                }
                CryptoError::UnsupportedAlgorithm(_) => {
                    "crypto_error.unsupported_algorithm_message"
                }
                CryptoError::InsufficientEntropy => "crypto_error.insufficient_entropy_message",
                CryptoError::MemoryProtectionFailed(_) => "crypto_error.memory_protection_failed",
                CryptoError::MemoryAllocationFailed(_) => "crypto_error.memory_allocation_failed",
                CryptoError::MemoryTransferFailed(_) => "crypto_error.memory_transfer_failed",
                CryptoError::MemoryTampered => "crypto_error.memory_tampered",
                CryptoError::FipsError(_) => "crypto_error.fips_error_message",
                CryptoError::SideChannelError(_) => "crypto_error.side_channel_error_message",
                CryptoError::SecurityError(_) => "crypto_error.security_error_message",
                CryptoError::NotImplemented(_) => "crypto_error.not_implemented_message",
                CryptoError::IoError(_) => "crypto_error.io_error_message",
                CryptoError::TimeError => "crypto_error.time_error_message",
                CryptoError::PluginError(_) => "crypto_error.plugin_error_message",
                CryptoError::InternalError(_) => "crypto_error.internal_error_message",
                CryptoError::SigningFailed(_) => "crypto_error.signing_failed_message",
                CryptoError::VerificationFailed(_) => "crypto_error.verification_failed_message",
                CryptoError::UnknownError => "crypto_error.unknown_error_message",
                CryptoError::InvalidKeyLength(_) => "crypto_error.invalid_key_length_message",
                CryptoError::HardwareAccelerationUnavailable(_) => {
                    "crypto_error.hardware_acceleration_unavailable_message"
                }
                CryptoError::AsyncOperationFailed(_) => {
                    "crypto_error.async_operation_failed_message"
                }
                CryptoError::HardwareInitializationFailed(_) => {
                    "crypto_error.hardware_initialization_failed_message"
                }
            }
        }
    }

    pub fn get_localized_message(error: &CryptoError) -> String {
        use super::LocalizedError;
        use crate::i18n::translate_with_args;

        let key = error.get_message_key();
        let args: Vec<(&str, String)> = match error {
            CryptoError::InvalidKeySize { expected, actual } => {
                vec![
                    ("expected", expected.to_string()),
                    ("actual", actual.to_string()),
                ]
            }
            CryptoError::InvalidParameter(msg)
            | CryptoError::InvalidInput(msg)
            | CryptoError::InvalidState(msg)
            | CryptoError::DecryptionFailed(msg)
            | CryptoError::EncryptionFailed(msg)
            | CryptoError::KeyNotFound(msg)
            | CryptoError::KeyError(msg) => {
                vec![("message", msg.clone())]
            }
            CryptoError::KeyUsageLimitExceeded {
                key_id,
                limit_type,
                current_count,
                max_count,
            } => {
                vec![
                    ("key_id", key_id.clone()),
                    ("limit_type", limit_type.clone()),
                    ("current_count", current_count.to_string()),
                    ("max_count", max_count.to_string()),
                ]
            }
            CryptoError::UnsupportedAlgorithm(alg) => {
                vec![("message", alg.clone())]
            }
            CryptoError::MemoryProtectionFailed(msg)
            | CryptoError::MemoryAllocationFailed(msg)
            | CryptoError::MemoryTransferFailed(msg)
            | CryptoError::FipsError(msg)
            | CryptoError::SideChannelError(msg)
            | CryptoError::SecurityError(msg)
            | CryptoError::PluginError(msg)
            | CryptoError::InternalError(msg)
            | CryptoError::SigningFailed(msg)
            | CryptoError::VerificationFailed(msg) => {
                vec![("message", msg.clone())]
            }
            CryptoError::NotImplemented(feature) => {
                vec![("feature", feature.clone())]
            }
            CryptoError::IoError(msg) => {
                vec![("message", msg.clone())]
            }
            CryptoError::InsufficientEntropy
            | CryptoError::MemoryTampered
            | CryptoError::TimeError
            | CryptoError::UnknownError => {
                vec![]
            }
            CryptoError::InvalidKeyLength(_)
            | CryptoError::HardwareAccelerationUnavailable(_)
            | CryptoError::AsyncOperationFailed(_)
            | CryptoError::NotInitialized
            | CryptoError::HardwareInitializationFailed(_) => {
                vec![]
            }
        };

        if args.is_empty() {
            crate::i18n::translate(key)
        } else {
            let args_refs: Vec<(&str, &str)> = args.iter().map(|(k, v)| (*k, v.as_str())).collect();
            translate_with_args(key, &args_refs)
        }
    }

    pub fn get_localized_title(error: &CryptoError) -> String {
        let key = error.get_translation_key();
        crate::i18n::translate(key)
    }

    pub fn get_localized_error(error: &CryptoError) -> (String, String) {
        (get_localized_title(error), get_localized_message(error))
    }
}

#[cfg(feature = "i18n")]
pub use i18n_error_impl::{
    get_localized_error, get_localized_message, get_localized_title, LocalizedError,
};

pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(feature = "python_ffi")]
impl std::convert::From<CryptoError> for pyo3::PyErr {
    fn from(error: CryptoError) -> Self {
        pyo3::exceptions::PyRuntimeError::new_err(error.to_string())
    }
}

impl From<crate::ffi::interface::CiphernError> for CryptoError {
    fn from(error: crate::ffi::interface::CiphernError) -> Self {
        use crate::ffi::interface::CiphernError::*;
        match error {
            Success => panic!("Cannot convert Success to CryptoError"),
            InvalidParameter => CryptoError::InvalidParameter("FFI Invalid Parameter".into()),
            MemoryAllocationFailed => CryptoError::InternalError("Memory allocation failed".into()),
            KeyNotFound => CryptoError::KeyNotFound("Key not found via FFI".into()),
            AlgorithmNotSupported => {
                CryptoError::UnsupportedAlgorithm("Algorithm not supported".into())
            }
            EncryptionFailed => CryptoError::EncryptionFailed("Encryption failed via FFI".into()),
            DecryptionFailed => CryptoError::DecryptionFailed("Decryption failed via FFI".into()),
            FipsError => CryptoError::FipsError("FIPS error via FFI".into()),
            KeyLifecycleError => CryptoError::KeyError("Key lifecycle error".into()),
            BufferTooSmall => CryptoError::InternalError("Buffer too small".into()),
            InvalidKeySize => CryptoError::InvalidKeySize {
                expected: 0,
                actual: 0,
            }, // Lossy conversion
            NullPointer => CryptoError::InvalidParameter("Null pointer".into()),
            UnknownError => CryptoError::UnknownError,
        }
    }
}

#[cfg(feature = "gpu-cuda")]
impl From<cudarc::driver::result::DriverError> for CryptoError {
    fn from(error: cudarc::driver::result::DriverError) -> Self {
        CryptoError::HardwareInitializationFailed(format!("CUDA error code: {:?}", error.0))
    }
}
