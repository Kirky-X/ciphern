// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use thiserror::Error;

#[cfg(feature = "python_ffi")]
use pyo3::exceptions::PyRuntimeError;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

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
    IoError(#[from] std::io::Error),

    #[error("System time error")]
    TimeError,

    #[error("Plugin error: {0}")]
    PluginError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Unknown error")]
    UnknownError,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(feature = "python_ffi")]
impl std::convert::From<CryptoError> for pyo3::PyErr {
    fn from(error: CryptoError) -> Self {
        PyRuntimeError::new_err(error.to_string())
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
