// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use thiserror::Error;

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

    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
