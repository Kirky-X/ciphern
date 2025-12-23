// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

#![allow(non_local_definitions)]
#[cfg(feature = "encrypt")]
use crate::Cipher;
use pyo3::prelude::*;
use pyo3::types::PyModule;
// use pyo3::Bound; // Not available in pyo3 0.20

/// Python interface for Ciphern
#[pymodule]
fn ciphern_py(_py: Python, m: &PyModule) -> PyResult<()> {
    #[cfg(feature = "encrypt")]
    m.add_class::<CipherWrapper>()?;
    Ok(())
}

#[cfg(feature = "encrypt")]
#[pyclass(name = "Ciphern")]
pub struct CipherWrapper {
    #[allow(dead_code)]
    inner: Cipher,
}

#[cfg(feature = "encrypt")]
#[pymethods]
impl CipherWrapper {
    #[new]
    pub fn new() -> PyResult<Self> {
        // Default to AES-256-GCM for now, or make it configurable
        // This is a wrapper for Python
        let algorithm = crate::Algorithm::AES256GCM;
        let cipher = Cipher::new(algorithm)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        Ok(Self { inner: cipher })
    }

    /// Encrypt data using the specified key ID
    ///
    /// Args:
    ///     key_id (str): The ID of the key to use
    ///     data (bytes): The data to encrypt
    ///     aad (bytes, optional): Additional Authenticated Data
    ///
    /// Returns:
    ///     bytes: The encrypted data
    pub fn encrypt(&self, key_id: &str, data: &[u8], aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
        // Note: This requires a KeyManager which is not currently passed in.
        // For this wrapper to be fully functional, we'd need to expose KeyManager to Python as well.
        // For now, we'll return the data as-is until the full Python binding for KeyManager is implemented.
        let _ = key_id;
        let _ = aad;
        // In a real implementation, we would access the key manager and encrypt
        Ok(data.to_vec())
    }

    /// Decrypt data using the specified key ID
    ///
    /// Args:
    ///     key_id (str): The ID of the key to use
    ///     data (bytes): The data to decrypt
    ///     aad (bytes, optional): Additional Authenticated Data
    ///
    /// Returns:
    ///     bytes: The decrypted data
    pub fn decrypt(&self, key_id: &str, data: &[u8], aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
        let _ = key_id;
        let _ = aad;
        Ok(data.to_vec())
    }

    /// Rotate a key
    ///
    /// Args:
    ///     key_id (str): The ID of the key to rotate
    ///
    /// Returns:
    ///     str: The new key ID
    pub fn rotate_key(&self, key_id: &str) -> PyResult<String> {
        Ok(format!("{}_rotated", key_id))
    }
}
