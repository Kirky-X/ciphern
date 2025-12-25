// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

#![allow(non_local_definitions)]

#[cfg(feature = "encrypt")]
use crate::key::Key;
#[cfg(feature = "encrypt")]
use crate::Algorithm;
#[cfg(feature = "encrypt")]
use crate::Cipher;
#[cfg(feature = "encrypt")]
use crate::KeyManager;
#[cfg(feature = "encrypt")]
use crate::Signer;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::Bound;
use std::sync::Arc;

#[pymodule]
fn ciphern_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[cfg(feature = "encrypt")]
    {
        m.add_class::<KeyManagerWrapper>()?;
        m.add_class::<KeyWrapper>()?;
        m.add_class::<CipherWrapper>()?;
        m.add_class::<SignerWrapper>()?;
    }
    m.add_function(wrap_pyfunction!(py_hash_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(py_hash_sha512, m)?)?;
    m.add_function(wrap_pyfunction!(py_hash_sm3, m)?)?;
    Ok(())
}

#[pyfunction]
fn py_hash_sha256(data: &[u8]) -> PyResult<Vec<u8>> {
    Ok(crate::Hash::sha256(data)?)
}

#[pyfunction]
fn py_hash_sha512(data: &[u8]) -> PyResult<Vec<u8>> {
    Ok(crate::Hash::sha512(data)?)
}

#[pyfunction]
fn py_hash_sm3(data: &[u8]) -> PyResult<Vec<u8>> {
    Ok(crate::Hash::sm3(data)?)
}

#[cfg(feature = "encrypt")]
#[pyclass(name = "Key")]
#[derive(Clone)]
pub struct KeyWrapper {
    #[allow(dead_code)]
    inner: Arc<Key>,
}

#[cfg(feature = "encrypt")]
#[pymethods]
impl KeyWrapper {
    #[getter]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    #[getter]
    pub fn algorithm(&self) -> String {
        format!("{:?}", self.inner.algorithm())
    }

    #[getter]
    pub fn state(&self) -> String {
        format!("{:?}", self.inner.state())
    }
}

#[cfg(feature = "encrypt")]
#[pyclass(name = "KeyManager")]
#[derive(Clone)]
pub struct KeyManagerWrapper {
    #[allow(dead_code)]
    inner: Arc<KeyManager>,
}

#[cfg(feature = "encrypt")]
#[pymethods]
impl KeyManagerWrapper {
    #[new]
    pub fn new() -> PyResult<Self> {
        let manager = KeyManager::new()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(manager),
        })
    }

    pub fn generate_key(&self, algorithm: &str) -> PyResult<String> {
        let algo = parse_algorithm(algorithm)?;
        self.inner
            .generate_key(algo)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    pub fn generate_key_with_alias(&self, algorithm: &str, alias: &str) -> PyResult<String> {
        let algo = parse_algorithm(algorithm)?;
        self.inner
            .generate_key_with_alias(algo, alias)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    pub fn get_key(&self, key_id_or_alias: &str) -> PyResult<KeyWrapper> {
        let key = self
            .inner
            .get_key(key_id_or_alias)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        Ok(KeyWrapper {
            inner: Arc::new(key),
        })
    }

    pub fn activate_key(&self, key_id_or_alias: &str) -> PyResult<()> {
        self.inner
            .activate_key(key_id_or_alias)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    pub fn suspend_key(&self, key_id_or_alias: &str) -> PyResult<()> {
        self.inner
            .suspend_key(key_id_or_alias)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    pub fn destroy_key(&self, key_id_or_alias: &str) -> PyResult<()> {
        self.inner
            .destroy_key(key_id_or_alias)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    pub fn list_keys(&self) -> PyResult<Vec<String>> {
        self.inner
            .list_keys()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }
}

fn parse_algorithm(algo_str: &str) -> PyResult<Algorithm> {
    match algo_str.to_uppercase().as_str() {
        "AES256GCM" => Ok(Algorithm::AES256GCM),
        "SM4GCM" => Ok(Algorithm::SM4GCM),
        "ED25519" => Ok(Algorithm::Ed25519),
        "ECDSA_P256" | "ECDSA256" => Ok(Algorithm::ECDSAP256),
        "ECDSA_P384" | "ECDSA384" => Ok(Algorithm::ECDSAP384),
        "RSA2048" => Ok(Algorithm::RSA2048),
        "RSA3072" => Ok(Algorithm::RSA3072),
        "RSA4096" => Ok(Algorithm::RSA4096),
        _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Unsupported algorithm: {}",
            algo_str
        ))),
    }
}

#[cfg(feature = "encrypt")]
#[pyclass(name = "Ciphern")]
pub struct CipherWrapper {
    #[allow(dead_code)]
    inner: Cipher,
    #[allow(dead_code)]
    key_manager: Arc<KeyManager>,
}

#[cfg(feature = "encrypt")]
#[pymethods]
impl CipherWrapper {
    #[new]
    pub fn new(key_manager: &Bound<'_, PyAny>) -> PyResult<Self> {
        if !key_manager.is_instance_of::<KeyManagerWrapper>() {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Expected a KeyManager instance",
            ));
        }
        let wrapper: KeyManagerWrapper = key_manager.extract()?;
        let key_manager_arc = wrapper.inner.clone();

        let algorithm = Algorithm::AES256GCM;
        let cipher = Cipher::new(algorithm)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        Ok(Self {
            inner: cipher,
            key_manager: key_manager_arc,
        })
    }

    #[staticmethod]
    pub fn with_algorithm(key_manager: &Bound<'_, PyAny>, algorithm: &str) -> PyResult<Self> {
        if !key_manager.is_instance_of::<KeyManagerWrapper>() {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Expected a KeyManager instance",
            ));
        }
        let wrapper: KeyManagerWrapper = key_manager.extract()?;
        let key_manager_arc = wrapper.inner.clone();

        let algo = parse_algorithm(algorithm)?;
        let cipher = Cipher::new(algo)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        Ok(Self {
            inner: cipher,
            key_manager: key_manager_arc,
        })
    }

    pub fn encrypt(&self, key_id: &str, data: &[u8], _aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
        self.inner
            .encrypt(&self.key_manager, key_id, data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    pub fn decrypt(&self, key_id: &str, data: &[u8], _aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
        self.inner
            .decrypt(&self.key_manager, key_id, data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }
}

#[cfg(feature = "encrypt")]
#[pyclass(name = "Signer")]
pub struct SignerWrapper {
    #[allow(dead_code)]
    inner: Signer,
    #[allow(dead_code)]
    key_manager: Arc<KeyManager>,
}

#[cfg(feature = "encrypt")]
#[pymethods]
impl SignerWrapper {
    #[staticmethod]
    pub fn new(key_manager: &Bound<'_, PyAny>, algorithm: &str) -> PyResult<Self> {
        if !key_manager.is_instance_of::<KeyManagerWrapper>() {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Expected a KeyManager instance",
            ));
        }
        let wrapper: KeyManagerWrapper = key_manager.extract()?;
        let key_manager_arc = wrapper.inner.clone();

        let algo = parse_algorithm(algorithm)?;
        let signer = Signer::new(algo)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        Ok(Self {
            inner: signer,
            key_manager: key_manager_arc,
        })
    }

    pub fn sign(&self, key_id: &str, data: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .sign(&self.key_manager, key_id, data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    pub fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> PyResult<bool> {
        self.inner
            .verify(&self.key_manager, key_id, data, signature)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }
}
