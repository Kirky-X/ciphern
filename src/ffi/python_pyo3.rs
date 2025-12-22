// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Python PyO3 模块
//! 
//! 为 Python 提供本地接口支持

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::ffi::CString;

use crate::ffi::{ciphern_cleanup, ciphern_decrypt, ciphern_encrypt, ciphern_generate_key, ciphern_init, CiphernError};

#[pyclass]
pub struct Ciphern {
}

#[pymethods]
impl Ciphern {
    #[new]
    fn new() -> PyResult<Self> {
        let result = ciphern_init();
        if result == CiphernError::Success {
            Ok(Ciphern {})
        } else {
            Err(PyRuntimeError::new_err(format!("Failed to initialize Ciphern library: {:?}", result)))
        }
    }

    fn generate_key(&self, algorithm: &str) -> PyResult<String> {
        let algo_cstring = CString::new(algorithm).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let mut key_id_buffer = [0u8; 256];
        
        let result = ciphern_generate_key(
            algo_cstring.as_ptr(),
            key_id_buffer.as_mut_ptr() as *mut i8,
            key_id_buffer.len(),
        );
        
        if result == CiphernError::Success {
            let key_id = unsafe { std::ffi::CStr::from_ptr(key_id_buffer.as_ptr() as *const i8).to_string_lossy().into_owned() };
            Ok(key_id)
        } else {
            Err(PyRuntimeError::new_err(format!("Failed to generate key: {:?}", result)))
        }
    }

    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> PyResult<Vec<u8>> {
        let key_id_cstring = CString::new(key_id).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let mut ciphertext_buffer = vec![0u8; plaintext.len() + 256];
        let mut ciphertext_len: usize = 0;
        
        let result = ciphern_encrypt(
            key_id_cstring.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext_buffer.as_mut_ptr(),
            ciphertext_buffer.len(),
            &mut ciphertext_len as *mut usize,
        );
        
        if result == CiphernError::Success {
            ciphertext_buffer.truncate(ciphertext_len);
            Ok(ciphertext_buffer)
        } else {
            Err(PyRuntimeError::new_err(format!("Encryption failed: {:?}", result)))
        }
    }

    fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> PyResult<Vec<u8>> {
        let key_id_cstring = CString::new(key_id).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let mut plaintext_buffer = vec![0u8; ciphertext.len()];
        let mut plaintext_len: usize = 0;
        
        let result = ciphern_decrypt(
            key_id_cstring.as_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            plaintext_buffer.as_mut_ptr(),
            plaintext_buffer.len(),
            &mut plaintext_len as *mut usize,
        );
        
        if result == CiphernError::Success {
            plaintext_buffer.truncate(plaintext_len);
            Ok(plaintext_buffer)
        } else {
            Err(PyRuntimeError::new_err(format!("Decryption failed: {:?}", result)))
        }
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __exit__(&self, _exc_type: PyObject, _exc_value: PyObject, _traceback: PyObject) {
        ciphern_cleanup();
    }
}

#[pymodule]
fn ciphern(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Ciphern>()?;
    Ok(())
}
