// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! C FFI (Foreign Function Interface) 模块
//! 
//! 提供 C 语言兼容的 API，支持跨语言调用
//! 遵循 Rust FFI 安全最佳实践

use once_cell::sync::LazyStatic;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::Mutex;
use zeroize::Zeroize;

use crate::fips::{FipsContext, FipsMode};
use crate::key::{KeyLifecycleManager, KeyLifecyclePolicy};
use crate::{Algorithm, Cipher, CryptoError, KeyManager, Result};

pub mod java_jni;
pub mod python_pyo3;

/// 错误代码定义
#[repr(C)]
pub enum CiphernError {
    Success = 0,
    InvalidParameter = -1,
    MemoryAllocationFailed = -2,
    KeyNotFound = -3,
    AlgorithmNotSupported = -4,
    EncryptionFailed = -5,
    DecryptionFailed = -6,
    FipsError = -7,
    KeyLifecycleError = -8,
    BufferTooSmall = -9,
    InvalidKeySize = -10,
    UnknownError = -999,
}

/// 全局上下文管理器
struct GlobalContext {
    key_manager: Option<Arc<KeyManager>>,
    lifecycle_manager: Option<Arc<KeyLifecycleManager>>,
    fips_context: Option<Arc<FipsContext>>,
}

impl GlobalContext {
    fn new() -> Self {
        Self {
            key_manager: None,
            lifecycle_manager: None,
            fips_context: None,
        }
    }
}

static GLOBAL_CONTEXT: LazyStatic<Mutex<GlobalContext>> = LazyStatic::new(|| {
    Mutex::new(GlobalContext::new())
});

/// 初始化库
#[no_mangle]
pub extern "C" fn ciphern_init() -> CiphernError {
    match std::panic::catch_unwind(|| {
        // 初始化 Rust 库
        if let Err(e) = crate::init() {
            return CiphernError::UnknownError;
        }
        
        // 创建全局上下文
        let mut context = GLOBAL_CONTEXT.lock().unwrap();
        
        // 创建密钥管理器
        match KeyManager::new() {
            Ok(km) => context.key_manager = Some(Arc::new(km)),
            Err(_) => return CiphernError::MemoryAllocationFailed,
        }
        
        // 创建生命周期管理器
        match KeyLifecycleManager::new() {
            Ok(lm) => context.lifecycle_manager = Some(Arc::new(lm)),
            Err(_) => return CiphernError::MemoryAllocationFailed,
        }
        
        CiphernError::Success
    }) {
        Ok(result) => result,
        Err(_) => CiphernError::UnknownError,
    }
}

/// 清理库资源
#[no_mangle]
pub extern "C" fn ciphern_cleanup() {
    match std::panic::catch_unwind(|| {
        let mut context = GLOBAL_CONTEXT.lock().unwrap();
        context.key_manager = None;
        context.lifecycle_manager = None;
        context.fips_context = None;
    }) {
        Ok(_) => {},
        Err(_) => {
            // Log the panic but don't propagate it across FFI boundary
            eprintln!("ciphern_cleanup: Panic occurred during cleanup");
        }
    }
}

/// 启用 FIPS 模式
#[no_mangle]
pub extern "C" fn ciphern_enable_fips() -> CiphernError {
    match std::panic::catch_unwind(|| {
        match FipsContext::enable() {
            Ok(_) => {
                // 更新全局上下文
                let mut context = GLOBAL_CONTEXT.lock().unwrap();
                if let Some(ref km) = context.key_manager {
                    context.fips_context = Some(Arc::new(
                        match FipsContext::new(FipsMode::Enabled) {
                            Ok(fc) => fc,
                            Err(_) => return CiphernError::FipsError,
                        }
                    ));
                }
                CiphernError::Success
            },
            Err(_) => CiphernError::FipsError,
        }
    }) {
        Ok(result) => result,
        Err(_) => CiphernError::UnknownError,
    }
}

/// 检查 FIPS 模式是否启用
#[no_mangle]
pub extern "C" fn ciphern_is_fips_enabled() -> c_int {
    match std::panic::catch_unwind(|| {
        if crate::fips::is_fips_enabled() {
            1
        } else {
            0
        }
    }) {
        Ok(result) => result,
        Err(_) => {
            // Log the panic and return safe default
            eprintln!("ciphern_is_fips_enabled: Panic occurred");
            0
        }
    }
}

/// 生成密钥
#[no_mangle]
pub extern "C" fn ciphern_generate_key(
    algorithm_name: *const c_char,
    key_id_buffer: *mut c_char,
    key_id_buffer_size: usize,
) -> CiphernError {
    if algorithm_name.is_null() || key_id_buffer.is_null() {
        return CiphernError::InvalidParameter;
    }
    
    match std::panic::catch_unwind(|| {
        // 转换算法名称
        let algo_str = unsafe {
            match CStr::from_ptr(algorithm_name).to_str() {
                Ok(s) => s,
                Err(_) => return CiphernError::InvalidParameter,
            }
        };
        
        // 解析算法
        let algorithm = match parse_algorithm(algo_str) {
            Ok(algo) => algo,
            Err(_) => return CiphernError::AlgorithmNotSupported,
        };
        
        // 获取密钥管理器
        let context = GLOBAL_CONTEXT.lock().unwrap();
        let key_manager = match context.key_manager.as_ref() {
            Some(km) => km.clone(),
            None => return CiphernError::UnknownError,
        };
        
        // 生成密钥
        let key_id = match key_manager.generate_key(algorithm) {
            Ok(id) => id,
            Err(_) => return CiphernError::KeyLifecycleError,
        };

        // 自动激活密钥
        if let Ok(mut key) = key_manager.get_key(&key_id) {
            let _ = key.activate(None);
            let _ = key_manager.update_key(key);
        }
        
        // 复制密钥ID到缓冲区
        let key_id_cstring = match CString::new(key_id) {
            Ok(s) => s,
            Err(_) => return CiphernError::MemoryAllocationFailed,
        };
        
        let key_id_bytes = key_id_cstring.as_bytes_with_nul();
        if key_id_bytes.len() > key_id_buffer_size {
            return CiphernError::BufferTooSmall;
        }
        
        unsafe {
            ptr::copy_nonoverlapping(
                key_id_bytes.as_ptr() as *const c_char,
                key_id_buffer,
                key_id_bytes.len(),
            );
        }
        
        CiphernError::Success
    }) {
        Ok(result) => result,
        Err(_) => CiphernError::UnknownError,
    }
}

/// 销毁密钥
#[no_mangle]
pub extern "C" fn ciphern_destroy_key(key_id: *const c_char) -> CiphernError {
    if key_id.is_null() {
        return CiphernError::InvalidParameter;
    }
    
    match std::panic::catch_unwind(|| {
        // 转换密钥ID
        let key_id_str = unsafe {
            match CStr::from_ptr(key_id).to_str() {
                Ok(s) => s,
                Err(_) => return CiphernError::InvalidParameter,
            }
        };
        
        // 获取密钥管理器
        let context = GLOBAL_CONTEXT.lock().unwrap();
        let key_manager = match context.key_manager.as_ref() {
            Some(km) => km.clone(),
            None => return CiphernError::UnknownError,
        };
        
        // 销毁密钥
        match key_manager.destroy_key(key_id_str) {
            Ok(_) => CiphernError::Success,
            Err(_) => CiphernError::KeyNotFound,
        }
    }) {
        Ok(result) => result,
        Err(_) => CiphernError::UnknownError,
    }
}

/// 加密数据
#[no_mangle]
pub extern "C" fn ciphern_encrypt(
    key_id: *const c_char,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut u8,
    ciphertext_buffer_size: usize,
    ciphertext_len: *mut usize,
) -> CiphernError {
    debug_assert!(!key_id.is_null(), "Key ID should not be null");
    debug_assert!(!plaintext.is_null(), "Plaintext should not be null");
    debug_assert!(!ciphertext.is_null(), "Ciphertext buffer should not be null");
    debug_assert!(!ciphertext_len.is_null(), "Ciphertext length pointer should not be null");
    debug_assert!(plaintext_len > 0, "Plaintext length should be greater than 0");
    debug_assert!(plaintext_len <= 1024 * 1024, "Plaintext length should not exceed 1MB for performance");
    debug_assert!(ciphertext_buffer_size >= plaintext_len + 32, "Ciphertext buffer should be large enough to hold encrypted data");

    if key_id.is_null() || plaintext.is_null() || ciphertext.is_null() || ciphertext_len.is_null() {
        return CiphernError::InvalidParameter;
    }
    
    match std::panic::catch_unwind(|| {
        // 转换密钥ID
        let key_id_str = unsafe {
            match CStr::from_ptr(key_id).to_str() {
                Ok(s) => s,
                Err(_) => return CiphernError::InvalidParameter,
            }
        };
        
        // 创建明文切片
        let plaintext_slice = unsafe {
            slice::from_raw_parts(plaintext, plaintext_len)
        };
        
        // 获取密钥管理器
        let context = GLOBAL_CONTEXT.lock().unwrap();
        let key_manager = match context.key_manager.as_ref() {
            Some(km) => km.clone(),
            None => return CiphernError::UnknownError,
        };
        
        // 获取密钥
        let key = match key_manager.get_key(key_id_str) {
            Ok(k) => k,
            Err(_) => return CiphernError::KeyNotFound,
        };
        
        // 创建加密器
        let cipher = match Cipher::new(key.algorithm()) {
            Ok(c) => c,
            Err(_) => return CiphernError::AlgorithmNotSupported,
        };
        
        // 加密
        let encrypted = match cipher.encrypt(&key_manager, key_id_str, plaintext_slice) {
            Ok(data) => data,
            Err(_) => return CiphernError::EncryptionFailed,
        };
        
        // 检查缓冲区大小
        if encrypted.len() > ciphertext_buffer_size {
            return CiphernError::BufferTooSmall;
        }
        
        // 复制加密数据
        unsafe {
            ptr::copy_nonoverlapping(
                encrypted.as_ptr(),
                ciphertext,
                encrypted.len(),
            );
            *ciphertext_len = encrypted.len();
        }

        // 清零加密数据，防止敏感信息残留
        encrypted.zeroize();

        CiphernError::Success
    }) {
        Ok(result) => result,
        Err(_) => CiphernError::UnknownError,
    }
}

/// 解密数据
#[no_mangle]
pub extern "C" fn ciphern_decrypt(
    key_id: *const c_char,
    ciphertext: *const u8,
    ciphertext_len: usize,
    plaintext: *mut u8,
    plaintext_buffer_size: usize,
    plaintext_len: *mut usize,
) -> CiphernError {
    debug_assert!(!key_id.is_null(), "Key ID should not be null");
    debug_assert!(!ciphertext.is_null(), "Ciphertext should not be null");
    debug_assert!(!plaintext.is_null(), "Plaintext buffer should not be null");
    debug_assert!(!plaintext_len.is_null(), "Plaintext length pointer should not be null");
    debug_assert!(ciphertext_len > 0, "Ciphertext length should be greater than 0");
    debug_assert!(ciphertext_len <= 1024 * 1024 + 32, "Ciphertext length should not exceed 1MB + 32 bytes for performance");
    debug_assert!(plaintext_buffer_size >= ciphertext_len - 32, "Plaintext buffer should be large enough to hold decrypted data");

    if key_id.is_null() || ciphertext.is_null() || plaintext.is_null() || plaintext_len.is_null() {
        return CiphernError::InvalidParameter;
    }
    
    match std::panic::catch_unwind(|| {
        // 转换密钥ID
        let key_id_str = unsafe {
            match CStr::from_ptr(key_id).to_str() {
                Ok(s) => s,
                Err(_) => return CiphernError::InvalidParameter,
            }
        };
        
        // 创建密文切片
        let ciphertext_slice = unsafe {
            slice::from_raw_parts(ciphertext, ciphertext_len)
        };
        
        // 获取密钥管理器
        let context = GLOBAL_CONTEXT.lock().unwrap();
        let key_manager = match context.key_manager.as_ref() {
            Some(km) => km.clone(),
            None => return CiphernError::UnknownError,
        };
        
        // 获取密钥
        let key = match key_manager.get_key(key_id_str) {
            Ok(k) => k,
            Err(_) => return CiphernError::KeyNotFound,
        };
        
        // 创建解密器
        let cipher = match Cipher::new(key.algorithm()) {
            Ok(c) => c,
            Err(_) => return CiphernError::AlgorithmNotSupported,
        };
        
        // 解密
        let decrypted = match cipher.decrypt(&key_manager, key_id_str, ciphertext_slice) {
            Ok(data) => data,
            Err(_) => return CiphernError::DecryptionFailed,
        };
        
        // 检查缓冲区大小
        if decrypted.len() > plaintext_buffer_size {
            return CiphernError::BufferTooSmall;
        }
        
        // 复制解密数据
        unsafe {
            ptr::copy_nonoverlapping(
                decrypted.as_ptr(),
                plaintext,
                decrypted.len(),
            );
            *plaintext_len = decrypted.len();
        }

        // 清零解密数据，防止敏感信息残留
        decrypted.zeroize();

        CiphernError::Success
    }) {
        Ok(result) => result,
        Err(_) => CiphernError::UnknownError,
    }
}

/// 获取错误描述
#[no_mangle]
pub extern "C" fn ciphern_error_string(error: CiphernError) -> *const c_char {
    match std::panic::catch_unwind(|| {
        let error_str = match error {
            CiphernError::Success => "Success",
            CiphernError::InvalidParameter => "Invalid parameter",
            CiphernError::MemoryAllocationFailed => "Memory allocation failed",
            CiphernError::KeyNotFound => "Key not found",
            CiphernError::AlgorithmNotSupported => "Algorithm not supported",
            CiphernError::EncryptionFailed => "Encryption failed",
            CiphernError::DecryptionFailed => "Decryption failed",
            CiphernError::FipsError => "FIPS error",
            CiphernError::KeyLifecycleError => "Key lifecycle error",
            CiphernError::BufferTooSmall => "Buffer too small",
            CiphernError::InvalidKeySize => "Invalid key size",
            CiphernError::UnknownError => "Unknown error",
        };

        // 使用线程本地存储避免竞态条件
        thread_local! {
            static ERROR_STRING: std::cell::RefCell<Option<CString>> = std::cell::RefCell::new(None);
        }

        ERROR_STRING.with(|cell| {
            let mut borrow = cell.borrow_mut();
            *borrow = Some(CString::new(error_str).unwrap_or_else(|_| CString::new("Unknown error").unwrap()));
            borrow.as_ref().unwrap().as_ptr()
        })
    }) {
        Ok(ptr) => ptr,
        Err(_) => {
            // Log panic and return a static string
            eprintln!("ciphern_error_string: Panic occurred");
            b"Unknown error\0".as_ptr() as *const c_char
        }
    }
}

/// 解析算法名称
fn parse_algorithm(name: &str) -> Result<Algorithm> {
    match name.to_uppercase().as_str() {
        "AES128GCM" => Ok(Algorithm::AES128GCM),
        "AES192GCM" => Ok(Algorithm::AES192GCM),
        "AES256GCM" => Ok(Algorithm::AES256GCM),
        "ECDSAP256" => Ok(Algorithm::ECDSAP256),
        "ECDSAP384" => Ok(Algorithm::ECDSAP384),
        "ECDSAP521" => Ok(Algorithm::ECDSAP521),
        "RSA2048" => Ok(Algorithm::RSA2048),
        "RSA3072" => Ok(Algorithm::RSA3072),
        "RSA4096" => Ok(Algorithm::RSA4096),
        "SHA256" => Ok(Algorithm::SHA256),
        "SHA384" => Ok(Algorithm::SHA384),
        "SHA512" => Ok(Algorithm::SHA512),
        "SHA3_256" => Ok(Algorithm::SHA3_256),
        "SHA3_384" => Ok(Algorithm::SHA3_384),
        "SHA3_512" => Ok(Algorithm::SHA3_512),
        "HKDF" => Ok(Algorithm::HKDF),
        "PBKDF2" => Ok(Algorithm::PBKDF2),
        "SM4GCM" => Ok(Algorithm::SM4GCM),
        "SM2" => Ok(Algorithm::SM2),
        "ED25519" => Ok(Algorithm::ED25519),
        _ => Err(CryptoError::AlgorithmNotSupported),
    }
}

/// C FFI 头文件生成辅助函数
#[cfg(feature = "generate_headers")]
pub fn generate_c_header() -> String {
    format!(r#"
#ifndef CIPHERN_H
#define CIPHERN_H

#include <stddef.h>

typedef enum {{
    CIPHERN_SUCCESS = 0,
    CIPHERN_INVALID_PARAMETER = -1,
    CIPHERN_MEMORY_ALLOCATION_FAILED = -2,
    CIPHERN_KEY_NOT_FOUND = -3,
    CIPHERN_ALGORITHM_NOT_SUPPORTED = -4,
    CIPHERN_ENCRYPTION_FAILED = -5,
    CIPHERN_DECRYPTION_FAILED = -6,
    CIPHERN_FIPS_ERROR = -7,
    CIPHERN_KEY_LIFECYCLE_ERROR = -8,
    CIPHERN_BUFFER_TOO_SMALL = -9,
    CIPHERN_INVALID_KEY_SIZE = -10,
    CIPHERN_UNKNOWN_ERROR = -999,
}} CiphernError;

#ifdef __cplusplus
extern "C" {{
#endif

// 初始化和清理
CiphernError ciphern_init(void);
void ciphern_cleanup(void);

// FIPS 模式
CiphernError ciphern_enable_fips(void);
int ciphern_is_fips_enabled(void);

// 密钥管理
CiphernError ciphern_generate_key(const char* algorithm_name, char* key_id_buffer, size_t key_id_buffer_size);
CiphernError ciphern_destroy_key(const char* key_id);

// 加密和解密
CiphernError ciphern_encrypt(
    const char* key_id,
    const unsigned char* plaintext,
    size_t plaintext_len,
    unsigned char* ciphertext,
    size_t ciphertext_buffer_size,
    size_t* ciphertext_len
);

CiphernError ciphern_decrypt(
    const char* key_id,
    const unsigned char* ciphertext,
    size_t ciphertext_len,
    unsigned char* plaintext,
    size_t plaintext_buffer_size,
    size_t* plaintext_len
);

// 错误处理
const char* ciphern_error_string(CiphernError error);

#ifdef __cplusplus
}}
#endif

#endif // CIPHERN_H
"#)
}