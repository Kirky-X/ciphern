// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! C API Implementation
//!
//! Implements the C-compatible Foreign Function Interface (FFI).

use std::ffi::CString;
use std::os::raw::{c_char, c_int};

use crate::ffi::interface::parse_algorithm;
use crate::ffi::interface::validation;
use crate::ffi::interface::write_c_string;

use crate::Cipher;
use zeroize::Zeroize;

use crate::ffi::context::{self, with_context};
use crate::ffi::interface::CiphernError;

/// 初始化库
#[no_mangle]
pub extern "C" fn ciphern_init() -> CiphernError {
    match std::panic::catch_unwind(|| context::initialize_context()) {
        Ok(result) => match result {
            Ok(_) => CiphernError::Success,
            Err(_) => CiphernError::UnknownError,
        },
        Err(_) => {
            eprintln!("ciphern_init: Panic occurred during initialization");
            CiphernError::UnknownError
        }
    }
}

/// 清理库资源
#[no_mangle]
pub extern "C" fn ciphern_cleanup() {
    match std::panic::catch_unwind(|| context::cleanup_context()) {
        Ok(_) => {}
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
        with_context(|context| {
            // 启用FIPS模式
            match crate::fips::FipsContext::enable() {
                Ok(_) => {
                    // 创建新的FIPS上下文
                    let _fips_context =
                        match crate::fips::FipsContext::new(crate::fips::FipsMode::Enabled) {
                            Ok(fc) => fc,
                            Err(_) => return Ok(CiphernError::FipsError),
                        };

                    // 更新上下文中的FIPS状态
                    context.set_fips_enabled(true);
                    Ok(CiphernError::Success)
                }
                Err(_) => Ok(CiphernError::FipsError),
            }
        })
        .unwrap_or(CiphernError::UnknownError)
    }) {
        Ok(result) => result,
        Err(_) => CiphernError::UnknownError,
    }
}

/// 检查 FIPS 模式是否启用
#[no_mangle]
pub extern "C" fn ciphern_is_fips_enabled() -> c_int {
    match std::panic::catch_unwind(|| {
        with_context(|context| {
            if context.is_fips_enabled() {
                Ok(1)
            } else {
                Ok(0)
            }
        })
        .unwrap_or(0)
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
        with_context(|context| {
            // 验证参数
            let algo_str = unsafe { validation::validate_c_str(algorithm_name) }
                .map_err(|_e| CiphernError::InvalidParameter)?;
            // output buffer should not be validated as c_str (which implies reading it)
            validation::validate_mut_ptr(key_id_buffer, "key_id_buffer")
                .map_err(|_e| CiphernError::InvalidParameter)?;

            // 解析算法
            let algorithm =
                parse_algorithm(algo_str).map_err(|_e| CiphernError::InvalidParameter)?;

            // 获取密钥管理器
            let key_manager = context
                .key_manager()
                .map_err(|_| CiphernError::UnknownError)?;

            // 生成密钥
            let key_id = key_manager
                .generate_key(algorithm)
                .map_err(|_| CiphernError::KeyLifecycleError)?;

            // 自动激活密钥
            if let Ok(mut key) = key_manager.get_key(&key_id) {
                let _ = key.activate(None);
            }

            // 复制密钥ID到缓冲区
            unsafe { write_c_string(&key_id, key_id_buffer, key_id_buffer_size) }
                .map_err(|_e| CiphernError::BufferTooSmall)?;

            Ok(CiphernError::Success)
        })
        .unwrap_or(CiphernError::UnknownError)
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
        with_context(|context| {
            // 验证参数
            let key_id_str = unsafe { validation::validate_c_str(key_id) }
                .map_err(|_e| CiphernError::InvalidParameter)?;

            // 获取密钥管理器
            let key_manager = context
                .key_manager()
                .map_err(|_| CiphernError::UnknownError)?;

            // 销毁密钥
            key_manager
                .destroy_key(key_id_str)
                .map_err(|_| CiphernError::KeyNotFound)?;

            Ok(CiphernError::Success)
        })
        .unwrap_or_else(|e| e)
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
    debug_assert!(
        !ciphertext.is_null(),
        "Ciphertext buffer should not be null"
    );
    debug_assert!(
        !ciphertext_len.is_null(),
        "Ciphertext length pointer should not be null"
    );
    debug_assert!(
        plaintext_len > 0,
        "Plaintext length should be greater than 0"
    );
    debug_assert!(
        plaintext_len <= 1024 * 1024,
        "Plaintext length should not exceed 1MB for performance"
    );
    debug_assert!(
        ciphertext_buffer_size >= plaintext_len + 32,
        "Ciphertext buffer should be large enough to hold encrypted data"
    );

    if key_id.is_null() || plaintext.is_null() || ciphertext.is_null() || ciphertext_len.is_null() {
        return CiphernError::InvalidParameter;
    }

    match std::panic::catch_unwind(|| {
        with_context(|context| {
            // 验证参数
            let key_id_str = unsafe { validation::validate_c_str(key_id) }
                .map_err(|_e| CiphernError::InvalidParameter)?;
            let plaintext_slice = unsafe { validation::validate_slice(plaintext, plaintext_len) }
                .map_err(|_e| CiphernError::InvalidParameter)?;
            let ciphertext_buffer =
                unsafe { validation::validate_mut_slice(ciphertext, ciphertext_buffer_size) }
                    .map_err(|_e| CiphernError::InvalidParameter)?;
            let ciphertext_len_ptr =
                unsafe { validation::validate_mut_usize(ciphertext_len, "ciphertext_len") }
                    .map_err(|_e| CiphernError::InvalidParameter)?;

            // 获取密钥管理器
            let key_manager = context
                .key_manager()
                .map_err(|_| CiphernError::UnknownError)?;

            // 获取密钥
            let key = key_manager
                .get_key(key_id_str)
                .map_err(|_| CiphernError::KeyNotFound)?;

            // 创建加密器
            let cipher =
                Cipher::new(key.algorithm()).map_err(|_| CiphernError::AlgorithmNotSupported)?;

            // 加密
            let mut encrypted = cipher
                .encrypt(&key_manager, key_id_str, plaintext_slice)
                .map_err(|_| CiphernError::EncryptionFailed)?;

            // 检查缓冲区大小
            if encrypted.len() > ciphertext_buffer_size {
                return Err(CiphernError::BufferTooSmall);
            }

            // 复制加密数据
            ciphertext_buffer[..encrypted.len()].copy_from_slice(&encrypted);
            *ciphertext_len_ptr = encrypted.len();

            // 清零加密数据，防止敏感信息残留
            encrypted.zeroize();

            Ok(CiphernError::Success)
        })
        .unwrap_or(CiphernError::UnknownError)
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
    debug_assert!(
        !plaintext_len.is_null(),
        "Plaintext length pointer should not be null"
    );
    debug_assert!(
        ciphertext_len > 0,
        "Ciphertext length should be greater than 0"
    );
    debug_assert!(
        ciphertext_len <= 1024 * 1024 + 32,
        "Ciphertext length should not exceed 1MB + 32 bytes for performance"
    );
    debug_assert!(
        plaintext_buffer_size >= ciphertext_len - 32,
        "Plaintext buffer should be large enough to hold decrypted data"
    );

    if key_id.is_null() || ciphertext.is_null() || plaintext.is_null() || plaintext_len.is_null() {
        return CiphernError::InvalidParameter;
    }

    match std::panic::catch_unwind(|| {
        with_context(|context| {
            // 验证参数
            let key_id_str = unsafe { validation::validate_c_str(key_id) }
                .map_err(|_e| CiphernError::InvalidParameter)?;
            let ciphertext_slice =
                unsafe { validation::validate_slice(ciphertext, ciphertext_len) }
                    .map_err(|_e| CiphernError::InvalidParameter)?;
            let plaintext_buffer =
                unsafe { validation::validate_mut_slice(plaintext, plaintext_buffer_size) }
                    .map_err(|_e| CiphernError::InvalidParameter)?;
            let plaintext_len_ptr =
                unsafe { validation::validate_mut_usize(plaintext_len, "plaintext_len") }
                    .map_err(|_e| CiphernError::InvalidParameter)?;

            // 获取密钥管理器
            let key_manager = context
                .key_manager()
                .map_err(|_| CiphernError::UnknownError)?;

            // 获取密钥
            let key = key_manager
                .get_key(key_id_str)
                .map_err(|_| CiphernError::KeyNotFound)?;

            // 创建解密器
            let cipher =
                Cipher::new(key.algorithm()).map_err(|_| CiphernError::AlgorithmNotSupported)?;

            // 解密
            let mut decrypted = cipher
                .decrypt(&key_manager, key_id_str, ciphertext_slice)
                .map_err(|_| CiphernError::DecryptionFailed)?;

            // 检查缓冲区大小
            if decrypted.len() > plaintext_buffer_size {
                *plaintext_len_ptr = decrypted.len();
                return Err(CiphernError::BufferTooSmall);
            }

            // 复制解密数据
            plaintext_buffer[..decrypted.len()].copy_from_slice(&decrypted);
            *plaintext_len_ptr = decrypted.len();

            // 清零解密数据，防止敏感信息残留
            decrypted.zeroize();

            Ok(CiphernError::Success)
        })
        .unwrap_or(CiphernError::UnknownError)
    }) {
        Ok(result) => result,
        Err(_) => CiphernError::UnknownError,
    }
}

// Thread-local error storage
thread_local! {
    static ERROR_STRING: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

/// 获取最后一次错误的描述
#[no_mangle]
pub extern "C" fn ciphern_get_last_error() -> *const c_char {
    ERROR_STRING.with(|error_string| match error_string.borrow().as_ref() {
        Some(s) => s.as_ptr(),
        None => c"Unknown error".as_ptr(),
    })
}

#[allow(dead_code)]
fn set_last_error(msg: &str) {
    ERROR_STRING.with(|error_string| {
        *error_string.borrow_mut() = Some(CString::new(msg).unwrap_or_default());
    });
}

/// C FFI 头文件生成辅助函数
#[cfg(feature = "generate_headers")]
#[allow(dead_code)]
pub fn generate_c_header() -> String {
    r#"
#ifndef CIPHERN_H
#define CIPHERN_H

#include <stddef.h>

typedef enum {
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
} CiphernError;

#ifdef __cplusplus
extern "C" {
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
}
#endif

#endif // CIPHERN_H
"#.to_string()
}
