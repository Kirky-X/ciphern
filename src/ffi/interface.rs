// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! FFI 接口定义
//!
//! 所有 FFI 绑定的统一接口定义

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use zeroize::Zeroize;

/// FFI 错误码定义
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    NullPointer = -11,
    UnknownError = -999,
}

impl CiphernError {
    /// 获取错误描述
    pub fn description(&self) -> &'static str {
        match self {
            CiphernError::Success => "成功",
            CiphernError::InvalidParameter => "无效参数",
            CiphernError::MemoryAllocationFailed => "内存分配失败",
            CiphernError::KeyNotFound => "密钥未找到",
            CiphernError::AlgorithmNotSupported => "不支持的算法",
            CiphernError::EncryptionFailed => "加密失败",
            CiphernError::DecryptionFailed => "解密失败",
            CiphernError::FipsError => "FIPS 错误",
            CiphernError::KeyLifecycleError => "密钥生命周期错误",
            CiphernError::BufferTooSmall => "缓冲区太小",
            CiphernError::InvalidKeySize => "无效的密钥大小",
            CiphernError::NullPointer => "空指针",
            CiphernError::UnknownError => "未知错误",
        }
    }

    /// 从 Rust Result 转换错误
    pub fn from_result<T>(result: Result<T, crate::CryptoError>) -> CiphernError {
        match result {
            Ok(_) => CiphernError::Success,
            Err(e) => Self::from_crypto_error(e),
        }
    }

    /// 从 CryptoError 转换
    pub fn from_crypto_error(error: crate::CryptoError) -> CiphernError {
        use crate::CryptoError;
        match error {
            CryptoError::InvalidParameter(_) => CiphernError::InvalidParameter,
            CryptoError::KeyNotFound(_) => CiphernError::KeyNotFound,
            CryptoError::UnsupportedAlgorithm(_) => CiphernError::AlgorithmNotSupported,
            CryptoError::EncryptionFailed(_) => CiphernError::EncryptionFailed,
            CryptoError::DecryptionFailed(_) => CiphernError::DecryptionFailed,
            CryptoError::KeyError(_) => CiphernError::KeyLifecycleError,
            CryptoError::InvalidKeySize { .. } => CiphernError::InvalidKeySize,
            CryptoError::FipsError(_) => CiphernError::FipsError,
            _ => CiphernError::UnknownError,
        }
    }
}

/// FFI 缓冲区结构
#[repr(C)]
#[allow(dead_code)]
pub struct CiphernBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl CiphernBuffer {
    /// 创建新的缓冲区
    #[allow(dead_code)]
    pub fn new(capacity: usize) -> Result<Self, CiphernError> {
        if capacity == 0 {
            return Ok(Self {
                data: ptr::null_mut(),
                len: 0,
                capacity: 0,
            });
        }

        let mut vec = Vec::with_capacity(capacity);
        let data = vec.as_mut_ptr();
        let capacity = vec.capacity();

        // 防止 Vec 被释放
        std::mem::forget(vec);

        Ok(Self {
            data,
            len: 0,
            capacity,
        })
    }

    /// 从 Vec 创建缓冲区
    #[allow(dead_code)]
    pub fn from_vec(mut vec: Vec<u8>) -> Self {
        let data = vec.as_mut_ptr();
        let len = vec.len();
        let capacity = vec.capacity();

        std::mem::forget(vec);

        Self {
            data,
            len,
            capacity,
        }
    }

    /// 转换为 Vec
    ///
    /// # Safety
    ///
    /// 调用者必须确保:
    /// 1. `data` 指针有效且由 `Vec::from_raw_parts` 分配
    /// 2. `len` 和 `capacity` 正确
    /// 3. 此函数转移所有权，调用后原始结构不应再被使用
    #[allow(dead_code)]
    #[allow(clippy::wrong_self_convention)]
    pub unsafe fn to_vec(self) -> Vec<u8> {
        if self.data.is_null() || self.capacity == 0 {
            return Vec::new();
        }

        Vec::from_raw_parts(self.data, self.len, self.capacity)
    }

    /// 从原始指针创建（不拥有所有权）
    ///
    /// # Safety
    ///
    /// 调用者必须确保指针有效性
    #[allow(dead_code)]
    pub unsafe fn from_raw_parts(data: *mut u8, len: usize, capacity: usize) -> Self {
        Self {
            data,
            len,
            capacity,
        }
    }

    /// 释放缓冲区
    ///
    /// # Safety
    ///
    /// 调用者必须确保:
    /// 1. `data` 指针有效且由 Rust 分配
    /// 2. `capacity` 正确
    /// 3. 未被 double free
    #[allow(dead_code)]
    pub unsafe fn free(self) {
        if !self.data.is_null() && self.capacity > 0 {
            let _ = Vec::from_raw_parts(self.data, 0, self.capacity);
        }
    }
}

/// FFI 字符串结构
#[repr(C)]
pub struct CiphernString {
    pub data: *mut c_char,
    pub len: usize,
}

impl CiphernString {
    /// 创建新的字符串
    #[allow(dead_code)]
    pub fn new(s: &str) -> Result<Self, CiphernError> {
        let cstring = CString::new(s).map_err(|_| CiphernError::InvalidParameter)?;
        let len = cstring.as_bytes_with_nul().len();
        let data = cstring.into_raw();

        Ok(Self { data, len })
    }

    /// 释放字符串
    ///
    /// # Safety
    ///
    /// 调用者必须确保:
    /// 1. `data` 指针有效且由 `CString` 分配
    /// 2. 未被 double free
    #[allow(dead_code)]
    pub unsafe fn free(self) {
        if !self.data.is_null() {
            let _ = CString::from_raw(self.data);
        }
    }
}

/// 参数验证工具
pub mod validation {
    use super::*;

    /// 验证指针参数
    pub fn validate_ptr<T>(ptr: *const T, name: &str) -> Result<(), CiphernError> {
        if ptr.is_null() {
            eprintln!("FFI: Null pointer for parameter '{}'", name);
            return Err(CiphernError::InvalidParameter);
        }
        Ok(())
    }

    /// 验证可变指针参数
    pub fn validate_mut_ptr<T>(ptr: *mut T, name: &str) -> Result<(), CiphernError> {
        if ptr.is_null() {
            eprintln!("FFI: Null pointer for parameter '{}'", name);
            return Err(CiphernError::InvalidParameter);
        }
        Ok(())
    }

    /// 验证缓冲区大小
    #[allow(dead_code)]
    pub fn validate_buffer_size(
        size: usize,
        min_size: usize,
        name: &str,
    ) -> Result<(), CiphernError> {
        if size < min_size {
            eprintln!("FFI: Buffer '{}' too small: {} < {}", name, size, min_size);
            return Err(CiphernError::BufferTooSmall);
        }
        Ok(())
    }

    /// 验证数据长度
    pub fn validate_length(len: usize, max_len: usize, name: &str) -> Result<(), CiphernError> {
        if len > max_len {
            eprintln!("FFI: Data '{}' too large: {} > {}", name, len, max_len);
            return Err(CiphernError::InvalidParameter);
        }
        Ok(())
    }

    /// 验证 C 字符串
    pub unsafe fn validate_c_str<'a>(ptr: *const c_char) -> Result<&'a str, CiphernError> {
        c_str_to_str(ptr, "c_str")
    }

    /// 验证切片
    pub unsafe fn validate_slice<'a>(
        data: *const u8,
        len: usize,
    ) -> Result<&'a [u8], CiphernError> {
        create_slice(data, len, "slice")
    }

    /// 验证可变切片
    pub unsafe fn validate_mut_slice<'a>(
        data: *mut u8,
        len: usize,
    ) -> Result<&'a mut [u8], CiphernError> {
        create_mut_slice(data, len, "mut_slice")
    }

    /// 验证可变 usize 指针
    pub unsafe fn validate_mut_usize<'a>(
        ptr: *mut usize,
        name: &str,
    ) -> Result<&'a mut usize, CiphernError> {
        validate_mut_ptr(ptr, name)?;
        Ok(&mut *ptr)
    }

    /// 安全转换 C 字符串
    pub unsafe fn c_str_to_str<'a>(
        ptr: *const c_char,
        name: &str,
    ) -> Result<&'a str, CiphernError> {
        validate_ptr(ptr, name)?;

        CStr::from_ptr(ptr).to_str().map_err(|_| {
            eprintln!("FFI: Invalid UTF-8 in parameter '{}'", name);
            CiphernError::InvalidParameter
        })
    }

    /// 安全创建切片
    pub unsafe fn create_slice<'a>(
        data: *const u8,
        len: usize,
        name: &str,
    ) -> Result<&'a [u8], CiphernError> {
        validate_ptr(data, name)?;
        validate_length(len, 1024 * 1024, name)?; // 1MB 限制

        Ok(slice::from_raw_parts(data, len))
    }

    /// 安全创建可变切片
    pub unsafe fn create_mut_slice<'a>(
        data: *mut u8,
        len: usize,
        name: &str,
    ) -> Result<&'a mut [u8], CiphernError> {
        validate_mut_ptr(data, name)?;
        validate_length(len, 1024 * 1024, name)?; // 1MB limit

        Ok(slice::from_raw_parts_mut(data, len))
    }
}

/// 字符串写入工具
pub unsafe fn write_c_string(s: &str, buf: *mut c_char, size: usize) -> Result<(), CiphernError> {
    if buf.is_null() || size == 0 {
        return Err(CiphernError::InvalidParameter);
    }

    let c_string = CString::new(s).map_err(|_| CiphernError::InvalidParameter)?;
    let bytes = c_string.as_bytes_with_nul();

    if bytes.len() > size {
        return Err(CiphernError::BufferTooSmall);
    }

    ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, bytes.len());
    Ok(())
}

/// 内存管理工具
pub mod memory {
    use super::*;

    /// 安全复制数据到缓冲区
    #[allow(dead_code)]
    pub unsafe fn copy_to_buffer(
        src: &[u8],
        dst: *mut u8,
        dst_size: usize,
    ) -> Result<usize, CiphernError> {
        if src.len() > dst_size {
            return Err(CiphernError::BufferTooSmall);
        }

        ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        Ok(src.len())
    }

    /// 零内存（安全擦除）
    #[allow(dead_code)]
    pub unsafe fn zero_memory(ptr: *mut u8, len: usize) {
        if !ptr.is_null() && len > 0 {
            let slice = slice::from_raw_parts_mut(ptr, len);
            slice.zeroize();
        }
    }

    /// 创建临时缓冲区
    #[allow(dead_code)]
    pub fn create_temp_buffer(size: usize) -> Vec<u8> {
        vec![0u8; size]
    }
}

/// 算法解析工具
pub mod algorithm {
    use crate::Algorithm;
    /// 解析算法名称
    pub fn parse_algorithm(name: &str) -> Result<Algorithm, super::CiphernError> {
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
            "ED25519" => Ok(Algorithm::Ed25519),
            _ => Err(super::CiphernError::AlgorithmNotSupported),
        }
    }
}

pub use algorithm::parse_algorithm;
#[allow(unused_imports)]
pub use memory::*;
#[allow(unused_imports)]
pub use validation::*;

#[cfg(feature = "plugin")]
pub mod plugin_interface {
    use super::*;
    use std::os::raw::{c_char, c_int};

    /// 加载插件
    #[no_mangle]
    pub unsafe extern "C" fn ciphern_plugin_load(_path: *const c_char) -> CiphernError {
        // Implementation placeholder
        CiphernError::AlgorithmNotSupported
    }

    /// 卸载插件
    #[no_mangle]
    pub unsafe extern "C" fn ciphern_plugin_unload(_name: *const c_char) -> CiphernError {
        // Implementation placeholder
        CiphernError::AlgorithmNotSupported
    }

    /// 获取插件信息（占位实现）
    #[no_mangle]
    pub unsafe extern "C" fn ciphern_plugin_get_info(
        _name: *const c_char,
        _buf: *mut c_char,
        _len: usize,
    ) -> CiphernError {
        CiphernError::AlgorithmNotSupported
    }

    /// 注册算法
    #[no_mangle]
    pub unsafe extern "C" fn ciphern_plugin_register_algorithm(
        _name: *const c_char,
        _algo_type: c_int,
    ) -> CiphernError {
        // Implementation placeholder
        CiphernError::AlgorithmNotSupported
    }

    /// 获取插件列表（占位实现）
    #[no_mangle]
    pub unsafe extern "C" fn ciphern_plugin_list(_buf: *mut c_char, _len: usize) -> CiphernError {
        CiphernError::AlgorithmNotSupported
    }
}

#[cfg(feature = "plugin")]
#[allow(unused_imports)]
pub use plugin_interface::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversion() {
        let error =
            CiphernError::from_result::<()>(Err(crate::CryptoError::KeyNotFound("test".into())));
        assert_eq!(error, CiphernError::KeyNotFound);
    }

    #[test]
    fn test_buffer_management() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer = CiphernBuffer::from_vec(data.clone());

        unsafe {
            let recovered = buffer.to_vec();
            assert_eq!(recovered, data);
        }
    }

    #[test]
    fn test_algorithm_parsing() {
        use crate::Algorithm;
        assert_eq!(
            algorithm::parse_algorithm("AES128GCM").unwrap(),
            Algorithm::AES128GCM
        );
        assert_eq!(
            algorithm::parse_algorithm("aes256gcm").unwrap(),
            Algorithm::AES256GCM
        );
        assert!(algorithm::parse_algorithm("INVALID").is_err());
    }
}
