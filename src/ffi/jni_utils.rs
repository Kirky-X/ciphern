// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! JNI 工具模块
//!
//! 提供统一的JNI类型转换和错误处理工具，减少代码重复

use jni::errors::Error as JniErrorType;
use jni::objects::{JByteArray, JString};
use jni::sys::jint;
use jni::JNIEnv;
use std::ffi::CString;

use crate::ffi::{ciphern_cleanup, ciphern_init, CiphernError};

/// JNI 结果类型别名
pub type JniResult<T> = Result<T, JniError>;

/// JNI 错误类型
#[derive(Debug)]
#[allow(dead_code)]
pub enum JniError {
    Jni(()),
    Ciphern(()),
    InvalidString,
    InvalidBuffer,
}

impl std::fmt::Display for JniError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for JniError {}

impl From<JniErrorType> for JniError {
    fn from(_error: JniErrorType) -> Self {
        JniError::Jni(())
    }
}

impl From<CiphernError> for JniError {
    fn from(_error: CiphernError) -> Self {
        JniError::Ciphern(())
    }
}

/// JNI 环境包装器，提供统一的错误处理
pub struct JniEnv<'a> {
    env: JNIEnv<'a>,
}

impl<'a> JniEnv<'a> {
    pub fn new(env: JNIEnv<'a>) -> Self {
        Self { env }
    }

    /// 获取字符串并转换为 CString
    pub fn get_cstring(&mut self, string: &JString) -> JniResult<CString> {
        let rust_string: String = self.env.get_string(string)?.into();
        CString::new(rust_string).map_err(|_| JniError::InvalidString)
    }

    /// 获取字节数组
    pub fn get_bytes(&mut self, array: &JByteArray) -> JniResult<Vec<u8>> {
        self.env.convert_byte_array(array).map_err(JniError::from)
    }

    /// 将 Rust 字符串转换为 Java 字符串
    pub fn new_string(&self, string: &str) -> JniResult<JString<'a>> {
        self.env.new_string(string).map_err(JniError::from)
    }

    /// 从 Rust 切片创建 Java 字节数组
    pub fn byte_array_from_slice(&self, data: &[u8]) -> JniResult<JByteArray<'a>> {
        self.env.byte_array_from_slice(data).map_err(JniError::from)
    }

    /// 抛出异常
    pub fn throw_exception(&mut self, class_name: &str, message: &str) -> JniResult<()> {
        self.env
            .throw_new(class_name, message)
            .map_err(|_e| JniError::Jni(()))
    }

    /// 处理 CiphernError 并抛出对应的 Java 异常
    pub fn handle_ciphern_error(&mut self, error: CiphernError) -> JniResult<()> {
        let class_name = "com/ciphern/CiphernException";
        let message = format!("Ciphern operation failed: {:?}", error);
        self.throw_exception(class_name, &message)
    }

    /// 获取底层 JNIEnv（用于需要直接访问的情况）
    #[allow(dead_code)]
    pub fn inner(&mut self) -> &mut JNIEnv<'a> {
        &mut self.env
    }
}

/// JNI 初始化工具
pub struct JniInitializer;

impl JniInitializer {
    /// 初始化 Ciphern 库
    pub fn init() -> jint {
        match ciphern_init() {
            CiphernError::Success => 0,
            _ => -1,
        }
    }

    /// 清理 Ciphern 库
    pub fn cleanup() {
        ciphern_cleanup();
    }
}

/// 缓冲区管理工具
pub struct JniBuffer;

impl JniBuffer {
    /// 创建适当大小的缓冲区（用于加密输出）
    pub fn create_encrypt_buffer(input_len: usize) -> Vec<u8> {
        vec![0u8; input_len + 256] // 预留256字节用于认证标签等
    }

    /// 创建适当大小的缓冲区（用于解密输出）
    pub fn create_decrypt_buffer(input_len: usize) -> Vec<u8> {
        vec![0u8; input_len] // 解密后数据通常不会变大
    }

    /// 调整缓冲区大小到实际数据长度
    pub fn truncate_buffer(buffer: &mut Vec<u8>, actual_len: usize) {
        buffer.truncate(actual_len);
    }
}

/// 宏定义，提供 JNI 函数的标准错误处理和返回值转换封装
#[macro_export]
macro_rules! jni_wrap {
    ($env:expr, $body:expr) => {{
        let mut jni_env = $crate::ffi::jni_utils::JniEnv::new($env);
        match $body {
            Ok(result) => result,
            Err(e) => {
                let _ = jni_env.handle_ciphern_error(e.into());
                Default::default()
            }
        }
    }};
}

/// 宏定义，安全地将 Java 字符串转换为 Rust CString
#[macro_export]
macro_rules! jni_get_string {
    ($env:expr, $string:expr) => {{
        let mut jni_env = $crate::ffi::jni_utils::JniEnv::new($env);
        jni_env.get_cstring($string)?
    }};
}

/// 宏定义，提供 Java 字节数组到 Rust Vec<u8> 的安全转换封装
#[macro_export]
macro_rules! jni_get_bytes {
    ($env:expr, $array:expr) => {{
        let mut jni_env = $crate::ffi::jni_utils::JniEnv::new($env);
        jni_env.get_bytes($array)?
    }};
}

#[cfg(test)]
mod tests {
    use super::JniBuffer;

    #[test]
    fn test_buffer_creation() {
        let encrypt_buffer = JniBuffer::create_encrypt_buffer(100);
        assert_eq!(encrypt_buffer.len(), 356); // 100 + 256

        let decrypt_buffer = JniBuffer::create_decrypt_buffer(100);
        assert_eq!(decrypt_buffer.len(), 100);
    }
}
