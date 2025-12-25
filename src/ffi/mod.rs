// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! C FFI (Foreign Function Interface) 模块
//!
//! 提供 C 语言兼容的 API，支持跨语言调用
//! 遵循 Rust FFI 安全最佳实践

pub mod c_api;
pub mod context;
pub mod interface;

#[cfg(feature = "java_ffi")]
pub mod java_jni;

#[cfg(feature = "java_ffi")]
pub mod jni_utils;

#[cfg(feature = "python_ffi")]
pub mod python_pyo3;

// 重新导出统一的接口定义
pub use interface::CiphernError;

#[allow(unused_imports)]
// 重新导出 C API 函数供其他 FFI 模块使用
pub use c_api::{
    ciphern_cleanup, ciphern_decrypt, ciphern_encrypt, ciphern_generate_key, ciphern_init,
};

#[cfg(feature = "plugin")]
#[allow(unused_imports)]
pub use interface::{
    ciphern_plugin_get_info, ciphern_plugin_list, ciphern_plugin_load, ciphern_plugin_unload,
};

#[cfg(feature = "plugin")]
#[allow(unused_imports)]
pub use interface::ciphern_plugin_register_algorithm;

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::ffi::interface::algorithm;
}
