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
pub mod java_jni;
pub mod python_pyo3;
pub mod jni_utils;

// 重新导出统一的接口定义
pub use interface::CiphernError;

// Re-export C API functions to maintain compatibility
pub use c_api::*;

#[cfg(feature = "plugin")]
#[allow(unused_imports)]
pub use interface::{
    ciphern_plugin_load, ciphern_plugin_unload, ciphern_plugin_get_info, ciphern_plugin_list,
};

#[cfg(feature = "plugin")]
#[allow(unused_imports)]
pub use interface::{
    ciphern_plugin_register_algorithm,
};

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::ffi::interface::algorithm;
}
