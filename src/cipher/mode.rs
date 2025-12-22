// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::types::Algorithm;

/// 加密模式枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// GCM模式 - 不需要填充
    Gcm,
    /// CBC模式 - 需要PKCS#7填充
    #[allow(dead_code)]
    Cbc,
    /// ECB模式 - 需要PKCS#7填充
    #[allow(dead_code)]
    Ecb,
    /// CTR模式 - 不需要填充
    #[allow(dead_code)]
    Ctr,
}

impl CipherMode {
    /// 判断模式是否需要填充
    pub fn requires_padding(&self) -> bool {
        matches!(self, CipherMode::Cbc | CipherMode::Ecb)
    }
}

/// 从算法推断加密模式
pub fn infer_cipher_mode(algorithm: Algorithm) -> CipherMode {
    match algorithm {
        Algorithm::AES128GCM | Algorithm::AES192GCM | Algorithm::AES256GCM | Algorithm::SM4GCM => {
            CipherMode::Gcm
        }
        // 这里可以扩展支持更多模式
        _ => CipherMode::Gcm, // 默认使用GCM模式
    }
}

/// 获取算法的块大小
#[allow(dead_code)]
pub fn get_block_size(algorithm: Algorithm) -> usize {
    match algorithm {
        Algorithm::AES128GCM | Algorithm::AES192GCM | Algorithm::AES256GCM => 16,
        Algorithm::SM4GCM => 16,
        _ => 16, // 默认16字节块大小
    }
}
