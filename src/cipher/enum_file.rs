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
    Cbc,
    /// ECB模式 - 需要PKCS#7填充
    Ecb,
    /// CTR模式 - 不需要填充
    Ctr,
}

impl CipherMode {
    /// 判断模式是否需要填充
    pub fn requires_padding(&self) -> bool {
        matches!(self, CipherMode::Cbc | CipherMode::Ecb)
    }
}
