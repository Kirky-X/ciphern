// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! 模糊测试模块
//!
//! 此模块包含各种模糊测试，用于发现加密库中的潜在漏洞和错误。

mod fuzz_cipher;
mod fuzz_random;

/// 运行所有模糊测试
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_fuzz_tests() {
        println!("Running fuzzy tests...");
        // 所有模糊测试都会自动运行
    }
}