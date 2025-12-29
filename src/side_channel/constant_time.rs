// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Constant-time operations to prevent timing attacks
//!
//! This module provides constant-time implementations of common operations
//! that are vulnerable to timing attacks, such as comparisons and table lookups.

use std::hint::black_box;

/// Constant-time comparison of two byte arrays
///
/// This function compares two byte arrays in constant time regardless
/// of whether they are equal or not, and regardless of their content.
///
/// Returns true if the arrays are equal, false otherwise.
#[allow(dead_code)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_match = a.len() == b.len();
    let min_len = a.len().min(b.len());

    let mut result = 0u8;
    for i in 0..min_len {
        result |= a[i] ^ b[i];
    }

    if !len_match {
        result |= 1;
    }

    black_box(result) == 0
}

/// Constant-time selection between two values based on a condition
pub fn constant_time_select(condition: bool, a: u8, b: u8) -> u8 {
    let mask = -(condition as i8) as u8;
    (a & mask) | (b & !mask)
}

/// 带条件执行的恒定时间字节数组复制
#[allow(dead_code)]
pub fn constant_time_copy(condition: bool, dest: &mut [u8], src: &[u8]) {
    if dest.len() != src.len() {
        return;
    }

    for i in 0..dest.len() {
        dest[i] = constant_time_select(condition, src[i], dest[i]);
    }
}

/// Constant-time lookup in a table
pub fn constant_time_lookup(table: &[u8], index: usize) -> u8 {
    if index >= table.len() {
        return 0;
    }

    let mut result = 0u8;
    let mut found = false;

    for (i, &value) in table.iter().enumerate() {
        let is_target = constant_time_eq_u8(i as u8, index as u8);
        result = constant_time_select(is_target, value, result);
        found = found || is_target;
    }

    // Return 0 if index out of bounds (in constant time)
    constant_time_select(found, result, 0)
}

/// 两个 u8 值的恒定时间比较
fn constant_time_eq_u8(a: u8, b: u8) -> bool {
    black_box(a ^ b) == 0
}

/// Constant-time comparison of two u32 values
#[allow(dead_code)]
pub fn constant_time_eq_u32(a: u32, b: u32) -> bool {
    black_box(a ^ b) == 0
}

/// 两个 u64 值的恒定时间比较
#[allow(dead_code)]
pub fn constant_time_eq_u64(a: u64, b: u64) -> bool {
    black_box(a ^ b) == 0
}

/// Constant-time conditional swap
#[allow(dead_code)]
pub fn constant_time_swap(condition: bool, a: &mut [u8], b: &mut [u8]) {
    if a.len() != b.len() {
        return;
    }

    let mask = -(condition as i8) as u8;

    for i in 0..a.len() {
        let a_val = a[i];
        let b_val = b[i];
        a[i] = (a_val & !mask) | (b_val & mask);
        b[i] = (b_val & !mask) | (a_val & mask);
    }
}

/// Constant-time comparison for u32
/// 如果 a < b 返回 -1，如果 a == b 返回 0，如果 a > b 返回 1
#[allow(dead_code)]
pub fn constant_time_cmp_u32(a: u32, b: u32) -> i32 {
    let gt = (b.wrapping_sub(a) >> 31) as i32;
    let lt = (a.wrapping_sub(b) >> 31) as i32;
    gt - lt
}

/// Constant-time modular reduction
#[allow(dead_code)]
pub fn constant_time_mod_u32(value: u32, modulus: u32) -> u32 {
    if modulus == 0 {
        return value;
    }

    let remainder = value % modulus;
    let quotient = value / modulus;
    let overflow = (quotient > 0) as u32;

    // Select remainder if no overflow, otherwise value
    let condition = overflow == 0;
    constant_time_select_u32(condition, remainder, value)
}

/// 在两个 u32 值之间进行恒定时间选择
fn constant_time_select_u32(condition: bool, a: u32, b: u32) -> u32 {
    let mask = -(condition as i32) as u32;
    (a & mask) | (b & !mask)
}

/// Constant-time AES S-box lookup
pub fn constant_time_aes_sbox(input: u8) -> u8 {
    const AES_SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    constant_time_lookup(&AES_SBOX, input as usize)
}

/// 恒定时间条件递增
#[allow(dead_code)]
pub fn constant_time_inc(condition: bool, value: u32) -> u32 {
    value + (condition as u32)
}

/// 恒定时间条件递减
#[allow(dead_code)]
pub fn constant_time_dec(condition: bool, value: u32) -> u32 {
    value - (condition as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello rust";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, &b[..5]));
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(true, 0xFF, 0x00), 0xFF);
        assert_eq!(constant_time_select(false, 0xFF, 0x00), 0x00);
    }

    #[test]
    fn test_constant_time_lookup() {
        let table = [0x00, 0x11, 0x22, 0x33, 0x44];

        assert_eq!(constant_time_lookup(&table, 0), 0x00);
        assert_eq!(constant_time_lookup(&table, 2), 0x22);
        assert_eq!(constant_time_lookup(&table, 4), 0x44);
        assert_eq!(constant_time_lookup(&table, 5), 0x00); // 超出范围
    }

    #[test]
    fn test_constant_time_swap() {
        let mut a = [0x01, 0x02, 0x03];
        let mut b = [0xAA, 0xBB, 0xCC];

        constant_time_swap(true, &mut a, &mut b);
        assert_eq!(a, [0xAA, 0xBB, 0xCC]);
        assert_eq!(b, [0x01, 0x02, 0x03]);

        constant_time_swap(false, &mut a, &mut b);
        assert_eq!(a, [0xAA, 0xBB, 0xCC]);
        assert_eq!(b, [0x01, 0x02, 0x03]);
    }
}
