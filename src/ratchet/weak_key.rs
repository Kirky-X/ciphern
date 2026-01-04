// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! 弱密钥检测
//!
//! 实现弱密钥检测功能，识别全零、重复模式等低熵密钥。

use crate::error::{CryptoError, Result};

/// 检测密钥是否为弱密钥
pub fn is_weak_key(key: &[u8]) -> bool {
    if key.is_empty() {
        return true;
    }

    // 检测全零
    if is_all_zeros(key) {
        return true;
    }

    // 检测全相同字节
    if is_all_same(key) {
        return true;
    }

    // 检测低熵
    let entropy = calculate_entropy(key);
    entropy < MIN_ENTROPY_THRESHOLD
}

/// 检测全零字节
fn is_all_zeros(key: &[u8]) -> bool {
    key.iter().all(|&b| b == 0)
}

/// 检测全相同字节
fn is_all_same(key: &[u8]) -> bool {
    if key.is_empty() {
        return true;
    }
    let first = key[0];
    key.iter().all(|&b| b == first)
}

/// 计算字节数组的熵
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// 检测重复模式
pub fn has_repeated_pattern(key: &[u8]) -> bool {
    if key.len() < 4 {
        return false;
    }

    // 检测短重复模式
    for pattern_len in 1..(key.len() / 2) {
        let pattern = &key[..pattern_len];
        let mut matches = true;

        for chunk in key.chunks_exact(pattern_len) {
            if chunk != pattern {
                matches = false;
                break;
            }
        }

        if matches {
            return true;
        }
    }

    false
}

/// 检测密钥的统计特性
#[allow(dead_code)]
pub fn analyze_key_statistics(key: &[u8]) -> KeyStatistics {
    let len = key.len();
    let mut zero_count = 0;
    let mut byte_counts = [0u32; 256];
    let mut consecutive_increments = 0;

    for (i, &byte) in key.iter().enumerate() {
        if byte == 0 {
            zero_count += 1;
        }
        byte_counts[byte as usize] += 1;

        if i > 0 {
            // 检测连续递增
            if *key.get(i - 1).unwrap_or(&0) + 1 == byte {
                consecutive_increments += 1;
            }
        }
    }

    KeyStatistics {
        length: len,
        zero_ratio: zero_count as f64 / len as f64,
        unique_bytes: byte_counts.iter().filter(|&&c| c > 0).count(),
        consecutive_increments,
        entropy: calculate_entropy(key),
    }
}

/// 密钥统计信息
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KeyStatistics {
    pub length: usize,
    pub zero_ratio: f64,
    pub unique_bytes: usize,
    pub consecutive_increments: usize,
    pub entropy: f64,
}

/// 验证密钥质量
pub fn validate_key_quality(key: &[u8], min_entropy: f64) -> Result<()> {
    if is_weak_key(key) {
        return Err(CryptoError::InvalidState(
            "Key has insufficient entropy".into(),
        ));
    }

    let entropy = calculate_entropy(key);
    if entropy < min_entropy {
        return Err(CryptoError::InvalidState(format!(
            "Key entropy {} below threshold {}",
            entropy, min_entropy
        )));
    }

    if has_repeated_pattern(key) {
        return Err(CryptoError::InvalidState(
            "Key has repeated patterns".into(),
        ));
    }

    Ok(())
}

/// 最小熵阈值
const MIN_ENTROPY_THRESHOLD: f64 = 3.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_zeros() {
        assert!(is_all_zeros(&[0, 0, 0, 0]));
        assert!(!is_all_zeros(&[0, 0, 1, 0]));
        assert!(!is_all_zeros(&[1, 2, 3, 4]));
    }

    #[test]
    fn test_all_same() {
        assert!(is_all_same(&[0xFF, 0xFF, 0xFF, 0xFF]));
        assert!(!is_all_same(&[0xAA, 0xAA, 0xAA, 0xAB]));
    }

    #[test]
    fn test_weak_keys() {
        assert!(is_weak_key(&[0, 0, 0, 0]));
        assert!(is_weak_key(&[0xFF, 0xFF, 0xFF, 0xFF]));
        assert!(!is_weak_key(&(0..32).collect::<Vec<_>>()));
    }

    #[test]
    fn test_entropy_calculation() {
        let zeros = vec![0u8; 32];
        assert_eq!(calculate_entropy(&zeros), 0.0);

        let ones = vec![1u8; 32];
        assert_eq!(calculate_entropy(&ones), 0.0);

        let random: Vec<u8> = (0..32).map(|_| rand::random()).collect();
        let entropy = calculate_entropy(&random);
        assert!(entropy > 3.5, "Random data should have entropy > 3.5");
    }

    #[test]
    fn test_repeated_pattern() {
        // 重复模式
        assert!(has_repeated_pattern(&[0xAA, 0xAA, 0xAA, 0xAA]));
        assert!(has_repeated_pattern(&[1, 2, 1, 2, 1, 2]));

        // 无重复模式
        assert!(!has_repeated_pattern(&(0..16).collect::<Vec<_>>()));
    }

    #[test]
    fn test_key_statistics() {
        let random: Vec<u8> = (0..32).map(|_| rand::random()).collect();
        let stats = analyze_key_statistics(&random);

        assert!(stats.entropy > 3.0);
        assert!(stats.unique_bytes > 16);
    }

    #[test]
    fn test_validate_key_quality() {
        let good_key: Vec<u8> = (0..32).map(|_| rand::random()).collect();
        assert!(validate_key_quality(&good_key, 3.0).is_ok());

        let weak_key = vec![0xAA; 32];
        assert!(validate_key_quality(&weak_key, 3.0).is_err());
    }
}
