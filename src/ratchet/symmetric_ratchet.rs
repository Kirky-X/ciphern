// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! 对称密钥 Ratchet 实现
//!
//! 实现 Double Ratchet 协议中的对称密钥 Ratchet 部分，负责链密钥和消息密钥的派生。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{CryptoError, Result};
use crate::memory::SecretBytes;

type HmacSha256 = Hmac<Sha256>;

/// KDF_CK 函数 - 派生链密钥和消息密钥
///
/// 根据 Signal Protocol 规范，使用 HMAC-SHA256 派生。
#[allow(dead_code)]
pub fn kdf_ck(chain_key: &SecretBytes, key_info: &[u8]) -> Result<(SecretBytes, SecretBytes)> {
    // 派生消息密钥 (Constant-time operation)
    let mut mac = HmacSha256::new_from_slice(chain_key.as_bytes())
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;
    mac.update(b"\x01");
    mac.update(key_info);
    let message_key_result = mac.finalize().into_bytes();

    // 派生新的链密钥
    let mut mac = HmacSha256::new_from_slice(chain_key.as_bytes())
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;
    mac.update(b"\x02");
    mac.update(key_info);
    let chain_key_result = mac.finalize().into_bytes();

    Ok((
        SecretBytes::new(chain_key_result.to_vec())?,
        SecretBytes::new(message_key_result.to_vec())?,
    ))
}

/// KDF_RK 函数 - 派生根密钥
pub fn kdf_rk(
    root_key: &SecretBytes,
    dh_shared: &[u8; 32],
    key_info: &[u8],
) -> Result<SecretBytes> {
    let mut mac = HmacSha256::new_from_slice(root_key.as_bytes())
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;
    mac.update(dh_shared);
    mac.update(key_info);
    let result = mac.finalize().into_bytes();

    SecretBytes::new(result.to_vec())
}

/// 内部 KDF_CK 实现
pub fn kdf_chain_internal(
    chain_key: &SecretBytes,
    key_info: &[u8],
    _message_number: u64,
) -> Result<(SecretBytes, SecretBytes)> {
    // 派生消息密钥
    let mut mac = HmacSha256::new_from_slice(chain_key.as_bytes())
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;
    mac.update(b"0");
    mac.update(key_info);
    let message_key_result = mac.finalize().into_bytes();

    // 派生新的链密钥
    let mut mac = HmacSha256::new_from_slice(chain_key.as_bytes())
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;
    mac.update(b"1");
    mac.update(key_info);
    let new_chain_key_result = mac.finalize().into_bytes();

    Ok((
        SecretBytes::new(new_chain_key_result.to_vec())?,
        SecretBytes::new(message_key_result.to_vec())?,
    ))
}

/// 派生消息密钥
pub fn derive_message_key(chain_key: &SecretBytes, message_number: u64) -> Result<SecretBytes> {
    let mut mac = HmacSha256::new_from_slice(chain_key.as_bytes())
        .map_err(|e| CryptoError::InvalidState(e.to_string()))?;
    mac.update(b"MessageKey");
    mac.update(&message_number.to_le_bytes());
    let message_key_result = mac.finalize().into_bytes();

    SecretBytes::new(message_key_result.to_vec())
}

/// 计算密钥熵
#[allow(dead_code)]
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

/// 批量生成消息密钥
///
/// 从一个链密钥派生出多个消息密钥，返回所有消息密钥和最终的链密钥。
/// 注意：由于 KDF 的链式依赖特性，此函数内部仍为顺序执行。
/// 对于大量密钥派生场景，考虑使用专门的 KDF 算法如 HKDF。
///
/// # Arguments
///
/// * `chain_key` - 当前链密钥
/// * `key_info` - 密钥派生信息标签
/// * `count` - 要派生的消息密钥数量
///
/// # Returns
///
/// 消息密钥列表和最终的链密钥
pub fn kdf_ck_parallel(
    chain_key: &SecretBytes,
    key_info: &[u8],
    count: usize,
) -> Result<(Vec<SecretBytes>, SecretBytes)> {
    let mut current_chain = chain_key.clone();
    let mut message_keys = Vec::with_capacity(count);

    for _ in 0..count {
        let (new_chain, msg_key) = kdf_chain_internal(&current_chain, key_info, 0)?;
        current_chain = new_chain;
        message_keys.push(msg_key);
    }

    Ok((message_keys, current_chain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_ck() {
        let chain_key = SecretBytes::new(vec![0xau8; 32]).unwrap();
        let key_info = b"TestKey";

        let (new_chain, message_key) = kdf_ck(&chain_key, key_info).unwrap();

        // 验证链密钥和消息密钥不同
        assert_ne!(new_chain.as_bytes(), chain_key.as_bytes());
        assert_ne!(new_chain.as_bytes(), message_key.as_bytes());

        // 验证长度
        assert_eq!(new_chain.as_bytes().len(), 32);
        assert_eq!(message_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_kdf_rk() {
        let root_key = SecretBytes::new(vec![0xbu8; 32]).unwrap();
        let dh_shared = [0xcu8; 32];
        let key_info = b"RootKey";

        let new_root = kdf_rk(&root_key, &dh_shared, key_info).unwrap();

        assert_eq!(new_root.as_bytes().len(), 32);
        assert_ne!(new_root.as_bytes(), root_key.as_bytes());
    }

    #[test]
    fn test_derive_message_key() {
        let chain_key = SecretBytes::new(vec![0xdu8; 32]).unwrap();

        let key1 = derive_message_key(&chain_key, 0).unwrap();
        let key2 = derive_message_key(&chain_key, 1).unwrap();

        assert_eq!(key1.as_bytes().len(), 32);
        assert_eq!(key2.as_bytes().len(), 32);
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_entropy_calculation() {
        let zeros = vec![0u8; 32];
        assert_eq!(calculate_entropy(&zeros), 0.0);
    }

    #[test]
    fn test_kdf_ck_parallel() {
        let chain_key = SecretBytes::new(vec![0xau8; 32]).unwrap();
        let key_info = b"TestKey";
        let count = 5;

        let (message_keys, final_chain) = kdf_ck_parallel(&chain_key, key_info, count).unwrap();

        // 验证生成了正确数量的密钥
        assert_eq!(message_keys.len(), count);

        // 验证所有消息密钥长度正确
        for key in &message_keys {
            assert_eq!(key.as_bytes().len(), 32);
        }

        // 验证所有消息密钥不同
        for i in 0..count {
            for j in (i + 1)..count {
                assert_ne!(message_keys[i].as_bytes(), message_keys[j].as_bytes());
            }
        }

        // 验证最终链密钥与初始不同
        assert_ne!(final_chain.as_bytes(), chain_key.as_bytes());
    }
}
