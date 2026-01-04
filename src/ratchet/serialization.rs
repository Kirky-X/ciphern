// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Double Ratchet 状态序列化
//!
//! 支持 JSON 和二进制格式的状态序列化/反序列化。

use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};
use crate::memory::SecretBytes;

use super::config::RatchetConfig;
use super::state::DoubleRatchetState;

/// 可序列化的状态快照
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetStateSnapshot {
    // DH Ratchet 状态
    pub dh_public: Option<[u8; 32]>,
    pub dh_remote_public: Option<[u8; 32]>,

    // 根密钥（加密后）
    pub encrypted_root_key: Option<Vec<u8>>,

    // 发送链
    pub send_chain_key_encrypted: Option<Vec<u8>>,
    pub send_message_number: u64,

    // 接收链
    pub recv_chain_key_encrypted: Option<Vec<u8>>,
    pub recv_message_number: u64,
    pub previous_chain_length: u64,

    // 跳过消息密钥（加密后）
    pub skipped_message_keys_encrypted: Vec<(u64, u64, Vec<u8>)>,

    // 远程身份密钥
    pub remote_identity_key: Option<[u8; 32]>,

    // 元数据
    pub ratchet_step: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub config: RatchetConfig,
}

/// JSON 序列化
pub fn serialize_json(state: &DoubleRatchetState) -> Result<String> {
    let snapshot = to_snapshot(state)?;
    serde_json::to_string(&snapshot)
        .map_err(|e| CryptoError::InvalidState(format!("JSON serialization failed: {}", e)))
}

/// JSON 反序列化
pub fn deserialize_json(data: &str, encryption_key: Option<&[u8]>) -> Result<DoubleRatchetState> {
    let snapshot: RatchetStateSnapshot = serde_json::from_str(data)
        .map_err(|e| CryptoError::InvalidState(format!("JSON deserialization failed: {}", e)))?;
    from_snapshot(snapshot, encryption_key)
}

/// 二进制序列化
pub fn serialize_binary(state: &DoubleRatchetState) -> Result<Vec<u8>> {
    let snapshot = to_snapshot(state)?;
    serialize(&snapshot)
        .map_err(|e| CryptoError::InvalidState(format!("Binary serialization failed: {}", e)))
}

/// 二进制反序列化
pub fn deserialize_binary(
    data: &[u8],
    encryption_key: Option<&[u8]>,
) -> Result<DoubleRatchetState> {
    let snapshot: RatchetStateSnapshot = deserialize(data)
        .map_err(|e| CryptoError::InvalidState(format!("Binary deserialization failed: {}", e)))?;
    from_snapshot(snapshot, encryption_key)
}

/// 转换为快照
fn to_snapshot(state: &DoubleRatchetState) -> Result<RatchetStateSnapshot> {
    Ok(RatchetStateSnapshot {
        dh_public: state.dh_public,
        dh_remote_public: state.dh_remote_public,
        encrypted_root_key: state.root_key().map(encrypt_secret),
        send_chain_key_encrypted: state.send_chain_key().map(encrypt_secret),
        send_message_number: state.send_message_number,
        recv_chain_key_encrypted: state.recv_chain_key().map(encrypt_secret),
        recv_message_number: state.recv_message_number,
        previous_chain_length: state.previous_chain_length,
        skipped_message_keys_encrypted: state
            .skipped_message_keys
            .iter()
            .map(|(k, v)| (k.0, k.1, encrypt_secret(v)))
            .collect(),
        remote_identity_key: state.remote_identity_key,
        ratchet_step: state.ratchet_step,
        created_at: state.created_at,
        last_activity: state.last_activity,
        config: state.config.clone(),
    })
}

/// 从快照恢复
fn from_snapshot(
    snapshot: RatchetStateSnapshot,
    encryption_key: Option<&[u8]>,
) -> Result<DoubleRatchetState> {
    let mut state = DoubleRatchetState::new(snapshot.config.clone(), None)?;

    state.dh_public = snapshot.dh_public;
    state.dh_remote_public = snapshot.dh_remote_public;
    if let Some(root_key) = snapshot
        .encrypted_root_key
        .map(|k| decrypt_secret(&k, encryption_key))
        .transpose()?
    {
        state.set_root_key(root_key);
    }
    if let Some(send_chain_key) = snapshot
        .send_chain_key_encrypted
        .map(|k| decrypt_secret(&k, encryption_key))
        .transpose()?
    {
        state.set_send_chain_key(send_chain_key);
    }
    state.send_message_number = snapshot.send_message_number;
    if let Some(recv_chain_key) = snapshot
        .recv_chain_key_encrypted
        .map(|k| decrypt_secret(&k, encryption_key))
        .transpose()?
    {
        state.set_recv_chain_key(recv_chain_key);
    }
    state.recv_message_number = snapshot.recv_message_number;
    state.previous_chain_length = snapshot.previous_chain_length;
    state.remote_identity_key = snapshot.remote_identity_key;
    state.ratchet_step = snapshot.ratchet_step;

    // 恢复跳过消息密钥
    for (chain_len, msg_num, encrypted_key) in snapshot.skipped_message_keys_encrypted {
        if let Ok(key) = decrypt_secret(&encrypted_key, encryption_key) {
            state.skipped_message_keys.insert((chain_len, msg_num), key);
        }
    }

    Ok(state)
}

/// 加密敏感数据（简单异或加密，实际使用应使用更强的加密）
fn encrypt_secret(secret: &SecretBytes) -> Vec<u8> {
    let data = secret.as_bytes().to_vec();
    // 简单混淆，不提供实际加密
    data.into_iter().map(|b| b ^ 0xAA).collect()
}

/// 解密敏感数据
fn decrypt_secret(encrypted: &[u8], _encryption_key: Option<&[u8]>) -> Result<SecretBytes> {
    let data = encrypted.iter().map(|b| b ^ 0xAA).collect();
    SecretBytes::new(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_serialization() {
        let config = RatchetConfig::default();
        let state = DoubleRatchetState::new(config, None).unwrap();

        let json = serialize_json(&state).unwrap();
        let restored = deserialize_json(&json, None).unwrap();

        assert_eq!(state.ratchet_step, restored.ratchet_step);
    }

    #[test]
    fn test_binary_serialization() {
        let config = RatchetConfig::default();
        let state = DoubleRatchetState::new(config, None).unwrap();

        let binary = serialize_binary(&state).unwrap();
        let restored = deserialize_binary(&binary, None).unwrap();

        assert_eq!(state.ratchet_step, restored.ratchet_step);
    }

    #[test]
    fn test_encrypt_decrypt_secret() {
        let data = vec![1u8, 2, 3, 4, 5];
        let secret = SecretBytes::new(data.clone()).unwrap();

        let encrypted = encrypt_secret(&secret);
        let decrypted = decrypt_secret(&encrypted, None).unwrap();

        assert_eq!(data, decrypted.as_bytes());
    }
}
