// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! DH Ratchet 实现
//!
//! 实现 Double Ratchet 协议中的 DH Ratchet 部分，负责密钥交换和链密钥派生。

use crate::error::{CryptoError, Result};
use crate::memory::SecretBytes;
use x25519_dalek::x25519;

use super::state::DoubleRatchetState;
use super::symmetric_ratchet::{kdf_chain_internal, kdf_rk};

/// 执行 DH Ratchet 步骤
///
/// 此函数在收到对端的新 DH 公钥时调用，更新根密钥和链密钥。
pub fn dh_ratchet_step(state: &mut DoubleRatchetState, remote_public: &[u8; 32]) -> Result<()> {
    let dh_private = state
        .take_dh_private()
        .ok_or(CryptoError::InvalidState("DH private key not set".into()))?;

    // 执行 X25519 密钥交换
    let dh_shared = x25519(
        dh_private
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidState("Invalid DH private key length".into()))?,
        *remote_public,
    );

    // 更新远程公钥
    state.dh_remote_public = Some(*remote_public);

    // 保存 DH 共享密钥（用于初始链密钥派生）
    state.set_dh_shared_secret(dh_shared);

    // 保存新的 DH 私钥
    state.set_dh_private(dh_private);

    // 获取保存的共享密钥
    let dh_shared = state
        .dh_shared_secret
        .ok_or(CryptoError::InvalidState("DH shared secret not set".into()))?;

    // 派生根密钥
    let root_key_info = &state.config.root_key_info;
    let root_key = kdf_rk(
        state
            .root_key()
            .unwrap_or(&SecretBytes::new(vec![0u8; 32])?),
        &dh_shared,
        root_key_info,
    )?;

    // 派生发送链密钥（使用 DH 共享密钥确保双方一致）
    // 注意：始终从 DH 共享密钥派生链密钥，使用零密钥作为输入确保双方初始链密钥一致
    let chain_key_info = &state.config.chain_key_info;
    let zero_key = SecretBytes::new(vec![0u8; 32])?;
    let chain_key = kdf_rk(&zero_key, &dh_shared, chain_key_info)?;

    // 更新根密钥和发送链密钥
    state.set_root_key(root_key);
    state.set_send_chain_key(chain_key);
    state.send_message_number = 0;
    state.previous_chain_length = state.recv_message_number;
    state.recv_message_number = 0;

    // 增加 ratchet 步数
    state.ratchet_step += 1;

    tracing::debug!("DH ratchet step completed, step: {}", state.ratchet_step);

    Ok(())
}

/// 执行对称密钥 Ratchet
///
/// 使用当前链密钥派生新的链密钥和消息密钥。
pub fn symmetric_key_ratchet(state: &mut DoubleRatchetState) -> Result<SecretBytes> {
    let chain_key = if let Some(key) = state.take_send_chain_key() {
        key
    } else if let Some(shared) = state.dh_shared_secret {
        // 初始化发送链（用于发起方的第一条消息）
        // 从 DH 共享密钥派生初始链密钥，使用零密钥作为输入确保与接收方一致
        let zero_key = SecretBytes::new(vec![0u8; 32])?;
        kdf_rk(&zero_key, &shared, &state.config.chain_key_info)?
    } else {
        return Err(CryptoError::InvalidState(
            "Send chain key not set and no DH shared secret available".into(),
        ));
    };

    // 派生新的链密钥和消息密钥
    let (new_chain_key, message_key) = kdf_chain_internal(
        &chain_key,
        &state.config.message_key_info,
        state.send_message_number,
    )?;

    state.set_send_chain_key(new_chain_key);
    state.send_message_number += 1;

    Ok(message_key)
}

/// 执行接收方对称密钥 Ratchet
///
/// 使用接收链密钥派生新的链密钥和消息密钥。
/// 用于接收方解密消息时推进接收链。
pub fn recv_symmetric_key_ratchet(state: &mut DoubleRatchetState) -> Result<SecretBytes> {
    let chain_key = state
        .recv_chain_key
        .as_ref()
        .ok_or(CryptoError::InvalidState(
            "Receive chain key not initialized".into(),
        ))?
        .clone();

    // 派生新的链密钥和消息密钥
    let (new_chain_key, message_key) = kdf_chain_internal(
        &chain_key,
        &state.config.message_key_info,
        state.recv_message_number,
    )?;

    state.set_recv_chain_key(new_chain_key);
    state.recv_message_number += 1;

    Ok(message_key)
}

/// 执行 KDF_Ratchet（密钥派生函数）
///
/// 根据 Signal Protocol 规范，使用 HMAC-SHA256 派生密钥。
pub fn kdf_ratchet(state: &mut DoubleRatchetState) -> Result<SecretBytes> {
    symmetric_key_ratchet(state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_dh_ratchet_step() {
        // This test would require a full session setup
        // For now, we just verify the module compiles
    }

    #[test]
    fn test_symmetric_key_ratchet() {
        // This test would require a full session setup
        // For now, we just verify the module compiles
    }
}
