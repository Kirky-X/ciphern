// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Double Ratchet 消息加密/解密
//!
//! 实现消息的加密和解密，包括跳过消息处理。

use aes_gcm::KeyInit;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::{CryptoError, Result};
use crate::memory::SecretBytes;

use super::state::{DoubleRatchetState, RatchetMessage, RatchetMessageHeader};

/// 加密消息
pub fn encrypt_message(state: &mut DoubleRatchetState, plaintext: &[u8]) -> Result<RatchetMessage> {
    // 检查消息大小限制
    if state.config.max_plaintext_size > 0 && plaintext.len() > state.config.max_plaintext_size {
        return Err(CryptoError::InvalidParameter(format!(
            "Plaintext size {} exceeds maximum allowed size {}",
            plaintext.len(),
            state.config.max_plaintext_size
        )));
    }

    // 执行对称密钥 Ratchet 获取消息密钥
    let message_key = super::dh_ratchet::symmetric_key_ratchet(state)?;

    // 生成随机数
    let mut nonce = [0u8; 12];
    state.rng.fill(&mut nonce)?;

    // 创建 ChaCha20-Poly1305 加密器
    let key_bytes: [u8; 32] = message_key
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed("Invalid key length".into()))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // 加密消息
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // 构建消息头
    let dh_public = state.dh_public.ok_or(CryptoError::InvalidState(
        "Local DH public key not set".into(),
    ))?;

    let header = RatchetMessageHeader {
        dh_public,
        message_number: state.send_message_number - 1,
        previous_chain_length: state.previous_chain_length,
    };

    // 可选：对密文进行签名
    let signature = state.sign_message(&ciphertext)?;

    Ok(RatchetMessage {
        version: 1,
        header,
        ciphertext,
        signature,
    })
}

/// 解密消息
pub fn decrypt_message(
    state: &mut DoubleRatchetState,
    message: &RatchetMessage,
) -> Result<Vec<u8>> {
    // 首先检查是否是跳过消息
    if let Some(message_key) = handle_skipped_messages(state, message)? {
        return Ok(message_key);
    }

    // 检查是否需要执行 DH Ratchet
    // 使用 dh_remote_public 而不是 dh_public 来判断是否需要 DH Ratchet
    // 这样可以避免对第一条消息重复执行 DH Ratchet
    if state.dh_remote_public != Some(message.header.dh_public) {
        // 保存旧接收链的消息密钥（如果有）
        if let Some(recv_chain) = state.recv_chain_key.take() {
            save_skipped_message_keys(
                state,
                &recv_chain,
                state.recv_message_number,
                state.previous_chain_length,
            )?;
        }

        // 执行 DH Ratchet
        super::dh_ratchet::dh_ratchet_step(state, &message.header.dh_public)?;

        // 注意：不覆盖 recv_chain_key！
        // recv_chain_key 已经在 initialize 中设置为 Alice 的原始链密钥
        // 保持不变以确保可以正确解密消息
        state.recv_message_number = 0;
        state.previous_chain_length = message.header.previous_chain_length;
    }

    // 尝试使用当前接收链解密
    let plaintext = try_recv_chain_decrypt(state, message)?;

    state.recv_message_number += 1;

    // 验证签名（如果消息包含签名）
    if let Some(ref sig) = message.signature {
        state.verify_signature(&message.ciphertext, sig)?;
    }

    Ok(plaintext)
}

/// 处理跳过消息
pub fn handle_skipped_messages(
    state: &mut DoubleRatchetState,
    message: &RatchetMessage,
) -> Result<Option<Vec<u8>>> {
    let key = (
        message.header.previous_chain_length,
        message.header.message_number,
    );

    if let Some(message_key) = state.skipped_message_keys.remove(&key) {
        let mut nonce = [0u8; 12];
        state.rng.fill(&mut nonce)?;

        let key_bytes: [u8; 32] = message_key
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed("Invalid key length".into()))?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let plaintext = cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &message.ciphertext,
                    aad: &[],
                },
            )
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        state.cleanup_old_skipped_keys()?;

        tracing::debug!("Decrypted skipped message: ({}, {})", key.0, key.1);

        return Ok(Some(plaintext));
    }

    Ok(None)
}

/// 保存跳过消息的密钥
pub fn save_skipped_message_keys(
    state: &mut DoubleRatchetState,
    chain_key: &SecretBytes,
    message_number: u64,
    chain_length: u64,
) -> Result<()> {
    use super::symmetric_ratchet::kdf_chain_internal;

    let max_skipped = state.config.max_skip_messages.min(100);
    let mut current_chain = chain_key.clone();

    for i in 0..max_skipped {
        let key = (chain_length, message_number + i as u64);

        let (new_chain, message_key) = kdf_chain_internal(
            &current_chain,
            &state.config.message_key_info,
            message_number + i as u64,
        )?;

        state.skipped_message_keys.insert(key, message_key);
        current_chain = new_chain;
    }

    Ok(())
}

/// 尝试使用接收链解密
fn try_recv_chain_decrypt(
    state: &mut DoubleRatchetState,
    message: &RatchetMessage,
) -> Result<Vec<u8>> {
    // 使用接收方对称密钥 Ratchet 推进接收链密钥并获取消息密钥
    let message_key = super::dh_ratchet::recv_symmetric_key_ratchet(state)?;

    // 生成 nonce
    let mut nonce = [0u8; 12];
    state.rng.fill(&mut nonce)?;

    // 解密
    let key_bytes: [u8; 32] = message_key
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("Invalid key length".into()))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &message.ciphertext,
                aad: &[],
            },
        )
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::RatchetConfig;

    #[test]
    fn test_message_encrypt_decrypt() {
        let config = RatchetConfig::default();
        let mut alice = DoubleRatchetState::new(config, None).unwrap();
        let mut bob = DoubleRatchetState::new(RatchetConfig::default(), None).unwrap();

        // 设置相同的初始根密钥
        let mut initial_root_key = vec![0x42u8; 32];
        alice.rng.fill(&mut initial_root_key).unwrap();
        let root_key = SecretBytes::new(initial_root_key).unwrap();
        alice.set_root_key(root_key.clone());
        bob.set_root_key(root_key);

        // 生成密钥对
        let alice_public = alice.generate_dh_keypair().unwrap();
        let bob_public = bob.generate_dh_keypair().unwrap();

        // 双方执行 DH Ratchet
        alice.initialize(&bob_public, None, false).unwrap();
        bob.initialize(&alice_public, None, true).unwrap();

        // 准备发送第一条消息
        alice.prepare_first_message().unwrap();

        // 加密消息
        let plaintext = b"Hello, Double Ratchet!";
        let message = alice.encrypt(plaintext).unwrap();

        // 解密消息
        let decrypted = bob.decrypt(&message).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_multiple_messages() {
        let config = RatchetConfig::default();
        let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
        let mut bob = DoubleRatchetState::new(config, None).unwrap();

        // 设置相同的初始根密钥
        let mut initial_root_key = vec![0x42u8; 32];
        alice.rng.fill(&mut initial_root_key).unwrap();
        let root_key = SecretBytes::new(initial_root_key).unwrap();
        alice.set_root_key(root_key.clone());
        bob.set_root_key(root_key);

        // 生成密钥对
        let alice_pub = alice.generate_dh_keypair().unwrap();
        let bob_pub = bob.generate_dh_keypair().unwrap();

        // 双方执行 DH Ratchet
        alice.initialize(&bob_pub, None, false).unwrap();
        bob.initialize(&alice_pub, None, true).unwrap();

        // 准备发送第一条消息
        alice.prepare_first_message().unwrap();

        for i in 1..=5 {
            let plaintext = format!("Message {}", i);
            let message = alice.encrypt(plaintext.as_bytes()).unwrap();
            let decrypted = bob.decrypt(&message).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }
}
