// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Double Ratchet 协议状态管理
//!
//! 实现 Double Ratchet 会话的完整状态管理，包括 DH Ratchet、对称密钥 Ratchet、
//! 消息加密/解密、跳过消息处理等功能。

use super::symmetric_ratchet::kdf_rk;
use super::weak_key::{is_weak_key, validate_key_quality};
use crate::audit::AuditLogger;
use crate::error::{CryptoError, Result};
use crate::memory::SecretBytes;
use crate::random::SecureRandom;
use crate::types::Algorithm;
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use x25519_dalek::x25519;

pub use super::config::RatchetConfig;
pub use super::dh_ratchet::{
    dh_ratchet_step, kdf_ratchet, recv_symmetric_key_ratchet, symmetric_key_ratchet,
};
pub use super::message::{decrypt_message, encrypt_message, handle_skipped_messages};
pub use super::serialization::{
    deserialize_binary, deserialize_json, serialize_binary, serialize_json,
};
pub use super::symmetric_ratchet::{derive_message_key, kdf_chain_internal};

/// Double Ratchet 消息头
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RatchetMessageHeader {
    /// 发送者的 DH 公钥
    pub dh_public: [u8; 32],
    /// 消息编号
    pub message_number: u64,
    /// 上一条链的长度
    pub previous_chain_length: u64,
}

/// Double Ratchet 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// 协议版本
    pub version: u8,
    /// 消息头
    pub header: RatchetMessageHeader,
    /// 加密的密文
    pub ciphertext: Vec<u8>,
    /// 可选的 Ed25519 签名
    pub signature: Option<Vec<u8>>,
}

/// Double Ratchet 协议状态
///
/// 包含完整的 Double Ratchet 会话状态，包括：
/// - DH Ratchet 状态（公钥/私钥）
/// - 根密钥
/// - 发送/接收链密钥
/// - 消息编号
/// - 跳过消息密钥缓存
/// - 可选的 Ed25519 身份密钥
pub struct DoubleRatchetState {
    /// DH 密钥对（用于 DH Ratchet）
    dh_private: Option<SecretBytes>,
    pub(crate) dh_public: Option<[u8; 32]>,
    pub(crate) dh_remote_public: Option<[u8; 32]>,

    /// DH 共享密钥（用于初始链密钥派生）
    pub(crate) dh_shared_secret: Option<[u8; 32]>,

    /// 根密钥
    root_key: Option<SecretBytes>,

    /// 发送链密钥
    pub(crate) send_chain_key: Option<SecretBytes>,
    pub(crate) send_message_number: u64,

    /// 接收链密钥
    pub(crate) recv_chain_key: Option<SecretBytes>,
    pub(crate) recv_message_number: u64,
    pub(crate) previous_chain_length: u64,

    /// 跳过消息密钥缓存
    pub(crate) skipped_message_keys: BTreeMap<(u64, u64), SecretBytes>,

    /// 可选的 Ed25519 身份密钥（用于签名验证）
    identity_key: Option<SecretBytes>,
    pub(crate) remote_identity_key: Option<[u8; 32]>,

    /// 配置
    pub(crate) config: RatchetConfig,

    /// 状态元数据
    pub(crate) ratchet_step: u64,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) last_activity: DateTime<Utc>,

    /// 随机数生成器
    pub(crate) rng: SecureRandom,
}

impl std::fmt::Debug for DoubleRatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoubleRatchetState")
            .field(
                "dh_public",
                &self.dh_public.map(|k| format!("{:?}", &k[..8])),
            )
            .field("send_message_number", &self.send_message_number)
            .field("recv_message_number", &self.recv_message_number)
            .field("ratchet_step", &self.ratchet_step)
            .field("skipped_keys_count", &self.skipped_message_keys.len())
            .finish()
    }
}

impl Clone for DoubleRatchetState {
    fn clone(&self) -> Self {
        Self {
            dh_private: None, // Cannot clone SecretBytes
            dh_public: self.dh_public,
            dh_remote_public: self.dh_remote_public,
            dh_shared_secret: self.dh_shared_secret,
            root_key: None,       // Cannot clone SecretBytes
            send_chain_key: None, // Cannot clone SecretBytes
            send_message_number: self.send_message_number,
            recv_chain_key: None, // Cannot clone SecretBytes
            recv_message_number: self.recv_message_number,
            previous_chain_length: self.previous_chain_length,
            skipped_message_keys: BTreeMap::new(), // Cannot clone SecretBytes
            identity_key: None,                    // Cannot clone SecretBytes
            remote_identity_key: self.remote_identity_key,
            config: self.config.clone(),
            ratchet_step: self.ratchet_step,
            created_at: self.created_at,
            last_activity: self.last_activity,
            rng: SecureRandom::new().expect("Failed to create SecureRandom for clone"),
        }
    }
}

impl DoubleRatchetState {
    /// 创建新的 Double Ratchet 会话
    pub fn new(config: RatchetConfig, identity_key: Option<[u8; 32]>) -> Result<Self> {
        let now = Utc::now();

        // 验证配置
        if config.enable_weak_key_detection {
            if let Err(e) =
                validate_key_quality(&config.chain_key_info, config.min_entropy_threshold)
            {
                return Err(CryptoError::InvalidParameter(format!(
                    "Config validation failed: {}",
                    e
                )));
            }
        }

        Ok(Self {
            dh_private: None,
            dh_public: None,
            dh_remote_public: None,
            dh_shared_secret: None,
            root_key: None,
            send_chain_key: None,
            send_message_number: 0,
            recv_chain_key: None,
            recv_message_number: 0,
            previous_chain_length: 0,
            skipped_message_keys: BTreeMap::new(),
            identity_key: identity_key
                .map(|k| SecretBytes::new(k.to_vec()))
                .transpose()?,
            remote_identity_key: None,
            config,
            ratchet_step: 0,
            created_at: now,
            last_activity: now,
            rng: SecureRandom::new()?,
        })
    }

    /// 获取并移除 DH 私钥（用于 DH Ratchet）
    pub fn take_dh_private(&mut self) -> Option<SecretBytes> {
        self.dh_private.take()
    }

    /// 设置 DH 私钥
    pub fn set_dh_private(&mut self, key: SecretBytes) {
        self.dh_private = Some(key);
    }

    /// 获取根密钥引用
    pub fn root_key(&self) -> Option<&SecretBytes> {
        self.root_key.as_ref()
    }

    /// 获取并移除根密钥
    pub fn take_root_key(&mut self) -> Option<SecretBytes> {
        self.root_key.take()
    }

    /// 设置根密钥
    pub fn set_root_key(&mut self, key: SecretBytes) {
        self.root_key = Some(key);
    }

    /// 获取发送链密钥引用
    pub fn send_chain_key(&self) -> Option<&SecretBytes> {
        self.send_chain_key.as_ref()
    }

    /// 获取并移除发送链密钥
    pub fn take_send_chain_key(&mut self) -> Option<SecretBytes> {
        self.send_chain_key.take()
    }

    /// 设置发送链密钥
    pub fn set_send_chain_key(&mut self, key: SecretBytes) {
        self.send_chain_key = Some(key);
    }

    /// 获取接收链密钥引用
    pub fn recv_chain_key(&self) -> Option<&SecretBytes> {
        self.recv_chain_key.as_ref()
    }

    /// 获取并移除接收链密钥
    pub fn take_recv_chain_key(&mut self) -> Option<SecretBytes> {
        self.recv_chain_key.take()
    }

    /// 设置接收链密钥
    pub fn set_recv_chain_key(&mut self, key: SecretBytes) {
        self.recv_chain_key = Some(key);
    }

    /// 设置 DH 共享密钥
    pub(crate) fn set_dh_shared_secret(&mut self, shared: [u8; 32]) {
        self.dh_shared_secret = Some(shared);
    }

    /// 初始化会话（响应方）
    ///
    /// 此函数用于响应方（Bob）初始化会话。发起方（Alice）应在发送第一条消息前调用 `prepare_first_message()`。
    /// `clear_send_chain` 参数控制是否清空发送链（响应方需要清空，发起方不需要）。
    pub fn initialize(
        &mut self,
        remote_dh_public: &[u8; 32],
        remote_identity: Option<&[u8; 32]>,
        clear_send_chain: bool,
    ) -> Result<()> {
        self.update_activity();

        // 保存远程身份密钥
        if let (Some(remote_id), true) =
            (remote_identity, self.config.enable_signature_verification)
        {
            self.remote_identity_key = Some(*remote_id);
        }

        // 验证弱密钥
        if self.config.enable_weak_key_detection && is_weak_key(remote_dh_public) {
            return Err(CryptoError::InvalidState(
                "Weak DH public key detected".into(),
            ));
        }

        // 生成新的 DH 密钥对（如果尚未生成）
        self.generate_dh_keypair()?;

        // 执行 DH Ratchet
        dh_ratchet_step(self, remote_dh_public)?;

        // 从 DH 共享密钥派生新的根密钥和链密钥
        let dh_shared = *self
            .dh_shared_secret
            .as_ref()
            .ok_or(CryptoError::InvalidState("DH shared secret not set".into()))?;

        // 使用 DH 共享密钥派生根密钥（与发送方一致）
        let new_root_key = kdf_rk(
            &SecretBytes::new(vec![0u8; 32])?, // 使用零密钥确保双方一致
            &dh_shared,
            &self.config.root_key_info,
        )?;
        self.set_root_key(new_root_key);

        // 获取发送方（Alice）的原始链密钥，用于设置接收链
        // 直接从 DH 共享密钥派生，确保与发送方一致
        let alice_chain_key = kdf_rk(
            &SecretBytes::new(vec![0u8; 32])?,
            &dh_shared,
            &self.config.chain_key_info,
        )?;

        // 设置接收链为发送方（Alice）的原始链密钥
        // 这样当 Alice 执行对称 Ratchet 后，Bob 可以使用相同的链密钥派生消息密钥
        self.recv_chain_key = Some(alice_chain_key);
        self.recv_message_number = 0;
        self.previous_chain_length = 0;

        // 根据角色决定是否清空发送链
        if clear_send_chain {
            self.send_chain_key = None;
        }

        Ok(())
    }

    /// 准备发送第一条消息（发起方使用）
    ///
    /// 在调用 `initialize()` 后，发起方应调用此函数准备发送第一条消息。
    /// 此函数确保发送链已正确设置。
    pub fn prepare_first_message(&mut self) -> Result<()> {
        // 如果发送链不存在，从 DH 共享密钥派生
        if self.send_chain_key.is_none() {
            if let (Some(_), Some(shared)) = (self.root_key(), self.dh_shared_secret) {
                let zero_key = SecretBytes::new(vec![0u8; 32])?;
                let chain_key = kdf_rk(&zero_key, &shared, &self.config.chain_key_info)?;
                self.send_chain_key = Some(chain_key);
            }
        }
        Ok(())
    }

    /// 生成新的 DH 密钥对
    pub fn generate_dh_keypair(&mut self) -> Result<[u8; 32]> {
        self.update_activity();

        // 如果已有密钥对，直接返回公钥
        if let Some(public_key) = self.dh_public {
            return Ok(public_key);
        }

        let mut private_key = [0u8; 32];
        self.rng.fill(&mut private_key)?;

        // 验证弱密钥
        if self.config.enable_weak_key_detection && is_weak_key(&private_key) {
            return Err(CryptoError::InvalidState(
                "Weak DH private key detected".into(),
            ));
        }

        let public_key = x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);

        self.dh_private = Some(SecretBytes::new(private_key.to_vec())?);
        self.dh_public = Some(public_key);

        // 注意：根密钥不在这里生成，而是由 dh_ratchet_step 从 DH 共享密钥派生
        // 这样可以确保双方使用相同的方式派生根密钥，保持一致性

        // 审计日志
        AuditLogger::log(
            "RATCHET_DH_KEYPAIR_GENERATED",
            Some(Algorithm::X25519),
            None,
            Ok(()),
        );

        Ok(public_key)
    }

    /// 获取本地公钥
    pub fn local_public(&self) -> Option<&[u8; 32]> {
        self.dh_public.as_ref()
    }

    /// 加密消息
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        self.update_activity();

        // 验证状态
        if self.root_key.is_none() {
            return Err(CryptoError::InvalidState("Root key not initialized".into()));
        }

        // 验证弱密钥
        if self.config.enable_weak_key_detection {
            if let Some(ref root_key) = self.root_key {
                if is_weak_key(root_key.as_bytes()) {
                    return Err(CryptoError::InvalidState("Weak root key detected".into()));
                }
            }
        }

        // 执行对称密钥 Ratchet 获取消息密钥
        let message_key = symmetric_key_ratchet(self)?;

        // 生成 nonce（使用消息编号确保双方一致）
        // 使用 12 字节的 nonce，其中前 8 字节是消息编号
        let nonce = {
            let mut n = [0u8; 12];
            let msg_num = self.send_message_number.to_le_bytes();
            n[..8].copy_from_slice(&msg_num);
            n
        };

        // 创建 ChaCha20-Poly1305 加密器
        let key_bytes: [u8; 32] = message_key
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::EncryptionFailed("Invalid message key length".into()))?;
        let cipher =
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|_| {
                CryptoError::EncryptionFailed("Invalid key for ChaCha20-Poly1305".into())
            })?;

        // 加密消息
        let ciphertext = cipher
            .encrypt(
                &nonce.into(),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))?;

        // 构建消息头
        let dh_public = self.dh_public.ok_or(CryptoError::InvalidState(
            "Local DH public key not set".into(),
        ))?;

        let header = RatchetMessageHeader {
            dh_public,
            message_number: self.send_message_number - 1,
            previous_chain_length: self.previous_chain_length,
        };

        // 可选签名
        let signature = self.sign_message(&ciphertext)?;

        // 审计日志
        AuditLogger::log(
            "RATCHET_MESSAGE_ENCRYPTED",
            Some(Algorithm::ChaCha20Poly1305),
            None,
            Ok(()),
        );

        Ok(RatchetMessage {
            version: 1,
            header,
            ciphertext,
            signature,
        })
    }

    /// 解密消息
    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>> {
        self.update_activity();

        // 首先检查是否是跳过消息
        if let Some(message_key) = handle_skipped_messages(self, message)? {
            AuditLogger::log(
                "RATCHET_SKIPPED_MESSAGE_DECRYPTED",
                Some(Algorithm::ChaCha20Poly1305),
                None,
                Ok(()),
            );
            return Ok(message_key);
        }

        // 检查是否需要执行 DH Ratchet
        // 使用 dh_remote_public 而不是 dh_public 来判断是否需要 DH Ratchet
        if self.dh_remote_public != Some(message.header.dh_public) {
            // 保存旧接收链的消息密钥
            if let Some(recv_chain) = self.recv_chain_key.take() {
                save_skipped_message_keys(
                    self,
                    &recv_chain,
                    self.recv_message_number,
                    self.previous_chain_length,
                )?;
            }

            // 生成新的 DH 密钥对
            let mut private_key = [0u8; 32];
            self.rng.fill(&mut private_key)?;
            let public_key = x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);

            self.dh_private = Some(SecretBytes::new(private_key.to_vec())?);
            self.dh_public = Some(public_key);

            // 执行 DH Ratchet
            dh_ratchet_step(self, &message.header.dh_public)?;

            // 设置接收链
            self.recv_chain_key = self.send_chain_key.clone();
            self.recv_message_number = 0;
            self.previous_chain_length = message.header.previous_chain_length;
            self.send_chain_key = None;
        }

        // 验证签名
        if let Some(ref sig) = message.signature {
            self.verify_signature(&message.ciphertext, sig)?;
        }

        // 尝试使用当前接收链解密
        let plaintext = try_recv_chain_decrypt(self, message)?;

        self.recv_message_number += 1;

        // 审计日志
        AuditLogger::log(
            "RATCHET_MESSAGE_DECRYPTED",
            Some(Algorithm::ChaCha20Poly1305),
            None,
            Ok(()),
        );

        Ok(plaintext)
    }

    /// 设置本地 Ed25519 身份密钥
    pub fn set_identity_key(&mut self, key: SecretBytes) {
        self.identity_key = Some(key);
    }

    /// 设置远程 Ed25519 身份密钥
    pub fn set_remote_identity_key(&mut self, key: &[u8; 32]) {
        self.remote_identity_key = Some(*key);
    }

    /// 可选签名消息
    pub(crate) fn sign_message(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if !self.config.enable_signature_verification {
            return Ok(None);
        }

        let private_key = match &self.identity_key {
            Some(key) => key,
            None => return Ok(None),
        };

        // 从私钥派生公钥并创建 Ed25519KeyPair
        let key_pair = Ed25519KeyPair::from_pkcs8(private_key.as_bytes())
            .map_err(|e| CryptoError::KeyError(format!("Invalid Ed25519 private key: {}", e)))?;

        // 对数据进行签名
        let signature = key_pair.sign(data);

        AuditLogger::log(
            "RATCHET_MESSAGE_SIGNED",
            Some(Algorithm::Ed25519),
            None,
            Ok(()),
        );

        Ok(Some(signature.as_ref().to_vec()))
    }

    /// 验证签名
    pub(crate) fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        if !self.config.enable_signature_verification {
            return Ok(());
        }

        let remote_public_key = match &self.remote_identity_key {
            Some(key) => key.as_slice(),
            None => {
                // 没有远程身份密钥，无法验证签名
                return Ok(());
            }
        };

        // 创建未解析的公钥验证器
        let unparsed_key = UnparsedPublicKey::new(&ED25519, remote_public_key);

        unparsed_key.verify(data, signature).map_err(|e| {
            let err_msg = format!("Signature verification failed: {}", e);
            AuditLogger::log(
                "RATCHET_SIGNATURE_VERIFY_FAILED",
                Some(Algorithm::Ed25519),
                None,
                Err(CryptoError::InvalidState(err_msg.clone())),
            );
            CryptoError::InvalidState(err_msg)
        })?;

        AuditLogger::log(
            "RATCHET_SIGNATURE_VERIFIED",
            Some(Algorithm::Ed25519),
            None,
            Ok(()),
        );

        Ok(())
    }

    /// 清理旧的跳过消息密钥
    pub(crate) fn cleanup_old_skipped_keys(&mut self) -> Result<()> {
        let max_keys = self.config.max_skipped_keys_memory;

        while self.skipped_message_keys.len() > max_keys {
            if let Some(key) = self.skipped_message_keys.keys().next().cloned() {
                self.skipped_message_keys.remove(&key);
            }
        }

        Ok(())
    }

    /// 获取状态信息
    pub fn state_info(&self) -> RatchetStateInfo {
        RatchetStateInfo {
            send_message_number: self.send_message_number,
            recv_message_number: self.recv_message_number,
            ratchet_step: self.ratchet_step,
            skipped_keys_count: self.skipped_message_keys.len(),
            is_initialized: self.root_key.is_some(),
            created_at: self.created_at,
            last_activity: self.last_activity,
        }
    }

    /// 更新最后活动时间
    fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    /// 保存状态为 JSON 字符串
    ///
    /// 便捷方法，将状态序列化为加密的 JSON 格式。
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - 可选的加密密钥（32字节），用于加密敏感数据
    ///
    /// # Returns
    ///
    /// 加密后的 JSON 字符串
    pub fn save_state(&self) -> Result<String> {
        serialize_json(self)
    }

    /// 从 JSON 字符串加载状态
    ///
    /// 便捷方法，从 JSON 字符串恢复状态。
    ///
    /// # Arguments
    ///
    /// * `data` - JSON 字符串
    /// * `encryption_key` - 可选的加密密钥（32字节），用于解密敏感数据
    ///
    /// # Returns
    ///
    /// 恢复的 DoubleRatchetState
    pub fn load_state(data: &str, encryption_key: Option<&[u8]>) -> Result<Self> {
        deserialize_json(data, encryption_key)
    }

    /// 保存状态为二进制格式
    ///
    /// 便捷方法，将状态序列化为二进制格式。
    ///
    /// # Returns
    ///
    /// 二进制数据
    pub fn save_state_binary(&self) -> Result<Vec<u8>> {
        serialize_binary(self)
    }

    /// 从二进制数据加载状态
    ///
    /// 便捷方法，从二进制数据恢复状态。
    ///
    /// # Arguments
    ///
    /// * `data` - 二进制数据
    /// * `encryption_key` - 可选的加密密钥（32字节），用于解密敏感数据
    ///
    /// # Returns
    ///
    /// 恢复的 DoubleRatchetState
    pub fn load_state_binary(data: &[u8], encryption_key: Option<&[u8]>) -> Result<Self> {
        deserialize_binary(data, encryption_key)
    }
}

/// 保存跳过消息的密钥
fn save_skipped_message_keys(
    state: &mut DoubleRatchetState,
    chain_key: &SecretBytes,
    message_number: u64,
    chain_length: u64,
) -> Result<()> {
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
    let message_key = recv_symmetric_key_ratchet(state)?;

    // 生成 nonce（使用消息头中的消息编号+1确保双方一致）
    // 这是关键：发送方使用 send_message_number（递增后的值）
    // 消息头中的 message_number 是该链上之前的消息数量，所以需要 +1
    let nonce = {
        let mut n = [0u8; 12];
        let msg_num = (message.header.message_number + 1).to_le_bytes();
        n[..8].copy_from_slice(&msg_num);
        n
    };

    // 解密
    let key_bytes: [u8; 32] = message_key
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("Invalid message key length".into()))?;

    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|_| CryptoError::DecryptionFailed("Invalid key for ChaCha20-Poly1305".into()))?;

    let plaintext = cipher
        .decrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: &message.ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed("Decryption failed".into()))?;

    Ok(plaintext)
}

/// Double Ratchet 状态信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetStateInfo {
    pub send_message_number: u64,
    pub recv_message_number: u64,
    pub ratchet_step: u64,
    pub skipped_keys_count: usize,
    pub is_initialized: bool,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::RatchetConfig;

    #[test]
    fn test_new_session() {
        let config = RatchetConfig::default();
        let state = DoubleRatchetState::new(config, None);

        assert!(state.is_ok());
        let state = state.unwrap();

        assert!(state.root_key.is_none());
        assert_eq!(state.send_message_number, 0);
        assert_eq!(state.recv_message_number, 0);
    }

    #[test]
    fn test_keypair_generation() {
        let config = RatchetConfig::default();
        let mut state = DoubleRatchetState::new(config, None).unwrap();

        let public = state.generate_dh_keypair().unwrap();

        assert_eq!(public.len(), 32);
        assert!(state.dh_private.is_some());
        assert!(state.dh_public.is_some());
        // root_key is set during initialize(), not generate_dh_keypair()
        // assert!(state.root_key.is_some());
    }

    #[test]

    fn test_encrypt_decrypt() {
        let config = RatchetConfig::default();

        let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();

        let mut bob = DoubleRatchetState::new(config, None).unwrap();

        // Alice 生成密钥对

        let alice_public = alice.generate_dh_keypair().unwrap();

        // Bob 初始化会话（使用 Alice 的公钥）

        bob.initialize(&alice_public, None, true).unwrap();

        // Bob 生成自己的密钥对

        let bob_public = bob.generate_dh_keypair().unwrap();

        // Alice 初始化响应（使用 Bob 的公钥）

        alice.initialize(&bob_public, None, false).unwrap();

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

        // 设置相同的初始根密钥（模拟共享的主密钥）
        let mut initial_root_key = vec![0x42u8; 32];
        alice.rng.fill(&mut initial_root_key).unwrap();
        let root_key = SecretBytes::new(initial_root_key).unwrap();
        alice.set_root_key(root_key.clone());
        bob.set_root_key(root_key.clone());

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

    #[test]
    fn test_signature_verification() {
        // 创建状态（启用签名验证）
        let config = RatchetConfig::new().with_signature_verification(true);
        let state = DoubleRatchetState::new(config, None).unwrap();

        // 测试数据
        let test_data = b"Test message for signature";

        // 没有设置身份密钥时，签名应返回 None
        let signature = state.sign_message(test_data).unwrap();
        assert!(signature.is_none());

        // 没有启用签名验证时，签名应返回 None
        let config_disabled = RatchetConfig::new().with_signature_verification(false);
        let state_disabled = DoubleRatchetState::new(config_disabled, None).unwrap();
        let signature = state_disabled.sign_message(test_data).unwrap();
        assert!(signature.is_none());

        // 验证签名 API - 没有远程公钥时验证应静默通过
        let result = state.verify_signature(test_data, &[]);
        assert!(result.is_ok());

        // 验证配置选项
        let config_enabled = RatchetConfig::new().with_signature_verification(true);
        let state_enabled = DoubleRatchetState::new(config_enabled, None).unwrap();
        assert!(state_enabled.config.enable_signature_verification);

        let config_disabled_check = RatchetConfig::new().with_signature_verification(false);
        let state_disabled_check = DoubleRatchetState::new(config_disabled_check, None).unwrap();
        assert!(!state_disabled_check.config.enable_signature_verification);
    }
}
