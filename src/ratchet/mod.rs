// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Double Ratchet 协议模块
//!
//! 完整的 Double Ratchet 协议实现，提供前向安全的消息加密。
//!
//! # 特性
//!
//! - Double Ratchet 算法（结合 DH Ratchet 和对称密钥 Ratchet）
//! - 跳过消息处理（支持乱序消息）
//! - 弱密钥检测
//! - 状态序列化（JSON 和二进制格式）
//! - 可选的 Ed25519 签名验证
//!
//! # 使用示例
//!
//! ```rust
//! use ciphern::ratchet::{DoubleRatchetState, RatchetConfig};
//!
//! // 创建会话配置
//! let config = RatchetConfig::default();
//!
//! // 创建会话（Alice）
//! let mut alice = DoubleRatchetState::new(config.clone(), None).unwrap();
//! let alice_public = alice.generate_dh_keypair().unwrap();
//!
//! // 响应方创建会话（Bob）
//! let mut bob = DoubleRatchetState::new(config, None).unwrap();
//! // initialize 第三个参数 clear_send_chain: 响应方需要清空发送链，设为 true
//! bob.initialize(&alice_public, None, true).unwrap();
//! let bob_public = bob.generate_dh_keypair().unwrap();
//!
//! // Alice 初始化响应
//! // initialize 第三个参数 clear_send_chain: 发起方不需要清空发送链，设为 false
//! alice.initialize(&bob_public, None, false).unwrap();
//!
//! // 加密消息
//! let plaintext = b"Hello, secure world!";
//! let message = alice.encrypt(plaintext).unwrap();
//!
//! // 解密消息
//! let decrypted = bob.decrypt(&message).unwrap();
//! assert_eq!(&decrypted, plaintext);
//! ```

pub mod config;
mod dh_ratchet;
mod message;
mod serialization;
pub mod state;
mod symmetric_ratchet;
mod weak_key;

pub use config::RatchetConfig;
pub use dh_ratchet::{dh_ratchet_step, kdf_ratchet, symmetric_key_ratchet};
pub use message::{
    decrypt_message, encrypt_message, handle_skipped_messages, save_skipped_message_keys,
};
pub use state::{
    deserialize_binary, deserialize_json, serialize_binary, serialize_json, DoubleRatchetState,
    RatchetMessage, RatchetMessageHeader,
};
pub use symmetric_ratchet::{derive_message_key, kdf_chain_internal, kdf_ck_parallel};
pub use weak_key::{calculate_entropy, is_weak_key, validate_key_quality};
