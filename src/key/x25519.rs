// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! X25519 密钥交换实现
//!
//! 此模块提供 X25519 椭圆曲线密钥交换（ECDH）的完整实现，
//! 用于安全地建立共享密钥。

use crate::audit::AuditLogger;
use crate::error::{CryptoError, Result};
use crate::key::derivation::Hkdf;
use crate::key::Key;
use crate::random::SecureRandom;
use crate::types::Algorithm;
use x25519_dalek::x25519;

/// X25519 密钥对管理器
pub struct X25519KeyManager {
    rng: SecureRandom,
}

impl X25519KeyManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            rng: SecureRandom::new()?,
        })
    }

    pub fn generate_keypair(&self) -> Result<(Key, [u8; 32])> {
        let mut private_key = [0u8; 32];
        self.rng.fill(&mut private_key)?;
        let public_key = x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);

        let key = Key::new_active(Algorithm::X25519, private_key.to_vec())?;

        AuditLogger::log(
            "X25519_KEY_GENERATE",
            Some(Algorithm::X25519),
            Some(key.id()),
            Ok(()),
        );

        Ok((key, public_key))
    }

    pub fn generate_ephemeral_keypair(&self) -> Result<(Vec<u8>, [u8; 32])> {
        let mut private_key = [0u8; 32];
        self.rng.fill(&mut private_key)?;
        let public = x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);

        Ok((private_key.to_vec(), public))
    }

    pub fn key_agreement(&self, private_key: &Key, peer_public_key: &[u8]) -> Result<[u8; 32]> {
        if private_key.algorithm() != Algorithm::X25519 {
            return Err(CryptoError::UnsupportedAlgorithm(
                "Key algorithm mismatch for X25519 key agreement".into(),
            ));
        }

        if peer_public_key.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "Invalid X25519 public key length, must be 32 bytes".into(),
            ));
        }

        let private_bytes = private_key.secret_bytes()?;
        let private_array: [u8; 32] = private_bytes
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::KeyError("Invalid X25519 private key length".into()))?;

        let shared_secret = x25519(private_array, *array_ref!(peer_public_key, 0, 32));

        AuditLogger::log(
            "X25519_KEY_AGREEMENT",
            Some(Algorithm::X25519),
            Some(private_key.id()),
            Ok(()),
        );

        Ok(shared_secret)
    }

    pub fn ephemeral_key_agreement(
        &self,
        ephemeral_private: &[u8],
        peer_public_key: &[u8],
    ) -> Result<[u8; 32]> {
        if peer_public_key.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "Invalid X25519 public key length, must be 32 bytes".into(),
            ));
        }

        let private_array: [u8; 32] = ephemeral_private
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("Invalid private key length".into()))?;

        Ok(x25519(private_array, *array_ref!(peer_public_key, 0, 32)))
    }

    pub fn derive_session_key(
        &self,
        shared_secret: &[u8; 32],
        info: Option<&[u8]>,
        output_algorithm: Algorithm,
    ) -> Result<Key> {
        let master_key = Key::new_active(Algorithm::X25519, shared_secret.to_vec())?;
        let derived_key = Hkdf::derive(
            &master_key,
            b"ciphern-x25519-session-key",
            info.unwrap_or(b"session-key"),
            output_algorithm,
        )?;

        AuditLogger::log(
            "X25519_SESSION_KEY_DERIVE",
            Some(output_algorithm),
            Some(derived_key.id()),
            Ok(()),
        );

        Ok(derived_key)
    }

    pub fn derive_key_pair(&self, shared_secret: &[u8; 32], context: &[u8]) -> Result<(Key, Key)> {
        let enc_key = self.derive_session_key(
            shared_secret,
            Some(&[context, b"-encryption"].concat()),
            Algorithm::ChaCha20Poly1305,
        )?;

        let mac_key = self.derive_session_key(
            shared_secret,
            Some(&[context, b"-authentication"].concat()),
            Algorithm::ChaCha20Poly1305,
        )?;

        Ok((enc_key, mac_key))
    }

    pub fn validate_public_key(public_key: &[u8]) -> Result<bool> {
        if public_key.len() != 32 {
            return Ok(false);
        }
        let valid = public_key[31] & 0xF8 == 0x78;
        Ok(valid)
    }

    pub fn encode_public_key_hex(public_key: &[u8; 32]) -> String {
        hex::encode(public_key.as_ref())
    }

    pub fn decode_public_key_hex(hex_str: &str) -> Result<[u8; 32]> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidInput("Invalid hex string".into()))?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "Invalid public key length from hex".into(),
            ));
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    }
}

impl Default for X25519KeyManager {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

pub struct X25519Session {
    local_private: Vec<u8>,
    local_public: [u8; 32],
    peer_public: Option<[u8; 32]>,
    shared_secret: Option<[u8; 32]>,
}

impl X25519Session {
    pub fn new(key_manager: &X25519KeyManager) -> Result<Self> {
        let (private, public) = key_manager.generate_ephemeral_keypair()?;

        Ok(Self {
            local_private: private,
            local_public: public,
            peer_public: None,
            shared_secret: None,
        })
    }

    pub fn local_public(&self) -> &[u8; 32] {
        &self.local_public
    }

    pub fn set_peer_public(
        &mut self,
        peer_public: &[u8],
        key_manager: &X25519KeyManager,
    ) -> Result<()> {
        let peer_array: [u8; 32] = peer_public
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("Invalid peer public key length".into()))?;

        self.peer_public = Some(peer_array);
        self.shared_secret =
            Some(key_manager.ephemeral_key_agreement(&self.local_private, peer_public)?);

        Ok(())
    }

    pub fn is_established(&self) -> bool {
        self.shared_secret.is_some()
    }

    pub fn shared_secret(&self) -> Option<&[u8; 32]> {
        self.shared_secret.as_ref()
    }

    pub fn derive_session_key(
        &self,
        key_manager: &X25519KeyManager,
        info: Option<&[u8]>,
        algorithm: Algorithm,
    ) -> Result<Key> {
        let shared = self
            .shared_secret
            .as_ref()
            .ok_or(CryptoError::NotInitialized)?;

        key_manager.derive_session_key(shared, info, algorithm)
    }

    pub fn clear(&mut self) {
        self.peer_public = None;
        self.shared_secret = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_generation() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (private_key, public_key) = key_manager.generate_keypair().unwrap();
        assert_eq!(private_key.algorithm(), Algorithm::X25519);
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn test_x25519_key_agreement() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (alice_private, alice_public) = key_manager.generate_keypair().unwrap();
        let (bob_private, bob_public) = key_manager.generate_keypair().unwrap();

        let alice_shared = key_manager
            .key_agreement(&alice_private, &bob_public)
            .unwrap();
        let bob_shared = key_manager
            .key_agreement(&bob_private, &alice_public)
            .unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_x25519_session() {
        let key_manager = X25519KeyManager::new().unwrap();
        let mut alice_session = X25519Session::new(&key_manager).unwrap();
        let alice_public = *alice_session.local_public();

        let mut bob_session = X25519Session::new(&key_manager).unwrap();
        let bob_public = *bob_session.local_public();

        alice_session
            .set_peer_public(&bob_public, &key_manager)
            .unwrap();
        bob_session
            .set_peer_public(&alice_public, &key_manager)
            .unwrap();

        assert!(alice_session.is_established());
        assert_eq!(
            alice_session.shared_secret().unwrap(),
            bob_session.shared_secret().unwrap()
        );
    }

    #[test]
    fn test_x25519_ephemeral_keypair() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (private, public) = key_manager.generate_ephemeral_keypair().unwrap();

        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
    }

    #[test]
    fn test_x25519_ephemeral_key_agreement() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (alice_private, alice_public) = key_manager.generate_ephemeral_keypair().unwrap();
        let (bob_private, bob_public) = key_manager.generate_ephemeral_keypair().unwrap();

        let alice_shared = key_manager
            .ephemeral_key_agreement(&alice_private, &bob_public)
            .unwrap();
        let bob_shared = key_manager
            .ephemeral_key_agreement(&bob_private, &alice_public)
            .unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_x25519_validate_public_key() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (_, mut public_key) = key_manager.generate_keypair().unwrap();

        // 手动设置有效的 Clamp 值 (低3位为 0x78)
        public_key[31] = (public_key[31] & 0xF8) | 0x78;

        // 有效的公钥应该通过验证
        let is_valid = X25519KeyManager::validate_public_key(&public_key).unwrap();
        assert!(is_valid);

        // 无效长度的公钥应该返回 false
        let is_valid_short = X25519KeyManager::validate_public_key(&[0u8; 16]).unwrap();
        assert!(!is_valid_short);

        let is_valid_long = X25519KeyManager::validate_public_key(&[0u8; 64]).unwrap();
        assert!(!is_valid_long);

        // 测试不同的 Clamp 值
        let mut invalid_key = [0u8; 32];
        invalid_key[31] = 0x00; // 低3位不是 0x78
        let is_valid_clamp = X25519KeyManager::validate_public_key(&invalid_key).unwrap();
        assert!(!is_valid_clamp);
    }

    #[test]
    fn test_x25519_encode_decode_hex() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (_, public_key) = key_manager.generate_keypair().unwrap();

        // 编码为十六进制
        let hex_str = X25519KeyManager::encode_public_key_hex(&public_key);
        assert_eq!(hex_str.len(), 64); // 32 字节 = 64 十六进制字符

        // 从十六进制解码
        let decoded = X25519KeyManager::decode_public_key_hex(&hex_str).unwrap();
        assert_eq!(decoded, public_key);
    }

    #[test]
    fn test_x25519_decode_hex_invalid() {
        // 无效的十六进制字符串
        let result = X25519KeyManager::decode_public_key_hex("invalid_hex");
        assert!(result.is_err());

        // 长度不对的十六进制字符串
        let result = X25519KeyManager::decode_public_key_hex("1234");
        assert!(result.is_err());

        // 非十六进制字符
        let result = X25519KeyManager::decode_public_key_hex(
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_x25519_derive_session_key() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (alice_private, _alice_public) = key_manager.generate_keypair().unwrap();
        let (_bob_private, bob_public) = key_manager.generate_keypair().unwrap();

        let shared_secret = key_manager
            .key_agreement(&alice_private, &bob_public)
            .unwrap();

        // 派生 ChaCha20 会话密钥
        let session_key = key_manager
            .derive_session_key(&shared_secret, None, Algorithm::ChaCha20Poly1305)
            .unwrap();

        assert_eq!(session_key.algorithm(), Algorithm::ChaCha20Poly1305);
    }

    #[test]
    fn test_x25519_derive_session_key_with_info() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (alice_private, _alice_public) = key_manager.generate_keypair().unwrap();
        let (_bob_private, bob_public) = key_manager.generate_keypair().unwrap();

        let shared_secret = key_manager
            .key_agreement(&alice_private, &bob_public)
            .unwrap();

        let info = b"custom-info";
        let session_key = key_manager
            .derive_session_key(&shared_secret, Some(info), Algorithm::ChaCha20Poly1305)
            .unwrap();

        assert_eq!(session_key.algorithm(), Algorithm::ChaCha20Poly1305);
    }

    #[test]
    fn test_x25519_derive_key_pair() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (alice_private, _alice_public) = key_manager.generate_keypair().unwrap();
        let (_bob_private, bob_public) = key_manager.generate_keypair().unwrap();

        let shared_secret = key_manager
            .key_agreement(&alice_private, &bob_public)
            .unwrap();

        let context = b"test-session";
        let (enc_key, mac_key) = key_manager
            .derive_key_pair(&shared_secret, context)
            .unwrap();

        assert_eq!(enc_key.algorithm(), Algorithm::ChaCha20Poly1305);
        assert_eq!(mac_key.algorithm(), Algorithm::ChaCha20Poly1305);
    }

    #[test]
    fn test_x25519_session_clear() {
        let key_manager = X25519KeyManager::new().unwrap();
        let mut session = X25519Session::new(&key_manager).unwrap();
        let peer_public = [0x12u8; 32];

        session.set_peer_public(&peer_public, &key_manager).unwrap();
        assert!(session.is_established());
        assert!(session.shared_secret().is_some());

        session.clear();

        assert!(!session.is_established());
        assert!(session.shared_secret().is_none());
    }

    #[test]
    fn test_x25519_session_derive_session_key() {
        let key_manager = X25519KeyManager::new().unwrap();
        let mut alice_session = X25519Session::new(&key_manager).unwrap();
        let _alice_public = *alice_session.local_public();

        let bob_session = X25519Session::new(&key_manager).unwrap();
        let bob_public = *bob_session.local_public();

        alice_session
            .set_peer_public(&bob_public, &key_manager)
            .unwrap();

        // 从会话派生会话密钥
        let session_key = alice_session
            .derive_session_key(&key_manager, None, Algorithm::ChaCha20Poly1305)
            .unwrap();

        assert_eq!(session_key.algorithm(), Algorithm::ChaCha20Poly1305);
    }

    #[test]
    fn test_x25519_key_agreement_wrong_algorithm() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (_alice_private, alice_public) = key_manager.generate_keypair().unwrap();

        // 使用 AES 密钥进行 X25519 密钥协商
        let aes_key_data = vec![0x12u8; 32];
        let aes_key = Key::new_active(Algorithm::AES256GCM, aes_key_data).unwrap();

        let result = key_manager.key_agreement(&aes_key, &alice_public);
        assert!(result.is_err());
        match result {
            Err(CryptoError::UnsupportedAlgorithm(msg)) => {
                assert!(msg.contains("mismatch"));
            }
            _ => panic!("Expected UnsupportedAlgorithm error"),
        }
    }

    #[test]
    fn test_x25519_key_agreement_invalid_public_key_length() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (_alice_private, _alice_public) = key_manager.generate_keypair().unwrap();
        let bob_private = Key::new_active(Algorithm::X25519, vec![0x34u8; 32]).unwrap();

        // 使用错误的公钥长度
        let short_public = &[0x56u8; 16];
        let result = key_manager.key_agreement(&bob_private, short_public);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.contains("32 bytes"));
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn test_x25519_ephemeral_key_agreement_invalid_length() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (_alice_private, alice_public) = key_manager.generate_keypair().unwrap();

        // 私钥长度错误
        let short_private = vec![0x78u8; 16];
        let result = key_manager.ephemeral_key_agreement(&short_private, &alice_public);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.contains("Invalid private key length"));
            }
            _ => panic!("Expected InvalidInput error"),
        }

        // 公钥长度错误
        let private = vec![0x9Au8; 32];
        let short_public = &[0xBCu8; 16];
        let result = key_manager.ephemeral_key_agreement(&private, short_public);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.contains("32 bytes"));
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn test_x25519_multiple_key_generations() {
        let key_manager = X25519KeyManager::new().unwrap();

        // 生成多个密钥对
        let keys: Vec<_> = (0..5)
            .map(|_| key_manager.generate_keypair().unwrap())
            .collect();

        // 确保所有公钥都是唯一的
        let public_keys: Vec<_> = keys.iter().map(|(_, pk)| *pk).collect();
        for i in 0..public_keys.len() {
            for j in (i + 1)..public_keys.len() {
                assert_ne!(public_keys[i], public_keys[j]);
            }
        }
    }

    #[test]
    fn test_x25519_key_consistency() {
        let key_manager = X25519KeyManager::new().unwrap();
        let (alice_private, _alice_public) = key_manager.generate_keypair().unwrap();

        // 多次使用同一个密钥对进行协商应该得到相同的结果
        let (_bob_private, bob_public) = key_manager.generate_keypair().unwrap();

        let shared1 = key_manager
            .key_agreement(&alice_private, &bob_public)
            .unwrap();
        let shared2 = key_manager
            .key_agreement(&alice_private, &bob_public)
            .unwrap();

        assert_eq!(shared1, shared2);
    }
}
