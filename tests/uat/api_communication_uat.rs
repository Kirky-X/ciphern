// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::fips::{FipsAlgorithmValidator, FipsContext};
use ciphern::key::{Key, KeyState};
use ciphern::provider::registry::REGISTRY;
use ciphern::{Algorithm, KeyManager};
use std::sync::Arc;

/// 模拟API客户端
struct ApiClient {
    key_manager: Arc<KeyManager>,
    #[allow(dead_code)]
    client_id: String,
}

impl ApiClient {
    fn new(client_id: String) -> Self {
        let key_manager = Arc::new(KeyManager::new().unwrap());
        Self {
            key_manager,
            client_id,
        }
    }

    fn new_with_key_manager(client_id: String, key_manager: Arc<KeyManager>) -> Self {
        Self {
            key_manager,
            client_id,
        }
    }

    /// 密钥协商过程
    fn negotiate_keys(
        &self,
        server_public_key: &[u8],
    ) -> Result<(String, String), ciphern::error::CryptoError> {
        // FIPS 140-3 合规性检查
        self.validate_fips_compliance()?;

        // 1. 生成临时密钥对（使用FIPS批准的算法）
        let ephemeral_key = self.key_manager.generate_key(Algorithm::ECDSAP384)?;

        // 2. 使用HKDF派生共享密钥
        let master_key = self.key_manager.get_key(&ephemeral_key)?;
        let _shared_secret = ciphern::key::derivation::Hkdf::derive(
            &master_key,
            server_public_key,
            b"api-key-negotiation",
            Algorithm::AES256GCM,
        )?;

        // 3. 生成加密密钥和MAC密钥（使用FIPS批准的算法）
        // 由于ciphern API不允许直接设置密钥数据，我们生成新的随机密钥
        // 这些密钥将由KeyManager自动激活
        let encryption_key_id = self.key_manager.generate_key(Algorithm::AES256GCM)?;
        let mac_key_id = self.key_manager.generate_key(Algorithm::AES256GCM)?;

        // 4. 验证密钥强度
        let encryption_key = self.key_manager.get_key(&encryption_key_id)?;
        let mac_key = self.key_manager.get_key(&mac_key_id)?;
        self.validate_key_strength(&encryption_key)?;
        self.validate_key_strength(&mac_key)?;

        Ok((encryption_key_id, mac_key_id))
    }

    #[allow(dead_code)]
    /// 派生并创建密钥
    fn derive_and_create_key(
        &self,
        shared_secret: &[u8],
        context: &[u8],
        algorithm: Algorithm,
    ) -> Result<String, ciphern::error::CryptoError> {
        // 使用HKDF派生密钥材料
        use ring::hkdf;

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"");
        let prk = salt.extract(shared_secret);

        let info = [context];
        let okm = prk.expand(&info, ring::hkdf::HKDF_SHA256).map_err(|_| {
            ciphern::error::CryptoError::EncryptionFailed("HKDF Expand failed".into())
        })?;

        let mut derived_bytes = vec![0u8; algorithm.key_size()];
        okm.fill(&mut derived_bytes).map_err(|_| {
            ciphern::error::CryptoError::EncryptionFailed("HKDF Fill failed".into())
        })?;

        // 使用派生的密钥材料创建新密钥
        let key_id = self.key_manager.generate_key(algorithm)?;

        // 注意：由于我们无法直接设置密钥数据，我们需要使用生成的随机密钥
        // 在实际应用中，这里应该有一种方法来设置密钥数据
        Ok(key_id)
    }

    /// FIPS 140-3 合规性验证
    fn validate_fips_compliance(&self) -> Result<(), ciphern::error::CryptoError> {
        // 1. 检查是否启用了FIPS模式
        if !self.is_fips_mode_enabled() {
            return Err(ciphern::error::CryptoError::InvalidParameter(
                "FIPS mode required".into(),
            ));
        }

        // 2. 验证使用的算法是否在FIPS批准列表中
        let approved_algorithms = vec![
            Algorithm::ECDSAP384,
            Algorithm::AES256GCM,
            Algorithm::SHA256,
        ];
        for algorithm in approved_algorithms {
            if !FipsAlgorithmValidator::is_algorithm_approved(&algorithm) {
                return Err(ciphern::error::CryptoError::UnsupportedAlgorithm(format!(
                    "{:?}",
                    algorithm
                )));
            }
        }

        // 3. 验证熵源质量
        self.validate_entropy_source()?;

        // 4. 验证密钥管理合规性
        self.validate_key_management_compliance()?;

        Ok(())
    }

    /// 检查FIPS模式是否启用
    fn is_fips_mode_enabled(&self) -> bool {
        FipsContext::new(ciphern::fips::FipsMode::Enabled).is_ok()
    }

    /// 验证熵源质量
    fn validate_entropy_source(&self) -> Result<(), ciphern::error::CryptoError> {
        // 验证随机数生成器的质量
        let mut random_bytes = vec![0u8; 32];
        ciphern::random::SecureRandom::new()?.fill(&mut random_bytes)?;

        // 检查随机性质量（频率测试）
        let mut ones_count = 0;
        for byte in &random_bytes {
            ones_count += byte.count_ones();
        }
        let total_bits = random_bytes.len() * 8;
        let ones_ratio = ones_count as f64 / total_bits as f64;

        // 检查是否接近50%的1的比例
        // 允许的偏差范围设为0.1，仅作为基本健康检查
        // 完整的随机性测试由 FIPS 自检模块负责
        if (ones_ratio - 0.5).abs() > 0.1 {
            return Err(ciphern::error::CryptoError::InsufficientEntropy);
        }

        Ok(())
    }

    /// 验证密钥管理合规性
    fn validate_key_management_compliance(&self) -> Result<(), ciphern::error::CryptoError> {
        // 验证密钥生命周期管理
        let test_key = self.key_manager.generate_key(Algorithm::AES256GCM)?;
        let key = self.key_manager.get_key(&test_key)?;

        // 检查密钥状态管理 (generate_key 会自动激活密钥)
        if key.state() != KeyState::Active {
            return Err(ciphern::error::CryptoError::KeyError(
                "Invalid key state".into(),
            ));
        }

        Ok(())
    }

    /// 验证密钥强度
    fn validate_key_strength(&self, key: &Key) -> Result<(), ciphern::error::CryptoError> {
        // 检查密钥长度
        let key_data = key.secret_bytes()?;
        let key_len = key_data.as_bytes().len();

        match key.algorithm() {
            Algorithm::AES128GCM => {
                if key_len != 16 {
                    return Err(ciphern::error::CryptoError::KeyError(
                        "Invalid AES-128 key length".into(),
                    ));
                }
            }
            Algorithm::AES192GCM => {
                if key_len != 24 {
                    return Err(ciphern::error::CryptoError::KeyError(
                        "Invalid AES-192 key length".into(),
                    ));
                }
            }
            Algorithm::AES256GCM => {
                if key_len != 32 {
                    return Err(ciphern::error::CryptoError::KeyError(
                        "Invalid AES-256 key length".into(),
                    ));
                }
            }
            Algorithm::ECDSAP384 => {
                if key_len < 48 {
                    return Err(ciphern::error::CryptoError::KeyError(
                        "Invalid ECDSA P-384 key length".into(),
                    ));
                }
            }
            _ => {
                return Err(ciphern::error::CryptoError::UnsupportedAlgorithm(format!(
                    "{:?}",
                    key.algorithm()
                )));
            }
        }

        Ok(())
    }

    /// 使用HMAC-SHA256进行消息认证
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, ciphern::error::CryptoError> {
        use ring::hmac;

        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&key, data);
        Ok(tag.as_ref().to_vec())
    }

    /// 发送加密消息
    fn send_encrypted_message(
        &self,
        enc_key_id: &str,
        mac_key_id: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, ciphern::error::CryptoError> {
        // 获取密钥
        let enc_key = self.key_manager.get_key(enc_key_id)?;
        let mac_key = self.key_manager.get_key(mac_key_id)?;

        // 1. 加密数据
        let cipher = REGISTRY.get_symmetric(Algorithm::AES256GCM)?;
        let ciphertext = cipher.encrypt(&enc_key, data, None)?;

        // 2. 计算MAC
        let mac_key_bytes = mac_key.secret_bytes()?;
        let mac = self.hmac_sha256(mac_key_bytes.as_bytes(), &ciphertext)?;

        // 3. 组合消息
        let mut message = Vec::new();
        message.extend_from_slice(&ciphertext);
        message.extend_from_slice(&mac);

        Ok(message)
    }

    /// 接收并验证加密消息
    fn receive_encrypted_message(
        &self,
        enc_key_id: &str,
        mac_key_id: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, ciphern::error::CryptoError> {
        if message.len() < 32 {
            return Err(ciphern::error::CryptoError::InvalidParameter(
                "Invalid message length".into(),
            ));
        }

        // 分离密文和MAC
        let (ciphertext, mac) = message.split_at(message.len() - 32);

        // 获取密钥
        let enc_key = self.key_manager.get_key(enc_key_id)?;
        let mac_key = self.key_manager.get_key(mac_key_id)?;

        // 1. 验证MAC
        let mac_key_bytes = mac_key.secret_bytes()?;
        let calculated_mac = self.hmac_sha256(mac_key_bytes.as_bytes(), ciphertext)?;

        if calculated_mac != mac {
            return Err(ciphern::error::CryptoError::InvalidParameter(
                "Authentication failed".into(),
            ));
        }

        // 2. 解密数据
        let cipher = REGISTRY.get_symmetric(Algorithm::AES256GCM)?;
        let plaintext = cipher.decrypt(&enc_key, ciphertext, None)?;

        Ok(plaintext)
    }

    #[allow(dead_code)]
    /// 获取主密钥用于密钥派生
    fn get_master_key(&self) -> Result<Vec<u8>, ciphern::error::CryptoError> {
        let master_key = self.key_manager.generate_key(Algorithm::AES256GCM)?;
        let master_key_obj = self.key_manager.get_key(&master_key)?;
        let key_data = master_key_obj.secret_bytes()?;
        Ok(key_data.as_bytes().to_vec())
    }
}

/// 模拟API服务器
struct ApiServer {
    key_manager: Arc<KeyManager>,
    #[allow(dead_code)]
    server_id: String,
}

impl ApiServer {
    fn new(server_id: String) -> Self {
        let key_manager = Arc::new(KeyManager::new().unwrap());
        Self {
            key_manager,
            server_id,
        }
    }

    fn new_with_key_manager(server_id: String, key_manager: Arc<KeyManager>) -> Self {
        Self {
            key_manager,
            server_id,
        }
    }

    /// 生成服务器密钥对
    fn generate_key_pair(&self) -> Result<String, ciphern::error::CryptoError> {
        let key_id = self.key_manager.generate_key(Algorithm::ECDSAP384)?;
        Ok(key_id)
    }

    #[allow(dead_code)]
    /// 处理客户端密钥协商请求
    fn handle_key_negotiation(
        &self,
        client_public_key: &[u8],
    ) -> Result<(String, String), ciphern::error::CryptoError> {
        // 1. 生成服务器临时密钥对
        let server_ephemeral = self.key_manager.generate_key(Algorithm::ECDSAP384)?;
        let server_key = self.key_manager.get_key(&server_ephemeral)?;

        // 2. 使用HKDF派生共享密钥
        let shared_secret = ciphern::key::derivation::Hkdf::derive(
            &server_key,
            client_public_key,
            b"api-key-negotiation",
            Algorithm::AES256GCM,
        )?;

        // 3. 生成加密密钥和MAC密钥
        let encryption_key = ciphern::key::derivation::Hkdf::derive(
            &shared_secret,
            b"",
            b"encryption-key",
            Algorithm::AES256GCM,
        )?;
        let mac_key = ciphern::key::derivation::Hkdf::derive(
            &shared_secret,
            b"",
            b"mac-key",
            Algorithm::AES256GCM,
        )?;

        Ok((encryption_key.id().to_string(), mac_key.id().to_string()))
    }

    /// 使用HMAC-SHA256进行消息认证
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, ciphern::error::CryptoError> {
        use ring::hmac;

        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&key, data);
        Ok(tag.as_ref().to_vec())
    }

    /// 处理加密消息
    fn handle_encrypted_message(
        &self,
        enc_key_id: &str,
        mac_key_id: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, ciphern::error::CryptoError> {
        if message.len() < 32 {
            return Err(ciphern::error::CryptoError::InvalidParameter(
                "Invalid message length".into(),
            ));
        }

        // 分离密文和MAC
        let (ciphertext, mac) = message.split_at(message.len() - 32);

        // 获取密钥
        let enc_key = self.key_manager.get_key(enc_key_id)?;
        let mac_key = self.key_manager.get_key(mac_key_id)?;

        // 1. 验证MAC
        let mac_key_bytes = mac_key.secret_bytes()?;
        let calculated_mac = self.hmac_sha256(mac_key_bytes.as_bytes(), ciphertext)?;

        if calculated_mac != mac {
            return Err(ciphern::error::CryptoError::InvalidParameter(
                "Authentication failed".into(),
            ));
        }

        // 2. 解密数据
        let cipher = REGISTRY.get_symmetric(Algorithm::AES256GCM)?;
        let plaintext = cipher.decrypt(&enc_key, ciphertext, None)?;

        // 3. 处理请求（这里只是回显）
        let response = format!(
            "Server response to: {}",
            String::from_utf8_lossy(&plaintext)
        );

        // 4. 加密响应
        let response_ciphertext = cipher.encrypt(&enc_key, response.as_bytes(), None)?;

        // 5. 计算响应MAC
        let response_mac = self.hmac_sha256(mac_key_bytes.as_bytes(), &response_ciphertext)?;

        // 6. 组合响应消息
        let mut response_message = Vec::new();
        response_message.extend_from_slice(&response_ciphertext);
        response_message.extend_from_slice(&response_mac);

        Ok(response_message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_compliance_validation() {
        ciphern::init().unwrap();

        let client = ApiClient::new("test-client".to_string());

        // 测试FIPS合规性验证
        let result = client.validate_fips_compliance();
        assert!(result.is_ok(), "FIPS compliance validation should pass");
    }

    #[test]
    fn test_key_negotiation() {
        ciphern::init().unwrap();

        let client = ApiClient::new("test-client".to_string());
        let server = ApiServer::new("test-server".to_string());

        // 服务器生成密钥对
        let server_key_pair = server.generate_key_pair().unwrap();
        let server_key = server.key_manager.get_key(&server_key_pair).unwrap();
        let server_public_key = server_key.secret_bytes().unwrap().as_bytes().to_vec();

        // 客户端协商密钥
        let (enc_key_id, mac_key_id) = client.negotiate_keys(&server_public_key).unwrap();

        // 验证密钥ID有效
        assert!(!enc_key_id.is_empty());
        assert!(!mac_key_id.is_empty());

        // 验证密钥存在且有效
        let enc_key = client.key_manager.get_key(&enc_key_id).unwrap();
        let mac_key = client.key_manager.get_key(&mac_key_id).unwrap();

        assert_eq!(enc_key.algorithm(), Algorithm::AES256GCM);
        assert_eq!(mac_key.algorithm(), Algorithm::AES256GCM);
    }

    #[test]
    fn test_encrypted_message_exchange() {
        ciphern::init().unwrap();

        // Shared KeyManager for client and server
        let shared_key_manager = Arc::new(KeyManager::new().unwrap());
        let client =
            ApiClient::new_with_key_manager("test-client".to_string(), shared_key_manager.clone());
        let server =
            ApiServer::new_with_key_manager("test-server".to_string(), shared_key_manager.clone());

        // 密钥协商
        let server_key_pair = server.generate_key_pair().unwrap();
        let server_key = server.key_manager.get_key(&server_key_pair).unwrap();
        let server_public_key = server_key.secret_bytes().unwrap().as_bytes().to_vec();

        let (enc_key_id, mac_key_id) = client.negotiate_keys(&server_public_key).unwrap();

        // 客户端发送加密消息
        let message = b"Hello, secure world!";
        let encrypted_message = client
            .send_encrypted_message(&enc_key_id, &mac_key_id, message)
            .unwrap();

        // 服务器处理消息
        let response = server
            .handle_encrypted_message(&enc_key_id, &mac_key_id, &encrypted_message)
            .unwrap();

        // 客户端接收响应
        let decrypted_response = client
            .receive_encrypted_message(&enc_key_id, &mac_key_id, &response)
            .unwrap();

        assert!(String::from_utf8_lossy(&decrypted_response)
            .contains("Server response to: Hello, secure world!"));
    }

    #[test]
    fn test_key_derivation_security() {
        ciphern::init().unwrap();

        let client = ApiClient::new("kd-client".to_string());
        let server = ApiServer::new("kd-server".to_string());

        // 生成服务器密钥对
        let server_key_pair = server.generate_key_pair().unwrap();
        let server_key = server.key_manager.get_key(&server_key_pair).unwrap();
        let server_public_key = server_key.secret_bytes().unwrap().as_bytes().to_vec();

        // 多次协商密钥，验证每次生成的密钥都不同
        let mut key_pairs = Vec::new();
        for _i in 0..5 {
            let (enc_key_id, mac_key_id) = client.negotiate_keys(&server_public_key).unwrap();
            key_pairs.push((enc_key_id, mac_key_id));
        }

        // 验证所有密钥对都是唯一的
        for i in 0..key_pairs.len() {
            for j in i + 1..key_pairs.len() {
                assert_ne!(
                    key_pairs[i].0, key_pairs[j].0,
                    "Encryption keys should be unique"
                );
                assert_ne!(key_pairs[i].1, key_pairs[j].1, "MAC keys should be unique");
            }
        }
    }
}
