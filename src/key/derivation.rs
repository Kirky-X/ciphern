// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::types::Algorithm;
use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use ring::hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub struct Hkdf;

impl Hkdf {
    pub fn derive(
        master_key: &Key,
        salt: &[u8],
        info: &[u8],
        output_algo: Algorithm,
    ) -> Result<Key> {
        debug_assert!(salt.len() <= 128, "Salt should not exceed 128 bytes for performance");
        debug_assert!(info.len() <= 1024, "Info should not exceed 1024 bytes for performance");

        let _secret = master_key.secret_bytes()?;
        let key_size = output_algo.key_size();

        // 对于32字节密钥，直接使用HKDF
        if key_size == 32 {
            return Self::derive_32_bytes(master_key, salt, info, output_algo);
        }

        // 对于16字节密钥，派生32字节然后截断
        if key_size == 16 {
            let full_key = Self::derive_32_bytes(master_key, salt, info, Algorithm::AES256GCM)?;
            let full_bytes = full_key.secret_bytes()?;
            let truncated: Vec<u8> = full_bytes.as_bytes()[..16].to_vec();
            // 清零临时密钥数据
            drop(full_key);
            return Key::new_active(output_algo, truncated);
        }

        // 对于24字节密钥，派生32字节然后截断
        if key_size == 24 {
            let full_key = Self::derive_32_bytes(master_key, salt, info, Algorithm::AES256GCM)?;
            let full_bytes = full_key.secret_bytes()?;
            let truncated: Vec<u8> = full_bytes.as_bytes()[..24].to_vec();
            // 清零临时密钥数据
            drop(full_key);
            return Key::new_active(output_algo, truncated);
        }

        // 其他大小的密钥不支持
        Err(CryptoError::InvalidParameter(format!(
            "Unsupported key size: {}",
            key_size
        )))
    }

    fn derive_32_bytes(
        master_key: &Key,
        salt: &[u8],
        info: &[u8],
        output_algo: Algorithm,
    ) -> Result<Key> {
        let secret = master_key.secret_bytes()?;
        let mut derived_bytes = vec![0u8; 32];

        // 使用提供的salt和info参数
        let salt_obj = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = salt_obj.extract(secret.as_bytes());

        // 使用单个info数组元素来避免ring crate的限制
        let info_array = [info];

        let okm = prk
            .expand(&info_array, hkdf::HKDF_SHA256)
            .map_err(|e| CryptoError::EncryptionFailed(format!("HKDF Expand failed: {:?}", e)))?;

        okm.fill(&mut derived_bytes)
            .map_err(|e| CryptoError::EncryptionFailed(format!("HKDF Fill failed: {:?}", e)))?;

        let result = Key::new_active(output_algo, derived_bytes.clone());

        // 清零派生过程中的敏感数据
        derived_bytes.zeroize();

        result
    }
}

pub struct Pbkdf2;

impl Pbkdf2 {
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output_algo: Algorithm,
    ) -> Result<Key> {
        debug_assert!(!password.is_empty(), "Password should not be empty for PBKDF2");
        debug_assert!(salt.len() <= 128, "Salt should not exceed 128 bytes for performance");
        debug_assert!(iterations >= 10000, "PBKDF2 iterations should be at least 10000 for security");

        let key_size = output_algo.key_size();
        let mut derived_key = vec![0u8; key_size];

        // 使用PBKDF2-HMAC-SHA256进行密钥派生
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut derived_key)
            .map_err(|e| CryptoError::EncryptionFailed(format!("PBKDF2 failed: {:?}", e)))?;

        let result = Key::new_active(output_algo, derived_key.clone());

        // 清零派生过程中的敏感数据
        derived_key.zeroize();

        result
    }
}

pub struct Argon2id;

impl Argon2id {
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        memory_cost: u32, // KB
        time_cost: u32,   // 迭代次数
        parallelism: u32, // 并行度
        output_algo: Algorithm,
    ) -> Result<Key> {
        debug_assert!(!password.is_empty(), "Password should not be empty for Argon2id");
        debug_assert!(salt.len() <= 128, "Salt should not exceed 128 bytes for performance");
        debug_assert!(memory_cost >= 65536, "Argon2id memory cost should be at least 64MB for security");
        debug_assert!(time_cost >= 3, "Argon2id time cost should be at least 3 for security");

        let key_size = output_algo.key_size();
        let mut derived_key = vec![0u8; key_size];

        // 配置Argon2id参数
        let params = Params::new(memory_cost, time_cost, parallelism, Some(key_size))
            .map_err(|e| CryptoError::InvalidParameter(format!("Argon2 params error: {:?}", e)))?;

        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);

        // 执行密钥派生
        argon2
            .hash_password_into(password, salt, &mut derived_key)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Argon2id failed: {:?}", e)))?;

        let result = Key::new_active(output_algo, derived_key.clone());

        // 清零派生过程中的敏感数据
        derived_key.zeroize();

        result
    }
}

pub struct Sm3Kdf;

impl Sm3Kdf {
    pub fn derive(
        master_key: &Key,
        fixed_data: &[u8],
        key_length: usize,
        output_algo: Algorithm,
    ) -> Result<Key> {
        debug_assert!(fixed_data.len() <= 128, "Fixed data should not exceed 128 bytes for performance");
        debug_assert!(key_length >= 16, "Key length should be at least 16 bytes for security");
        debug_assert!(key_length <= 1024, "Key length should not exceed 1024 bytes for performance");

        let secret = master_key.secret_bytes()?;
        let mut derived_key = vec![0u8; key_length];

        // SM3-KDF实现：基于SM3哈希函数的密钥派生
        // 使用类似NIST SP 800-108的计数器模式
        let mut counter: u32 = 1;
        let mut offset = 0;

        while offset < key_length {
            let mut input = Vec::new();
            input.extend_from_slice(secret.as_bytes());
            input.extend_from_slice(fixed_data);
            input.extend_from_slice(&counter.to_be_bytes());

            // 使用SM3哈希（这里用SHA256模拟，实际应该使用SM3）
            use sha2::Digest;
            let hash = Sha256::digest(&input);
            let hash_bytes = hash.as_slice();

            let remaining = key_length - offset;
            let copy_len = std::cmp::min(hash_bytes.len(), remaining);
            derived_key[offset..offset + copy_len].copy_from_slice(&hash_bytes[..copy_len]);

            offset += copy_len;
            counter += 1;

            // 清零临时输入数据
            input.zeroize();
        }

        // 如果派生长度与算法要求不匹配，调整长度
        let final_key = if derived_key.len() == output_algo.key_size() {
            derived_key.clone()
        } else if derived_key.len() > output_algo.key_size() {
            let truncated = derived_key[..output_algo.key_size()].to_vec();
            derived_key.zeroize(); // 清零原始数据
            truncated
        } else {
            // 如果派生长度不足，扩展密钥
            let mut extended_key = vec![0u8; output_algo.key_size()];
            extended_key[..derived_key.len()].copy_from_slice(&derived_key);
            derived_key.zeroize(); // 清零原始数据
            extended_key
        };

        let result = Key::new_active(output_algo, final_key);

        // 清零派生过程中的敏感数据
        if !derived_key.is_empty() {
            derived_key.zeroize();
        }

        result
    }
}
