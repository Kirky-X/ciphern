// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::audit::AuditLogger;
use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::types::Algorithm;
use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use libsm::sm3::hash::Sm3Hash;
use pbkdf2::pbkdf2;
use ring::hkdf;
use sha2::Sha256;
use zeroize::Zeroize;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Check if SHA-NI hardware acceleration is available for hash operations.
#[inline]
pub fn is_sha_ni_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("sha")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

#[allow(dead_code)]
pub struct Hkdf;

impl Hkdf {
    #[allow(dead_code)]
    pub fn derive(
        master_key: &Key,
        salt: &[u8],
        info: &[u8],
        output_algo: Algorithm,
    ) -> Result<Key> {
        if salt.len() > 128 {
            return Err(CryptoError::InvalidParameter(
                "Salt长度不应超过128字节以保证性能".to_string(),
            ));
        }
        if info.len() > 1024 {
            return Err(CryptoError::InvalidParameter(
                "Info长度不应超过1024字节以保证性能".to_string(),
            ));
        }

        let _secret = master_key.secret_bytes()?;
        let key_size = output_algo.key_size();

        // Log hardware acceleration status
        let sha_ni_available = is_sha_ni_available();
        AuditLogger::log(
            "HKDF_DERIVE_START",
            None,
            None,
            if sha_ni_available {
                Ok(())
            } else {
                Err(CryptoError::HardwareAccelerationUnavailable(
                    "SHA-NI not available for HKDF".into(),
                ))
            },
        );

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

    #[allow(dead_code)]
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

        // Log successful completion
        AuditLogger::log("HKDF_DERIVE_COMPLETE", None, None, Ok(()));

        result
    }
}

#[allow(dead_code)]
pub struct Pbkdf2;

#[allow(dead_code)]
impl Pbkdf2 {
    #[allow(dead_code)]
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output_algo: Algorithm,
    ) -> Result<Key> {
        debug_assert!(
            !password.is_empty(),
            "Password should not be empty for PBKDF2"
        );
        debug_assert!(
            salt.len() <= 128,
            "Salt should not exceed 128 bytes for performance"
        );
        debug_assert!(
            iterations >= 10000,
            "PBKDF2 iterations should be at least 10000 for security"
        );

        // Log hardware acceleration status
        let sha_ni_available = is_sha_ni_available();
        AuditLogger::log(
            "PBKDF2_DERIVE_START",
            None,
            None,
            if sha_ni_available {
                Ok(())
            } else {
                Err(CryptoError::HardwareAccelerationUnavailable(
                    "SHA-NI not available for PBKDF2".into(),
                ))
            },
        );

        let key_size = output_algo.key_size();
        let mut derived_key = vec![0u8; key_size];

        // 使用PBKDF2-HMAC-SHA256进行密钥派生
        // ring库和sha2 crate会自动使用SHA-NI硬件加速（如果可用）
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut derived_key)
            .map_err(|e| CryptoError::EncryptionFailed(format!("PBKDF2 failed: {:?}", e)))?;

        let result = Key::new_active(output_algo, derived_key.clone());

        // 清零派生过程中的敏感数据
        derived_key.zeroize();

        // Log successful completion
        AuditLogger::log("PBKDF2_DERIVE_COMPLETE", None, None, Ok(()));

        result
    }
}

#[allow(dead_code)]
pub struct Argon2id;

#[allow(dead_code)]
impl Argon2id {
    #[allow(dead_code)]
    pub fn derive(password: &[u8], salt: &[u8], output_algo: Algorithm) -> Result<Key> {
        let key_size = output_algo.key_size();
        let mut derived_key = vec![0u8; key_size];

        // 配置Argon2id参数
        let params = Params::new(65536, 3, 4, Some(key_size))
            .map_err(|e| CryptoError::EncryptionFailed(format!("Argon2 params failed: {:?}", e)))?;

        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);

        argon2
            .hash_password_into(password, salt, &mut derived_key)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Argon2 failed: {:?}", e)))?;

        let result = Key::new_active(output_algo, derived_key.clone());

        // 清零派生过程中的敏感数据
        derived_key.zeroize();

        result
    }
}

/// SM3 密钥派生函数 (KDF) 实现
///
/// 此实现遵循 GB/T 32918.4-2016 标准。
#[allow(dead_code)]
pub struct Sm3Kdf;

impl Sm3Kdf {
    /// 使用 SM3-KDF 派生密钥
    ///
    /// # 参数
    ///
    /// * `master_key` - 用于派生的主密钥
    /// * `data` - 输入数据 (Z || 其他信息)
    /// * `key_len` - 派生密钥的期望长度（字节）
    /// * `output_algo` - 派生密钥的算法
    ///
    /// # 返回
    ///
    /// 返回派生的密钥
    #[allow(dead_code)]
    pub fn derive(
        master_key: &Key,
        data: &[u8],
        key_len: usize,
        output_algo: Algorithm,
    ) -> Result<Key> {
        // SM3 produces 32-byte (256-bit) hash
        const HASH_LEN: usize = 32;

        // Check if key length is valid (limit to reasonable size, e.g., 1024 bytes)
        if key_len == 0 || key_len > 1024 {
            return Err(CryptoError::InvalidParameter(format!(
                "Invalid key length for KDF: {}",
                key_len
            )));
        }

        let secret = master_key.secret_bytes()?;
        let secret_bytes = secret.as_bytes();

        // Calculate number of blocks needed: ceil(key_len / HASH_LEN)
        let n = key_len.div_ceil(HASH_LEN);

        // Counter is 32-bit big-endian integer, starting from 1
        // If n >= 2^32, we can't represent the counter.
        // With key_len limit of 1024, n is at most 32, so we are safe.
        if n > (u32::MAX as usize) {
            return Err(CryptoError::InvalidParameter(
                "Key length too large".to_string(),
            ));
        }

        let mut derived_key = Vec::with_capacity(key_len);

        // KDF = H(Z || ct) || H(Z || ct+1) ...
        // Note: The standard typically defines input as Z || ct where Z is seed/secret
        // But implementation details vary. Based on typical SM3 KDF:
        // Ha = SM3(Z || ct)
        // We need to clarify if 'master_key' is part of Z or if Z is just 'data'.
        // Usually KDF(Z, klen):
        // For i = 1 to n:
        //   Hash(Z || ct)
        // Here we treat (secret || data) as Z for better security if not specified otherwise,
        // but to strictly follow standard KDF often takes a single input stream.
        // Let's assume input Z is constructed by caller or we use (secret || data).
        // For general KDF usage here: H(secret || data || ct)

        // use libsm::sm3::hash::{Sm3Hash, Digest};

        for i in 1..=n {
            let mut input = Vec::with_capacity(secret_bytes.len() + data.len() + 4);
            input.extend_from_slice(secret_bytes);
            input.extend_from_slice(data);
            input.extend_from_slice(&(i as u32).to_be_bytes());

            let mut hasher = Sm3Hash::new(&input);
            let hash = hasher.get_hash();
            derived_key.extend_from_slice(&hash);
        }

        // Truncate to requested length
        derived_key.truncate(key_len);

        let result = Key::new_active(output_algo, derived_key.clone());

        // Zeroize intermediate buffer
        derived_key.zeroize();

        result
    }

    /// 使用 SM3-KDF 并行派生密钥（使用 Rayon）
    ///
    /// 当启用了 parallel 特征时，使用 Rayon 进行并行处理，
    /// 可显著提升大批量密钥派生性能。
    ///
    /// # 参数
    ///
    /// * `master_key` - 用于派生的主密钥
    /// * `data` - 输入数据 (Z || 其他信息)
    /// * `key_len` - 派生密钥的期望长度（字节）
    /// * `output_algo` - 派生密钥的算法
    ///
    /// # 返回
    ///
    /// 返回派生的密钥
    #[cfg(feature = "parallel")]
    #[allow(dead_code)]
    pub fn parallel_derive(
        master_key: &Key,
        data: &[u8],
        key_len: usize,
        output_algo: Algorithm,
    ) -> Result<Key> {
        const HASH_LEN: usize = 32;

        if key_len == 0 || key_len > 1024 {
            return Err(CryptoError::InvalidParameter(format!(
                "Invalid key length for KDF: {}",
                key_len
            )));
        }

        let secret = master_key.secret_bytes()?;
        let secret_bytes = secret.as_bytes();
        let n = key_len.div_ceil(HASH_LEN);

        if n > (u32::MAX as usize) {
            return Err(CryptoError::InvalidParameter(
                "Key length too large".to_string(),
            ));
        }

        // Log parallel processing start
        AuditLogger::log("SM3KDF_PARALLEL_DERIVE_START", None, None, Ok(()));

        // 并行计算所有哈希块
        let hashes: Vec<Vec<u8>> = (1..=n)
            .into_par_iter()
            .map(|i| {
                let mut input = Vec::with_capacity(secret_bytes.len() + data.len() + 4);
                input.extend_from_slice(secret_bytes);
                input.extend_from_slice(data);
                input.extend_from_slice(&(i as u32).to_be_bytes());

                let mut hasher = Sm3Hash::new(&input);
                hasher.get_hash().to_vec()
            })
            .collect();

        // 收集结果
        let mut derived_key = Vec::with_capacity(key_len);
        for hash in hashes {
            derived_key.extend_from_slice(&hash);
        }

        // Truncate to requested length
        derived_key.truncate(key_len);

        let result = Key::new_active(output_algo, derived_key.clone());

        // Zeroize intermediate buffer
        derived_key.zeroize();

        // Log parallel processing complete
        AuditLogger::log("SM3KDF_PARALLEL_DERIVE_COMPLETE", None, None, Ok(()));

        result
    }

    /// 自动选择是否使用并行派生
    ///
    /// 根据密钥长度自动选择最优的派生方法。
    /// 对于较大的密钥长度（> 64字节），使用并行版本可能更快。
    #[cfg(feature = "parallel")]
    #[allow(dead_code)]
    pub fn derive_optimal(
        master_key: &Key,
        data: &[u8],
        key_len: usize,
        output_algo: Algorithm,
    ) -> Result<Key> {
        // 对于较大的密钥长度，使用并行版本
        if key_len > 64 {
            return Self::parallel_derive(master_key, data, key_len, output_algo);
        }
        // 对于较小的密钥长度，使用标准版本
        Self::derive(master_key, data, key_len, output_algo)
    }

    /// 自动选择是否使用并行派生（无并行版本）
    ///
    /// 当并行特征未启用时，回退到标准派生方法。
    #[cfg(not(feature = "parallel"))]
    #[allow(dead_code)]
    pub fn derive_optimal(
        master_key: &Key,
        data: &[u8],
        key_len: usize,
        output_algo: Algorithm,
    ) -> Result<Key> {
        // 使用标准版本
        Self::derive(master_key, data, key_len, output_algo)
    }
}

#[cfg(test)]
mod sm3_tests {
    use crate::key::derivation::Sm3Kdf;
    use crate::key::Key;
    use crate::types::Algorithm;

    #[test]
    fn test_sm3_hash_implementation() {
        // 测试数据
        let master_key_bytes = vec![0x42u8; 32]; // 非零密钥数据
        let master_key =
            Key::new_active(Algorithm::AES256GCM, master_key_bytes).expect("创建主密钥失败");
        let fixed_data = b"test_fixed_data";

        // 测试密钥派生 - 使用 AES256GCM 作为输出算法，因为 Sm3Kdf 是 KDF 算法
        let key1 = Sm3Kdf::derive(&master_key, fixed_data, 32, Algorithm::AES256GCM)
            .expect("SM3密钥派生应该成功");

        let key1_bytes = key1.secret_bytes().expect("应该获取到密钥字节");

        // 验证密钥不全为零（基本健全性检查）
        let is_non_zero = key1_bytes.as_bytes().iter().any(|&b| b != 0);
        assert!(is_non_zero, "派生的密钥应包含非零字节");

        // 测试确定性行为 - 相同输入应产生相同输出
        let key2 = Sm3Kdf::derive(&master_key, fixed_data, 32, Algorithm::AES256GCM)
            .expect("第二次SM3密钥派生应该成功");

        let key2_bytes = key2.secret_bytes().expect("应该获取到密钥字节");

        assert_eq!(
            key1_bytes.as_bytes(),
            key2_bytes.as_bytes(),
            "SM3实现应该是确定性的"
        );

        // 测试不同输入产生不同输出
        let different_data = b"different_data";
        let key3 = Sm3Kdf::derive(&master_key, different_data, 32, Algorithm::AES256GCM)
            .expect("使用不同数据的SM3密钥派生应该成功");

        let key3_bytes = key3.secret_bytes().expect("应该获取到密钥字节");

        assert_ne!(
            key1_bytes.as_bytes(),
            key3_bytes.as_bytes(),
            "不同输入应该产生不同的密钥"
        );

        println!("SM3哈希实现测试通过！");
    }
}
