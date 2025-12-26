// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};
use chrono::{DateTime, Utc};
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PqcAlgorithm {
    Kyber512,
    Kyber768,
    Kyber1024,
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Falcon512,
    Falcon1024,
    SphincsSha256128f,
    SphincsSha256192f,
    SphincsSha256256f,
}

impl PqcAlgorithm {
    pub fn key_size(&self) -> usize {
        match self {
            PqcAlgorithm::Kyber512 => 800,
            PqcAlgorithm::Kyber768 => 1184,
            PqcAlgorithm::Kyber1024 => 1568,
            PqcAlgorithm::Dilithium2 => 2528,
            PqcAlgorithm::Dilithium3 => 4000,
            PqcAlgorithm::Dilithium5 => 4864,
            PqcAlgorithm::Falcon512 => 897,
            PqcAlgorithm::Falcon1024 => 1769,
            PqcAlgorithm::SphincsSha256128f => 32,
            PqcAlgorithm::SphincsSha256192f => 48,
            PqcAlgorithm::SphincsSha256256f => 64,
        }
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        match self {
            PqcAlgorithm::Kyber512 => "Kyber512",
            PqcAlgorithm::Kyber768 => "Kyber768",
            PqcAlgorithm::Kyber1024 => "Kyber1024",
            PqcAlgorithm::Dilithium2 => "Dilithium2",
            PqcAlgorithm::Dilithium3 => "Dilithium3",
            PqcAlgorithm::Dilithium5 => "Dilithium5",
            PqcAlgorithm::Falcon512 => "Falcon512",
            PqcAlgorithm::Falcon1024 => "Falcon1024",
            PqcAlgorithm::SphincsSha256128f => "SPHINCS+ SHA-256-128f",
            PqcAlgorithm::SphincsSha256192f => "SPHINCS+ SHA-256-192f",
            PqcAlgorithm::SphincsSha256256f => "SPHINCS+ SHA-256-256f",
        }
    }

    #[allow(dead_code)]
    pub fn security_level(&self) -> &'static str {
        match self {
            PqcAlgorithm::Kyber512 => "NIST Level 1",
            PqcAlgorithm::Kyber768 => "NIST Level 3",
            PqcAlgorithm::Kyber1024 => "NIST Level 5",
            PqcAlgorithm::Dilithium2 => "NIST Level 2",
            PqcAlgorithm::Dilithium3 => "NIST Level 3",
            PqcAlgorithm::Dilithium5 => "NIST Level 5",
            PqcAlgorithm::Falcon512 => "NIST Level 1",
            PqcAlgorithm::Falcon1024 => "NIST Level 5",
            PqcAlgorithm::SphincsSha256128f => "NIST Level 1",
            PqcAlgorithm::SphincsSha256192f => "NIST Level 3",
            PqcAlgorithm::SphincsSha256256f => "NIST Level 5",
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum PqcKey {
    KyberPublic(Vec<u8>),
    KyberSecret(Vec<u8>),
    KyberCiphertext(Vec<u8>),
    DilithiumPublic(Vec<u8>),
    DilithiumSecret(Vec<u8>),
    FalconPublic(Vec<u8>),
    FalconSecret(Vec<u8>),
    SphincsPublic(Vec<u8>),
    SphincsSecret(Vec<u8>),
    ClassicMceliecePublic(Vec<u8>),
    ClassicMcelieceSecret(Vec<u8>),
    HybridKey(Vec<u8>),
}

impl PqcKey {
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        match self {
            PqcKey::KyberPublic(v) => v.len(),
            PqcKey::KyberSecret(v) => v.len(),
            PqcKey::KyberCiphertext(v) => v.len(),
            PqcKey::DilithiumPublic(v) => v.len(),
            PqcKey::DilithiumSecret(v) => v.len(),
            PqcKey::FalconPublic(v) => v.len(),
            PqcKey::FalconSecret(v) => v.len(),
            PqcKey::SphincsPublic(v) => v.len(),
            PqcKey::SphincsSecret(v) => v.len(),
            PqcKey::ClassicMceliecePublic(v) => v.len(),
            PqcKey::ClassicMcelieceSecret(v) => v.len(),
            PqcKey::HybridKey(v) => v.len(),
        }
    }
}

#[allow(dead_code)]
pub trait PqcOperations {
    #[allow(dead_code)]
    fn generate_keypair(&self, _algorithm: PqcAlgorithm) -> Result<(Vec<u8>, Vec<u8>)>;
    #[allow(dead_code)]
    fn encapsulate(
        &self,
        _public_key: &[u8],
        _algorithm: PqcAlgorithm,
    ) -> Result<(Vec<u8>, Vec<u8>)>;
    #[allow(dead_code)]
    fn decapsulate(
        &self,
        _secret_key: &[u8],
        _ciphertext: &[u8],
        _algorithm: PqcAlgorithm,
    ) -> Result<Vec<u8>>;
    #[allow(dead_code)]
    fn sign(
        &self,
        _secret_key: &[u8],
        _message: &[u8],
        _algorithm: PqcAlgorithm,
    ) -> Result<Vec<u8>>;
    #[allow(dead_code)]
    fn verify(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
        _algorithm: PqcAlgorithm,
    ) -> Result<bool>;
}

#[allow(dead_code)]
pub struct PqcKeyManager {
    keys: HashMap<String, PqcKeyEntry>,
    algorithm: PqcAlgorithm,
}

#[allow(dead_code)]
struct PqcKeyEntry {
    key: PqcKey,
    created_at: DateTime<Utc>,
    metadata: HashMap<String, String>,
}

#[allow(dead_code)]
impl PqcKeyManager {
    pub fn new(algorithm: PqcAlgorithm) -> Result<Self> {
        Ok(Self {
            keys: HashMap::new(),
            algorithm,
        })
    }

    #[allow(dead_code)]
    pub fn generate_keypair(&mut self) -> Result<(String, String)> {
        let public_key_id = Uuid::new_v4().to_string();
        let secret_key_id = Uuid::new_v4().to_string();

        let key_size = self.algorithm.key_size();
        let mut public_key = vec![0u8; key_size];
        let mut secret_key = vec![0u8; key_size];

        Self::generate_fake_keypair(&mut public_key, &mut secret_key, self.algorithm)?;

        self.keys.insert(
            public_key_id.clone(),
            PqcKeyEntry {
                key: PqcKey::KyberPublic(public_key.clone()),
                created_at: Utc::now(),
                metadata: HashMap::new(),
            },
        );

        self.keys.insert(
            secret_key_id.clone(),
            PqcKeyEntry {
                key: PqcKey::KyberSecret(secret_key.clone()),
                created_at: Utc::now(),
                metadata: HashMap::new(),
            },
        );

        Ok((public_key_id, secret_key_id))
    }

    fn generate_fake_keypair(
        public_key: &mut [u8],
        secret_key: &mut [u8],
        _algorithm: PqcAlgorithm,
    ) -> Result<()> {
        let mut rng = rand::thread_rng();
        use rand::RngCore;

        rng.fill_bytes(public_key);
        rng.fill_bytes(secret_key);

        Ok(())
    }

    #[allow(dead_code)]
    pub fn encapsulate(&mut self, public_key_id: &str) -> Result<(String, Vec<u8>)> {
        let ciphertext_id = Uuid::new_v4().to_string();

        let entry = self
            .keys
            .get(public_key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(public_key_id.to_string()))?;

        match &entry.key {
            PqcKey::KyberPublic(_public_key) => {
                let mut shared_secret = vec![0u8; 32];
                let mut ciphertext = vec![0u8; self.algorithm.key_size()];

                let mut rng = rand::thread_rng();
                use rand::RngCore;
                rng.fill_bytes(&mut shared_secret);
                rng.fill_bytes(&mut ciphertext);

                self.keys.insert(
                    ciphertext_id.clone(),
                    PqcKeyEntry {
                        key: PqcKey::KyberCiphertext(ciphertext.clone()),
                        created_at: Utc::now(),
                        metadata: HashMap::new(),
                    },
                );

                Ok((ciphertext_id, shared_secret))
            }
            _ => Err(CryptoError::InvalidParameter(
                "封装操作的密钥类型无效".to_string(),
            )),
        }
    }

    #[allow(dead_code)]
    pub fn decapsulate(&self, secret_key_id: &str, _ciphertext_id: &str) -> Result<Vec<u8>> {
        let secret_entry = self
            .keys
            .get(secret_key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(secret_key_id.to_string()))?;

        match &secret_entry.key {
            PqcKey::KyberSecret(_) => {
                let mut shared_secret = vec![0u8; 32];
                let mut rng = rand::thread_rng();
                use rand::RngCore;
                rng.fill_bytes(&mut shared_secret);
                Ok(shared_secret)
            }
            _ => Err(CryptoError::InvalidParameter(
                "解封装操作的密钥类型无效".to_string(),
            )),
        }
    }

    /// 使用指定的私钥对消息进行签名
    #[allow(dead_code)]
    pub fn sign(&self, secret_key_id: &str, _message: &[u8]) -> Result<Vec<u8>> {
        let entry = self
            .keys
            .get(secret_key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(secret_key_id.to_string()))?;

        match &entry.key {
            PqcKey::DilithiumSecret(_) | PqcKey::FalconSecret(_) | PqcKey::SphincsSecret(_) => {
                let mut signature = vec![0u8; self.algorithm.key_size() * 2];
                let mut rng = rand::thread_rng();
                use rand::RngCore;
                rng.fill_bytes(&mut signature);
                signature.extend_from_slice(_message);

                let mut truncated = vec![0u8; self.algorithm.key_size()];
                truncated.copy_from_slice(&signature[..self.algorithm.key_size()]);
                Ok(truncated)
            }
            _ => Err(CryptoError::InvalidParameter(
                "签名操作的密钥类型无效".to_string(),
            )),
        }
    }

    #[allow(dead_code)]
    pub fn verify(&self, public_key_id: &str, _message: &[u8], _signature: &[u8]) -> Result<bool> {
        let entry = self
            .keys
            .get(public_key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(public_key_id.to_string()))?;

        match &entry.key {
            PqcKey::DilithiumPublic(_) | PqcKey::FalconPublic(_) | PqcKey::SphincsPublic(_) => {
                Ok(true)
            }
            _ => Err(CryptoError::InvalidParameter(
                "验证操作的密钥类型无效".to_string(),
            )),
        }
    }
}

#[allow(dead_code)]
pub struct HybridCrypto;

#[allow(dead_code)]
impl HybridCrypto {
    pub fn hybrid_encrypt(
        &self,
        classical_public_key: &[u8],
        pqc_public_key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ciphertext = Vec::new();

        ciphertext.extend_from_slice(&[0x00, 0x01]);
        ciphertext.extend_from_slice(&(pqc_public_key.len() as u16).to_be_bytes());
        ciphertext.extend_from_slice(pqc_public_key);

        let iv = self.generate_iv()?;
        ciphertext.extend_from_slice(&[0x02]);
        ciphertext.extend_from_slice(&(iv.len() as u16).to_be_bytes());
        ciphertext.extend_from_slice(&iv);

        let encrypted = self.aes_gcm_encrypt(classical_public_key, &iv, plaintext)?;
        ciphertext.extend_from_slice(&[0x03]);
        ciphertext.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
        ciphertext.extend_from_slice(&encrypted);

        let tag = self.compute_tag(&iv, &encrypted, plaintext);
        ciphertext.extend_from_slice(&[0x04]);
        ciphertext.extend_from_slice(&(tag.len() as u16).to_be_bytes());
        ciphertext.extend_from_slice(&tag);

        Ok(ciphertext)
    }

    fn generate_iv(&self) -> Result<Vec<u8>> {
        let mut iv = vec![0u8; 12];
        let mut rng = rand::thread_rng();
        use rand::RngCore;
        rng.fill_bytes(&mut iv);
        Ok(iv)
    }

    fn aes_gcm_encrypt(&self, _key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; plaintext.len()];
        let tag = vec![0u8; 16];

        let mut rng = rand::thread_rng();
        use rand::RngCore;
        rng.fill_bytes(&mut ciphertext);
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);

        let mut result = Vec::new();
        result.extend_from_slice(iv);
        result.extend_from_slice(&[0x05]);
        result.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&[0x06]);
        result.extend_from_slice(&(tag.len() as u16).to_be_bytes());
        result.extend_from_slice(&tag);

        Ok(result)
    }

    fn compute_tag(&self, iv: &[u8], ciphertext: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(iv);
        hasher.update(ciphertext);
        hasher.update(plaintext);
        let result = hasher.finalize();
        result[..16].to_vec()
    }

    pub fn hybrid_decrypt(
        &self,
        _classical_secret_key: &[u8],
        _pqc_secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut pos = 0;

        if ciphertext[pos..pos + 2] != [0x00, 0x01] {
            return Err(CryptoError::DecryptionFailed(
                "无效的混合密文格式".to_string(),
            ));
        }
        pos += 2;

        let pqc_key_len = u16::from_be_bytes(
            ciphertext[pos..pos + 2]
                .try_into()
                .map_err(|_| CryptoError::InvalidParameter("无效的 PQC 密钥长度".to_string()))?,
        ) as usize;
        pos += 2;
        let _pqc_public_key = &ciphertext[pos..pos + pqc_key_len];
        pos += pqc_key_len;

        if ciphertext[pos] != 0x02 {
            return Err(CryptoError::DecryptionFailed("无效的 IV 标记".to_string()));
        }
        pos += 1;

        let iv_len = u16::from_be_bytes(
            ciphertext[pos..pos + 2]
                .try_into()
                .map_err(|_| CryptoError::InvalidParameter("无效的 IV 长度".to_string()))?,
        ) as usize;
        pos += 2;
        let _iv = &ciphertext[pos..pos + iv_len];
        pos += iv_len;

        if ciphertext[pos] != 0x03 {
            return Err(CryptoError::DecryptionFailed("无效的密文标记".to_string()));
        }
        pos += 1;

        let encrypted_len = u16::from_be_bytes(
            ciphertext[pos..pos + 2]
                .try_into()
                .map_err(|_| CryptoError::InvalidParameter("无效的加密数据长度".to_string()))?,
        ) as usize;
        pos += 2;
        let encrypted = &ciphertext[pos..pos + encrypted_len];
        pos += encrypted_len;

        if ciphertext[pos] != 0x04 {
            return Err(CryptoError::DecryptionFailed("无效的标签标记".to_string()));
        }
        pos += 1;

        let tag_len = u16::from_be_bytes(
            ciphertext[pos..pos + 2]
                .try_into()
                .map_err(|_| CryptoError::InvalidParameter("无效的标签长度".to_string()))?,
        ) as usize;
        pos += 2;
        let _tag = &ciphertext[pos..pos + tag_len];

        let decrypted_len = encrypted_len.saturating_sub(16);
        let plaintext = encrypted[..decrypted_len].to_vec();

        Ok(plaintext)
    }
}

#[allow(dead_code)]
pub struct PqcUtils;

#[allow(dead_code)]
impl PqcUtils {
    pub fn get_recommended_algorithms() -> Vec<PqcAlgorithm> {
        vec![
            PqcAlgorithm::Kyber768,
            PqcAlgorithm::Dilithium3,
            PqcAlgorithm::Falcon512,
        ]
    }

    pub fn get_high_security_algorithms() -> Vec<PqcAlgorithm> {
        vec![
            PqcAlgorithm::Kyber1024,
            PqcAlgorithm::Dilithium5,
            PqcAlgorithm::SphincsSha256256f,
        ]
    }

    pub fn get_performance_optimized_algorithms() -> Vec<PqcAlgorithm> {
        vec![
            PqcAlgorithm::Kyber512,
            PqcAlgorithm::Dilithium2,
            PqcAlgorithm::SphincsSha256128f,
        ]
    }

    pub fn get_hybrid_recommendation(classical_bits: usize) -> Vec<(PqcAlgorithm, &'static str)> {
        match classical_bits {
            bits if bits <= 112 => vec![
                (PqcAlgorithm::Kyber512, "NIST Level 1"),
                (PqcAlgorithm::Dilithium2, "NIST Level 2"),
            ],
            bits if bits <= 128 => vec![
                (PqcAlgorithm::Kyber768, "NIST Level 3"),
                (PqcAlgorithm::Dilithium3, "NIST Level 3"),
            ],
            bits if bits <= 192 => vec![
                (PqcAlgorithm::Kyber1024, "NIST Level 5"),
                (PqcAlgorithm::Dilithium5, "NIST Level 5"),
            ],
            _ => vec![
                (PqcAlgorithm::Kyber1024, "NIST Level 5"),
                (PqcAlgorithm::SphincsSha256256f, "NIST Level 5"),
            ],
        }
    }

    pub fn estimate_key_size(algorithm: PqcAlgorithm, count: usize) -> usize {
        algorithm.key_size() * count
    }

    pub fn estimate_signature_size(algorithm: PqcAlgorithm) -> usize {
        match algorithm {
            PqcAlgorithm::Dilithium2 => 2420,
            PqcAlgorithm::Dilithium3 => 3293,
            PqcAlgorithm::Dilithium5 => 4595,
            PqcAlgorithm::Falcon512 => 666,
            PqcAlgorithm::Falcon1024 => 1280,
            PqcAlgorithm::SphincsSha256128f => 17088,
            PqcAlgorithm::SphincsSha256192f => 35664,
            PqcAlgorithm::SphincsSha256256f => 49856,
            _ => algorithm.key_size() * 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PqcKeyWrapper {
    wrapped_key: Vec<u8>,
    algorithm: PqcAlgorithm,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    metadata: HashMap<String, String>,
}

#[allow(dead_code)]
impl PqcKeyWrapper {
    pub fn new(wrapped_key: Vec<u8>, algorithm: PqcAlgorithm) -> Self {
        Self {
            wrapped_key,
            algorithm,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn wrap(&mut self, key: &[u8]) -> Result<()> {
        let mut wrapped = Vec::with_capacity(key.len() + 32);
        wrapped.extend_from_slice(&[0x50, 0x51, 0x43]);
        wrapped.extend_from_slice(&(self.algorithm as u8).to_be_bytes());
        let len = key.len() as u32;
        wrapped.extend_from_slice(&len.to_be_bytes());
        wrapped.extend_from_slice(key);

        let mut hasher = Sha256::new();
        hasher.update(&wrapped);
        let hash = hasher.finalize();
        wrapped.extend_from_slice(&hash[..8]);

        self.wrapped_key = wrapped;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn unwrap(&self) -> Result<Vec<u8>> {
        if self.wrapped_key.len() < 10 || self.wrapped_key[..3] != [0x50, 0x51, 0x53] {
            return Err(CryptoError::InvalidParameter(
                "无效的包装密钥格式".to_string(),
            ));
        }

        let key_len = u32::from_be_bytes(
            self.wrapped_key[4..8]
                .try_into()
                .map_err(|_| CryptoError::InvalidParameter("无效的密钥长度".to_string()))?,
        ) as usize;

        let key_start = 8;
        let key_end = key_start + key_len;

        if key_end > self.wrapped_key.len() - 8 {
            return Err(CryptoError::InvalidParameter(
                "密钥数据超出包装大小".to_string(),
            ));
        }

        let key = self.wrapped_key[key_start..key_end].to_vec();
        let stored_hash = &self.wrapped_key[key_end..key_end + 8];

        let mut hasher = Sha256::new();
        hasher.update(&self.wrapped_key[..key_end]);
        let computed_hash = hasher.finalize();

        if stored_hash != &computed_hash[..8] {
            return Err(CryptoError::SecurityError(
                "包装密钥完整性检查失败".to_string(),
            ));
        }

        Ok(key)
    }
}
