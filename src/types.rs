// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    // Symmetric Encryption (FIPS Approved)
    AES128GCM,
    AES192GCM,
    AES256GCM,

    // Symmetric Encryption (Non-FIPS)
    SM4GCM,
    ChaCha20Poly1305, // Modern AEAD encryption (software-optimized)

    // Asymmetric Encryption/Signature (FIPS Approved)
    ECDSAP256,
    ECDSAP384,
    ECDSAP521,
    RSA2048,
    RSA3072,
    RSA4096,

    // Asymmetric Encryption/Signature (Non-FIPS)
    SM2,
    Ed25519,
    X25519, // Key exchange algorithm

    // Hash Functions (FIPS Approved)
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,

    // Hash Functions (Non-FIPS)
    SM3,

    // Key Derivation Functions (FIPS Approved)
    HKDF,
    PBKDF2,

    // Key Derivation Functions (Non-FIPS)
    Sm3Kdf,
    Argon2id,
}

impl Algorithm {
    pub fn key_size(&self) -> usize {
        match self {
            // Symmetric Encryption
            Algorithm::AES128GCM => 16,
            Algorithm::AES192GCM => 24,
            Algorithm::AES256GCM => 32,
            Algorithm::SM4GCM => 16,
            Algorithm::ChaCha20Poly1305 => 32, // 256-bit key

            // Asymmetric (approximate private key sizes)
            Algorithm::ECDSAP256 => 32,
            Algorithm::ECDSAP384 => 48,
            Algorithm::ECDSAP521 => 66,
            Algorithm::RSA2048 => 2048,
            Algorithm::RSA3072 => 3072,
            Algorithm::RSA4096 => 4096,
            Algorithm::SM2 => 32,
            Algorithm::Ed25519 => 32,
            Algorithm::X25519 => 32, // X25519 uses 32-byte private keys

            // Hash functions (no key)
            Algorithm::SHA256
            | Algorithm::SHA384
            | Algorithm::SHA512
            | Algorithm::SHA3_256
            | Algorithm::SHA3_384
            | Algorithm::SHA3_512
            | Algorithm::SM3 => 0,

            // KDF (no key)
            Algorithm::HKDF | Algorithm::PBKDF2 | Algorithm::Sm3Kdf | Algorithm::Argon2id => 0,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            // Symmetric Encryption
            Algorithm::AES128GCM => 12,
            Algorithm::AES192GCM => 12,
            Algorithm::AES256GCM => 12,
            Algorithm::SM4GCM => 12,
            Algorithm::ChaCha20Poly1305 => 12,

            // Other algorithms don't use nonces
            _ => 0,
        }
    }

    pub fn is_symmetric(&self) -> bool {
        matches!(
            self,
            Self::AES128GCM
                | Self::AES192GCM
                | Self::AES256GCM
                | Self::SM4GCM
                | Self::ChaCha20Poly1305
        )
    }

    pub fn is_fips_approved(&self) -> bool {
        matches!(
            self,
            // FIPS Approved Symmetric
            Self::AES128GCM | Self::AES192GCM | Self::AES256GCM |
            // FIPS Approved Asymmetric
            Self::ECDSAP256 | Self::ECDSAP384 | Self::ECDSAP521 |
            Self::RSA2048 | Self::RSA3072 | Self::RSA4096 |
            // FIPS Approved Hash
            Self::SHA256 | Self::SHA384 | Self::SHA512 |
            Self::SHA3_256 | Self::SHA3_384 | Self::SHA3_512 |
            // FIPS Approved KDF
            Self::HKDF | Self::PBKDF2
        )
    }

    #[must_use]
    pub const fn is_national_standard(&self) -> bool {
        matches!(self, Self::SM2 | Self::SM3 | Self::SM4GCM | Self::Sm3Kdf)
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::AES128GCM => "AES-128-GCM",
            Self::AES192GCM => "AES-192-GCM",
            Self::AES256GCM => "AES-256-GCM",
            Self::SM4GCM => "SM4-GCM",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::ECDSAP256 => "ECDSA-P256",
            Self::ECDSAP384 => "ECDSA-P384",
            Self::ECDSAP521 => "ECDSA-P521",
            Self::RSA2048 => "RSA-2048",
            Self::RSA3072 => "RSA-3072",
            Self::RSA4096 => "RSA-4096",
            Self::SM2 => "SM2",
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
            Self::SHA256 => "SHA-256",
            Self::SHA384 => "SHA-384",
            Self::SHA512 => "SHA-512",
            Self::SHA3_256 => "SHA3-256",
            Self::SHA3_384 => "SHA3-384",
            Self::SHA3_512 => "SHA3-512",
            Self::SM3 => "SM3",
            Self::HKDF => "HKDF",
            Self::PBKDF2 => "PBKDF2",
            Self::Sm3Kdf => "SM3-KDF",
            Self::Argon2id => "Argon2id",
        };
        write!(f, "{name}")
    }
}

/// 密钥状态枚举
///
/// 表示密钥在其生命周期中的不同状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyState {
    /// 密钥已生成，等待激活
    Generated,
    /// 密钥已激活，可以使用
    Active,
    /// 密钥已暂停，不能使用
    Suspended,
    /// 密钥正在轮换
    Rotating,
    /// 密钥已弃用
    Deprecated,
    /// 密钥已销毁，不能再使用
    Destroyed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_display() {
        assert_eq!(format!("{}", Algorithm::AES128GCM), "AES-128-GCM");
        assert_eq!(format!("{}", Algorithm::AES256GCM), "AES-256-GCM");
        assert_eq!(
            format!("{}", Algorithm::ChaCha20Poly1305),
            "ChaCha20-Poly1305"
        );
        assert_eq!(format!("{}", Algorithm::SM4GCM), "SM4-GCM");
        assert_eq!(format!("{}", Algorithm::RSA2048), "RSA-2048");
        assert_eq!(format!("{}", Algorithm::RSA4096), "RSA-4096");
        assert_eq!(format!("{}", Algorithm::ECDSAP256), "ECDSA-P256");
        assert_eq!(format!("{}", Algorithm::ECDSAP384), "ECDSA-P384");
        assert_eq!(format!("{}", Algorithm::Ed25519), "Ed25519");
        assert_eq!(format!("{}", Algorithm::SM2), "SM2");
        assert_eq!(format!("{}", Algorithm::X25519), "X25519");
    }

    #[test]
    fn test_algorithm_key_size() {
        assert_eq!(Algorithm::AES128GCM.key_size(), 16);
        assert_eq!(Algorithm::AES256GCM.key_size(), 32);
        assert_eq!(Algorithm::ChaCha20Poly1305.key_size(), 32);
        assert_eq!(Algorithm::SM4GCM.key_size(), 16);
    }

    #[test]
    fn test_algorithm_nonce_size() {
        assert_eq!(Algorithm::AES128GCM.nonce_size(), 12);
        assert_eq!(Algorithm::AES256GCM.nonce_size(), 12);
        assert_eq!(Algorithm::ChaCha20Poly1305.nonce_size(), 12);
        assert_eq!(Algorithm::SM4GCM.nonce_size(), 12);
    }

    #[test]
    fn test_key_state_transitions() {
        // 测试密钥状态转换
        let mut state = KeyState::Generated;
        assert_eq!(state, KeyState::Generated);

        state = KeyState::Active;
        assert_eq!(state, KeyState::Active);

        state = KeyState::Suspended;
        assert_eq!(state, KeyState::Suspended);

        state = KeyState::Rotating;
        assert_eq!(state, KeyState::Rotating);

        state = KeyState::Deprecated;
        assert_eq!(state, KeyState::Deprecated);

        state = KeyState::Destroyed;
        assert_eq!(state, KeyState::Destroyed);
    }

    #[test]
    fn test_key_state_serialization() {
        // 测试序列化和反序列化
        let state = KeyState::Active;
        let serialized = serde_json::to_string(&state).unwrap();
        let deserialized: KeyState = serde_json::from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn test_algorithm_equality() {
        assert_eq!(Algorithm::AES128GCM, Algorithm::AES128GCM);
        assert_ne!(Algorithm::AES128GCM, Algorithm::AES256GCM);
    }

    #[test]
    fn test_algorithm_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Algorithm::AES128GCM);
        set.insert(Algorithm::AES256GCM);
        set.insert(Algorithm::ChaCha20Poly1305);
        assert_eq!(set.len(), 3);
    }
}
