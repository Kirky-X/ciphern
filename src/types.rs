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

            // Asymmetric (approximate private key sizes)
            Algorithm::ECDSAP256 => 32,
            Algorithm::ECDSAP384 => 48,
            Algorithm::ECDSAP521 => 66,
            Algorithm::RSA2048 => 2048,
            Algorithm::RSA3072 => 3072,
            Algorithm::RSA4096 => 4096,
            Algorithm::SM2 => 32,
            Algorithm::Ed25519 => 32,

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

    pub fn is_symmetric(&self) -> bool {
        matches!(
            self,
            Self::AES128GCM | Self::AES192GCM | Self::AES256GCM | Self::SM4GCM
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
            Self::ECDSAP256 => "ECDSA-P256",
            Self::ECDSAP384 => "ECDSA-P384",
            Self::ECDSAP521 => "ECDSA-P521",
            Self::RSA2048 => "RSA-2048",
            Self::RSA3072 => "RSA-3072",
            Self::RSA4096 => "RSA-4096",
            Self::SM2 => "SM2",
            Self::Ed25519 => "Ed25519",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    Pending,
    Active,
    Rotating,
    Deprecated,
    Destroyed,
}
