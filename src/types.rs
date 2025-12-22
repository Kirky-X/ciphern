// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    // Symmetric Encryption (FIPS Approved)
    #[cfg(feature = "encrypt")]
    AES128GCM,
    #[cfg(feature = "encrypt")]
    AES192GCM,
    #[cfg(feature = "encrypt")]
    AES256GCM,

    // Symmetric Encryption (Non-FIPS)
    #[cfg(feature = "encrypt")]
    SM4GCM,

    // Asymmetric Encryption/Signature (FIPS Approved)
    #[cfg(feature = "encrypt")]
    ECDSAP256,
    #[cfg(feature = "encrypt")]
    ECDSAP384,
    #[cfg(feature = "encrypt")]
    ECDSAP521,
    #[cfg(feature = "encrypt")]
    RSA2048,
    #[cfg(feature = "encrypt")]
    RSA3072,
    #[cfg(feature = "encrypt")]
    RSA4096,

    // Asymmetric Encryption/Signature (Non-FIPS)
    #[cfg(feature = "encrypt")]
    SM2,
    #[cfg(feature = "encrypt")]
    Ed25519,

    // Hash Functions (FIPS Approved)
    #[cfg(feature = "hash")]
    SHA256,
    #[cfg(feature = "hash")]
    SHA384,
    #[cfg(feature = "hash")]
    SHA512,
    #[cfg(feature = "hash")]
    SHA3_256,
    #[cfg(feature = "hash")]
    SHA3_384,
    #[cfg(feature = "hash")]
    SHA3_512,

    // Hash Functions (Non-FIPS)
    #[cfg(feature = "hash")]
    SM3,

    // Key Derivation Functions (FIPS Approved)
    #[cfg(feature = "kdf")]
    HKDF,
    #[cfg(feature = "kdf")]
    PBKDF2,

    // Key Derivation Functions (Non-FIPS)
    #[cfg(feature = "kdf")]
    Sm3Kdf,
    #[cfg(feature = "kdf")]
    Argon2id,
}

impl Algorithm {
    pub fn key_size(&self) -> usize {
        match self {
            // Symmetric Encryption
            #[cfg(feature = "encrypt")]
            Algorithm::AES128GCM => 16,
            #[cfg(feature = "encrypt")]
            Algorithm::AES192GCM => 24,
            #[cfg(feature = "encrypt")]
            Algorithm::AES256GCM => 32,
            #[cfg(feature = "encrypt")]
            Algorithm::SM4GCM => 16,

            // Asymmetric (approximate private key sizes)
            #[cfg(feature = "encrypt")]
            Algorithm::ECDSAP256 => 32,
            #[cfg(feature = "encrypt")]
            Algorithm::ECDSAP384 => 48,
            #[cfg(feature = "encrypt")]
            Algorithm::ECDSAP521 => 66,
            #[cfg(feature = "encrypt")]
            Algorithm::RSA2048 => 2048,
            #[cfg(feature = "encrypt")]
            Algorithm::RSA3072 => 3072,
            #[cfg(feature = "encrypt")]
            Algorithm::RSA4096 => 4096,
            #[cfg(feature = "encrypt")]
            Algorithm::SM2 => 32,
            #[cfg(feature = "encrypt")]
            Algorithm::Ed25519 => 32,

            // Hash functions (no key)
            #[cfg(feature = "hash")]
            Algorithm::SHA256
            | Algorithm::SHA384
            | Algorithm::SHA512
            | Algorithm::SHA3_256
            | Algorithm::SHA3_384
            | Algorithm::SHA3_512
            | Algorithm::SM3 => 0,

            // KDF (no key)
            #[cfg(feature = "kdf")]
            Algorithm::HKDF | Algorithm::PBKDF2 | Algorithm::Sm3Kdf | Algorithm::Argon2id => 0,
        }
    }

    pub fn is_symmetric(&self) -> bool {
        #[cfg(feature = "encrypt")]
        return matches!(
            self,
            Self::AES128GCM | Self::AES192GCM | Self::AES256GCM | Self::SM4GCM
        );
        #[cfg(not(feature = "encrypt"))]
        return false;
    }

    pub fn is_fips_approved(&self) -> bool {
        match self {
            // FIPS Approved Symmetric
            #[cfg(feature = "encrypt")]
            Self::AES128GCM | Self::AES192GCM | Self::AES256GCM => true,
            // FIPS Approved Asymmetric  
            #[cfg(feature = "encrypt")]
            Self::ECDSAP256 | Self::ECDSAP384 | Self::ECDSAP521 |
            Self::RSA2048 | Self::RSA3072 | Self::RSA4096 => true,
            // FIPS Approved Hash
            #[cfg(feature = "hash")]
            Self::SHA256 | Self::SHA384 | Self::SHA512 |
            Self::SHA3_256 | Self::SHA3_384 | Self::SHA3_512 => true,
            // FIPS Approved KDF
            #[cfg(feature = "kdf")]
            Self::HKDF | Self::PBKDF2 => true,
            _ => false,
        }
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
