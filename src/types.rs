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
            Algorithm::SHA256 | Algorithm::SHA384 | Algorithm::SHA512 |
            Algorithm::SHA3_256 | Algorithm::SHA3_384 | Algorithm::SHA3_512 |
            Algorithm::SM3 => 0,
            
            // KDF (no key)
            Algorithm::HKDF | Algorithm::PBKDF2 | Algorithm::Sm3Kdf | Algorithm::Argon2id => 0,
        }
    }

    pub fn is_symmetric(&self) -> bool {
        matches!(self, 
            Algorithm::AES128GCM | Algorithm::AES192GCM | 
            Algorithm::AES256GCM | Algorithm::SM4GCM
        )
    }
    
    pub fn is_fips_approved(&self) -> bool {
        matches!(self,
            // FIPS Approved Symmetric
            Algorithm::AES128GCM | Algorithm::AES192GCM | Algorithm::AES256GCM |
            // FIPS Approved Asymmetric  
            Algorithm::ECDSAP256 | Algorithm::ECDSAP384 | Algorithm::ECDSAP521 |
            Algorithm::RSA2048 | Algorithm::RSA3072 | Algorithm::RSA4096 |
            // FIPS Approved Hash
            Algorithm::SHA256 | Algorithm::SHA384 | Algorithm::SHA512 |
            Algorithm::SHA3_256 | Algorithm::SHA3_384 | Algorithm::SHA3_512 |
            // FIPS Approved KDF
            Algorithm::HKDF | Algorithm::PBKDF2
        )
    }
    
    pub fn is_national_standard(&self) -> bool {
        matches!(self, Algorithm::SM2 | Algorithm::SM3 | Algorithm::SM4GCM | Algorithm::Sm3Kdf)
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