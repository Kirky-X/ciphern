// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::Result;
use sha2::Digest;

#[allow(dead_code)]
pub trait HashAlgorithm: Send + Sync {
    fn name(&self) -> &'static str;
    fn output_size(&self) -> usize;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
    fn reset(&mut self);
}

pub enum AnyHash {
    Sha256(Sha256Hasher),
    Sha384(Sha384Hasher),
    Sha512(Sha512Hasher),
    Sm3(Sm3Hasher),
}

impl AnyHash {
    pub fn new(algorithm: AlgorithmType) -> Self {
        match algorithm {
            AlgorithmType::Sha256 => AnyHash::Sha256(Sha256Hasher::new()),
            AlgorithmType::Sha384 => AnyHash::Sha384(Sha384Hasher::new()),
            AlgorithmType::Sha512 => AnyHash::Sha512(Sha512Hasher::new()),
            AlgorithmType::Sm3 => AnyHash::Sm3(Sm3Hasher::new()),
        }
    }
}

impl HashAlgorithm for AnyHash {
    fn name(&self) -> &'static str {
        match self {
            AnyHash::Sha256(h) => h.name(),
            AnyHash::Sha384(h) => h.name(),
            AnyHash::Sha512(h) => h.name(),
            AnyHash::Sm3(h) => h.name(),
        }
    }

    fn output_size(&self) -> usize {
        match self {
            AnyHash::Sha256(h) => h.output_size(),
            AnyHash::Sha384(h) => h.output_size(),
            AnyHash::Sha512(h) => h.output_size(),
            AnyHash::Sm3(h) => h.output_size(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            AnyHash::Sha256(h) => h.update(data),
            AnyHash::Sha384(h) => h.update(data),
            AnyHash::Sha512(h) => h.update(data),
            AnyHash::Sm3(h) => h.update(data),
        }
    }

    fn finalize(&mut self) -> Vec<u8> {
        match self {
            AnyHash::Sha256(h) => h.finalize(),
            AnyHash::Sha384(h) => h.finalize(),
            AnyHash::Sha512(h) => h.finalize(),
            AnyHash::Sm3(h) => h.finalize(),
        }
    }

    fn reset(&mut self) {
        match self {
            AnyHash::Sha256(h) => h.reset(),
            AnyHash::Sha384(h) => h.reset(),
            AnyHash::Sha512(h) => h.reset(),
            AnyHash::Sm3(h) => h.reset(),
        }
    }
}

impl Clone for AnyHash {
    fn clone(&self) -> Self {
        Self::new(self.algorithm())
    }
}

impl AnyHash {
    fn algorithm(&self) -> AlgorithmType {
        match self {
            AnyHash::Sha256(_) => AlgorithmType::Sha256,
            AnyHash::Sha384(_) => AlgorithmType::Sha384,
            AnyHash::Sha512(_) => AlgorithmType::Sha512,
            AnyHash::Sm3(_) => AlgorithmType::Sm3,
        }
    }
}

pub struct Sha256Hasher {
    hasher: sha2::Sha256,
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Self {
            hasher: Digest::new(),
        }
    }
}

impl Clone for Sha256Hasher {
    fn clone(&self) -> Self {
        Self {
            hasher: Digest::new(),
        }
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl HashAlgorithm for Sha256Hasher {
    fn name(&self) -> &'static str {
        "SHA-256"
    }

    fn output_size(&self) -> usize {
        32
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        self.hasher.finalize_reset().to_vec()
    }

    fn reset(&mut self) {
        self.hasher.reset();
    }
}

pub struct Sha384Hasher {
    hasher: sha2::Sha384,
}

impl Sha384Hasher {
    pub fn new() -> Self {
        Self {
            hasher: Digest::new(),
        }
    }
}

impl Clone for Sha384Hasher {
    fn clone(&self) -> Self {
        Self {
            hasher: Digest::new(),
        }
    }
}

impl Default for Sha384Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl HashAlgorithm for Sha384Hasher {
    fn name(&self) -> &'static str {
        "SHA-384"
    }

    fn output_size(&self) -> usize {
        48
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        self.hasher.finalize_reset().to_vec()
    }

    fn reset(&mut self) {
        self.hasher.reset();
    }
}

pub struct Sha512Hasher {
    hasher: sha2::Sha512,
}

impl Sha512Hasher {
    pub fn new() -> Self {
        Self {
            hasher: Digest::new(),
        }
    }
}

impl Clone for Sha512Hasher {
    fn clone(&self) -> Self {
        Self {
            hasher: Digest::new(),
        }
    }
}

impl Default for Sha512Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl HashAlgorithm for Sha512Hasher {
    fn name(&self) -> &'static str {
        "SHA-512"
    }

    fn output_size(&self) -> usize {
        64
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        self.hasher.finalize_reset().to_vec()
    }

    fn reset(&mut self) {
        self.hasher.reset();
    }
}

pub struct Sm3Hasher {
    hasher: libsm::sm3::hash::Sm3Hash,
    buffer: Vec<u8>,
}

impl Sm3Hasher {
    pub fn new() -> Self {
        Self {
            hasher: libsm::sm3::hash::Sm3Hash::new(&[]),
            buffer: Vec::new(),
        }
    }
}

impl Clone for Sm3Hasher {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Default for Sm3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl HashAlgorithm for Sm3Hasher {
    fn name(&self) -> &'static str {
        "SM3"
    }

    fn output_size(&self) -> usize {
        32
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        self.hasher = libsm::sm3::hash::Sm3Hash::new(&self.buffer);
    }

    fn finalize(&mut self) -> Vec<u8> {
        let result = self.hasher.get_hash().to_vec();
        self.buffer.clear();
        self.hasher = libsm::sm3::hash::Sm3Hash::new(&[]);
        result
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.hasher = libsm::sm3::hash::Sm3Hash::new(&[]);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgorithmType {
    Sha256,
    Sha384,
    Sha512,
    Sm3,
}

#[allow(dead_code)]
pub struct MultiHash {
    algorithm: AlgorithmType,
    hasher: AnyHash,
}

#[allow(dead_code)]
impl MultiHash {
    pub fn new(algorithm: AlgorithmType) -> Result<Self> {
        Ok(Self {
            algorithm,
            hasher: AnyHash::new(algorithm),
        })
    }

    pub fn algorithm(&self) -> AlgorithmType {
        self.algorithm
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        self.hasher.finalize()
    }

    pub fn output_size(&self) -> usize {
        self.hasher.output_size()
    }

    pub fn reset(&mut self) {
        self.hasher.reset();
    }

    pub fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm,
            hasher: self.hasher.clone(),
        }
    }
}

#[allow(dead_code)]
pub struct IncrementalHash {
    multi_hash: MultiHash,
}

#[allow(dead_code)]
impl IncrementalHash {
    pub fn new(algorithm: AlgorithmType) -> Result<Self> {
        Ok(Self {
            multi_hash: MultiHash::new(algorithm)?,
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.multi_hash.update(data);
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        self.multi_hash.finalize()
    }

    pub fn reset(&mut self) {
        self.multi_hash.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let mut hasher = Sha256Hasher::new();
        hasher.update(data);
        let result = hasher.finalize();

        let expected = hex::encode(&result);
        assert_eq!(
            expected,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha384() {
        let data = b"hello world";
        let mut hasher = Sha384Hasher::new();
        hasher.update(data);
        let result = hasher.finalize();

        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha512() {
        let data = b"hello world";
        let mut hasher = Sha512Hasher::new();
        hasher.update(data);
        let result = hasher.finalize();

        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_sm3() {
        let data = b"hello world";
        let mut hasher = Sm3Hasher::new();
        hasher.update(data);
        let result = hasher.finalize();

        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_multi_hash_sha256() {
        let data = b"hello world";
        let mut hasher = MultiHash::new(AlgorithmType::Sha256).unwrap();
        hasher.update(data);
        let result = hasher.finalize();

        let expected = hex::encode(&result);
        assert_eq!(
            expected,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_multi_hash_sm3() {
        let data = b"hello world";
        let mut hasher = MultiHash::new(AlgorithmType::Sm3).unwrap();
        hasher.update(data);
        let result = hasher.finalize();

        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_incremental_hash() {
        let data_parts: [&[u8]; 3] = [b"hello", b" ", b"world"];
        let mut hasher = IncrementalHash::new(AlgorithmType::Sha256).unwrap();

        for &part in &data_parts {
            hasher.update(part);
        }

        let result = hasher.finalize();

        let expected = hex::encode(&result);
        assert_eq!(
            expected,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
