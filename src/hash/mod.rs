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
    hasher: Box<dyn HashAlgorithm>,
}

#[allow(dead_code)]
impl MultiHash {
    pub fn new(algorithm: AlgorithmType) -> Result<Self> {
        let hasher: Box<dyn HashAlgorithm> = match algorithm {
            AlgorithmType::Sha256 => Box::new(Sha256Hasher::new()),
            AlgorithmType::Sha384 => Box::new(Sha384Hasher::new()),
            AlgorithmType::Sha512 => Box::new(Sha512Hasher::new()),
            AlgorithmType::Sm3 => Box::new(Sm3Hasher::new()),
        };

        Ok(Self { algorithm, hasher })
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
