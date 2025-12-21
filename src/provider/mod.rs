// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

pub mod registry;

use crate::types::Algorithm;
use crate::key::Key;
use crate::error::Result;

pub trait SymmetricCipher: Send + Sync {
    fn encrypt(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
    fn decrypt(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
    fn algorithm(&self) -> Algorithm;
}

pub trait Signer: Send + Sync {
    fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, key: &Key, message: &[u8], signature: &[u8]) -> Result<bool>;
}