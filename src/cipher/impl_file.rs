// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::cipher::struct_file::{AesGcmProvider, Sm4GcmProvider};
use crate::error::{CryptoError, Result};
use crate::key::Key;
use crate::provider::SymmetricCipher;
use crate::random::SecureRandom;
use crate::side_channel::{
    RotatingSboxMasking, SideChannelConfig, SideChannelContext,
};
use crate::types::Algorithm;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{aes::Aes192, AeadCore, AesGcm};
use std::sync::{Arc, Mutex};

// === AesGcmProvider Implementation ===

impl AesGcmProvider {
    pub fn new() -> Self {
        let side_channel_context = Some(Arc::new(Mutex::new(SideChannelContext::new(
            SideChannelConfig::default(),
        ))));
        let rotating_sbox = RotatingSboxMasking::new(4)
            .ok()
            .map(|sbox| Arc::new(Mutex::new(sbox)));

        Self {
            side_channel_context,
            rotating_sbox,
        }
    }

    pub fn with_side_channel_config(config: SideChannelConfig) -> Self {
        let rotating_sbox = if config.power_analysis_protection {
            RotatingSboxMasking::new(4)
                .ok()
                .map(|sbox| Arc::new(Mutex::new(sbox)))
        } else {
            None
        };

        Self {
            side_channel_context: Some(Arc::new(Mutex::new(SideChannelContext::new(config)))),
            rotating_sbox,
        }
    }

    fn encrypt_core(&self, algorithm: Algorithm, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let secret = key.secret_bytes()?;

        match algorithm {
            Algorithm::AES128GCM => {
                let unbound_key = UnboundKey::new(&AES_128_GCM, secret.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                let less_safe_key = LessSafeKey::new(unbound_key);

                let mut nonce_bytes = [0u8; 12];
                SecureRandom::new()?.fill(&mut nonce_bytes)?;
                let nonce = Nonce::assume_unique_for_key(nonce_bytes);

                let mut in_out = plaintext.to_vec();
                less_safe_key
                    .seal_in_place_append_tag(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
                    .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

                let mut result = nonce_bytes.to_vec();
                result.append(&mut in_out);
                Ok(result)
            }
            Algorithm::AES192GCM => {
                let cipher = AesGcm::<Aes192, U12>::new_from_slice(secret.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;

                let nonce = AesGcm::<Aes192, U12>::generate_nonce(&mut SecureRandom::new()?);

                let ciphertext = cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: plaintext,
                            aad: aad.unwrap_or(&[]),
                        },
                    )
                    .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))?;

                let mut result = nonce.to_vec();
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
            Algorithm::AES256GCM => {
                let unbound_key = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                let less_safe_key = LessSafeKey::new(unbound_key);

                let mut nonce_bytes = [0u8; 12];
                SecureRandom::new()?.fill(&mut nonce_bytes)?;
                let nonce = Nonce::assume_unique_for_key(nonce_bytes);

                let mut in_out = plaintext.to_vec();
                less_safe_key
                    .seal_in_place_append_tag(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
                    .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

                let mut result = nonce_bytes.to_vec();
                result.append(&mut in_out);
                Ok(result)
            }
            _ => Err(CryptoError::UnsupportedAlgorithm(format!("{:?}", algorithm))),
        }
    }

    fn decrypt_core(&self, algorithm: Algorithm, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let secret = key.secret_bytes()?;

        match algorithm {
            Algorithm::AES128GCM => {
                let unbound_key = UnboundKey::new(&AES_128_GCM, secret.as_bytes())
                    .map_err(|_| CryptoError::DecryptionFailed("Invalid Key".into()))?;
                let less_safe_key = LessSafeKey::new(unbound_key);

                if ciphertext.len() < 12 {
                    return Err(CryptoError::DecryptionFailed("Invalid ciphertext length".into()));
                }

                let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
                let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());

                let mut in_out = encrypted_data.to_vec();
                let plaintext = less_safe_key
                    .open_in_place(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
                    .map_err(|_| CryptoError::DecryptionFailed("Open failed".into()))?;

                Ok(plaintext.to_vec())
            }
            Algorithm::AES192GCM => {
                let cipher = AesGcm::<Aes192, U12>::new_from_slice(secret.as_bytes())
                    .map_err(|_| CryptoError::DecryptionFailed("Invalid Key".into()))?;

                if ciphertext.len() < 12 {
                    return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
                }

                let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
                let nonce = nonce_bytes.into();

                let plaintext = cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: encrypted_data,
                            aad: aad.unwrap_or(&[]),
                        },
                    )
                    .map_err(|_| CryptoError::DecryptionFailed("Decryption failed".into()))?;

                Ok(plaintext)
            }
            Algorithm::AES256GCM => {
                let unbound_key = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
                    .map_err(|_| CryptoError::DecryptionFailed("Invalid Key".into()))?;
                let less_safe_key = LessSafeKey::new(unbound_key);

                if ciphertext.len() < 12 {
                    return Err(CryptoError::DecryptionFailed("Invalid ciphertext length".into()));
                }

                let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
                let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());

                let mut in_out = encrypted_data.to_vec();
                let plaintext = less_safe_key
                    .open_in_place(nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
                    .map_err(|_| CryptoError::DecryptionFailed("Open failed".into()))?;

                Ok(plaintext.to_vec())
            }
            _ => Err(CryptoError::UnsupportedAlgorithm(format!("{:?}", algorithm))),
        }
    }
}

impl SymmetricCipher for AesGcmProvider {
    fn encrypt(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        self.encrypt_core(key.algorithm(), key, plaintext, aad)
    }

    fn decrypt(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        self.decrypt_core(key.algorithm(), key, ciphertext, aad)
    }

    fn encrypt_with_nonce(
        &self,
        key: &Key,
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let secret = key.secret_bytes()?;
        match key.algorithm() {
            Algorithm::AES128GCM => {
                let unbound_key = UnboundKey::new(&AES_128_GCM, secret.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                let less_safe_key = LessSafeKey::new(unbound_key);
                let ring_nonce = Nonce::assume_unique_for_key(nonce.try_into().map_err(|_| CryptoError::InvalidParameter("Invalid nonce length".into()))?);

                let mut in_out = plaintext.to_vec();
                less_safe_key
                    .seal_in_place_append_tag(ring_nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
                    .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

                Ok(in_out)
            }
            Algorithm::AES192GCM => {
                let cipher = AesGcm::<Aes192, U12>::new_from_slice(secret.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                let aes_nonce = nonce.into();

                let ciphertext = cipher
                    .encrypt(
                        aes_nonce,
                        Payload {
                            msg: plaintext,
                            aad: aad.unwrap_or(&[]),
                        },
                    )
                    .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".into()))?;

                Ok(ciphertext)
            }
            Algorithm::AES256GCM => {
                let unbound_key = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed("Invalid Key".into()))?;
                let less_safe_key = LessSafeKey::new(unbound_key);
                let ring_nonce = Nonce::assume_unique_for_key(nonce.try_into().map_err(|_| CryptoError::InvalidParameter("Invalid nonce length".into()))?);

                let mut in_out = plaintext.to_vec();
                less_safe_key
                    .seal_in_place_append_tag(ring_nonce, Aad::from(aad.unwrap_or(&[])), &mut in_out)
                    .map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;

                Ok(in_out)
            }
            _ => Err(CryptoError::UnsupportedAlgorithm(format!("{:?}", key.algorithm()))),
        }
    }
}

// === Sm4GcmProvider Implementation ===

impl Sm4GcmProvider {
    pub fn new() -> Self {
        let side_channel_context = Some(Arc::new(Mutex::new(SideChannelContext::new(
            SideChannelConfig::default(),
        ))));
        let rotating_sbox = RotatingSboxMasking::new(4)
            .ok()
            .map(|sbox| Arc::new(Mutex::new(sbox)));

        Self {
            side_channel_context,
            rotating_sbox,
        }
    }

    pub fn with_side_channel_config(config: SideChannelConfig) -> Self {
        let side_channel_context = Some(Arc::new(Mutex::new(SideChannelContext::new(config))));
        let rotating_sbox = RotatingSboxMasking::new(4)
            .ok()
            .map(|sbox| Arc::new(Mutex::new(sbox)));

        Self {
            side_channel_context,
            rotating_sbox,
        }
    }
}

impl SymmetricCipher for Sm4GcmProvider {
    fn encrypt(&self, key: &Key, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        SecureRandom::new()?.fill(&mut nonce)?;
        let mut ciphertext = self.encrypt_with_nonce(key, plaintext, &nonce, aad)?;
        let mut result = nonce.to_vec();
        result.append(&mut ciphertext);
        Ok(result)
    }

    fn decrypt(&self, key: &Key, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionFailed("Invalid ciphertext length".into()));
        }
        let (nonce, data) = ciphertext.split_at(12);
        self.decrypt_with_nonce(key, data, nonce, aad)
    }

    fn encrypt_with_nonce(
        &self,
        key: &Key,
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use ghash::{universal_hash::{KeyInit, UniversalHash}, GHash};
        use sm4::cipher::{KeyIvInit, StreamCipher};
        use sm4::Sm4;

        let secret = key.secret_bytes()?;
        let key_bytes: [u8; 16] = secret.as_bytes().try_into().map_err(|_| {
            CryptoError::KeyError("Invalid SM4 key length".into())
        })?;

        let mut ghash = GHash::new(&key_bytes.into());
        if let Some(a) = aad {
            if !a.is_empty() {
                ghash.update_padded(a);
            }
        }

        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[15] = 2;

        let mut ciphertext = plaintext.to_vec();
        type Sm4Ctr = ctr::Ctr128BE<Sm4>;
        let mut cipher = Sm4Ctr::new(&key_bytes.into(), &iv.into());
        cipher.apply_keystream(&mut ciphertext);

        ghash.update_padded(&ciphertext);

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(aad.unwrap_or(&[]).len() as u64 * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(ciphertext.len() as u64 * 8).to_be_bytes());
        ghash.update(&lengths.into());

        let mut tag = ghash.finalize();

        let mut iv_tag = [0u8; 16];
        iv_tag[..12].copy_from_slice(nonce);
        iv_tag[15] = 1;
        let mut tag_mask = [0u8; 16];
        let mut cipher_tag = Sm4Ctr::new(&key_bytes.into(), &iv_tag.into());
        cipher_tag.apply_keystream(&mut tag_mask);

        for i in 0..16 {
            tag[i] ^= tag_mask[i];
        }

        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    fn decrypt_with_nonce(
        &self,
        key: &Key,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::DecryptionFailed("Ciphertext too short for tag".into()));
        }

        let (data, tag) = ciphertext.split_at(ciphertext.len() - 16);
        
        use ghash::{universal_hash::{KeyInit, UniversalHash}, GHash};
        use sm4::cipher::{KeyIvInit, StreamCipher};
        use sm4::Sm4;

        let secret = key.secret_bytes()?;
        let key_bytes: [u8; 16] = secret.as_bytes().try_into().map_err(|_| {
            CryptoError::KeyError("Invalid SM4 key length".into())
        })?;

        let mut ghash = GHash::new(&key_bytes.into());
        if let Some(a) = aad {
            if !a.is_empty() {
                ghash.update_padded(a);
            }
        }
        ghash.update_padded(data);

        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(aad.unwrap_or(&[]).len() as u64 * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(data.len() as u64 * 8).to_be_bytes());
        ghash.update(&lengths.into());

        let mut expected_tag = ghash.finalize();
        let mut iv_tag = [0u8; 16];
        iv_tag[..12].copy_from_slice(nonce);
        iv_tag[15] = 1;
        let mut tag_mask = [0u8; 16];
        type Sm4Ctr = ctr::Ctr128BE<Sm4>;
        let mut cipher_tag = Sm4Ctr::new(&key_bytes.into(), &iv_tag.into());
        cipher_tag.apply_keystream(&mut tag_mask);

        for i in 0..16 {
            expected_tag[i] ^= tag_mask[i];
        }

        if tag != expected_tag.as_slice() {
            return Err(CryptoError::DecryptionFailed("Tag mismatch".into()));
        }

        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[15] = 2;

        let mut plaintext = data.to_vec();
        let mut cipher = Sm4Ctr::new(&key_bytes.into(), &iv.into());
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}
