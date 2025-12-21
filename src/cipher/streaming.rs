// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.


use crate::types::Algorithm;
use crate::key::Key;
use crate::error::{CryptoError, Result};
use crate::random::SecureRandom;
use crate::side_channel::{SideChannelConfig, SideChannelContext, protect_critical_operation};
use std::sync::{Arc, Mutex};

/// 流式加密器 - 支持大文件分块加密
pub struct StreamingCipher {
    algorithm: Algorithm,
    key: Option<Key>,
    context: Option<Arc<Mutex<SideChannelContext>>>,
    buffer: Vec<u8>,
    chunk_size: usize,
    is_initialized: bool,
    total_processed: usize,
    nonce: Option<Vec<u8>>,
    /// 用于解密的认证标签缓冲区
    tag_buffer: Vec<u8>,
    /// 当前模式：true表示加密，false表示解密
    encrypt_mode: Option<bool>,
}

impl StreamingCipher {
    /// 创建新的流式加密器
    pub fn new(algorithm: Algorithm, chunk_size: usize) -> Result<Self> {
        // 验证算法是否支持流式加密
        match algorithm {
            Algorithm::AES128GCM | Algorithm::AES192GCM | Algorithm::AES256GCM | Algorithm::SM4GCM => {},
            _ => return Err(CryptoError::InvalidParameter(format!("Algorithm {:?} does not support streaming encryption", algorithm))),
        }

        let context = Arc::new(Mutex::new(SideChannelContext::new(SideChannelConfig::default())));
        
        Ok(Self {
            algorithm,
            key: None,
            context: Some(context),
            buffer: Vec::with_capacity(chunk_size * 2),
            chunk_size,
            is_initialized: false,
            total_processed: 0,
            nonce: None,
            tag_buffer: Vec::new(),
            encrypt_mode: None,
        })
    }

    /// 检查是否处于加密模式
    fn is_encrypting(&self) -> bool {
        self.encrypt_mode.unwrap_or(true)
    }

    /// 使用自定义侧信道配置创建流式加密器
    pub fn with_side_channel_config(algorithm: Algorithm, chunk_size: usize, config: SideChannelConfig) -> Result<Self> {
        match algorithm {
            Algorithm::AES128GCM | Algorithm::AES192GCM | Algorithm::AES256GCM | Algorithm::SM4GCM => {},
            _ => return Err(CryptoError::InvalidParameter(format!("Algorithm {:?} does not support streaming encryption", algorithm))),
        }

        let context = Arc::new(Mutex::new(SideChannelContext::new(config)));
        
        Ok(Self {
            algorithm,
            key: None,
            context: Some(context),
            buffer: Vec::with_capacity(chunk_size * 2),
            chunk_size,
            is_initialized: false,
            total_processed: 0,
            nonce: None,
            tag_buffer: Vec::new(),
            encrypt_mode: None,
        })
    }

    /// 初始化加密器 - 设置密钥和nonce
    pub fn initialize(&mut self, key: Key, nonce: Option<Vec<u8>>) -> Result<()> {
        if self.is_initialized {
            return Err(CryptoError::InvalidState("Streaming cipher already initialized".into()));
        }

        // 验证密钥算法匹配
        if !self.is_key_compatible(&key) {
            return Err(CryptoError::InvalidParameter("Key algorithm mismatch".into()));
        }

        // 生成或验证nonce
        let final_nonce = match nonce {
            Some(n) => {
                if n.len() != 12 {
                    return Err(CryptoError::InvalidParameter("Nonce must be 12 bytes".into()));
                }
                n
            }
            None => {
                let mut nonce_bytes = vec![0u8; 12];
                SecureRandom::new()?.fill(&mut nonce_bytes)?;
                nonce_bytes
            }
        };

        self.key = Some(key);
        self.nonce = Some(final_nonce);
        self.is_initialized = true;
        self.total_processed = 0;

        Ok(())
    }

    /// 加密数据块
    pub fn encrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.is_initialized {
            return Err(CryptoError::InvalidState("Streaming cipher not initialized".into()));
        }

        // 设置加密模式
        if self.encrypt_mode.is_none() {
            self.encrypt_mode = Some(true);
        } else if self.encrypt_mode != Some(true) {
            return Err(CryptoError::InvalidState("Cannot mix encryption and decryption in same session".into()));
        }

        let context = self.context.clone();
        let mut context_guard = context.as_ref().unwrap().lock().unwrap();
        
        protect_critical_operation(&mut context_guard, || {
            self.process_chunk(data, true)
        })
    }

    /// 解密数据块
    pub fn decrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.is_initialized {
            return Err(CryptoError::InvalidState("Streaming cipher not initialized".into()));
        }

        // 设置解密模式
        if self.encrypt_mode.is_none() {
            self.encrypt_mode = Some(false);
        } else if self.encrypt_mode != Some(false) {
            return Err(CryptoError::InvalidState("Cannot mix encryption and decryption in same session".into()));
        }

        let context = self.context.clone();
        let mut context_guard = context.as_ref().unwrap().lock().unwrap();
        
        protect_critical_operation(&mut context_guard, || {
            self.process_chunk(data, false)
        })
    }

    /// 完成流式处理 - 处理剩余缓冲数据
    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        if !self.is_initialized {
            return Err(CryptoError::InvalidState("Streaming cipher not initialized".into()));
        }

        let context = self.context.clone();
        let mut context_guard = context.as_ref().unwrap().lock().unwrap();
        
        protect_critical_operation(&mut context_guard, || {
            let remaining = self.buffer.clone();
            self.buffer.clear();
            
            if remaining.is_empty() {
                self.is_initialized = false;
                self.encrypt_mode = None;
                Ok(Vec::new())
            } else {
                // 处理剩余数据
                let result = match self.encrypt_mode {
                    Some(true) => {
                        // 加密模式
                        self.process_chunk_internal(&remaining, true)?
                    }
                    Some(false) => {
                        // 解密模式 - 确保剩余数据包含完整的认证标签
                        if remaining.len() < 16 {
                            return Err(CryptoError::DecryptionFailed("Incomplete authentication tag".into()));
                        }
                        self.process_chunk_internal(&remaining, false)?
                    }
                    None => {
                        return Err(CryptoError::InvalidState("No encryption/decryption operation performed".into()));
                    }
                };
                self.is_initialized = false;
                self.encrypt_mode = None;
                Ok(result)
            }
        })
    }



    /// 重置加密器状态
    pub fn reset(&mut self) -> Result<()> {
        self.buffer.clear();
        self.tag_buffer.clear();
        self.is_initialized = false;
        self.total_processed = 0;
        self.nonce = None;
        self.key = None;
        self.encrypt_mode = None;
        Ok(())
    }

    /// 获取已处理的总字节数
    pub fn total_processed(&self) -> usize {
        self.total_processed
    }

    /// 获取当前nonce（用于验证）
    pub fn nonce(&self) -> Option<&Vec<u8>> {
        self.nonce.as_ref()
    }

    /// 验证密钥算法兼容性
    fn is_key_compatible(&self, key: &Key) -> bool {
        match (self.algorithm, key.algorithm()) {
            (Algorithm::AES128GCM, Algorithm::AES128GCM) => true,
            (Algorithm::AES192GCM, Algorithm::AES192GCM) => true,
            (Algorithm::AES256GCM, Algorithm::AES256GCM) => true,
            (Algorithm::SM4GCM, Algorithm::SM4GCM) => true,
            _ => false,
        }
    }

    /// 处理数据块（内部实现）
    fn process_chunk(&mut self, data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
        if encrypt {
            self.process_chunk_encrypt(data)
        } else {
            self.process_chunk_decrypt(data)
        }
    }

    /// 处理加密数据块
    fn process_chunk_encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // 添加到缓冲区
        self.buffer.extend_from_slice(data);
        
        let mut result = Vec::new();
        
        // 处理完整的块
        while self.buffer.len() >= self.chunk_size {
            let chunk = self.buffer[..self.chunk_size].to_vec();
            self.buffer.drain(..self.chunk_size);
            
            let processed = self.process_chunk_internal(&chunk, true)?;
            result.extend_from_slice(&processed);
        }
        
        Ok(result)
    }

    /// 处理解密数据块
    fn process_chunk_decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // 对于解密，我们需要处理完整的块（包括认证标签）
        // GCM认证标签是16字节
        const TAG_SIZE: usize = 16;
        
        // 添加到缓冲区
        self.buffer.extend_from_slice(data);
        
        let mut result = Vec::new();
        
        // 处理完整的块（数据 + 认证标签）
        while self.buffer.len() >= self.chunk_size + TAG_SIZE {
            let chunk_with_tag = self.buffer[..self.chunk_size + TAG_SIZE].to_vec();
            self.buffer.drain(..self.chunk_size + TAG_SIZE);
            
            let processed = self.process_chunk_internal(&chunk_with_tag, false)?;
            result.extend_from_slice(&processed);
        }
        
        Ok(result)
    }

    /// 内部块处理逻辑
    fn process_chunk_internal(&mut self, data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
        let key = self.key.as_ref().unwrap();
        let nonce = self.nonce.as_ref().unwrap();
        
        // 创建块计数器（用于GCM模式）
        let counter = (self.total_processed / self.chunk_size) as u32;
        let mut block_nonce = nonce.clone();
        
        // 将计数器编码到nonce的最后4字节
        let counter_bytes = counter.to_be_bytes();
        block_nonce[8..12].copy_from_slice(&counter_bytes);
        
        self.total_processed += data.len();
        
        // 使用底层加密提供程序处理
        match self.algorithm {
            Algorithm::AES128GCM | Algorithm::AES192GCM | Algorithm::AES256GCM => {
                self.process_aes_gcm_chunk(key, data, &block_nonce, encrypt)
            }
            Algorithm::SM4GCM => {
                self.process_sm4_gcm_chunk(key, data, &block_nonce, encrypt)
            }
            _ => Err(CryptoError::InvalidParameter("Unsupported algorithm for streaming".into())),
        }
    }

    /// 处理AES-GCM块
    fn process_aes_gcm_chunk(&self, key: &Key, data: &[u8], nonce: &[u8], encrypt: bool) -> Result<Vec<u8>> {
        // 这里使用ring库的AES-GCM实现
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
        
        let secret = key.secret_bytes()?;
        let unbound_key = UnboundKey::new(&AES_256_GCM, secret.as_bytes())
            .map_err(|_| CryptoError::EncryptionFailed("Invalid key".into()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        
        let nonce_array: [u8; 12] = nonce.try_into()
            .map_err(|_| CryptoError::InvalidParameter("Invalid nonce length".into()))?;
        let ring_nonce = Nonce::assume_unique_for_key(nonce_array);
        
        if encrypt {
            let mut in_out = data.to_vec();
            less_safe_key.seal_in_place_append_tag(
                ring_nonce,
                Aad::from(&[]),
                &mut in_out,
            ).map_err(|_| CryptoError::EncryptionFailed("Seal failed".into()))?;
            Ok(in_out)
        } else {
            let mut in_out = data.to_vec();
            let plaintext = less_safe_key.open_in_place(
                ring_nonce,
                Aad::from(&[]),
                &mut in_out,
            ).map_err(|_| CryptoError::DecryptionFailed("Open failed".into()))?;
            Ok(plaintext.to_vec())
        }
    }

    /// 处理SM4-GCM块
    fn process_sm4_gcm_chunk(&self, _key: &Key, _data: &[u8], _nonce: &[u8], _encrypt: bool) -> Result<Vec<u8>> {
        // SM4-GCM实现 - 这里需要集成SM4库
        // 暂时返回错误，后续可以集成具体的SM4实现
        Err(CryptoError::NotImplemented("SM4-GCM streaming not yet implemented".into()))
    }
}

/// 流式加密构建器
pub struct StreamingCipherBuilder {
    algorithm: Algorithm,
    chunk_size: usize,
    side_channel_config: Option<SideChannelConfig>,
}

impl StreamingCipherBuilder {
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            chunk_size: 4096, // 默认4KB块大小
            side_channel_config: None,
        }
    }

    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn side_channel_config(mut self, config: SideChannelConfig) -> Self {
        self.side_channel_config = Some(config);
        self
    }

    pub fn build(self) -> Result<StreamingCipher> {
        match self.side_channel_config {
            Some(config) => StreamingCipher::with_side_channel_config(self.algorithm, self.chunk_size, config),
            None => StreamingCipher::new(self.algorithm, self.chunk_size),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key;

    #[test]
    fn test_streaming_cipher_creation() {
        let cipher = StreamingCipher::new(Algorithm::AES256GCM, 1024).unwrap();
        assert_eq!(cipher.total_processed(), 0);
        assert!(!cipher.is_initialized);
    }

    #[test]
    fn test_streaming_cipher_builder() {
        let cipher = StreamingCipherBuilder::new(Algorithm::AES256GCM)
            .chunk_size(2048)
            .build()
            .unwrap();
        
        assert_eq!(cipher.chunk_size, 2048);
    }

    #[test]
    fn test_streaming_encryption_decryption() {
        let mut encryptor = StreamingCipher::new(Algorithm::AES256GCM, 64).unwrap(); // 使用较小的块大小
        let mut decryptor = StreamingCipher::new(Algorithm::AES256GCM, 64).unwrap();
        
        // 创建测试密钥
        let key = Key::new_active(Algorithm::AES256GCM, vec![0u8; 32]).unwrap();
        
        // 初始化加密器
        encryptor.initialize(key.clone(), None).unwrap();
        decryptor.initialize(key.clone(), encryptor.nonce().cloned()).unwrap();
        
        // 测试数据 - 确保大于块大小
        let test_data = b"Hello, streaming encryption world! This is a test message that is longer than the chunk size.";
        
        // 加密
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(&encryptor.encrypt_chunk(test_data).unwrap());
        
        // 完成加密并获取剩余数据
        let final_encrypted = encryptor.finalize().unwrap();
        encrypted.extend_from_slice(&final_encrypted);
        
        assert!(!encrypted.is_empty());
        
        // 解密
        let mut decrypted = Vec::new();
        decrypted.extend_from_slice(&decryptor.decrypt_chunk(&encrypted).unwrap());
        
        // 完成解密并获取剩余数据
        let final_decrypted = decryptor.finalize().unwrap();
        decrypted.extend_from_slice(&final_decrypted);
        
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_streaming_large_data() {
        let mut encryptor = StreamingCipher::new(Algorithm::AES256GCM, 512).unwrap();
        let mut decryptor = StreamingCipher::new(Algorithm::AES256GCM, 512).unwrap();
        
        let key = Key::new_active(Algorithm::AES256GCM, vec![0u8; 32]).unwrap();
        
        encryptor.initialize(key.clone(), None).unwrap();
        decryptor.initialize(key.clone(), encryptor.nonce().cloned()).unwrap();
        
        // 生成大数据
        let large_data = vec![0x42u8; 2048];
        
        // 分块加密
        let mut all_encrypted = Vec::new();
        for chunk in large_data.chunks(256) {
            let encrypted_chunk = encryptor.encrypt_chunk(chunk).unwrap();
            all_encrypted.extend_from_slice(&encrypted_chunk);
        }
        
        // 最终化
        let final_encrypted = encryptor.finalize().unwrap();
        all_encrypted.extend_from_slice(&final_encrypted);
        
        // 分块解密 - 使用相同的块大小进行解密
        let mut all_decrypted = Vec::new();
        for chunk in all_encrypted.chunks(256 + 16) { // 256字节数据 + 16字节认证标签
            let decrypted_chunk = decryptor.decrypt_chunk(chunk).unwrap();
            all_decrypted.extend_from_slice(&decrypted_chunk);
        }
        
        let final_decrypted = decryptor.finalize().unwrap();
        all_decrypted.extend_from_slice(&final_decrypted);
        
        // 验证结果
        assert_eq!(all_decrypted.len(), large_data.len());
        assert_eq!(&all_decrypted[..large_data.len()], &large_data[..]);
    }
}