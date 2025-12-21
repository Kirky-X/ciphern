// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::error::{CryptoError, Result};

/// PKCS#7填充实现
pub struct Pkcs7Padding;

impl Pkcs7Padding {
    /// 对数据进行PKCS#7填充
    ///
    /// # 参数
    /// * `data` - 需要填充的数据
    /// * `block_size` - 块大小（必须是2-255之间的值）
    ///
    /// # 返回
    /// 填充后的数据
    pub fn pad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
        if !(2..=255).contains(&block_size) {
            return Err(CryptoError::InvalidParameter(format!(
                "Invalid block size: {}",
                block_size
            )));
        }

        let padding_len = block_size - (data.len() % block_size);
        if padding_len == 0 {
            // 如果数据正好是块大小的倍数，添加一个完整的填充块
            let mut result = data.to_vec();
            result.extend(vec![block_size as u8; block_size]);
            return Ok(result);
        }

        let mut result = data.to_vec();
        result.extend(vec![padding_len as u8; padding_len]);
        Ok(result)
    }

    /// 移除PKCS#7填充
    ///
    /// # 参数
    /// * `data` - 包含填充的数据
    /// * `block_size` - 块大小（必须是2-255之间的值）
    ///
    /// # 返回
    /// 移除填充后的原始数据
    pub fn unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
        if !(2..=255).contains(&block_size) {
            return Err(CryptoError::InvalidParameter(format!(
                "Invalid block size: {}",
                block_size
            )));
        }

        if data.len() < block_size || !data.len().is_multiple_of(block_size) {
            return Err(CryptoError::DecryptionFailed(
                "Invalid padded data length".into(),
            ));
        }

        let padding_len = data[data.len() - 1] as usize;
        if padding_len == 0 || padding_len > block_size {
            return Err(CryptoError::DecryptionFailed(
                "Invalid padding length".into(),
            ));
        }

        // 验证所有填充字节是否正确
        for i in 1..=padding_len {
            if data[data.len() - i] != padding_len as u8 {
                return Err(CryptoError::DecryptionFailed(
                    "Invalid padding bytes".into(),
                ));
            }
        }

        Ok(data[..data.len() - padding_len].to_vec())
    }

    /// 获取需要填充的长度
    pub fn get_padding_length(data_len: usize, block_size: usize) -> usize {
        if block_size == 0 {
            return 0;
        }
        let remainder = data_len % block_size;
        if remainder == 0 {
            block_size
        } else {
            block_size - remainder
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_pad_normal() {
        let data = b"Hello World";
        let block_size = 16;

        let padded = Pkcs7Padding::pad(data, block_size).unwrap();
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[11], 5);
        assert_eq!(padded[12], 5);
        assert_eq!(padded[13], 5);
        assert_eq!(padded[14], 5);
        assert_eq!(padded[15], 5);
    }

    #[test]
    fn test_pkcs7_pad_exact_block() {
        let data = b"1234567890123456"; // 正好16字节
        let block_size = 16;

        let padded = Pkcs7Padding::pad(data, block_size).unwrap();
        assert_eq!(padded.len(), 32); // 需要添加一个完整的填充块
        assert_eq!(padded[16], 16);
        assert_eq!(padded[31], 16);
    }

    #[test]
    fn test_pkcs7_unpad_normal() {
        let data = b"Hello World";
        let block_size = 16;

        let padded = Pkcs7Padding::pad(data, block_size).unwrap();
        let unpadded = Pkcs7Padding::unpad(&padded, block_size).unwrap();

        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pkcs7_unpad_exact_block() {
        let data = b"1234567890123456"; // 正好16字节
        let block_size = 16;

        let padded = Pkcs7Padding::pad(data, block_size).unwrap();
        let unpadded = Pkcs7Padding::unpad(&padded, block_size).unwrap();

        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pkcs7_invalid_block_size() {
        let data = b"test";

        assert!(Pkcs7Padding::pad(data, 1).is_err());
        assert!(Pkcs7Padding::pad(data, 256).is_err());
        assert!(Pkcs7Padding::unpad(data, 1).is_err());
        assert!(Pkcs7Padding::unpad(data, 256).is_err());
    }

    #[test]
    fn test_pkcs7_invalid_padding() {
        let invalid_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 20]; // 填充字节为20，但块大小为16

        assert!(Pkcs7Padding::unpad(&invalid_data, 16).is_err());
    }

    #[test]
    fn test_get_padding_length() {
        assert_eq!(Pkcs7Padding::get_padding_length(10, 16), 6);
        assert_eq!(Pkcs7Padding::get_padding_length(16, 16), 16);
        assert_eq!(Pkcs7Padding::get_padding_length(20, 16), 12);
        assert_eq!(Pkcs7Padding::get_padding_length(0, 16), 16);
    }
}
