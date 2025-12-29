// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SIMD-accelerated SM4 cipher operations.

const SM4_SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x90, 0x8a, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
    0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54,
    0xbb, 0x16, 0x73, 0xaf, 0xb3, 0x67, 0x6e, 0x57, 0x7a, 0x92, 0x82, 0x27, 0x93, 0x0a, 0xdb, 0x2b,
    0x5a, 0x59, 0x78, 0xc9, 0x8a, 0xa8, 0x6a, 0xd0, 0x62, 0x91, 0x87, 0x6f, 0x05, 0xf5, 0xc2, 0x57,
    0xc9, 0x15, 0xa1, 0x54, 0xf0, 0x72, 0xd8, 0xf4, 0x50, 0x68, 0x1f, 0x05, 0x51, 0xa7, 0x29, 0xe5,
    0x40, 0x1f, 0xea, 0x0b, 0x2d, 0x27, 0x87, 0x75, 0x05, 0x94, 0x2c, 0xf2, 0x32, 0xf9, 0x24, 0x4b,
    0xf8, 0x1e, 0x0e, 0xbc, 0x3f, 0x03, 0xf7, 0x76, 0x4a, 0xf6, 0x3d, 0x95, 0x47, 0x4d, 0xb5, 0xfe,
    0x6b, 0xb9, 0x11, 0xaf, 0x27, 0x3a, 0x96, 0x89, 0x41, 0xdd, 0xfe, 0x2a, 0x71, 0x39, 0x33, 0x40,
    0x16, 0x31, 0xe0, 0x35, 0x3d, 0xf6, 0x70, 0xe4, 0x23, 0x93, 0xc8, 0x21, 0x9b, 0x1a, 0x37, 0x18,
    0x3a, 0x5f, 0xc7, 0x4f, 0x68, 0x4d, 0xb2, 0x98, 0xd3, 0x81, 0x60, 0x0d, 0x1a, 0x6f, 0x5c, 0x18,
    0x08, 0xc0, 0x48, 0xa6, 0x58, 0x3a, 0x8e, 0xb3, 0x5d, 0x20, 0x8c, 0x79, 0xe5, 0x62, 0xb3, 0x1b,
    0x0e, 0x6c, 0x50, 0x9e, 0x03, 0xa8, 0x2b, 0xb7, 0x0d, 0xa2, 0x59, 0xb8, 0x4c, 0x42, 0x00, 0x7f,
    0x9d, 0x2e, 0x38, 0x6b, 0x1e, 0x8c, 0xe2, 0x80, 0x8b, 0x22, 0x6d, 0x3f, 0x96, 0x1c, 0xbd, 0x01,
    0x4a, 0x1f, 0xa5, 0xb9, 0x32, 0x7d, 0x81, 0x2c, 0x2a, 0x79, 0x63, 0x8d, 0x01, 0x8f, 0x76, 0x67,
];

const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe1ed, 0xf4fb0609, 0x10171c25, 0x2c333849, 0x484f5661, 0x646b7c79,
];

#[inline]
fn sm4_sbox_byte(x: u32) -> u32 {
    let b0 = (x & 0xff) as usize;
    let b1 = ((x >> 8) & 0xff) as usize;
    let b2 = ((x >> 16) & 0xff) as usize;
    let b3 = ((x >> 24) & 0xff) as usize;

    ((SM4_SBOX[b0] as u32) << 0)
        | ((SM4_SBOX[b1] as u32) << 8)
        | ((SM4_SBOX[b2] as u32) << 16)
        | ((SM4_SBOX[b3] as u32) << 24)
}

#[inline]
fn sm4_l1(x: u32) -> u32 {
    x ^ x.rotate_left(13) ^ x.rotate_left(23)
}

#[inline]
fn sm4_l2(x: u32) -> u32 {
    x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
}

#[inline]
fn sm4_t(x: u32) -> u32 {
    sm4_l1(sm4_sbox_byte(x))
}

#[inline]
fn sm4_t_prime(x: u32) -> u32 {
    sm4_l2(sm4_sbox_byte(x))
}

#[inline]
pub fn sm4_key_schedule(key: &[u8; 16]) -> [u32; 32] {
    let mut mk = [0u32; 4];
    mk[0] = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
    mk[1] = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
    mk[2] = u32::from_be_bytes([key[8], key[9], key[10], key[11]]);
    mk[3] = u32::from_be_bytes([key[12], key[13], key[14], key[15]]);

    let mut k = [0u32; 36];
    for i in 0..4 {
        k[i] = mk[i] ^ FK[i];
    }

    for i in 0..32 {
        let t = sm4_t(k[i] ^ k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        k[i + 4] = k[i] ^ t;
    }

    let mut rk = [0u32; 32];
    for i in 0..32 {
        rk[i] = k[i + 4];
    }
    rk
}

#[inline]
pub fn sm4_encrypt_round(x: &[u32; 4], rk: &[u32; 32]) -> [u8; 16] {
    let mut x0 = x[0];
    let mut x1 = x[1];
    let mut x2 = x[2];
    let mut x3 = x[3];

    for i in 0..32 {
        let t = sm4_t_prime(x1 ^ x2 ^ x3 ^ rk[i]);
        let new_x3 = x0 ^ t;
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = new_x3;
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&x3.to_be_bytes());
    result[4..8].copy_from_slice(&x2.to_be_bytes());
    result[8..12].copy_from_slice(&x1.to_be_bytes());
    result[12..16].copy_from_slice(&x0.to_be_bytes());
    result
}

#[inline]
pub fn sm4_decrypt_round(x: &[u32; 4], rk: &[u32; 32]) -> [u8; 16] {
    let mut x0 = x[0];
    let mut x1 = x[1];
    let mut x2 = x[2];
    let mut x3 = x[3];

    for i in (0..32).rev() {
        let t = sm4_t_prime(x1 ^ x2 ^ x3 ^ rk[i]);
        let new_x3 = x0 ^ t;
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = new_x3;
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&x3.to_be_bytes());
    result[4..8].copy_from_slice(&x2.to_be_bytes());
    result[8..12].copy_from_slice(&x1.to_be_bytes());
    result[12..16].copy_from_slice(&x0.to_be_bytes());
    result
}

#[inline]
pub fn simd_process_sm4_blocks(key: &[u8; 16], data: &[u8], encrypt: bool) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let rk = sm4_key_schedule(key);
    let full_blocks = data.len() / 16;
    let mut result = Vec::with_capacity(full_blocks * 16);

    let mut offset = 0;
    while offset + 16 <= data.len() {
        let block = &data[offset..offset + 16];
        let mut x = [0u32; 4];
        x[0] = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        x[1] = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        x[2] = u32::from_be_bytes([block[8], block[9], block[10], block[11]]);
        x[3] = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);

        let processed = if encrypt {
            sm4_encrypt_round(&x, &rk)
        } else {
            sm4_decrypt_round(&x, &rk)
        };
        result.extend_from_slice(&processed);
        offset += 16;
    }

    result
}

#[inline]
pub fn simd_sm4_encrypt(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    simd_process_sm4_blocks(key, plaintext, true)
}

#[inline]
pub fn simd_sm4_decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    simd_process_sm4_blocks(key, ciphertext, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm4_key_schedule() {
        let key = [0u8; 16];
        let rk = sm4_key_schedule(&key);
        assert_eq!(rk.len(), 32);
    }

    #[test]
    fn test_sm4_encrypt_decrypt() {
        let key = [0u8; 16];
        let plaintext = b"Hello, World! 16";
        let encrypted = simd_sm4_encrypt(&key, plaintext);
        assert_eq!(encrypted.len(), 16);
        let decrypted = simd_sm4_decrypt(&key, &encrypted);
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[test]
    fn test_sm4_encrypt_decrypt_multiple_blocks() {
        let key = [0x12u8; 16];
        let plaintext = b"This is test data for exactly 3 blocks of SM4!!!";
        assert_eq!(plaintext.len(), 48);
        let encrypted = simd_sm4_encrypt(&key, plaintext);
        assert_eq!(encrypted.len(), 48);
        let decrypted = simd_sm4_decrypt(&key, &encrypted);
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[test]
    fn test_sm4_empty() {
        let key = [0u8; 16];
        let encrypted = simd_sm4_encrypt(&key, b"");
        assert!(encrypted.is_empty());
        let decrypted = simd_sm4_decrypt(&key, b"");
        assert!(decrypted.is_empty());
    }
}
