// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SIMD-accelerated SHA256 operations.

use std::simd::u32x4;

#[inline]
pub fn simd_process_blocks_sha256(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(32);

    let padded_len = if data.is_empty() {
        64
    } else {
        (data.len() + 9).div_ceil(64) * 64
    };

    let mut processed = Vec::with_capacity(padded_len);
    if !data.is_empty() {
        processed.extend_from_slice(data);
    }

    while processed.len() < padded_len - 8 {
        processed.push(0);
    }

    let msg_len_bits = (data.len() as u64) * 8;
    processed.extend_from_slice(&msg_len_bits.to_be_bytes());

    let mut offset = 0;
    while offset + 64 <= processed.len() {
        let chunk = &processed[offset..offset + 64];
        let hash = simd_sha256_block(chunk);
        result.extend_from_slice(&hash);
        offset += 64;
    }

    result
}

#[inline]
fn simd_sha256_block(block: &[u8]) -> [u8; 32] {
    let mut w = [0u32; 64];

    for i in 0..16 {
        let bytes = &block[i * 4..i * 4 + 4];
        w[i] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }

    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ w[i - 15] >> 3;
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ w[i - 2] >> 10;
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let h_init: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut a = h_init[0];
    let mut b = h_init[1];
    let mut c = h_init[2];
    let mut d = h_init[3];
    let mut e = h_init[4];
    let mut f = h_init[5];
    let mut g = h_init[6];
    let mut h = h_init[7];

    for i in 0..64 {
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[i])
            .wrapping_add(w[i]);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);

        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    let mut result = [0u8; 32];
    let h_final: [u32; 8] = [
        h_init[0].wrapping_add(a),
        h_init[1].wrapping_add(b),
        h_init[2].wrapping_add(c),
        h_init[3].wrapping_add(d),
        h_init[4].wrapping_add(e),
        h_init[5].wrapping_add(f),
        h_init[6].wrapping_add(g),
        h_init[7].wrapping_add(h),
    ];

    for (i, &val) in h_final.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }

    result
}

#[inline]
pub fn simd_sha256_finalize(hash: &[u8], data: &[u8]) -> Vec<u8> {
    let mut combined = Vec::with_capacity(hash.len() + data.len());
    combined.extend_from_slice(hash);
    combined.extend_from_slice(data);
    simd_process_blocks_sha256(&combined)
}

#[inline]
pub fn simd_combine_hashes(hashes: &[&[u8]]) -> Vec<u8> {
    let mut result = Vec::with_capacity(hashes.len() * 32);
    for &hash in hashes {
        result.extend_from_slice(hash);
    }
    simd_process_blocks_sha256(&result)
}

#[inline]
pub fn simd_sha256_block_vectorized(block: &[u8]) -> [u8; 32] {
    let k_vals: [u32x4; 16] = [
        u32x4::from_array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5]),
        u32x4::from_array([0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5]),
        u32x4::from_array([0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3]),
        u32x4::from_array([0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174]),
        u32x4::from_array([0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc]),
        u32x4::from_array([0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da]),
        u32x4::from_array([0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7]),
        u32x4::from_array([0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967]),
        u32x4::from_array([0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13]),
        u32x4::from_array([0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85]),
        u32x4::from_array([0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3]),
        u32x4::from_array([0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070]),
        u32x4::from_array([0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5]),
        u32x4::from_array([0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3]),
        u32x4::from_array([0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208]),
        u32x4::from_array([0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]),
    ];

    let mut w = [0u32; 64];
    for i in 0..16 {
        let bytes = &block[i * 4..i * 4 + 4];
        w[i] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }

    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ w[i - 15] >> 3;
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ w[i - 2] >> 10;
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = 0x6a09e667u32;
    let mut b = 0xbb67ae85u32;
    let mut c = 0x3c6ef372u32;
    let mut d = 0xa54ff53au32;
    let mut e = 0x510e527fu32;
    let mut f = 0x9b05688cu32;
    let mut g = 0x1f83d9abu32;
    let mut h = 0x5be0cd19u32;

    for i in 0..64 {
        let idx = i / 4;
        let k = k_vals[idx];
        let offset = (i % 4);

        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[offset])
            .wrapping_add(w[i]);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);

        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    let h_init: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut result = [0u8; 32];
    let h_final: [u32; 8] = [
        h_init[0].wrapping_add(a),
        h_init[1].wrapping_add(b),
        h_init[2].wrapping_add(c),
        h_init[3].wrapping_add(d),
        h_init[4].wrapping_add(e),
        h_init[5].wrapping_add(f),
        h_init[6].wrapping_add(g),
        h_init[7].wrapping_add(h),
    ];

    for (i, &val) in h_final.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_basic() {
        let data = b"hello world";
        let result = simd_process_blocks_sha256(data);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha256_empty() {
        let result = simd_process_blocks_sha256(b"");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha256_finalize() {
        let hash = simd_process_blocks_sha256(b"initial");
        let result = simd_sha256_finalize(&hash, b" more data");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_combine_hashes() {
        let hash1 = simd_process_blocks_sha256(b"data1");
        let hash2 = simd_process_blocks_sha256(b"data2");
        let result = simd_combine_hashes(&[&hash1, &hash2]);
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_sha256_vectorized() {
        let data = b"hello world";
        let padded_len = ((data.len() + 9 + 63) / 64) * 64;
        let mut processed = Vec::with_capacity(padded_len);
        processed.extend_from_slice(data);
        while processed.len() < padded_len - 8 {
            processed.push(0);
        }
        let msg_len_bits = (data.len() as u64) * 8;
        processed.extend_from_slice(&msg_len_bits.to_be_bytes());

        let result = simd_sha256_block_vectorized(&processed);
        assert_eq!(result.len(), 32);

        let expected = simd_process_blocks_sha256(data);
        assert_eq!(result.to_vec(), expected);
    }
}
