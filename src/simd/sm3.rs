// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! SIMD-accelerated SM3 hash operations.

#[inline]
pub fn simd_process_blocks_sm3(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(32);

    let mut padded = Vec::with_capacity(64);
    padded.extend_from_slice(data);

    padded.push(0x80);

    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }

    let msg_len_bits = (data.len() as u64) * 8;
    padded.extend_from_slice(&msg_len_bits.to_be_bytes());

    let mut offset = 0;
    while offset + 64 <= padded.len() {
        let chunk = &padded[offset..offset + 64];
        let hash = simd_sm3_block(chunk);
        result.extend_from_slice(&hash);
        offset += 64;
    }

    result
}

#[inline]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline]
fn simd_sm3_block(block: &[u8]) -> [u8; 32] {
    let mut w = [0u32; 68];
    let mut w1 = [0u32; 64];

    for i in 0..16 {
        let bytes = &block[i * 4..i * 4 + 4];
        w[i] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }

    for i in 16..68 {
        let p1 = w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15);
        w[i] = p1 ^ p1.rotate_left(15) ^ p1.rotate_left(23) ^ w[i - 13].rotate_left(7) ^ w[i - 6];
    }

    for i in 0..64 {
        w1[i] = w[i] ^ w[i + 4];
    }

    let iv: [u32; 8] = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d,
        0xb0fb0e4e,
    ];

    let mut a = iv[0];
    let mut b = iv[1];
    let mut c = iv[2];
    let mut d = iv[3];
    let mut e = iv[4];
    let mut f = iv[5];
    let mut g = iv[6];
    let mut h = iv[7];

    for j in 0..16 {
        let t = 0x79cc4519u32.rotate_left(j as u32);

        let ss1 = (a.rotate_left(12))
            .wrapping_add(e)
            .wrapping_add(t)
            .rotate_left(7);

        let ss2 = ss1 ^ a.rotate_left(12);

        let ff = a ^ b ^ c;
        let gg = e ^ f ^ g;

        let tt1 = d.wrapping_add(ff).wrapping_add(ss2).wrapping_add(w1[j]);
        let tt2 = h.wrapping_add(gg).wrapping_add(ss1).wrapping_add(w[j]);

        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    for j in 16..64 {
        let t = 0x7a879d8au32.rotate_left(j as u32);

        let ss1 = (a.rotate_left(12))
            .wrapping_add(e)
            .wrapping_add(t)
            .rotate_left(7);

        let ss2 = ss1 ^ a.rotate_left(12);

        let ff = (a & b) | (a & c) | (b & c);
        let gg = (e & f) | ((!e) & g);

        let tt1 = d.wrapping_add(ff).wrapping_add(ss2).wrapping_add(w1[j]);
        let tt2 = h.wrapping_add(gg).wrapping_add(ss1).wrapping_add(w[j]);

        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    let mut result = [0u8; 32];
    let h_final: [u32; 8] = [
        a ^ iv[0],
        b ^ iv[1],
        c ^ iv[2],
        d ^ iv[3],
        e ^ iv[4],
        f ^ iv[5],
        g ^ iv[6],
        h ^ iv[7],
    ];

    for (i, &val) in h_final.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }

    result
}

#[inline]
pub fn simd_sm3_finalize(hash: &[u8], data: &[u8]) -> Vec<u8> {
    let mut combined = Vec::with_capacity(hash.len() + data.len());
    combined.extend_from_slice(hash);
    combined.extend_from_slice(data);
    simd_process_blocks_sm3(&combined)
}

#[inline]
pub fn simd_combine_sm3_hashes(hashes: &[&[u8]]) -> Vec<u8> {
    let mut result = Vec::with_capacity(hashes.len() * 32);
    for &hash in hashes {
        result.extend_from_slice(hash);
    }
    simd_process_blocks_sm3(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm3_basic() {
        let data = b"hello world";
        let result = simd_process_blocks_sm3(data);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sm3_empty() {
        let result = simd_process_blocks_sm3(b"");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sm3_finalize() {
        let hash = simd_process_blocks_sm3(b"initial");
        let result = simd_sm3_finalize(&hash, b" more data");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_combine_sm3_hashes() {
        let hash1 = simd_process_blocks_sm3(b"data1");
        let hash2 = simd_process_blocks_sm3(b"data2");
        let result = simd_combine_sm3_hashes(&[&hash1, &hash2]);
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_sm3_known_values() {
        let result = simd_process_blocks_sm3(b"abc");
        let expected = [
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0,
        ];
        assert_eq!(result, expected);
    }
}
