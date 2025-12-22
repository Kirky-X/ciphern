// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Cryptographic masking for side-channel protection
//!
//! This module provides various masking techniques to protect against
//! power analysis and electromagnetic analysis attacks.

use crate::error::{CryptoError, Result};
use crate::random::SecureRandom;

// === Boolean Masking ===

/// Boolean masking for boolean values
#[allow(dead_code)]
pub struct BooleanMasking {
    masks: Vec<bool>,
}

#[allow(dead_code)]
impl BooleanMasking {
    pub fn new(size: usize) -> Result<Self> {
        let mut mask_bytes = vec![0u8; size.div_ceil(8)];
        SecureRandom::new()?.fill(&mut mask_bytes)?;
        let masks: Vec<bool> = (0..size)
            .map(|i| (mask_bytes[i / 8] & (1 << (i % 8))) != 0)
            .collect();
        Ok(Self { masks })
    }

    /// Mask a boolean value
    #[allow(dead_code)]
    pub fn mask_bool(&self, index: usize, value: bool) -> bool {
        if index < self.masks.len() {
            value ^ self.masks[index]
        } else {
            value
        }
    }

    /// Unmask a boolean value (XOR is its own inverse)
    pub fn unmask_bool(&self, index: usize, masked: bool) -> bool {
        self.mask_bool(index, masked)
    }
}

// === Arithmetic Masking ===

/// Arithmetic masking for arithmetic operations
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ArithmeticMasking {
    mask: u32,
}

#[allow(dead_code)]
impl ArithmeticMasking {
    pub fn new() -> Result<Self> {
        let mut mask_bytes = [0u8; 4];
        SecureRandom::new()?.fill(&mut mask_bytes)?;
        let mask = u32::from_le_bytes(mask_bytes);

        Ok(Self { mask })
    }

    /// Mask a value using modular addition
    pub fn mask(&self, value: u32) -> u32 {
        value.wrapping_add(self.mask)
    }

    /// Unmask a value
    pub fn unmask(&self, masked: u32) -> u32 {
        masked.wrapping_sub(self.mask)
    }

    /// Perform masked addition
    pub fn masked_add(&self, a: u32, b: u32) -> u32 {
        let masked_a = self.mask(a);
        let masked_b = self.mask(b);
        masked_a.wrapping_add(masked_b).wrapping_sub(self.mask)
    }
}

// === Multiplicative Masking ===

/// Multiplicative masking for multiplicative operations
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MultiplicativeMasking {
    mask: u32,
    inverse: u32,
}

#[allow(dead_code)]
impl MultiplicativeMasking {
    pub fn new() -> Result<Self> {
        // Generate odd mask (has modular inverse mod 2^32)
        let mut mask_bytes = [0u8; 4];
        SecureRandom::new()?.fill(&mut mask_bytes)?;
        let mut mask = u32::from_le_bytes(mask_bytes);
        mask |= 1; // Ensure odd

        let inverse = mod_inverse_u32(mask);

        Ok(Self { mask, inverse })
    }

    /// Mask a value using modular multiplication
    pub fn mask(&self, value: u32) -> u32 {
        value.wrapping_mul(self.mask)
    }

    /// Unmask a value
    pub fn unmask(&self, masked: u32) -> u32 {
        masked.wrapping_mul(self.inverse)
    }
}

// === XOR Masking ===

/// XOR masking for bitwise operations
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct XorMasking {
    masks: Vec<u8>,
}

#[allow(dead_code)]
impl XorMasking {
    pub fn new(size: usize) -> Result<Self> {
        let mut masks = vec![0u8; size];
        SecureRandom::new()?.fill(&mut masks)?;

        Ok(Self { masks })
    }

    /// Mask a byte array using XOR
    #[allow(dead_code)]
    pub fn mask(&self, values: &[u8]) -> Vec<u8> {
        values
            .iter()
            .zip(self.masks.iter())
            .map(|(v, m)| v ^ m)
            .collect()
    }

    /// Unmask a byte array (XOR is its own inverse)
    pub fn unmask(&self, masked: &[u8]) -> Vec<u8> {
        self.mask(masked)
    }
}

// === Higher-Order Masking ===

/// Higher-order masking using multiple shares
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HigherOrderMasking {
    order: usize,
    shares: Vec<Vec<u8>>,
}

#[allow(dead_code)]
impl HigherOrderMasking {
    pub fn new(order: usize, data_size: usize) -> Result<Self> {
        let mut shares = Vec::with_capacity(order + 1);

        // Generate random shares
        for _ in 0..order {
            let mut share = vec![0u8; data_size];
            SecureRandom::new()?.fill(&mut share)?;
            shares.push(share);
        }

        Ok(Self { order, shares })
    }

    /// Mask data using XOR of all shares
    pub fn mask(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        if data.len() != self.shares[0].len() {
            return Err(CryptoError::InvalidParameter("Size mismatch".into()));
        }

        // Compute the last share as data XOR all other shares
        let mut last_share = data.to_vec();

        for share in &self.shares[0..self.order] {
            for (i, &byte) in share.iter().enumerate() {
                last_share[i] ^= byte;
            }
        }

        self.shares.push(last_share);

        Ok(self.shares.clone())
    }

    /// Unmask data by XORing all shares
    #[allow(dead_code)]
    pub fn unmask(&self) -> Result<Vec<u8>> {
        if self.shares.len() != self.order + 1 {
            return Err(CryptoError::InvalidParameter(
                "Invalid number of shares".into(),
            ));
        }

        let mut result = vec![0u8; self.shares[0].len()];

        for share in &self.shares {
            for (i, &byte) in share.iter().enumerate() {
                result[i] ^= byte;
            }
        }

        Ok(result)
    }

    /// Refresh masking (re-randomize shares without changing value)
    pub fn refresh(&mut self) -> Result<()> {
        if self.shares.len() != self.order + 1 {
            return Err(CryptoError::InvalidParameter(
                "Invalid number of shares".into(),
            ));
        }
        for i in 0..self.order {
            let mut new_mask = vec![0u8; self.shares[i].len()];
            SecureRandom::new()?.fill(&mut new_mask)?;
            for (j, mask_byte) in new_mask.iter().enumerate() {
                self.shares[i][j] ^= mask_byte;
                self.shares[self.order][j] ^= mask_byte;
            }
        }
        Ok(())
    }
}

// === Masked Lookup Table ===

/// Masked lookup table for S-boxes and other lookup operations
#[derive(Debug)]
#[allow(dead_code)]
pub struct MaskedLookupTable {
    table: Vec<u8>,
    _input_mask: u8,
    output_mask: u8,
    _table_size: usize,
}

#[allow(dead_code)]
impl MaskedLookupTable {
    pub fn new(original_table: &[u8]) -> Result<Self> {
        let mut input_mask = [0u8; 1];
        let mut output_mask = [0u8; 1];

        SecureRandom::new()?.fill(&mut input_mask)?;
        SecureRandom::new()?.fill(&mut output_mask)?;

        let input_mask = input_mask[0];
        let output_mask = output_mask[0];

        // Create full 256-entry table to support all possible u8 indices
        let mut table = vec![output_mask; 256]; // Initialize with masked default value (0 ^ output_mask)

        // For each position in the original table, create a masked entry
        for (i, &value) in original_table.iter().enumerate() {
            // Calculate the masked position for this index
            let masked_position = (i as u8) ^ input_mask;

            // Store the masked value at the masked position
            table[masked_position as usize] = value ^ output_mask;
        }

        Ok(Self {
            table,
            _input_mask: input_mask,
            output_mask,
            _table_size: original_table.len(),
        })
    }

    /// Perform masked lookup
    pub fn lookup(&self, masked_input: u8) -> u8 {
        // Use the masked_input directly as table index
        let table_index = masked_input as usize;
        // Get the masked value from the table
        let masked_value = self.table[table_index];
        // Unmask the value
        masked_value ^ self.output_mask
    }
}

// === Rotating S-Box Masking ===

/// Rotating S-box masking for AES
#[derive(Debug)]
#[allow(dead_code)]
pub struct RotatingSboxMasking {
    sboxes: Vec<MaskedLookupTable>,
    current_index: usize,
}

#[allow(dead_code)]
impl RotatingSboxMasking {
    pub fn new(rotation_count: usize) -> Result<Self> {
        const AES_SBOX: [u8; 256] = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
            0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
            0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
            0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
            0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
            0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
            0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
            0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
            0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
            0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
            0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
            0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
            0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
            0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
            0xb0, 0x54, 0xbb, 0x16,
        ];

        let mut sboxes = Vec::with_capacity(rotation_count);

        for _ in 0..rotation_count {
            sboxes.push(MaskedLookupTable::new(&AES_SBOX)?);
        }

        Ok(Self {
            sboxes,
            current_index: 0,
        })
    }

    /// Perform lookup with rotating masks
    #[allow(dead_code)]
    pub fn lookup(&mut self, masked_input: u8) -> u8 {
        let result = self.sboxes[self.current_index].lookup(masked_input);

        // Rotate to next S-box
        self.current_index = (self.current_index + 1) % self.sboxes.len();

        result
    }
}

// === Utility Functions ===

/// Compute modular inverse for 32-bit values
#[allow(dead_code)]
fn mod_inverse_u32(a: u32) -> u32 {
    let mut t = 0i64;
    let mut newt = 1i64;
    let mut r = 0x100000000i64; // 2^32
    let mut newr = a as i64;

    while newr != 0 {
        let quotient = r / newr;
        (t, newt) = (newt, t - quotient * newt);
        (r, newr) = (newr, r - quotient * newr);
    }

    if t < 0 {
        t += 0x100000000i64;
    }

    t as u32
}

// === Tests ===

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolean_masking() {
        let masking = BooleanMasking::new(8).unwrap();

        let original = true;
        let masked = masking.mask_bool(0, original);
        let unmasked = masking.unmask_bool(0, masked);

        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_arithmetic_masking() {
        let masking = ArithmeticMasking::new().unwrap();

        let original = 0x12345678u32;
        let masked = masking.mask(original);
        let unmasked = masking.unmask(masked);

        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_multiplicative_masking() {
        let masking = MultiplicativeMasking::new().unwrap();

        let original = 0x12345678u32;
        let masked = masking.mask(original);
        let unmasked = masking.unmask(masked);

        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_xor_masking() {
        let masking = XorMasking::new(16).unwrap();

        let original = vec![0x01, 0x02, 0x03, 0x04];
        let masked = masking.mask(&original);
        let unmasked = masking.unmask(&masked);

        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_higher_order_masking() {
        let mut masking = HigherOrderMasking::new(2, 8).unwrap();

        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let shares = masking.mask(&original).unwrap();

        assert_eq!(shares.len(), 3); // order + 1

        let unmasked = masking.unmask().unwrap();
        assert_eq!(unmasked, original);
    }

    #[test]
    fn test_masked_lookup_table() {
        let table = vec![0x00, 0x11, 0x22, 0x33, 0x44];
        let masked_table = MaskedLookupTable::new(&table).unwrap();

        println!("Original table: {:?}", table);
        println!("Input mask: 0x{:02x}", masked_table._input_mask);
        println!("Output mask: 0x{:02x}", masked_table.output_mask);
        println!("Masked table length: {}", masked_table.table.len());

        // Test lookup for each index
        for (i, &expected) in table.iter().enumerate() {
            let masked_input = (i as u8) ^ masked_table._input_mask;
            let result = masked_table.lookup(masked_input);

            println!(
                "Index {}: masked_input=0x{:02x}, expected=0x{:02x}, result=0x{:02x}",
                i, masked_input, expected, result
            );

            // The result should be the original value (unmasked)
            assert_eq!(result, expected);

            // Test that lookup is consistent
            let result2 = masked_table.lookup(masked_input);
            assert_eq!(result2, expected);
        }

        // Test that invalid indices return 0 (or some default)
        let invalid_indices = vec![5u8, 6, 10, 100, 255];
        for &invalid_idx in &invalid_indices {
            let masked_input = invalid_idx ^ masked_table._input_mask;
            let result = masked_table.lookup(masked_input);
            println!(
                "Invalid index {}: masked_input=0x{:02x}, result=0x{:02x}",
                invalid_idx, masked_input, result
            );
            // Should return 0 for invalid indices
            assert_eq!(result, 0);
        }
    }
}
