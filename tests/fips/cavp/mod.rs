// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::{key::Key, Algorithm, Cipher};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct CavpTestVector {
    pub algorithm: String,
    pub key: String,
    pub iv: String,
    pub pt: String,
    pub aad: String,
    pub ct: String,
    pub tag: String,
}

#[derive(Debug, Deserialize)]
pub struct CavpTestSuite {
    pub name: String,
    pub vectors: Vec<CavpTestVector>,
}

pub fn run_aes_gcm_cavp_tests(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_path)?;
    let suite: CavpTestSuite = serde_json::from_str(&content)?;

    println!("Running CAVP Test Suite: {}", suite.name);

    for (i, v) in suite.vectors.iter().enumerate() {
        let algo = match v.algorithm.as_str() {
            "AES-128-GCM" => Algorithm::AES128GCM,
            "AES-192-GCM" => Algorithm::AES192GCM,
            "AES-256-GCM" => Algorithm::AES256GCM,
            _ => continue,
        };

        let key_bytes = hex::decode(&v.key)?;
        let iv_bytes = hex::decode(&v.iv)?;
        let pt_bytes = hex::decode(&v.pt)?;
        let aad_bytes = hex::decode(&v.aad)?;
        let expected_ct = hex::decode(&v.ct)?;
        let expected_tag = hex::decode(&v.tag)?;

        // Create a key for testing
        let key = Key::new_active(algo, key_bytes).map_err(|e| e.to_string())?;
        let cipher = Cipher::new(algo).map_err(|e| e.to_string())?;
        let cipher_impl = cipher.get_implementation();

        // 验证加密
        let nonce = iv_bytes.clone();
        let ct_with_tag = cipher_impl
            .encrypt_with_nonce(&key, &pt_bytes, &nonce, Some(&aad_bytes))
            .map_err(|e| e.to_string())?;

        println!(
            "  Vector {}: Generated CT+TAG len={}, expected CT len={}, expected TAG len={}",
            i,
            ct_with_tag.len(),
            expected_ct.len(),
            expected_tag.len()
        );

        // For empty plaintext, the result should just be the tag
        if pt_bytes.is_empty() {
            assert_eq!(
                ct_with_tag.len(),
                16,
                "Empty plaintext should produce 16-byte tag"
            );
            assert_eq!(
                ct_with_tag, expected_tag,
                "Tag mismatch for empty plaintext at vector {}",
                i
            );
        } else {
            // Split CT and Tag (GCM tag is 16 bytes)
            let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);

            println!(
                "  Vector {}: Generated CT={:?}, expected CT={:?}",
                i,
                hex::encode(ct),
                hex::encode(&expected_ct)
            );
            println!(
                "  Vector {}: Generated TAG={:?}, expected TAG={:?}",
                i,
                hex::encode(tag),
                hex::encode(&expected_tag)
            );

            assert_eq!(ct, expected_ct, "Ciphertext mismatch at vector {}", i);
            assert_eq!(tag, expected_tag, "Tag mismatch at vector {}", i);
        }

        // 验证解密 - combine nonce, ciphertext and tag for decryption
        let mut combined_input = iv_bytes.clone(); // Prepend nonce
        combined_input.extend_from_slice(&expected_ct);
        combined_input.extend_from_slice(&expected_tag);

        println!(
            "  Vector {}: pt_len={}, ct_len={}, tag_len={}, combined_input_len={}",
            i,
            pt_bytes.len(),
            expected_ct.len(),
            expected_tag.len(),
            combined_input.len()
        );

        let decrypted = cipher_impl
            .decrypt(&key, &combined_input, Some(&aad_bytes))
            .map_err(|e| e.to_string())?;
        assert_eq!(decrypted, pt_bytes, "Decryption mismatch at vector {}", i);

        println!("  Vector {}: Passed", i);
    }

    Ok(())
}
