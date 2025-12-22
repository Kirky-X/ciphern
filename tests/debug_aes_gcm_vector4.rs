// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::{key::Key, Algorithm, Cipher};

#[test]
fn debug_aes_gcm_vector4() {
    println!("=== Debugging AES-GCM Vector 4 ===");

    // 测试向量4的数据
    let key_hex = "000000000000000000000000000000000000000000000000";
    let iv_hex = "000000000000000000000000";
    let pt_hex = "00000000000000000000000000000000";
    let expected_ct_hex = "98e7247c07f0fe411c267e4384b0f600";
    let expected_tag_hex = "2ff58d80033927ab8ef4d4587514f0fb";

    let key_bytes = hex::decode(key_hex).unwrap();
    let iv_bytes = hex::decode(iv_hex).unwrap();
    let plaintext = hex::decode(pt_hex).unwrap();
    let expected_ct = hex::decode(expected_ct_hex).unwrap();
    let expected_tag = hex::decode(expected_tag_hex).unwrap();

    println!("Key: {}", key_hex);
    println!("IV: {}", iv_hex);
    println!("Plaintext: {}", pt_hex);
    println!("Expected CT: {}", expected_ct_hex);
    println!("Expected TAG: {}", expected_tag_hex);

    // 创建AES cipher和key
    let cipher = Cipher::new(Algorithm::AES192GCM).unwrap();
    let cipher_impl = cipher.get_implementation();
    let key = Key::new_active(Algorithm::AES192GCM, key_bytes).unwrap();

    // 使用自定义实现进行加密
    match cipher_impl.encrypt_with_nonce(&key, &plaintext, &iv_bytes, None) {
        Ok(result) => {
            let ct_len = plaintext.len();
            let (ct, tag) = result.split_at(ct_len);

            println!("\n=== Custom Implementation Result ===");
            println!("Generated CT: {}", hex::encode(ct));
            println!("Generated TAG: {}", hex::encode(tag));
            println!("CT matches expected: {}", ct == expected_ct);
            println!("TAG matches expected: {}", tag == expected_tag);

            if ct != expected_ct || tag != expected_tag {
                println!("\n=== MISMATCH DETECTED ===");
                println!(
                    "CT diff: expected {}, got {}",
                    expected_ct_hex,
                    hex::encode(ct)
                );
                println!(
                    "TAG diff: expected {}, got {}",
                    expected_tag_hex,
                    hex::encode(tag)
                );
            }
        }
        Err(e) => {
            println!("Encryption failed: {:?}", e);
        }
    }

    // 使用aes_gcm crate直接测试
    test_with_aes_gcm_crate();
}

fn test_with_aes_gcm_crate() {
    use aes_gcm::aead::consts::U12;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{aes::Aes192, AesGcm};

    let key_bytes = hex::decode("000000000000000000000000000000000000000000000000").unwrap();
    let iv_bytes = hex::decode("000000000000000000000000").unwrap();
    let plaintext = hex::decode("00000000000000000000000000000000").unwrap();
    let expected_ct = hex::decode("98e7247c07f0fe411c267e4384b0f600").unwrap();
    let expected_tag = hex::decode("2ff58d80033927ab8ef4d4587514f0fb").unwrap();

    println!("\n=== Testing with aes_gcm crate directly (Vector 4) ===");

    let cipher = AesGcm::<Aes192, U12>::new_from_slice(&key_bytes).unwrap();
    let nonce = aes_gcm::Nonce::from_slice(&iv_bytes);

    let result = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

    println!("aes_gcm result: {}", hex::encode(&result));

    let ct_len = plaintext.len();
    let (ct, tag) = result.split_at(ct_len);
    println!("aes_gcm CT: {}", hex::encode(ct));
    println!("aes_gcm TAG: {}", hex::encode(tag));
    println!("aes_gcm CT matches expected: {}", ct == expected_ct);
    println!("aes_gcm TAG matches expected: {}", tag == expected_tag);

    if ct != expected_ct || tag != expected_tag {
        println!("\n=== AES_GCM CRATE MISMATCH DETECTED ===");
        println!("This suggests the test vector may be incorrect!");
        println!("Consider updating the test vector to match aes_gcm crate's output");
    }
}
