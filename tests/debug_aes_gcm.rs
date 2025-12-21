#[cfg(test)]
mod tests {
    use ciphern::{key::Key, Algorithm, Cipher};

    #[test]
    fn debug_aes_gcm_vector_1() {
        // Test vector 1 from CAVP
        let key_bytes = hex::decode("00000000000000000000000000000000").unwrap();
        let iv_bytes = hex::decode("000000000000000000000000").unwrap();
        let plaintext = hex::decode("00000000000000000000000000000000").unwrap();
        let aad = b"";
        let expected_ct = hex::decode("0388dace60b6a392f328c2b971b2fe78").unwrap();
        let expected_tag = hex::decode("ab6e47d42cec13bdf53a67b21257bdcc").unwrap();

        println!("Key: {}", hex::encode(&key_bytes));
        println!("IV: {}", hex::encode(&iv_bytes));
        println!("Plaintext: {}", hex::encode(&plaintext));
        println!("Expected CT: {}", hex::encode(&expected_ct));
        println!("Expected TAG: {}", hex::encode(&expected_tag));

        let key = Key::new_active(Algorithm::AES128GCM, key_bytes).expect("Failed to create key");
        let cipher = Cipher::new(Algorithm::AES128GCM).expect("Failed to create cipher");
        let cipher_impl = cipher.get_implementation();

        // Test encryption with provided nonce
        let ciphertext = cipher_impl
            .encrypt_with_nonce(&key, &plaintext, &iv_bytes, Some(aad))
            .expect("Encryption failed");

        println!("Generated ciphertext+tag: {}", hex::encode(&ciphertext));
        println!("Generated ciphertext length: {}", ciphertext.len());

        // Split the result
        let ct_len = expected_ct.len();
        let (ct, tag) = ciphertext.split_at(ct_len);

        println!("Generated CT: {}", hex::encode(ct));
        println!("Generated TAG: {}", hex::encode(tag));

        println!("CT matches expected: {}", ct == expected_ct);
        println!("TAG matches expected: {}", tag == expected_tag);

        if tag != expected_tag {
            println!("TAG mismatch!");
            println!("Expected: {:?}", expected_tag);
            println!("Got: {:?}", tag);
            println!(
                "Difference at byte: {:?}",
                expected_tag
                    .iter()
                    .zip(tag.iter())
                    .enumerate()
                    .find(|(_, (e, g))| e != g)
            );
        }

        // Let's also test with ring directly to see if the issue is in our wrapper
        test_with_ring_directly();
    }

    fn test_with_ring_directly() {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

        let key_bytes = hex::decode("00000000000000000000000000000000").unwrap();
        let iv_bytes = hex::decode("000000000000000000000000").unwrap();
        let plaintext = hex::decode("00000000000000000000000000000000").unwrap();
        let expected_tag = hex::decode("ab6e47d42cec13bdf53a67b21257bdcc").unwrap();

        println!("\n=== Testing with ring directly ===");

        let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
        let less_safe_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(iv_bytes.try_into().unwrap());

        let mut in_out = plaintext.clone();
        less_safe_key
            .seal_in_place_append_tag(nonce, Aad::from(&b""[..]), &mut in_out)
            .unwrap();

        println!("Ring result: {}", hex::encode(&in_out));

        let (ct, tag) = in_out.split_at(plaintext.len());
        println!("Ring CT: {}", hex::encode(ct));
        println!("Ring TAG: {}", hex::encode(tag));
        println!("Ring TAG matches expected: {}", tag == expected_tag);

        if tag != expected_tag {
            println!("Ring TAG mismatch!");
            println!("Expected: {:?}", expected_tag);
            println!("Got: {:?}", tag);
        }
    }
}
