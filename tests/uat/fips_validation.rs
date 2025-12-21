// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

#[cfg(feature = "fips")]
#[test]
fn uat_fips_mode_validation() {
    use securevault::fips::FipsContext;
    use securevault::{Cipher, Algorithm, KeyManager};
    
    // 1. Enable FIPS
    FipsContext::enable().expect("Failed to enable FIPS mode");
    assert!(FipsContext::is_enabled());
    
    // 2. Validate Allowed Algorithm (AES)
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();
    
    let data = b"FIPS Data";
    let enc = cipher.encrypt(&key_manager, &key_id, data).unwrap();
    let dec = cipher.decrypt(&key_manager, &key_id, &enc).unwrap();
    assert_eq!(data, &dec[..]);
    
    // 3. Validate Disallowed Algorithm (SM4)
    // Note: This test expects failure in FIPS mode
    let sm4_key_res = key_manager.generate_key(Algorithm::SM4GCM);
    // Depending on implementation, generation might succeed but usage fail, or generation fail.
    // The provided implementation checks FIPS in Cipher::encrypt/decrypt and Registry.
    
    if let Ok(sm4_id) = sm4_key_res {
        let sm4_cipher = Cipher::new(Algorithm::SM4GCM).unwrap();
        let res = sm4_cipher.encrypt(&key_manager, &sm4_id, data);
        assert!(res.is_err(), "SM4 should fail in FIPS mode");
    }
}