// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

#[cfg(feature = "fips")]
mod tests {
    use ciphern::fips::{FipsAlgorithmValidator, FipsContext, FipsMode, FipsSelfTestEngine, FipsError};
    use ciphern::{Algorithm, KeyManager};
    use ciphern::provider::registry::REGISTRY;

    #[test]
    fn test_fips_mode_validation() {
        // 1. Enable FIPS
        let _context = FipsContext::new(FipsMode::Enabled).expect("Failed to enable FIPS mode");
        
        // 2. Validate Allowed Algorithm (AES)
        let key_manager = KeyManager::new().unwrap();
        let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
        
        let cipher = REGISTRY.get_symmetric(Algorithm::AES256GCM).unwrap();
        let key = key_manager.get_key(&key_id).unwrap();
        
        let data = b"FIPS Data";
        let enc = cipher.encrypt(&key, data, None).unwrap();
        let dec = cipher.decrypt(&key, &enc, None).unwrap();
        assert_eq!(data, &dec[..]);
        
        // 3. Validate Disallowed Algorithm (SM4)
        // In FIPS mode, non-approved algorithms should fail or be unavailable
        if FipsAlgorithmValidator::is_algorithm_approved(&Algorithm::SM4GCM) {
            panic!("SM4 should not be approved in FIPS mode");
        }
        
        let sm4_res = REGISTRY.get_symmetric(Algorithm::SM4GCM);
        assert!(sm4_res.is_err(), "SM4 should fail in FIPS mode");
    }

    #[test]
    fn test_fips_self_test_failure_handling() {
        let engine = FipsSelfTestEngine::new();
        
        // 模拟 KAT 失败
        let invalid_kat = b"invalid test vector";
        match engine.verify_kat("aes256_gcm", invalid_kat) {
            Err(FipsError::SelfTestFailed(_)) => {
                println!("Correctly detected KAT failure");
            }
            _ => panic!("Should have detected KAT failure"),
        }
        
        // 验证系统状态
        assert!(engine.is_in_error_state());
        assert!(!engine.can_perform_crypto_operations());
    }

    #[test]
    fn test_fips_algorithm_approval() {
        let approved = vec![
            Algorithm::AES256GCM,
            Algorithm::ECDSAP384,
            Algorithm::SHA256,
        ];
        
        for alg in approved {
            assert!(FipsAlgorithmValidator::is_algorithm_approved(&alg), "{:?} should be approved", alg);
        }
        
        let unapproved = vec![
            Algorithm::SM4GCM,
        ];
        
        for alg in unapproved {
            assert!(!FipsAlgorithmValidator::is_algorithm_approved(&alg), "{:?} should not be approved", alg);
        }
    }
}
