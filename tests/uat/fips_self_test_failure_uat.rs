#[cfg(feature = "fips")]
#[test]
fn test_fips_self_test_failure_handling() {
    use ciphern::fips::{FipsSelfTestEngine, FipsError};
    
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