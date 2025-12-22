// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use securevault::audit::AuditLogger;
use securevault::{Algorithm, Cipher, KeyManager};

#[test]
fn test_end_to_end_encryption() {
    // 1. Initialize
    let key_manager = KeyManager::new().unwrap();
    
    // 2. Create Key
    let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    
    // 3. Encrypt
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();
    let plaintext = b"End-to-end encryption test";
    let ciphertext = cipher.encrypt(&key_manager, &key_id, plaintext).unwrap();
    
    // 4. Decrypt
    let decrypted = cipher.decrypt(&key_manager, &key_id, &ciphertext).unwrap();
    assert_eq!(plaintext, &decrypted[..]);
    
    // 5. Audit Log (Verification would require inspecting the logger sink)
    // AuditLogger::global().get_recent_logs() ...
}