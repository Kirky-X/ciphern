// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use securevault::{Cipher, Algorithm, KeyManager};

#[test]
fn uat_api_communication() {
    // In a real scenario, this would use Asymmetric keys (Signer/Verifier).
    // Based on the provided implementation which focuses on Symmetric Cipher structure:
    
    let key_manager = KeyManager::new().unwrap();
    
    // 1. Shared Key (Simulating Key Exchange result)
    let session_key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();
    
    // 2. Client Request
    let request = b"{\"action\": \"transfer\", \"amount\": 1000}";
    let encrypted_req = cipher.encrypt(&key_manager, &session_key_id, request).unwrap();
    
    // 3. Server Receive & Decrypt
    let decrypted_req = cipher.decrypt(&key_manager, &session_key_id, &encrypted_req).unwrap();
    assert_eq!(request, &decrypted_req[..]);
    
    // 4. Server Response
    let response = b"{\"status\": \"success\"}";
    let encrypted_res = cipher.encrypt(&key_manager, &session_key_id, response).unwrap();
    
    // 5. Client Receive & Decrypt
    let decrypted_res = cipher.decrypt(&key_manager, &session_key_id, &encrypted_res).unwrap();
    assert_eq!(response, &decrypted_res[..]);
}