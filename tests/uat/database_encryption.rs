// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use securevault::{Algorithm, Cipher, KeyManager};

struct UserData {
    id_card: String,
    phone: String,
}

struct DbRecord {
    encrypted_id_card: Vec<u8>,
    encrypted_phone: Vec<u8>,
}

#[test]
fn uat_database_encryption() {
    let key_manager = KeyManager::new().unwrap();
    let key_id = key_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let cipher = Cipher::new(Algorithm::AES256GCM).unwrap();
    
    // 1. Simulate User Data
    let user_data = UserData {
        id_card: "110101199001011234".to_string(),
        phone: "13800138000".to_string(),
    };
    
    // 2. Encrypt
    let encrypted_id_card = cipher.encrypt(&key_manager, &key_id, user_data.id_card.as_bytes()).unwrap();
    let encrypted_phone = cipher.encrypt(&key_manager, &key_id, user_data.phone.as_bytes()).unwrap();
    
    // 3. Store (Simulated)
    let db_record = DbRecord {
        encrypted_id_card,
        encrypted_phone,
    };
    
    // 4. Retrieve and Decrypt
    let decrypted_id_card = String::from_utf8(
        cipher.decrypt(&key_manager, &key_id, &db_record.encrypted_id_card).unwrap()
    ).unwrap();
    
    let decrypted_phone = String::from_utf8(
        cipher.decrypt(&key_manager, &key_id, &db_record.encrypted_phone).unwrap()
    ).unwrap();
    
    // 5. Verify
    assert_eq!(user_data.id_card, decrypted_id_card);
    assert_eq!(user_data.phone, decrypted_phone);
}