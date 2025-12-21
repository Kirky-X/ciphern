// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Java JNI (Java Native Interface) 模块
//! 
//! 为 Java 提供本地接口支持

use jni::JNIEnv;
use jni::objects::{JClass, JString, JByteArray};
use jni::sys::{jint, jlong, jboolean};
use std::ffi::{CStr, CString};

use crate::ffi::{ciphern_init, ciphern_cleanup, ciphern_generate_key, ciphern_encrypt, ciphern_decrypt, CiphernError};

#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_init(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    ciphern_init() as jint
}

#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_cleanup(
    _env: JNIEnv,
    _class: JClass,
) {
    ciphern_cleanup();
}

#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_generateKey(
    mut env: JNIEnv,
    _class: JClass,
    algorithm: JString,
) -> JString {
    let algo_str: String = env.get_string(&algorithm).expect("Couldn't get java string!").into();
    let algo_cstring = CString::new(algo_str).unwrap();
    
    let mut key_id_buffer = [0u8; 256];
    let result = ciphern_generate_key(
        algo_cstring.as_ptr(),
        key_id_buffer.as_mut_ptr() as *mut i8,
        key_id_buffer.len(),
    );
    
    if result == CiphernError::Success {
        let key_id = unsafe { CStr::from_ptr(key_id_buffer.as_ptr() as *const i8).to_string_lossy().into_owned() };
        env.new_string(key_id).expect("Couldn't create java string!")
    } else {
        let msg = format!("Failed to generate key: {:?}", result);
        let _ = env.throw_new("com/ciphern/CiphernException", msg);
        env.new_string("").expect("Couldn't create java string!")
    }
}

#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_encrypt(
    mut env: JNIEnv,
    _class: JClass,
    key_id: JString,
    plaintext: JByteArray,
) -> JByteArray {
    let key_id_str: String = env.get_string(&key_id).expect("Couldn't get java string!").into();
    let key_id_cstring = CString::new(key_id_str).unwrap();
    
    let plaintext_bytes = env.convert_byte_array(&plaintext).expect("Couldn't get byte array!");
    
    let mut ciphertext_buffer = vec![0u8; plaintext_bytes.len() + 256]; // 预留空间
    let mut ciphertext_len: usize = 0;
    
    let result = ciphern_encrypt(
        key_id_cstring.as_ptr(),
        plaintext_bytes.as_ptr(),
        plaintext_bytes.len(),
        ciphertext_buffer.as_mut_ptr(),
        ciphertext_buffer.len(),
        &mut ciphertext_len as *mut usize,
    );
    
    if result == CiphernError::Success {
        ciphertext_buffer.truncate(ciphertext_len);
        env.byte_array_from_slice(&ciphertext_buffer).expect("Couldn't create byte array!")
    } else {
        let msg = format!("Encryption failed: {:?}", result);
        let _ = env.throw_new("com/ciphern/CiphernException", msg);
        env.new_byte_array(0).expect("Couldn't create byte array!")
    }
}

#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_decrypt(
    mut env: JNIEnv,
    _class: JClass,
    key_id: JString,
    ciphertext: JByteArray,
) -> JByteArray {
    let key_id_str: String = env.get_string(&key_id).expect("Couldn't get java string!").into();
    let key_id_cstring = CString::new(key_id_str).unwrap();
    
    let ciphertext_bytes = env.convert_byte_array(&ciphertext).expect("Couldn't get byte array!");
    
    let mut plaintext_buffer = vec![0u8; ciphertext_bytes.len()];
    let mut plaintext_len: usize = 0;
    
    let result = ciphern_decrypt(
        key_id_cstring.as_ptr(),
        ciphertext_bytes.as_ptr(),
        ciphertext_bytes.len(),
        plaintext_buffer.as_mut_ptr(),
        plaintext_buffer.len(),
        &mut plaintext_len as *mut usize,
    );
    
    if result == CiphernError::Success {
        plaintext_buffer.truncate(plaintext_len);
        env.byte_array_from_slice(&plaintext_buffer).expect("Couldn't create byte array!")
    } else {
        let msg = format!("Decryption failed: {:?}", result);
        let _ = env.throw_new("com/ciphern/CiphernException", msg);
        env.new_byte_array(0).expect("Couldn't create byte array!")
    }
}
