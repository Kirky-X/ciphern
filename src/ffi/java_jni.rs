// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Java JNI (Java Native Interface) 模块
//!
//! 为 Java 提供本地接口支持

use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::jint;
use jni::JNIEnv;
use std::ffi::CStr;

use crate::ffi::jni_utils::{JniBuffer, JniEnv, JniInitializer};
use crate::ffi::{ciphern_decrypt, ciphern_encrypt, ciphern_generate_key, CiphernError};

#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_init<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jint {
    JniInitializer::init()
}

#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_cleanup(_env: JNIEnv, _class: JClass) {
    JniInitializer::cleanup();
}

#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_generateKey<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    algorithm: JString<'local>,
) -> JString<'local> {
    let mut jni_env = JniEnv::new(env);

    // 获取算法名称
    let algo_cstring = match jni_env.get_cstring(&algorithm) {
        Ok(cstring) => cstring,
        Err(_) => {
            return jni_env
                .new_string("")
                .unwrap_or_else(|_| JObject::null().into())
        }
    };

    // 生成密钥
    let mut key_id_buffer = [0u8; 256];
    let result = ciphern_generate_key(
        algo_cstring.as_ptr(),
        key_id_buffer.as_mut_ptr() as *mut i8,
        key_id_buffer.len(),
    );

    match result {
        CiphernError::Success => {
            let key_id = unsafe {
                CStr::from_ptr(key_id_buffer.as_ptr() as *const i8)
                    .to_string_lossy()
                    .into_owned()
            };
            jni_env
                .new_string(&key_id)
                .unwrap_or_else(|_| JObject::null().into())
        }
        error => {
            let _ = jni_env.handle_ciphern_error(error);
            jni_env
                .new_string("")
                .unwrap_or_else(|_| JObject::null().into())
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_encrypt<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    key_id: JString<'local>,
    plaintext: JByteArray<'local>,
) -> JByteArray<'local> {
    let mut jni_env = JniEnv::new(env);

    // 获取参数
    let key_id_cstring = match jni_env.get_cstring(&key_id) {
        Ok(cstring) => cstring,
        Err(_) => {
            return jni_env
                .byte_array_from_slice(&[])
                .unwrap_or_else(|_| JObject::null().into())
        }
    };

    let plaintext_bytes = match jni_env.get_bytes(&plaintext) {
        Ok(bytes) => bytes,
        Err(_) => {
            return jni_env
                .byte_array_from_slice(&[])
                .unwrap_or_else(|_| JObject::null().into())
        }
    };

    // 执行加密
    let mut ciphertext_buffer = JniBuffer::create_encrypt_buffer(plaintext_bytes.len());
    let mut ciphertext_len: usize = 0;

    let result = ciphern_encrypt(
        key_id_cstring.as_ptr(),
        plaintext_bytes.as_ptr(),
        plaintext_bytes.len(),
        ciphertext_buffer.as_mut_ptr(),
        ciphertext_buffer.len(),
        &mut ciphertext_len as *mut usize,
    );

    match result {
        CiphernError::Success => {
            JniBuffer::truncate_buffer(&mut ciphertext_buffer, ciphertext_len);
            jni_env
                .byte_array_from_slice(&ciphertext_buffer)
                .unwrap_or_else(|_| JObject::null().into())
        }
        error => {
            let _ = jni_env.handle_ciphern_error(error);
            jni_env
                .byte_array_from_slice(&[])
                .unwrap_or_else(|_| JObject::null().into())
        }
    }
}

/// Java_com_ciphern_Ciphern_decrypt JNI 实现
#[no_mangle]
pub extern "system" fn Java_com_ciphern_Ciphern_decrypt<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    key_id: JString<'local>,
    ciphertext: JByteArray<'local>,
) -> JByteArray<'local> {
    let mut jni_env = JniEnv::new(env);

    // 获取参数
    let key_id_cstring = match jni_env.get_cstring(&key_id) {
        Ok(cstring) => cstring,
        Err(_) => {
            return jni_env
                .byte_array_from_slice(&[])
                .unwrap_or_else(|_| JObject::null().into())
        }
    };

    let ciphertext_bytes = match jni_env.get_bytes(&ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => {
            return jni_env
                .byte_array_from_slice(&[])
                .unwrap_or_else(|_| JObject::null().into())
        }
    };

    // 执行解密
    let mut plaintext_buffer = JniBuffer::create_decrypt_buffer(ciphertext_bytes.len());
    let mut plaintext_len: usize = 0;

    let result = ciphern_decrypt(
        key_id_cstring.as_ptr(),
        ciphertext_bytes.as_ptr(),
        ciphertext_bytes.len(),
        plaintext_buffer.as_mut_ptr(),
        plaintext_buffer.len(),
        &mut plaintext_len as *mut usize,
    );

    match result {
        CiphernError::Success => {
            JniBuffer::truncate_buffer(&mut plaintext_buffer, plaintext_len);
            jni_env
                .byte_array_from_slice(&plaintext_buffer)
                .unwrap_or_else(|_| JObject::null().into())
        }
        error => {
            let _ = jni_env.handle_ciphern_error(error);
            jni_env
                .byte_array_from_slice(&[])
                .unwrap_or_else(|_| JObject::null().into())
        }
    }
}
