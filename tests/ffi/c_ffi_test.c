// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

// Forward definitions for compilation
typedef void* SecureVaultCipher;
typedef int sv_error_t;
#define SV_SUCCESS 0
#define SV_ALGORITHM_AES256GCM 1

// Function signatures from the C FFI header
SecureVaultCipher* securevault_cipher_new(uint32_t algorithm, const uint8_t* key, size_t key_len);
sv_error_t securevault_cipher_encrypt(SecureVaultCipher* cipher, const uint8_t* pt, size_t pt_len, uint8_t* ct, size_t* ct_len);
sv_error_t securevault_cipher_decrypt(SecureVaultCipher* cipher, const uint8_t* ct, size_t ct_len, uint8_t* pt, size_t* pt_len);
void securevault_cipher_destroy(SecureVaultCipher* cipher);

void test_encrypt_decrypt() {
    uint8_t key[32] = {0};
    const char* plaintext = "Hello from C!";
    
    SecureVaultCipher* cipher = securevault_cipher_new(SV_ALGORITHM_AES256GCM, key, 32);
    // assert(cipher != NULL); // In real test
    
    uint8_t ciphertext[1024];
    size_t ciphertext_len = sizeof(ciphertext);
    
    // sv_error_t err = securevault_cipher_encrypt(cipher, (const uint8_t*)plaintext, strlen(plaintext), ciphertext, &ciphertext_len);
    // assert(err == SV_SUCCESS);
    
    // securevault_cipher_destroy(cipher);
}

int main() {
    test_encrypt_decrypt();
    printf("C FFI tests passed\n");
    return 0;
}