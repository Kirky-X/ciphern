// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

package com.ciphern;

public class Ciphern {
    static {
        System.loadLibrary("ciphern");
    }

    public static native int init();
    public static native void cleanup();
    public static native String generateKey(String algorithm);
    public static native byte[] encrypt(String keyId, byte[] plaintext);
    public static native byte[] decrypt(String keyId, byte[] ciphertext);

    public static void main(String[] args) {
        if (init() != 0) {
            System.err.println("Failed to initialize Ciphern library");
            System.exit(1);
        }

        try {
            String algorithm = "AES256GCM";
            String keyId = generateKey(algorithm);
            if (keyId.isEmpty()) {
                System.err.println("Failed to generate key");
                System.exit(1);
            }
            System.out.println("Generated key ID: " + keyId);

            String plaintext = "Hello from Java JNI!";
            byte[] ciphertext = encrypt(keyId, plaintext.getBytes());
            if (ciphertext.length == 0) {
                System.err.println("Encryption failed");
                System.exit(1);
            }
            System.out.println("Encryption successful");

            byte[] decrypted = decrypt(keyId, ciphertext);
            String decryptedStr = new String(decrypted);
            
            if (plaintext.equals(decryptedStr)) {
                System.out.println("Decryption successful: " + decryptedStr);
                System.out.println("Java JNI Test Passed!");
            } else {
                System.err.println("Decryption failed: expected '" + plaintext + "', got '" + decryptedStr + "'");
                System.exit(1);
            }
        } finally {
            cleanup();
        }
    }
}
