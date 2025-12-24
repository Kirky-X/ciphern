// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! Ciphern Crypto Library - Python API Examples
//!
//! This module provides examples of using Ciphern from Python via PyO3.
//!
//! # Python Usage
//!
//! ```python
//! from ciphern import Ciphern, KeyManager, Cipher, Algorithm, Hash
//!
//! # Initialize the library
//! Ciphern.init()
//!
//! # Create a key manager
//! key_manager = KeyManager()
//!
//! # Generate a key
//! key_id = key_manager.generate_key(Algorithm.AES_256_GCM)
//!
//! # Create a cipher and encrypt data
//! cipher = Cipher(Algorithm.AES_256_GCM)
//! plaintext = b"Hello, Ciphern!"
//! ciphertext = cipher.encrypt(key_manager, key_id, plaintext)
//!
//! # Decrypt the data
//! decrypted = cipher.decrypt(key_manager, key_id, ciphertext)
//!
//! # Verify
//! assert plaintext == decrypted
//! print("Python encryption successful!")
//! ```

use std::result::Result;

/// Python AES-256-GCM Encryption Example
///
/// Demonstrates using Ciphern from Python with AES-256-GCM encryption.
pub fn python_aes_example() {
    println!(
        r#"
Python AES-256-GCM Example
==========================

from ciphern import Ciphern, KeyManager, Cipher, Algorithm

# Initialize the library
Ciphern.init()

# Create a key manager
key_manager = KeyManager()

# Generate a key
key_id = key_manager.generate_key(Algorithm.AES_256_GCM)
print("Generated Key ID: {{}}".format(key_id))

# Create a cipher
cipher = Cipher(Algorithm.AES_256_GCM)

# Encrypt data
plaintext = b"Hello, Ciphern from Python!"
ciphertext = cipher.encrypt(key_manager, key_id, plaintext)
print("Ciphertext length: {{}} bytes".format(len(ciphertext)))

# Decrypt data
decrypted = cipher.decrypt(key_manager, key_id, ciphertext)
print("Decrypted: {{}}".format(decrypted.decode()))

# Verify
assert plaintext == decrypted
print("Python AES-256-GCM encryption successful!")
"#
    );
}

/// Python Digital Signature Example
///
/// Demonstrates digital signatures from Python.
pub fn python_signature_example() {
    println!(
        r#"
Python Digital Signature Example
================================

from ciphern import Ciphern, KeyManager, Signer, Algorithm

# Initialize the library
Ciphern.init()

# Create a key manager
key_manager = KeyManager()

# Generate an Ed25519 key pair
key_id = key_manager.generate_key(Algorithm.ED_25519)
print("Generated Key ID: {{}}".format(key_id))

# Create a signer
signer = Signer(Algorithm.ED_25519)

# Sign a message
message = b"Message to sign"
signature = signer.sign(key_manager, key_id, message)
print("Signature length: {{}} bytes".format(len(signature)))

# Verify the signature
is_valid = signer.verify(key_manager, key_id, message, signature)
print("Signature valid: {{}}".format(is_valid))

assert is_valid
print("Python digital signature successful!")
"#
    );
}

/// Python SM4 Encryption Example
///
/// Demonstrates SM4 encryption (Chinese national standard) from Python.
pub fn python_sm4_example() {
    println!(
        r#"
Python SM4-GCM Example (Chinese National Standard)
===================================================

from ciphern import Ciphern, KeyManager, Cipher, Algorithm

# Initialize the library
Ciphern.init()

# Create a key manager
key_manager = KeyManager()

# Generate an SM4 key
key_id = key_manager.generate_key(Algorithm.SM4_GCM)
print("Generated SM4 Key ID: {{}}".format(key_id))

# Create a cipher
cipher = Cipher(Algorithm.SM4_GCM)

# Encrypt data
plaintext = b"Hello, SM4 encryption from Python!"
ciphertext = cipher.encrypt(key_manager, key_id, plaintext)
print("Ciphertext length: {{}} bytes".format(len(ciphertext)))

# Decrypt data
decrypted = cipher.decrypt(key_manager, key_id, ciphertext)
print("Decrypted: {{}}".format(decrypted.decode()))

# Verify
assert plaintext == decrypted
print("Python SM4-GCM encryption successful!")
"#
    );
}

/// Python Key Management Example
///
/// Demonstrates key management from Python.
pub fn python_key_management_example() {
    println!(
        r#"
Python Key Management Example
=============================

from ciphern import Ciphern, KeyManager, Algorithm, KeyState

# Initialize the library
Ciphern.init()

# Create a key manager
key_manager = KeyManager()

# Generate multiple keys
key_id_1 = key_manager.generate_key(Algorithm.AES_256_GCM)
key_id_2 = key_manager.generate_key(Algorithm.SM4_GCM)
key_id_3 = key_manager.generate_key(Algorithm.ED_25519)

print("Generated 3 keys:")
print("  1. {{}}".format(key_id_1))
print("  2. {{}}".format(key_id_2))
print("  3. {{}}".format(key_id_3))

# Get key state
state = key_manager.get_key_state(key_id_1)
print("Key 1 state: {{}}".format(state))

# Rotate key
key_manager.rotate_key(key_id_1)
print("Key 1 rotated successfully")

# Deprecate key
key_manager.deprecate_key(key_id_2)
print("Key 2 deprecated successfully")

# Destroy key
key_manager.destroy_key(key_id_3)
print("Key 3 destroyed successfully")

print("Python key management successful!")
"#
    );
}

/// Python Hash Operations Example
///
/// Demonstrates hash operations from Python.
pub fn python_hash_example() {
    println!(
        r#"
Python Hash Operations Example
==============================

from ciphern import Ciphern, Hash

# Initialize the library
Ciphern.init()

# Data to hash
data = b"Hello, Ciphern!"

# Compute SHA-256 hash
sha256 = Hash.sha256(data)
print("SHA-256: {{}}...".format(sha256.hex()[:32]))

# Compute SHA-512 hash
sha512 = Hash.sha512(data)
print("SHA-512: {{}}...".format(sha512.hex()[:32]))

# Compute SM3 hash (Chinese national standard)
sm3 = Hash.sm3(data)
print("SM3: {{}}...".format(sm3.hex()[:32]))

# Compute BLAKE3 hash (high performance)
blake3 = Hash.blake3(data)
print("BLAKE3: {{}}...".format(blake3.hex()[:32]))

print("Python hash operations successful!")
"#
    );
}

/// Python Random Generation Example
///
/// Demonstrates secure random generation from Python.
pub fn python_random_example() {
    println!(
        r#"
Python Random Generation Example
================================

from ciphern import Ciphern, Random

# Initialize the library
Ciphern.init()

# Generate random bytes
random_bytes = Random.bytes(32)
print("Random bytes: {{}}...".format(random_bytes.hex()[:32]))

# Generate a UUID v4
uuid = Random.uuid_v4()
print("UUID v4: {{}}".format(uuid))

# Generate random number in range
random_int = Random.randint(1, 1000)
print("Random int (1-1000): {{}}".format(random_int))

print("Python random generation successful!")
"#
    );
}

/// Python Complete Example
///
/// A complete Python example demonstrating multiple features.
pub fn python_complete_example() {
    println!(
        r#"
Python Complete Example
=======================

from ciphern import Ciphern, KeyManager, Cipher, Signer, Algorithm, Hash, Random

def main():
    # Initialize
    Ciphern.init()
    print("Ciphern initialized")

    # Key management
    key_manager = KeyManager()
    aes_key = key_manager.generate_key(Algorithm.AES_256_GCM)
    sign_key = key_manager.generate_key(Algorithm.ED_25519)
    print("Keys generated: {{}}..., {{}}...".format(aes_key[:8], sign_key[:8]))

    # Encryption
    cipher = Cipher(Algorithm.AES_256_GCM)
    plaintext = b"Secret message from Python!"
    ciphertext = cipher.encrypt(key_manager, aes_key, plaintext)
    print("Data encrypted: {{}} bytes".format(len(ciphertext)))

    # Decryption
    decrypted = cipher.decrypt(key_manager, aes_key, ciphertext)
    print("Data decrypted: {{}}".format(decrypted.decode()))

    # Digital signature
    signer = Signer(Algorithm.ED_25519)
    message = b"Message to sign"
    signature = signer.sign(key_manager, sign_key, message)
    print("Message signed: {{}} bytes".format(len(signature)))

    # Verify signature
    is_valid = signer.verify(key_manager, sign_key, message, signature)
    print("Signature valid: {{}}".format(is_valid))

    # Hash operations
    hash_result = Hash.sha256(plaintext)
    print("SHA-256: {{}}...".format(hash_result.hex()[:32]))

    # Random generation
    random_data = Random.bytes(16)
    print("Random bytes: {{}}".format(random_data.hex()))

    # Key lifecycle
    key_manager.rotate_key(aes_key)
    print("Key rotated")

    key_manager.deprecate_key(aes_key)
    print("Key deprecated")

    key_manager.destroy_key(aes_key)
    print("Key destroyed")

    print("\nAll operations completed successfully!")

if __name__ == "__main__":
    main()
"#
    );
}

/// Python Web Application Example
///
/// Example of using Ciphern in a Python web application.
pub fn python_web_example() {
    println!(
        r#"
Python Web Application Example (FastAPI)
========================================

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from ciphern import Ciphern, KeyManager, Cipher, Algorithm
from typing import Optional

app = FastAPI()

# Initialize Ciphern on startup
@app.on_event("startup")
async def startup():
    Ciphern.init()
    # In production, load keys from secure storage

# Dependency for key manager
def get_key_manager() -> KeyManager:
    return KeyManager()

class EncryptRequest(BaseModel):
    plaintext: str
    algorithm: str = "AES_256_GCM"

class EncryptResponse(BaseModel):
    ciphertext: str
    key_id: str

@app.post("/encrypt", response_model=EncryptResponse)
async def encrypt(
    request: EncryptRequest,
    key_manager: KeyManager = Depends(get_key_manager)
):
    try:
        algo = Algorithm[request.algorithm]
        cipher = Cipher(algo)
        key_id = key_manager.generate_key(algo)

        plaintext_bytes = request.plaintext.encode()
        ciphertext = cipher.encrypt(key_manager, key_id, plaintext_bytes)

        return EncryptResponse(
            ciphertext=ciphertext.hex(),
            key_id=key_id
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/decrypt")
async def decrypt(
    ciphertext: str,
    key_id: str,
    algorithm: str,
    key_manager: KeyManager = Depends(get_key_manager)
):
    try:
        algo = Algorithm[algorithm]
        cipher = Cipher(algo)

        ciphertext_bytes = bytes.fromhex(ciphertext)
        decrypted = cipher.decrypt(key_manager, key_id, ciphertext_bytes)

        return {{"plaintext": decrypted.decode()}}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Run with: uvicorn main:app --reload
"#
    );
}

pub fn run_all() -> Result<(), Box<dyn std::error::Error>> {
    python_aes_example();
    python_signature_example();
    python_hash_example();
    python_key_management_example();
    python_web_example();
    Ok(())
}

fn main() {
    if let Err(e) = run_all() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
