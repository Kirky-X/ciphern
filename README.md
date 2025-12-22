# Ciphern Crypto Library

[![Crates.io](https://img.shields.io/crates/v/ciphern.svg)](https://crates.io/crates/ciphern)
[![Documentation](https://docs.rs/ciphern/badge.svg)](https://docs.rs/ciphern)
[![License](https://img.shields.io/github/license/Kirky-X/ciphern)](LICENSE)
[![Build Status](https://github.com/Kirky-X/ciphern/actions/workflows/health-check.yml/badge.svg)](https://github.com/Kirky-X/ciphern/actions/workflows/health-check.yml)
[![Coverage](https://img.shields.io/codecov/c/github/Kirky-X/ciphern)](https://codecov.io/gh/Kirky-X/ciphern)
[![Security Audit](https://img.shields.io/badge/security-audited-success)](docs/SECURITY_AUDIT.md)

**Ciphern** is an enterprise-grade, security-first Rust cryptographic library providing cryptographic capabilities that comply with both Chinese National Standards (GuoMi) and international standards. Designed for data storage encryption, communication encryption, and key management.

[English](README.md) | [中文文档](README_zh.md)

---

## ✨ Core Features

### 🔒 Security First

- **Memory Protection**: Securely clear keys using `zeroize`, support for memory locking
- **Compliance**: Compliant with Chinese National Standards (SM2/SM3/SM4) and FIPS 140-3 basic requirements
- **Audit Logs**: Full audit trail for cryptographic operations
- **Key Lifecycle**: Support for basic lifecycle management including key generation, activation, and destruction

### ⚡ High Performance

- **Zero-Copy Design**: Minimizes memory allocation and copying
- **Smart Caching**: Reuses keys and algorithm instances
- **Pure Rust Implementation**: No external dependencies, compile-time optimization

### 🔧 Easy Integration

- **Unified Interface**: Simple API that hides underlying complexity
- **Multi-language Support**: C FFI interface, basic Java JNI and Python PyO3 bindings
- **Pluggable Architecture**: Supports custom cryptographic algorithm plugins (basic framework)
- **Rich Testing**: Includes unit tests, integration tests, and performance tests

### 🌐 Standard Compatibility

- **International Standards**: AES-128/192/256-GCM, ECDSA-P256/P384/P521, RSA-2048/3072/4096, Ed25519
- **National Standards**: SM2, SM3, SM4-GCM
- **Hash Functions**: SHA-256/384/512, SHA3-256/384/512, SM3
- **Key Derivation**: HKDF, PBKDF2, Argon2id, SM3-KDF

---

## 🚀 Quick Start

### Installation

**Rust (Cargo)**

```toml
[dependencies]
ciphern = "0.1"
```

**Java (Maven)**

Java bindings are under development, requiring manual compilation of the JNI library:

```xml
<!-- Maven direct installation is not yet supported, requires compilation from source -->
```

**Python (pip)**

Python bindings are under development, requiring manual compilation:

```bash
# pip direct installation is not yet supported, requires compilation from source
# pip install ciphern  # Not available yet
```

### 5-Minute Examples

#### Basic Encryption/Decryption (Rust)

```rust
use ciphern::{Cipher, Algorithm, KeyManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    ciphern::init()?;
    
    // Initialize KeyManager
    let km = KeyManager::new()?;
    
    // Generate a key
    let key_id = km.generate_key(Algorithm::AES256GCM)?;
    
    // Create a cipher
    let cipher = Cipher::new(Algorithm::AES256GCM)?;
    
    // Encrypt
    let plaintext = b"Hello, Ciphern!";
    let ciphertext = cipher.encrypt(&km, &key_id, plaintext)?;
    
    // Decrypt
    let decrypted = cipher.decrypt(&km, &key_id, &ciphertext)?;
    assert_eq!(plaintext, &decrypted[..]);
    
    println!("✅ Encryption and decryption successful!");
    Ok(())
}
```

#### Digital Signature (Rust)

```rust
use ciphern::{Signer, Algorithm, KeyManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    ciphern::init()?;
    
    // Initialize KeyManager
    let km = KeyManager::new()?;
    
    // Generate a key pair (using ECDSA-P256 as an example)
    let key_id = km.generate_key(Algorithm::ECDSAP256)?;
    
    // Create a signer
    let signer = Signer::new(Algorithm::ECDSAP256)?;
    
    // Sign
    let message = b"Important message";
    let signature = signer.sign(&km, &key_id, message)?;
    
    // Verify
    let is_valid = signer.verify(&km, &key_id, message, &signature)?;
    assert!(is_valid);
    
    println!("✅ Signature verified!");
    Ok(())
}
```

#### National Standard Algorithms (Rust)

```rust
use ciphern::{Cipher, Algorithm, KeyManager, Hash};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    ciphern::init()?;
    
    let km = KeyManager::new()?;

    // SM4 Encryption
    let key_id = km.generate_key(Algorithm::SM4GCM)?;
    let cipher = Cipher::new(Algorithm::SM4GCM)?;
    let ciphertext = cipher.encrypt(&km, &key_id, b"GuoMi encryption test")?;
    
    // SM3 Hash
    let hash = Hash::sm3(b"Data integrity verification")?;
    
    println!("✅ National standard algorithms executed successfully!");
    Ok(())
}
```

#### Java Example

Java bindings are under development, currently requiring manual compilation of the JNI library:

```java
// Direct usage is not yet supported, requires compilation of the JNI library from source
// import com.ciphern.*;
```

#### Python Example

Python bindings are under development, currently requiring manual compilation:

```python
# Direct usage is not yet supported, requires compilation of the PyO3 extension from source
# from ciphern import Cipher, Algorithm
```

---

## 📚 Documentation

### Core Documentation

- **[User Guide](docs/USER_GUIDE.md)** - Detailed instructions and best practices
- **[API Reference](https://docs.rs/ciphern)** - Complete API reference
- **[Examples](examples/)** - Examples covering common scenarios

### Advanced Topics

- **[Architecture](docs/ARCHITECTURE.md)** - System architecture and design decisions
- **[Performance Optimization](docs/PERFORMANCE.md)** - SIMD, hardware acceleration, benchmark
- **[Security Guide](docs/SECURITY.md)** - Threat model, security best practices
- **[Multi-Tenancy Guide](docs/MULTI_TENANT.md)** - Key isolation and access control

### Developer Documentation

- **[Contributing Guide](CONTRIBUTING.md)** - How to participate in development
- **[Plugin Development](docs/PLUGIN_DEVELOPMENT.md)** - Implementing custom algorithms
- **[FFI Guide](docs/FFI_GUIDE.md)** - C/Java/Python bindings

---

## 🎯 Use Cases

### Data Storage Encryption

Protect sensitive data in databases and file systems

```rust
use ciphern::{Cipher, KeyManager, Algorithm};

ciphern::init()?;
let km = KeyManager::new()?;
let key_id = km.generate_key_with_alias(Algorithm::AES256GCM, "database-encryption")?;
let cipher = Cipher::new(Algorithm::AES256GCM)?;

// Encrypt sensitive field
let encrypted_ssn = cipher.encrypt(&km, &key_id, user.ssn.as_bytes())?;
db.save_encrypted_field(user.id, "ssn", &encrypted_ssn)?;
```

### API Communication Encryption

Protect the confidentiality and integrity of API requests and responses

```rust
use ciphern::{Signer, Algorithm, KeyManager};

ciphern::init()?;
let km = KeyManager::new()?;
let key_id = km.generate_key(Algorithm::ECDSAP384)?;
let signer = Signer::new(Algorithm::ECDSAP384)?;
let signature = signer.sign(&km, &key_id, &request_body)?;

http_request
    .header("X-Signature", base64::encode(&signature))
    .body(request_body)
    .send()?;
```

### Key Management

Basic key lifecycle management

```rust
use ciphern::{KeyManager, Algorithm};

ciphern::init()?;
let km = KeyManager::new()?;

// Generate a key
let key_id = km.generate_key(Algorithm::AES256GCM)?;

// Manage keys using aliases
let alias_key_id = km.generate_key_with_alias(Algorithm::AES256GCM, "my-app-key")?;
```

---

## 🔧 Advanced Features

### FIPS 140-3 Compliance Mode

```toml
[dependencies]
ciphern = { version = "0.1", features = ["fips"] }
```

```rust
use ciphern::{is_fips_enabled, Algorithm, Cipher};

// Enable FIPS mode during initialization
ciphern::init()?;

// Check if FIPS mode is enabled
if is_fips_enabled() {
    println!("FIPS mode is enabled");
}

// In FIPS mode, non-approved algorithms will be rejected
let result = Cipher::new(Algorithm::SM4GCM);
assert!(result.is_err()); // CryptoError::FipsError
```

### Audit Logging and Monitoring

```rust
use ciphern::audit::{AuditLogger, AuditEvent, PerformanceMetrics};
use std::sync::Arc;

// Initialize the library
ciphern::init()?;

// Create an audit logger
let audit_logger = Arc::new(AuditLogger::new());

// Log an event
let event = AuditEvent::new("encryption", "AES256GCM", "success");
audit_logger.log_event(event)?;

// Get performance metrics
let metrics = audit_logger.get_performance_metrics()?;
println!("Throughput: {:.2} ops/sec", metrics.avg_throughput_ops_per_sec);
println!("Cache hit rate: {:.1}%", metrics.avg_cache_hit_rate * 100.0);
```

### Custom Algorithm Plugins

```rust
use ciphern::plugin::{Plugin, CipherPlugin};
// Extend algorithms by implementing Plugin and CipherPlugin traits
```

---

## 📊 Performance Metrics

### Performance Metrics

The current version is based on a pure Rust implementation. Performance data can be obtained through the audit system:

```rust
use ciphern::audit::{AuditLogger, PerformanceMetrics};

let audit_logger = AuditLogger::new();
let metrics = audit_logger.get_performance_metrics()?;

println!("Average Throughput: {:.2} ops/sec", metrics.avg_throughput_ops_per_sec);
println!("Average Latency: {:.2} μs", metrics.avg_latency_us);
println!("Cache Hit Rate: {:.1}%", metrics.avg_cache_hit_rate * 100.0);
```

> Note: SIMD optimization and hardware acceleration features are under development. The current version provides a basic implementation of cryptographic functions.

Run benchmark:

```bash
cargo bench
```

---

## 🔐 Security

### Security Features

- ✅ **Automatic Memory Erasure**: Securely clear keys using `zeroize`
- ✅ **FIPS 140-3 Basic Compliance**: Supports verification of FIPS-approved algorithms
- ✅ **Audit Logs**: Full audit trail for cryptographic operations
- ✅ **Algorithm Verification**: Built-in algorithm correctness self-checks
- ✅ **Error Handling**: Secure error state management

> Note: Constant-time implementation, memory locking, side-channel protection, and other advanced security features are under development.

### Security Audit

Ciphern security features are based on the following implementations:

- ✅ Uses mature cryptographic libraries (`ring`, `libsm`) as the underlying implementation
- ✅ Built-in algorithm correctness verification
- ✅ FIPS 140-3 algorithm approval checks
- ✅ Comprehensive error handling and state management

> Note: NIST CAVP testing, Fuzzing, third-party security audits, etc., are planned.

### Vulnerability Reporting

If you find a security vulnerability, please report it in the GitHub Issues.

> Note: A dedicated security email and SECURITY.md documentation are being prepared.

---

## 🛠️ Development Environment

### Prerequisites

- Rust 1.75+ (stable)
- Standard C compiler (for FFI bindings)

### Build

```bash
# Clone the repository
git clone https://github.com/Kirky-X/ciphern.git
cd ciphern

# Default build
cargo build --release

# Enable all features
cargo build --release --all-features

# FIPS mode
cargo build --release --features fips
```

### Test

```bash
# Run all tests
cargo test --all-features

# Run benchmarks
cargo bench

# Check code quality
cargo clippy --all-features
```

### Cross-Compilation

```bash
# ARM64 Linux
cargo build --target aarch64-unknown-linux-gnu --release

# Windows
cargo build --target x86_64-pc-windows-msvc --release

# macOS ARM (Apple Silicon)
cargo build --target aarch64-apple-darwin --release
```

---

## 🗺️ Roadmap

### v0.1.0 - MVP (Completed) ✅

- [x] Core encryption (AES-128/192/256-GCM, SM4-GCM)
- [x] Digital signatures (ECDSA-P256/P384/P521, RSA-2048/3072/4096, Ed25519, SM2)
- [x] Hash functions (SHA-256/384/512, SHA3-256/384/512, SM3)
- [x] Key derivation (HKDF, PBKDF2, Argon2id, SM3-KDF)
- [x] Basic key management
- [x] Rust API
- [x] Audit logging system
- [x] FIPS 140-3 basic support

### v0.2.0 - Multi-language Support (Partially Completed) 🚧

- [x] C FFI interface
- [ ] Java JNI bindings (basic framework exists)
- [ ] Python PyO3 bindings (basic framework exists)
- [ ] Memory protection enhancements
- [ ] Plugin system improvements

### v0.3.0 - Extensibility (Planned) 📋

- [ ] SIMD optimization
- [ ] WASM support
- [ ] HSM integration (PKCS#11)
- [ ] TEE support (Intel SGX, ARM TrustZone)

### v1.0.0 - Production Ready (Planned) 🎯

- [ ] Complete security audit
- [ ] FIPS 140-3 certification
- [ ] Performance optimization (SIMD, multi-core)
- [ ] Full documentation and examples

---

## 🤝 Contributing

We welcome all forms of contribution!

### How to Contribute

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

> Note: CONTRIBUTING.md documentation is being prepared.

### Contributors

Thanks to all contributors!

[![Contributors](https://contrib.rocks/image?repo=Kirky-X/ciphern)](https://github.com/Kirky-X/ciphern/graphs/contributors)

---

## 📄 License

This project is dual-licensed:

- **MIT License** - see [LICENSE-MIT](LICENSE-MIT)
- **Apache License 2.0** - see [LICENSE-APACHE](LICENSE-APACHE)

You may choose either license for your use.

> Note: License files are being prepared. The current version follows standard Rust open-source protocols.

---

## 🙏 Acknowledgments

Ciphern is built upon these excellent open-source projects:

- [ring](https://github.com/briansmith/ring) - High-performance cryptography library (v0.17)
- [libsm](https://github.com/citahub/libsm) - GuoMi algorithm implementation (v0.6)
- [aes-gcm](https://github.com/RustCrypto/AEADs) - AES-GCM implementation (v0.10)
- [argon2](https://github.com/RustCrypto/password-hashes) - Argon2 key derivation (v0.5)
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) - Secure memory erasure (v1.7)

Special thanks to all security researchers who audited the code and provided feedback.

---

## 📞 Contact

- **Issues**: https://github.com/Kirky-X/ciphern/issues
- **Discussions**: https://github.com/Kirky-X/ciphern/discussions

> Note: Official website, documentation site, and dedicated support email are being prepared.

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Kirky-X/ciphern&type=Date)](https://star-history.com/#Kirky-X/ciphern&Date)

---

**Built with ❤️ by the Ciphern Team**

[⬆ Back to Top](#ciphern-crypto-library)
