# Ciphern Crypto Library

[![Crates.io](https://img.shields.io/crates/v/ciphern.svg)](https://crates.io/crates/ciphern)
[![Documentation](https://docs.rs/ciphern/badge.svg)](https://docs.rs/ciphern)
[![License](https://img.shields.io/crates/l/ciphern.svg)](LICENSE)
[![Build Status](https://github.com/Kirky-X/ciphern/workflows/CI/badge.svg)](https://github.com/Kirky-X/ciphern/actions)
[![Coverage](https://img.shields.io/codecov/c/github/Kirky-X/ciphern)](https://codecov.io/gh/Kirky-X/ciphern)
[![Security Audit](https://img.shields.io/badge/security-audited-success)](docs/SECURITY_AUDIT.md)

**Ciphern** is an enterprise-grade, security-first Rust cryptographic library providing cryptographic capabilities that
comply with both Chinese National Standards (GuoMi) and international standards. It is designed for data storage
encryption, communication encryption, and key management.

[English](README.md) | [中文文档](README_zh.md)

---

## ✨ Key Features

### 🔒 Security First

- **Multi-layer Protection**: Memory protection, side-channel resistance, and key isolation.
- **Compliance**: Compliant with Chinese National Standards (SM2/SM3/SM4) and FIPS 140-3.
- **Zero-Knowledge Auditing**: Full operation logs without leaking sensitive data.

### ⚡ High Performance
- **Zero-Copy Design**: Minimizes memory allocation and copying.
- **Smart Caching**: Reuses keys and algorithm instances.
- **Pure Rust Implementation**: No external dependencies, compile-time optimizations.
> Note: SIMD optimization and hardware acceleration features are under development

### 🔧 Easy Integration

- **Unified Interface**: Simple API that masks underlying complexity.
- **Multi-language Support**: Rust / Java / Python / C.
- **Pluggable Architecture**: Allows user-defined cryptographic algorithms.
- **Rich Examples**: Covers common usage scenarios.
> Note: JavaScript WASM bindings are under development

### 🌐 Standard Compatibility

- **International Standards**: AES-128/192/256-GCM, ECDSA-P256/P384/P521, RSA-2048/3072/4096, SHA-256/384/512, SHA3-256/384/512, Ed25519
- **National Standards**: SM2, SM3, SM4-GCM
- **Key Derivation**: HKDF, PBKDF2, SM3-KDF, Argon2id
> Note: TLS 1.3, JWE, and PKCS#11 support are under development

---

## 🚀 Quick Start

### Installation

**Rust (Cargo)**

```toml
[dependencies]
ciphern = "0.1"
```

**Java (Maven)**

```xml

<dependency>
    <groupId>com.ciphern</groupId>
    <artifactId>ciphern-jni</artifactId>
    <version>0.1.0</version>
</dependency>
```

**Python (pip)**

```bash
pip install ciphern
```

### 5-Minute Examples

#### Basic Encryption and Decryption (Rust)

```rust
use ciphern::{Cipher, Algorithm, KeyManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library (required)
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
    // Initialize the library (required)
    ciphern::init()?;
    
    // Initialize KeyManager
    let km = KeyManager::new()?;

    // Generate a key pair (using SM2 as an example)
    let key_id = km.generate_key(Algorithm::SM2)?;

    // Create a signer
    let signer = Signer::new(Algorithm::SM2)?;

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
    // Initialize the library (required)
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

#### Java Example (Partial Implementation)

```java
import com.ciphern.*;

public class Example {
    public static void main(String[] args) {
        try (KeyManager km = new KeyManager()) {
            String key_id = km.generateKey(Algorithm.AES256GCM);
            try (Cipher cipher = new Cipher(Algorithm.AES256GCM)) {
                byte[] plaintext = "Hello, Java!".getBytes();
                byte[] ciphertext = cipher.encrypt(km, key_id, plaintext);
                byte[] decrypted = cipher.decrypt(km, key_id, ciphertext);
                
                System.out.println("✅ Success: " + new String(decrypted));
            }
        } catch (CryptoException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
```

#### Python Example (Partial Implementation)

```python
from ciphern import Cipher, Algorithm, KeyManager

with KeyManager() as km:
    key_id = km.generate_key(Algorithm.AES256GCM)
    with Cipher(Algorithm.AES256GCM) as cipher:
        plaintext = b"Hello, Python!"
        ciphertext = cipher.encrypt(km, key_id, plaintext)
        decrypted = cipher.decrypt(km, key_id, ciphertext)
        
        assert plaintext == decrypted
        print("✅ Success!")
```

---

## 📚 Documentation

### Core Documentation

- **[User Guide](USE_GUIDE.md)** - Detailed instructions and best practices.
- **[API Reference](https://docs.rs/ciphern)** - Complete API documentation.
- **[Examples](examples/)** - Code examples for common scenarios.

### Advanced Topics

- **[Architecture](docs/ARCHITECTURE.md)** - System architecture and design decisions.
- **[Performance](docs/PERFORMANCE.md)** - SIMD, hardware acceleration, and benchmarks.
- **[Security](docs/SECURITY.md)** - Threat model and security best practices.
- **[Multi-Tenancy](docs/MULTI_TENANT.md)** - Key isolation and access control.

### Developer Documentation

- **[Contributing](CONTRIBUTING.md)** - How to participate in development.
- **[Plugin Development](docs/PLUGIN_DEVELOPMENT.md)** - Implementing custom algorithms.
- **[FFI Guide](docs/FFI_GUIDE.md)** - C/Java/Python bindings.

---

## 🎯 Use Cases

### Data Storage Encryption

Protect sensitive data in databases and file systems.

```rust
use ciphern::{Cipher, KeyManager, Algorithm};

// Initialize the library (required)
ciphern::init()?;

let km = KeyManager::new()?;
let key_id = km.generate_key_with_alias(Algorithm::AES256GCM, "database-encryption")?;
let cipher = Cipher::new(Algorithm::AES256GCM)?;

// Encrypt sensitive field
let encrypted_ssn = cipher.encrypt(&km, &key_id, user.ssn.as_bytes())?;
db.save_encrypted_field(user.id, "ssn", &encrypted_ssn)?;
```

### API Communication Encryption

Protect the confidentiality and integrity of API requests and responses.

```rust
use ciphern::{Signer, Algorithm, KeyManager};

// Initialize the library (required)
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

Multi-tenant isolation and audit logging.

```rust
use ciphern::{KeyManager, Algorithm};
use ciphern::audit::AuditLogger;

// Initialize the library (required)
ciphern::init()?;

// Initialize audit system
AuditLogger::init();

let km = KeyManager::new()?;
let key_id = km.generate_key(Algorithm::AES256GCM)?;
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

// Check if FIPS mode is enabled
if is_fips_enabled() {
println ! ("FIPS mode is enabled");
}

// In FIPS mode, non-approved algorithms will be rejected
let result = Cipher::new(Algorithm::SM4GCM);
assert!(result.is_err()); // CryptoError::FipsError
```

### SIMD Performance Optimization (Under Development)

```toml
[dependencies]
ciphern = { version = "0.1", features = ["simd"] }
```

Planned features:
- **x86_64**: AES-NI + AVX2
- **ARM64**: ARM Crypto Extensions  
- **Fallback**: Pure software implementation

> Note: SIMD optimization is currently under development

### Audit Logging and Monitoring

```rust
use ciphern::audit::AuditLogger;

// Initialize audit system
AuditLogger::init();

// The system automatically records all encryption/decryption/key management operations
```

### Custom Algorithm Plugins

```rust
use ciphern::plugin::{Plugin, CipherPlugin};
// Extend algorithms by implementing Plugin and CipherPlugin traits
```

---

## 📊 Performance Metrics

Performance metrics are available through the built-in `AuditLogger` system:

```rust
use ciphern::audit::{AuditLogger, PerformanceStats};

// Initialize audit system
AuditLogger::init();

// Get performance statistics
let stats = AuditLogger::get_performance_stats();
println!("Total operations: {}", stats.total_operations);
println!("Average latency: {} μs", stats.avg_latency_us);
println!("Average throughput: {} ops/sec", stats.avg_throughput_ops_per_sec);
println!("Cache hit rate: {}%", stats.avg_cache_hit_rate * 100.0);
```

Run benchmarks:

```bash
cargo bench
```

> Note: Detailed throughput and latency benchmarks will be available once the SIMD optimization features are implemented. Current performance metrics are tracked via the audit system.

---

## 🔐 Security

### Security Features

- ✅ **Constant-time Implementation**: Prevents timing attacks.
- ✅ **Automatic Memory Zeroing**: Uses `zeroize` to securely clear keys.
- ✅ **Memory Locking**: Uses `mlock` to prevent keys from being swapped to disk (Unix systems).
- ✅ **Memory Tampering Detection**: ProtectedKey with canary + checksum for integrity verification.
- ✅ **Audit Logging**: Built-in operation logging and performance monitoring.
> Note: Side-channel protection and power analysis resistance are under development

### Security Audit

Ciphern includes basic security testing:

- ✅ Basic test vector verification
- ✅ Memory safety through Rust's type system
- ✅ Audit logging for operation tracking

Planned security enhancements:
- NIST CAVP test vector verification
- Continuous fuzzing
- Third-party security audit
> Note: Security audit documentation will be available once formal audits are completed

### Vulnerability Reporting

If you find a security vulnerability, please email security@ciphern.dev. We will respond within 48 hours.

See [SECURITY.md](SECURITY.md) for more details.

---

## 🛠️ Development

### Prerequisites

- Rust 1.75+ (stable)
- For Unix systems: Standard development tools (gcc, make)

### Build

```bash
# Clone the repository
git clone https://github.com/Kirky-X/ciphern.git
cd ciphern

# Default build
cargo build --release

# Enable all features
cargo build --release --all-features

# FIPS mode (basic compliance)
cargo build --release --features fips
```

> Note: SIMD optimization features are under development

### Test

```bash
# Run all tests
cargo test --all-features

# Run specific test suites
cargo test --test memory_protection_test
cargo test --test signature_test
cargo test --test key_test
```

> Note: Test coverage and fuzzing tools will be configured in future releases

### Cross-Compilation

```bash
# ARM64 Linux (with appropriate target installed)
cargo build --target aarch64-unknown-linux-gnu --release

# Windows (with appropriate target installed)
cargo build --target x86_64-pc-windows-msvc --release

# macOS ARM (Apple Silicon, with appropriate target installed)
cargo build --target aarch64-apple-darwin --release
```

> Note: Cross-compilation requires installing the appropriate Rust targets and system toolchains

---

## 🗺️ Roadmap

### v0.1.0 - MVP (Completed) ✅

- [x] Core encryption (AES, SM4)
- [x] Digital signatures (ECDSA, SM2)
- [x] Hash functions (SHA-256/384/512, SM3)
- [x] Basic key management
- [x] Rust API

### v0.2.0 - Security Enhancements (In Progress) 🚧

- [x] Memory protection mechanisms
- [x] Side-channel protection
- [x] FIPS 140-3 mode
- [x] Java/Python bindings

### v0.3.0 - Extensibility (Planned) 📋

- [ ] Plugin system
- [ ] WASM support
- [ ] HSM integration (PKCS#11)
- [ ] TEE support (Intel SGX, ARM TrustZone)

### v1.0.0 - Production Ready (Q2 2026) 🎯

- [ ] Complete security audit
- [ ] FIPS 140-3 certification
- [ ] Performance optimization (SIMD, multi-core)
- [ ] Full documentation and examples

---

## 🤝 Contributing

We welcome all forms of contribution!

### How to Contribute

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'Add amazing feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Create a Pull Request.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

### Contributors

Thanks to all our contributors!

[![Contributors](https://contrib.rocks/image?repo=Kirky-X/ciphern)](https://github.com/Kirky-X/ciphern/graphs/contributors)

---

## 📄 License

This project is dual-licensed:

- **MIT License** - see [LICENSE-MIT](LICENSE-MIT)
- **Apache License 2.0** - see [LICENSE-APACHE](LICENSE-APACHE)

You may choose either license for your use.

---

## 🙏 Acknowledgments

Ciphern is built upon these excellent open-source projects:

- [ring](https://github.com/briansmith/ring) - High-performance cryptography library.
- [libsm](https://github.com/citahub/libsm) - GuoMi algorithm implementation.
- [RustCrypto](https://github.com/RustCrypto) - Pure Rust cryptographic algorithms.
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) - Secure memory erasure.

Special thanks to all security researchers who audited the code and provided feedback.

---

## 📞 Contact

- **Official Website**: https://ciphern.dev
- **Documentation**: https://docs.ciphern.dev
- **Issues**: https://github.com/Kirky-X/ciphern/issues
- **Discussions**: https://github.com/Kirky-X/ciphern/discussions
- **Email**: support@ciphern.dev

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Kirky-X/ciphern&type=Date)](https://star-history.com/#Kirky-X/ciphern&Date)

---

**Built with ❤️ by the Ciphern Team**

[⬆ Back to Top](#ciphern-crypto-library)
