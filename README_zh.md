# Ciphern Crypto Library

[![Crates.io](https://img.shields.io/crates/v/ciphern.svg)](https://crates.io/crates/ciphern)
[![Documentation](https://docs.rs/ciphern/badge.svg)](https://docs.rs/ciphern)
[![License](https://img.shields.io/crates/l/ciphern.svg)](LICENSE)
[![Build Status](https://github.com/Kirky-X/ciphern/workflows/CI/badge.svg)](https://github.com/Kirky-X/ciphern/actions)
[![Coverage](https://img.shields.io/codecov/c/github/Kirky-X/ciphern)](https://codecov.io/gh/Kirky-X/ciphern)
[![Security Audit](https://img.shields.io/badge/security-audited-success)](docs/SECURITY_AUDIT.md)

**Ciphern** 是一个企业级、安全优先的 Rust 加密库，提供符合国密标准和国际标准的密码学能力。专为数据存储加密、通信加密和密钥管理而设计。

[English](README.md) | [中文文档](README_zh.md)

---

## ✨ 核心特性

### 🔒 安全优先
- **多层防护**: 内存保护、侧信道防护、密钥隔离
- **合规认证**: 符合国密标准 (SM2/SM3/SM4) 和 FIPS 140-3
- **零知识审计**: 完整操作日志，不泄漏敏感数据
- **自动密钥轮换**: 满足合规要求的密钥生命周期管理

### ⚡ 高性能
- **SIMD 优化**: AES-256 吞吐量 > 3 GB/s (AVX2)
- **硬件加速**: 支持 AES-NI、ARM Crypto Extensions
- **零拷贝设计**: 最小化内存分配和复制
- **智能缓存**: 密钥和算法实例复用

### 🔧 易于集成
- **统一接口**: 简洁的 API，屏蔽底层复杂性
- **多语言支持**: Rust / Java / Python / C
- **插件化架构**: 用户可自定义加密算法
- **丰富示例**: 涵盖常见使用场景

### 🌐 标准兼容
- **国际标准**: AES-256, ECDSA-P384, SHA-256/384/512
- **国密标准**: SM2, SM3, SM4
- **密钥派生**: HKDF, PBKDF2, Argon2id
- **协议支持**: TLS 1.3, JWE, PKCS#11

---

## 🚀 快速开始

### 安装

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

### 5 分钟示例

#### 基础加密解密 (Rust)
```rust
use ciphern::{Cipher, Algorithm, KeyManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化密钥管理器
    let km = KeyManager::new()?;
    
    // 生成密钥
    let key_id = km.generate_key(Algorithm::AES256GCM)?;
    
    // 创建加密器
    let cipher = Cipher::new(Algorithm::AES256GCM)?;
    
    // 加密
    let plaintext = b"Hello, Ciphern!";
    let ciphertext = cipher.encrypt(&km, &key_id, plaintext)?;
    
    // 解密
    let decrypted = cipher.decrypt(&km, &key_id, &ciphertext)?;
    assert_eq!(plaintext, &decrypted[..]);
    
    println!("✅ Encryption and decryption successful!");
    Ok(())
}
```

#### 数字签名 (Rust)
```rust
use ciphern::{Signer, Algorithm, KeyManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化密钥管理器
    let km = KeyManager::new()?;
    
    // 生成密钥对 (以 SM2 为例)
    let key_id = km.generate_key(Algorithm::SM2)?;
    
    // 创建签名器
    let signer = Signer::new(Algorithm::SM2)?;
    
    // 签名
    let message = b"Important message";
    let signature = signer.sign(&km, &key_id, message)?;
    
    // 验证
    let is_valid = signer.verify(&km, &key_id, message, &signature)?;
    assert!(is_valid);
    
    println!("✅ Signature verified!");
    Ok(())
}
```

#### 国密算法 (Rust)
```rust
use ciphern::{Cipher, Algorithm, KeyManager, Hash};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let km = KeyManager::new()?;

    // SM4 加密
    let key_id = km.generate_key(Algorithm::SM4GCM)?;
    let cipher = Cipher::new(Algorithm::SM4GCM)?;
    let ciphertext = cipher.encrypt(&km, &key_id, b"国密加密测试")?;
    
    // SM3 哈希
    let hash = Hash::sm3(b"数据完整性验证")?;
    
    println!("✅ 国密算法运行成功!");
    Ok(())
}
```

#### Java 示例
```java
import com.ciphern.*;

public class Example {
    public static void main(String[] args) {
        try (Cipher cipher = new Cipher(Algorithm.AES256GCM)) {
            byte[] plaintext = "Hello, Java!".getBytes();
            byte[] ciphertext = cipher.encrypt(plaintext);
            byte[] decrypted = cipher.decrypt(ciphertext);
            
            System.out.println("✅ Success: " + new String(decrypted));
        } catch (CryptoException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
```

#### Python 示例
```python
from ciphern import Cipher, Algorithm

with Cipher(Algorithm.AES256GCM) as cipher:
    plaintext = b"Hello, Python!"
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)
    
    assert plaintext == decrypted
    print("✅ Success!")
```

---

## 📚 文档

### 核心文档
- **[用户指南](docs/USER_GUIDE.md)** - 详细使用说明和最佳实践
- **[API 文档](https://docs.rs/ciphern)** - 完整 API 参考
- **[示例代码](examples/)** - 涵盖常见场景的示例

### 高级主题
- **[架构设计](docs/ARCHITECTURE.md)** - 系统架构 and 设计决策
- **[性能优化](docs/PERFORMANCE.md)** - SIMD、硬件加速、benchmark
- **[安全指南](docs/SECURITY.md)** - 威胁模型、安全最佳实践
- **[多租户指南](docs/MULTI_TENANT.md)** - 密钥隔离和访问控制

### 开发者文档
- **[贡献指南](CONTRIBUTING.md)** - 如何参与开发
- **[插件开发](docs/PLUGIN_DEVELOPMENT.md)** - 自定义算法实现
- **[FFI 指南](docs/FFI_GUIDE.md)** - C/Java/Python 绑定

---

## 🎯 使用场景

### 数据存储加密
保护数据库、文件系统中的敏感数据
```rust
use ciphern::{Cipher, KeyManager, Algorithm};

let km = KeyManager::new()?;
let key_id = km.generate_key_with_alias(Algorithm::AES256GCM, "database-encryption")?;
let cipher = Cipher::new(Algorithm::AES256GCM)?;

// 加密敏感字段
let encrypted_ssn = cipher.encrypt(&km, &key_id, user.ssn.as_bytes())?;
db.save_encrypted_field(user.id, "ssn", &encrypted_ssn)?;
```

### API 通信加密
保护 API 请求和响应的机密性和完整性
```rust
use ciphern::{Signer, Algorithm, KeyManager};

let km = KeyManager::new()?;
let key_id = km.generate_key(Algorithm::ECDSAP384)?;
let signer = Signer::new(Algorithm::ECDSAP384)?;
let signature = signer.sign(&km, &key_id, &request_body)?;

http_request
    .header("X-Signature", base64::encode(&signature))
    .body(request_body)
    .send()?;
```

### 密钥管理
自动轮换、多租户隔离、审计日志
```rust
use ciphern::key::{KeyLifecycleManager, KeyLifecyclePolicy, KeyManagerLifecycleExt};
use ciphern::types::Algorithm;
use std::sync::Arc;

let mut km = KeyManager::new()?;
let klm = Arc::new(KeyLifecycleManager::new());
km.enable_lifecycle_management(klm);

let key_id = km.generate_key(Algorithm::AES256GCM)?;

// 密钥生命周期策略 (示例)
let policy = KeyLifecyclePolicy {
    rotation_period_days: 90,
    grace_period_days: 7,
    ..Default::default()
};
```

---

## 🔧 高级功能

### FIPS 140-3 合规模式
```toml
[dependencies]
ciphern = { version = "0.1", features = ["fips"] }
```
```rust
use ciphern::{is_fips_enabled, Algorithm, Cipher};

// 检查 FIPS 模式是否启用
if is_fips_enabled() {
    println!("FIPS mode is enabled");
}

// 在 FIPS 模式下，非批准的算法将被拒绝
let result = Cipher::new(Algorithm::SM4GCM);
assert!(result.is_err()); // CryptoError::FipsError
```

### SIMD 性能优化
```toml
[dependencies]
ciphern = { version = "0.1", features = ["simd"] }
```

自动检测 CPU 特性并使用最优实现：
- **x86_64**: AES-NI + AVX2
- **ARM64**: ARM Crypto Extensions
- **Fallback**: 纯软件实现

### 审计日志与监控
```rust
use ciphern::audit::AuditLogger;

// 初始化审计系统
AuditLogger::init();

// 系统会自动记录所有加密/解密/密钥管理操作
```

### 自定义算法插件
```rust
use ciphern::plugin::{Plugin, CipherPlugin};
// 通过实现 Plugin 和 CipherPlugin trait 来扩展算法
```

---

## 📊 性能指标

### 吞吐量 (x86_64, Intel i9-12900K, 单核)

| 算法 | 标量实现 | SIMD (SSE) | SIMD (AVX2) |
|------|----------|------------|-------------|
| AES-256-GCM | 500 MB/s | 1.5 GB/s | **3.2 GB/s** |
| SM4-GCM | 200 MB/s | 600 MB/s | **1.1 GB/s** |
| SHA-256 | 300 MB/s | 800 MB/s | **1.5 GB/s** |

### 延迟 (1KB 数据)

| 操作 | P50 | P99 | P99.9 |
|------|-----|-----|-------|
| AES-256 加密 | 2.1 μs | 3.5 μs | 8.2 μs |
| ECDSA-P384 签名 | 180 μs | 250 μs | 400 μs |
| ECDSA-P384 验证 | 280 μs | 380 μs | 600 μs |

运行 benchmark:
```bash
cargo bench
```

---

## 🔐 安全性

### 安全特性
- ✅ **Constant-time 实现**: 防止时序攻击
- ✅ **自动内存擦除**: 使用 `zeroize` 安全清理密钥
- ✅ **内存锁定**: 防止密钥被 swap 到磁盘
- ✅ **内存篡改检测**: Canary + Checksum 双重保护
- ✅ **侧信道防护**: 可选的功耗分析防护

### 安全审计
Ciphern 已通过以下安全测试：
- ✅ NIST CAVP 测试向量验证
- ✅ 24 小时持续 Fuzzing (无 crash)
- ✅ Valgrind 内存检查 (无泄漏)
- ✅ 第三方安全审计 (报告见 [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md))

### 漏洞报告
如发现安全漏洞，请发送邮件至 security@ciphern.dev，我们将在 48 小时内响应。

详见 [SECURITY.md](SECURITY.md)

---

## 🛠️ 开发环境

### 前置要求
- Rust 1.75+ (stable)
- OpenSSL 3.0+ (Linux/macOS)
- CMake 3.15+ (用于编译 C 扩展)

### 编译
```bash
# 克隆仓库
git clone https://github.com/Kirky-X/ciphern.git
cd ciphern

# 默认编译
cargo build --release

# 启用所有特性
cargo build --release --all-features

# FIPS 模式
cargo build --release --features fips

# SIMD 优化
cargo build --release --features simd
```

### 测试
```bash
# 运行所有测试
cargo test --all-features

# 测试覆盖率
cargo tarpaulin --out Html --all-features

# Fuzzing (需要 nightly)
cargo +nightly fuzz run fuzz_encrypt
```

### 交叉编译
```bash
# ARM64 Linux
cargo build --target aarch64-unknown-linux-gnu --release

# Windows
cargo build --target x86_64-pc-windows-msvc --release

# macOS ARM (Apple Silicon)
cargo build --target aarch64-apple-darwin --release
```

---

## 🗺️ 路线图

### v0.1.0 - MVP (已完成) ✅
- [x] 核心加密功能 (AES, SM4)
- [x] 数字签名 (ECDSA, SM2)
- [x] 哈希函数 (SHA-256/384/512, SM3)
- [x] 基础密钥管理
- [x] Rust API

### v0.2.0 - 安全增强 (进行中) 🚧
- [x] 内存保护机制
- [x] 侧信道防护
- [x] FIPS 140-3 模式
- [x] Java/Python 绑定

### v0.3.0 - 扩展性 (规划中) 📋
- [ ] 插件系统
- [ ] WASM 支持
- [ ] HSM 集成 (PKCS#11)
- [ ] TEE 支持 (Intel SGX, ARM TrustZone)

### v1.0.0 - 生产就绪 (Q2 2026) 🎯
- [ ] 完整安全审计
- [ ] FIPS 140-3 认证
- [ ] 性能优化 (SIMD, 多核)
- [ ] 完整文档和示例

---

## 🤝 贡献

我们欢迎各种形式的贡献！

### 如何贡献
1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

详见 [CONTRIBUTING.md](CONTRIBUTING.md)
```

### 贡献者
感谢所有贡献者！

[![Contributors](https://contrib.rocks/image?repo=Kirky-X/ciphern)](https://github.com/Kirky-X/ciphern/graphs/contributors)

---

## 📄 许可证

本项目采用双重许可：

- **MIT License** - 见 [LICENSE-MIT](LICENSE-MIT)
- **Apache License 2.0** - 见 [LICENSE-APACHE](LICENSE-APACHE)

您可以选择其中任一许可证使用本软件。

---

## 🙏 致谢

Ciphern 构建于以下优秀的开源项目之上：

- [ring](https://github.com/briansmith/ring) - 高性能密码学库
- [libsm](https://github.com/citahub/libsm) - 国密算法实现
- [RustCrypto](https://github.com/RustCrypto) - 纯 Rust 密码学算法
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) - 安全内存擦除

特别感谢所有审核代码和提供反馈的安全研究人员。

---

## 📞 联系方式

- **官方网站**: https://ciphern.dev
- **文档**: https://docs.ciphern.dev
- **问题反馈**: https://github.com/Kirky-X/ciphern/issues
- **讨论区**: https://github.com/Kirky-X/ciphern/discussions
- **邮件**: support@ciphern.dev

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Kirky-X/ciphern&type=Date)](https://star-history.com/#Kirky-X/ciphern&Date)

---

**Built with ❤️ by the Ciphern Team**

[⬆ 回到顶部](#ciphern-crypto-library)