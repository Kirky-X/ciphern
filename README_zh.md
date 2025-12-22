# Ciphern Crypto Library

[![Crates.io](https://img.shields.io/crates/v/ciphern.svg)](https://crates.io/crates/ciphern)
[![Documentation](https://docs.rs/ciphern/badge.svg)](https://docs.rs/ciphern)
[![License](https://img.shields.io/crates/l/ciphern.svg)](LICENSE)
[![Build Status](https://github.com/Kirky-X/ciphern/actions/workflows/health-check.yml/badge.svg)](https://github.com/Kirky-X/ciphern/actions/workflows/health-check.yml)
[![Coverage](https://img.shields.io/codecov/c/github/Kirky-X/ciphern)](https://codecov.io/gh/Kirky-X/ciphern)
[![Security Audit](https://img.shields.io/badge/security-audited-success)](docs/SECURITY_AUDIT.md)

**Ciphern** 是一个企业级、安全优先的 Rust 加密库，提供符合国密标准和国际标准的密码学能力。专为数据存储加密、通信加密和密钥管理而设计。

[English](README.md) | [中文文档](README_zh.md)

---

## ✨ 核心特性

### 🔒 安全优先

- **内存保护**: 使用 `zeroize` 安全清理密钥，支持内存锁定
- **合规认证**: 符合国密标准 (SM2/SM3/SM4) 和 FIPS 140-3 基础要求
- **审计日志**: 完整的加密操作审计追踪
- **密钥生命周期**: 支持密钥生成、激活、销毁等基础生命周期管理

### ⚡ 高性能

- **零拷贝设计**: 最小化内存分配和复制
- **智能缓存**: 密钥和算法实例复用
- **纯 Rust 实现**: 无外部依赖，编译时优化

### 🔧 易于集成

- **统一接口**: 简洁的 API，屏蔽底层复杂性
- **多语言支持**: C FFI 接口，基础 Java JNI 和 Python PyO3 绑定
- **插件化架构**: 支持自定义加密算法插件（基础框架）
- **丰富测试**: 包含单元测试、集成测试和性能测试

### 🌐 标准兼容

- **国际标准**: AES-128/192/256-GCM, ECDSA-P256/P384/P521, RSA-2048/3072/4096, Ed25519
- **国密标准**: SM2, SM3, SM4-GCM
- **哈希函数**: SHA-256/384/512, SHA3-256/384/512, SM3
- **密钥派生**: HKDF, PBKDF2, Argon2id, SM3-KDF

---

## 🚀 快速开始

### 安装

**Rust (Cargo)**

```toml
[dependencies]
ciphern = "0.1"
```

**Java (Maven)**

Java 绑定正在开发中，需要手动编译 JNI 库：

```xml
<!-- 暂不支持 Maven 直接安装，需要从源码编译 -->
```

**Python (pip)**

Python 绑定正在开发中，需要手动编译：

```bash
# 暂不支持 pip 直接安装，需要从源码编译
# pip install ciphern  # 暂不可用
```

### 5 分钟示例

#### 基础加密解密 (Rust)

```rust
use ciphern::{Cipher, Algorithm, KeyManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化库
    ciphern::init()?;
    
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
    // 初始化库
    ciphern::init()?;
    
    // 初始化密钥管理器
    let km = KeyManager::new()?;
    
    // 生成密钥对 (以 ECDSA-P256 为例)
    let key_id = km.generate_key(Algorithm::ECDSAP256)?;
    
    // 创建签名器
    let signer = Signer::new(Algorithm::ECDSAP256)?;
    
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
    // 初始化库
    ciphern::init()?;
    
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

Java 绑定正在开发中，当前需要手动编译 JNI 库：

```java
// 暂不支持直接使用，需要从源码编译 JNI 库
// import com.ciphern.*;
```

#### Python 示例

Python 绑定正在开发中，当前需要手动编译：

```python
# 暂不支持直接使用，需要从源码编译 PyO3 扩展
# from ciphern import Cipher, Algorithm
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

ciphern::init()?;
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

### 密钥管理

基础密钥生命周期管理

```rust
use ciphern::{KeyManager, Algorithm};

ciphern::init()?;
let km = KeyManager::new()?;

// 生成密钥
let key_id = km.generate_key(Algorithm::AES256GCM)?;

// 使用别名管理密钥
let alias_key_id = km.generate_key_with_alias(Algorithm::AES256GCM, "my-app-key")?;
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

// 初始化时启用 FIPS 模式
ciphern::init()?;

// 检查 FIPS 模式是否启用
if is_fips_enabled() {
    println!("FIPS mode is enabled");
}

// 在 FIPS 模式下，非批准的算法将被拒绝
let result = Cipher::new(Algorithm::SM4GCM);
assert!(result.is_err()); // CryptoError::FipsError
```

### 审计日志与监控

```rust
use ciphern::audit::{AuditLogger, AuditEvent, PerformanceMetrics};
use std::sync::Arc;

// 初始化库
ciphern::init()?;

// 创建审计日志器
let audit_logger = Arc::new(AuditLogger::new());

// 记录事件
let event = AuditEvent::new("encryption", "AES256GCM", "success");
audit_logger.log_event(event)?;

// 获取性能指标
let metrics = audit_logger.get_performance_metrics()?;
println!("Throughput: {:.2} ops/sec", metrics.avg_throughput_ops_per_sec);
println!("Cache hit rate: {:.1}%", metrics.avg_cache_hit_rate * 100.0);
```

### 自定义算法插件

```rust
use ciphern::plugin::{Plugin, CipherPlugin};
// 通过实现 Plugin 和 CipherPlugin trait 来扩展算法
```

---

## 📊 性能指标

### 性能指标

当前版本基于纯 Rust 实现，性能数据可通过审计系统获取：

```rust
use ciphern::audit::{AuditLogger, PerformanceMetrics};

let audit_logger = AuditLogger::new();
let metrics = audit_logger.get_performance_metrics()?;

println!("平均吞吐量: {:.2} ops/sec", metrics.avg_throughput_ops_per_sec);
println!("平均延迟: {:.2} μs", metrics.avg_latency_us);
println!("缓存命中率: {:.1}%", metrics.avg_cache_hit_rate * 100.0);
```

> 注：SIMD 优化和硬件加速功能正在开发中，当前版本提供基础的加密功能实现

运行 benchmark:

```bash
cargo bench
```

---

## 🔐 安全性

### 安全特性

- ✅ **自动内存擦除**: 使用 `zeroize` 安全清理密钥
- ✅ **FIPS 140-3 基础合规**: 支持 FIPS 批准的算法验证
- ✅ **审计日志**: 完整的加密操作审计追踪
- ✅ **算法验证**: 内置算法正确性自检
- ✅ **错误处理**: 安全的错误状态管理

> 注：Constant-time 实现、内存锁定、侧信道防护等高级安全特性正在开发中

### 安全审计

Ciphern 安全特性基于以下实现：

- ✅ 使用成熟加密库 (`ring`, `libsm`) 作为底层实现
- ✅ 内置算法正确性验证
- ✅ FIPS 140-3 算法批准检查
- ✅ 完整的错误处理和状态管理

> 注：NIST CAVP 测试、Fuzzing、第三方安全审计等正在计划中

### 漏洞报告

如发现安全漏洞，请在 GitHub Issues 中报告。

> 注：专用安全邮箱和 SECURITY.md 文档正在准备中

---

## 🛠️ 开发环境

### 前置要求

- Rust 1.75+ (stable)
- 标准 C 编译器 (用于 FFI 绑定)

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
```

### 测试

```bash
# 运行所有测试
cargo test --all-features

# 运行基准测试
cargo bench

# 检查代码质量
cargo clippy --all-features
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

- [x] 核心加密功能 (AES-128/192/256-GCM, SM4-GCM)
- [x] 数字签名 (ECDSA-P256/P384/P521, RSA-2048/3072/4096, Ed25519, SM2)
- [x] 哈希函数 (SHA-256/384/512, SHA3-256/384/512, SM3)
- [x] 密钥派生 (HKDF, PBKDF2, Argon2id, SM3-KDF)
- [x] 基础密钥管理
- [x] Rust API
- [x] 审计日志系统
- [x] FIPS 140-3 基础支持

### v0.2.0 - 多语言支持 (部分完成) 🚧

- [x] C FFI 接口
- [ ] Java JNI 绑定 (基础框架已存在)
- [ ] Python PyO3 绑定 (基础框架已存在)
- [ ] 内存保护增强
- [ ] 插件系统完善

### v0.3.0 - 扩展性 (规划中) 📋

- [ ] SIMD 优化
- [ ] WASM 支持
- [ ] HSM 集成 (PKCS#11)
- [ ] TEE 支持 (Intel SGX, ARM TrustZone)

### v1.0.0 - 生产就绪 (规划中) 🎯

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

> 注：CONTRIBUTING.md 文档正在准备中


### 贡献者
感谢所有贡献者！

[![Contributors](https://contrib.rocks/image?repo=Kirky-X/ciphern)](https://github.com/Kirky-X/ciphern/graphs/contributors)

---

## 📄 许可证

本项目采用双重许可：

- **MIT License** - 见 [LICENSE-MIT](LICENSE-MIT)
- **Apache License 2.0** - 见 [LICENSE-APACHE](LICENSE-APACHE)

您可以选择其中任一许可证使用本软件。

> 注：许可证文件正在准备中，当前版本遵循标准 Rust 开源协议

---

## 🙏 致谢

Ciphern 构建于以下优秀的开源项目之上：

- [ring](https://github.com/briansmith/ring) - 高性能密码学库 (v0.17)
- [libsm](https://github.com/citahub/libsm) - 国密算法实现 (v0.6)
- [aes-gcm](https://github.com/RustCrypto/AEADs) - AES-GCM 实现 (v0.10)
- [argon2](https://github.com/RustCrypto/password-hashes) - Argon2 密钥派生 (v0.5)
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) - 安全内存擦除 (v1.7)

特别感谢所有审核代码和提供反馈的安全研究人员。

---

## 📞 联系方式

- **问题反馈**: https://github.com/Kirky-X/ciphern/issues
- **讨论区**: https://github.com/Kirky-X/ciphern/discussions

> 注：官方网站、文档站点和专用支持邮箱正在准备中

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Kirky-X/ciphern&type=Date)](https://star-history.com/#Kirky-X/ciphern&Date)

---

**Built with ❤️ by the Ciphern Team**

[⬆ 回到顶部](#ciphern-crypto-library)