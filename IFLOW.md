# Ciphern 项目说明

## 项目概述

**Ciphern** 是一个企业级、安全优先的 Rust 加密库，提供符合中国国密标准（GuoMi）和国际标准的密码学能力。项目专为企业级数据存储加密、通信加密和密钥管理场景设计。

### 核心技术栈

- **语言**: Rust (edition 2021)
- **构建工具**: Cargo
- **最低 Rust 版本**: 1.75+ (stable)
- **主要依赖**:
  - `ring` (v0.17.8) - 高性能密码学库
  - `libsm` (v0.6.0) - 国密算法实现
  - `aes-gcm` (v0.10.3) - AES-GCM 实现
  - `chacha20poly1305` (v0.10.1) - ChaCha20-Poly1305 AEAD
  - `x25519-dalek` (v2.0.1) - X25519 密钥交换
  - `zeroize` (v1.8.2) - 安全内存擦除

### 项目架构

项目采用模块化设计，主要模块包括：

- `cipher/` - 加密算法实现（AES, SM4, ChaCha20-Poly1305）
- `key/` - 密钥管理和生命周期管理
- `signer/` - 数字签名（ECDSA, RSA, Ed25519, SM2）
- `hash/` - 哈希函数（SHA, SHA3, SM3）
- `fips/` - FIPS 140-3 合规支持
- `audit/` - 审计日志系统
- `hardware/` - 硬件加速支持（CPU SIMD, GPU）
- `side_channel/` - 侧信道防护
- `memory/` - 内存安全管理
- `ffi/` - 多语言绑定（C, Java JNI, Python PyO3）
- `i18n/` - 国际化支持（英文/中文）

## 构建和运行

### 基本构建命令

```bash
# 默认构建
cargo build --release

# 启用所有特性
cargo build --release --all-features

# FIPS 模式构建
cargo build --release --features fips

# 开发构建
cargo build
```

### 测试命令

```bash
# 运行所有测试
cargo test --all-features

# 运行特定测试
cargo test --test integration_test

# 运行基准测试
cargo bench

# 代码质量检查
cargo clippy --all-features

# 格式检查
cargo fmt --check
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

### 运行示例

```bash
# 对称加密示例
cargo run --example symmetric_encryption

# 数字签名示例
cargo run --example digital_signatures

# 密钥管理示例
cargo run --example key_management

# FIPS 合规示例
cargo run --example fips_compliance

# 国密算法示例
cargo run --example key_exchange_chacha
```

## 开发约定

### 代码风格

- 遵循 Rust 官方代码风格指南
- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 进行代码质量检查
- 所有公开 API 必须有文档注释
- 使用 `#[cfg(feature = "...")]` 控制条件编译

### 测试规范

- 单元测试位于各模块的 `tests.rs` 或 `mod.rs` 中
- 集成测试位于 `tests/` 目录
- 性能测试位于 `benches/` 目录
- UAT 测试位于 `tests/uat/` 目录
- 所有测试必须通过 `cargo test --all-features`

### 特性标志（Features）

项目使用 Cargo features 管理可选功能：

- `default`: 启用 std, fips, hash, encrypt, kdf, c_ffi, i18n, parallel
- `std`: 标准库支持
- `fips`: FIPS 140-3 合规模式
- `hash`: 哈希函数支持
- `encrypt`: 加密功能
- `kdf`: 密钥派生函数
- `parallel`: 并行处理（使用 rayon）
- `c_ffi`: C FFI 接口
- `java_ffi`: Java JNI 绑定
- `python_ffi`: Python PyO3 绑定
- `plugin`: 插件系统
- `i18n`: 国际化支持
- `gpu`: GPU 加速
- `simd`: SIMD 优化
- `post_quantum`: 后量子密码学

### 安全规范

- 所有敏感数据使用 `SecretBytes` 和 `ProtectedKey` 保护
- 密钥使用 `zeroize` 自动安全擦除
- 使用 `mlock` 防止敏感数据被交换到磁盘
- 实现 constant-time 操作防止时序攻击
- 所有加密操作记录审计日志
- 密钥生命周期严格管理（生成 -> 激活 -> 暂停/销毁）

### 错误处理

- 使用 `Result<T>` 和 `CryptoError` 枚举处理错误
- 密钥相关错误转换为通用错误防止信息泄露
- 所有公开函数必须有错误处理文档
- 使用 `thiserror` 简化错误定义

### 国际化（i18n）

- 支持英文（en）和中文（zh）两种语言
- 使用 `tr!()` 宏进行简单翻译
- 使用 `tr_with_args!()` 宏进行带参数的翻译
- 语言环境文件位于 `locales/` 目录
- 使用 `set_locale("en")` 或 `set_locale("zh")` 切换语言

### 密钥管理

- 使用 `KeyManager` 管理所有密钥
- 密钥状态：Generated -> Active -> Suspended/Destroyed
- 支持密钥别名管理
- 支持密钥使用次数限制
- 支持密钥过期时间
- 支持密钥轮换

## 项目特性

### 支持的算法

**对称加密**:
- AES-128/192/256-GCM (FIPS 批准)
- SM4-GCM (国密标准)
- ChaCha20-Poly1305 (现代 AEAD)

**非对称加密/签名**:
- ECDSA-P256/P384/P521 (FIPS 批准)
- RSA-2048/3072/4096 (FIPS 批准)
- Ed25519 (现代签名算法)
- SM2 (国密标准)
- X25519 (密钥交换)

**哈希函数**:
- SHA-256/384/512 (FIPS 批准)
- SHA3-256/384/512 (FIPS 批准)
- SM3 (国密标准)

**密钥派生**:
- HKDF (FIPS 批准)
- PBKDF2 (FIPS 批准)
- Argon2id (现代 KDF)
- Sm3Kdf (国密标准)

### 安全特性

- ✅ 自动内存擦除（zeroize）
- ✅ 内存锁定（mlock）
- ✅ 完整性校验
- ✅ Constant-time 操作
- ✅ FIPS 140-3 基础合规
- ✅ 完整审计日志
- ✅ 侧信道防护
- ✅ 密钥生命周期管理

### 性能优化

- 零拷贝设计
- 智能缓存
- CPU SIMD 加速（AES-NI, AVX2, SHA-NI）
- GPU 加速（CUDA, OpenCL）
- 并行处理（rayon）
- 批量操作优化

## 重要文件说明

- `Cargo.toml` - 项目配置和依赖管理
- `src/lib.rs` - 库主入口，导出公开 API
- `src/types.rs` - 核心类型定义（Algorithm, KeyState 等）
- `src/cipher/mod.rs` - 加密算法模块
- `src/key/mod.rs` - 密钥管理模块
- `src/fips/` - FIPS 合规实现
- `src/audit.rs` - 审计日志系统
- `src/hardware/` - 硬件加速支持
- `src/ffi/` - 多语言绑定
- `src/i18n/` - 国际化实现
- `examples/` - 示例代码
- `tests/` - 测试代码
- `benches/` - 性能测试

## 版本信息

- 当前版本: 0.2.1
- Rust Edition: 2021
- 许可证: MIT / Apache-2.0 (双重许可)

## 开发注意事项

1. **线程安全**: `Key` 类型不是线程安全的，在多线程环境中必须使用 `Arc<Mutex<Key>>` 或 `Arc<RwLock<Key>>` 保护
2. **内存安全**: 敏感数据必须使用 `SecretBytes` 和 `ProtectedKey` 包装
3. **错误处理**: 密钥相关错误应转换为通用错误防止信息泄露
4. **审计日志**: 所有加密操作都应记录审计日志
5. **FIPS 合规**: 在 FIPS 模式下，非批准的算法将被拒绝
6. **性能优化**: 优先使用硬件加速（SIMD, GPU）提升性能
7. **国际化**: 所有用户可见的文本都应支持国际化

## 常见问题

### 如何启用 FIPS 模式？

在 `Cargo.toml` 中启用 `fips` 特性：

```toml
[dependencies]
ciphern = { version = "0.2", features = ["fips"] }
```

然后在代码中调用 `ciphern::init()` 初始化 FIPS 上下文。

### 如何使用 GPU 加速？

启用 `gpu` 特性：

```toml
[dependencies]
ciphern = { version = "0.2", features = ["gpu"] }
```

### 如何添加新的加密算法？

1. 在 `src/cipher/` 目录下实现算法
2. 在 `src/cipher/provider.rs` 中注册算法
3. 在 `src/types.rs` 中添加算法枚举
4. 在 `src/fips/validator.rs` 中添加 FIPS 验证（如适用）
5. 添加单元测试和集成测试

### 如何添加新的语言支持？

1. 在 `locales/` 目录下创建新的语言文件（如 `fr.toml`）
2. 在 `src/i18n/mod.rs` 中注册新语言
3. 添加翻译字符串
