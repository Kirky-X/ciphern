# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

Ciphern 是一个企业级、安全优先的 Rust 加密库，同时支持国密标准 (SM2/SM3/SM4) 和国际标准 (AES/ECDSA/RSA/Ed25519)。库设计用于数据加密、通信安全和密钥管理。

## 核心架构

### 分层结构

```
lib.rs                 # 公共 API 接口层和高阶 API (Cipher、Hasher、Signer 等)
  ├─ cipher/           # 对称加密提供者抽象和实现 (AES、SM4、ChaCha20-Poly1305)
  ├─ signer/           # 数字签名实现 (ECDSA、RSA、Ed25519、SM2)
  ├─ key/              # 密钥管理和生命周期 (KeyManager、密钥派生、旋转)
  ├─ hardware/         # 硬件加速基础设施 (AES-NI、AVX2、GPU/CUDA/OpenCL)
  ├─ fips/             # FIPS 140-3 合规性实现和自检
  ├─ side_channel/     # 侧信道防护 (恒定时间操作、缓存攻击防护)
  ├─ memory/           # 内存保护 (mlock、zeroize、完整性校验)
  ├─ random/           # 安全随机数生成 (硬件 RNG 监控)
  ├─ audit/            # 加密操作审计日志
  ├─ algorithm/        # 算法实现层
  └─ ffi/              # 多语言绑定 (C FFI、Java JNI、Python PyO3)
```

### 重要设计模式

**提供者模式 (Provider Pattern)**:
- `cipher::provider::SymmetricCipher` - 对称加密提供者 trait
- `cipher::provider::Signer` - 签名提供者 trait
- `cipher::provider::REGISTRY` - 算法注册中心，用于查找对应实现
- 通过 `Cipher::new(algorithm)` 按以下优先级选择实现: 插件 → 内置实现

**密钥生命周期管理**:
- `KeyManager` 负责密钥生成、存储和访问控制
- 所有密钥通过 `ProtectedKey` 包装，使用 `zeroize` 自动清除
- 支持密钥别名、旋转、使用限制

**内存安全**:
- 敏感数据必须使用 `ProtectedKey` 或 `SecretBytes` 包装
- 自动零化内存以防止内存泄漏
- 支持 `mlock` 防止交换到磁盘

## 常用命令

### 构建

```bash
# 默认构建
cargo build --release

# 启用所有特性
cargo build --release --all-features

# FIPS 模式
cargo build --release --features fips

# Java JNI 绑定
cargo build --release --features java_ffi

# Python 绑定
cargo build --release --features python_ffi

# GPU 加速 (CUDA)
cargo build --release --features gpu-cuda
```

### 测试

```bash
# 运行所有测试
cargo test --all-features

# 运行特定测试
cargo test --all-features -- test_aes_gcm

# 显示测试输出
cargo test --all-features -- --nocapture

# 运行集成测试
cargo test --all-features --test '*'

# 运行并发测试以发现竞态条件
cargo test --all-features -- --test-threads=1
```

### 代码质量

```bash
# 格式检查
cargo fmt --all -- --check

# 自动格式化
cargo fmt

# Clippy 静态分析
cargo clippy --all-features --workspace -- -D warnings

# 忽略特定警告
cargo clippy --all-features --workspace -- -A clippy::type_complexity
```

### 基准测试

```bash
# 运行所有基准测试
cargo bench

# 运行特定基准测试
cargo bench -- cipher_bench

# 生成报告 (HTML)
cargo bench -- --output-format html
```

### 文档

```bash
# 生成文档
cargo doc --all-features --no-deps

# 打开文档
cargo doc --all-features --open
```

## 特性系统

### 核心特性

- `encrypt`: 启用加密和签名功能（默认）
- `hash`: 启用哈希功能（默认）
- `fips`: 启用 FIPS 140-3 合规模式
- `kdf`: 启用密钥派生功能
- `i18n`: 启用国际化（英文和中文）
- `parallel`: 启用并行处理（Rayon）

### 绑定特性

- `c_ffi`: C FFI 接口（默认）
- `java_ffi`: Java JNI 绑定（需要 `jni` 依赖）
- `python_ffi`: Python PyO3 绑定（需要 `pyo3` 依赖）

### 加速特性

- `simd`: SIMD 加速（AVX2, AVX-512）
- `cpu-aesni`: AES-NI 硬件加速
- `gpu-cuda`: CUDA GPU 加速
- `gpu-opencl`: OpenCL GPU 加速
- `plugin`: 插件系统

### 开发特性

- `generate_headers`: 生成头文件

## 核心模块详解

### 算法使用流程

1. **对称加密**:
   ```rust
   ciphern::init()?;
   let km = KeyManager::new()?;
   let key_id = km.generate_key(Algorithm::AES256GCM)?;
   let cipher = Cipher::new(Algorithm::AES256GCM)?;
   let ciphertext = cipher.encrypt(&km, &key_id, plaintext)?;
   ```

2. **非对称签名**:
   ```rust
   let cipher = Cipher::new(Algorithm::ECDSAP256)?;
   let signature = cipher.sign(&km, &key_id, message)?;
   let is_valid = cipher.verify(&km, &key_id, message, &signature)?;
   ```

3. **密钥管理**:
   - 使用别名: `km.generate_key_with_alias(algorithm, "alias-name")`
   - 密钥访问: `km.with_key(key_id, |key| { ... })`
   - 密钥旋转: `km.rotate_key(key_id)?`

### 硬件加速

- CPU 特性检测在 `hardware::cpu.rs` 中实现
- GPU 支持通过 `XpuManager` 提供抽象
- 当启用 `gpu-cuda` 特性时，加密操作会优先使用 GPU

### FIPS 合规

- 所有加密操作前自动运行条件自检
- 初始化时运行 FIPS 启动自检
- 非批准算法会被拒绝（当启用 FIPS 模式时）

### 审计日志

- 所有敏感操作自动记录到审计日志
- 密钥 ID 在日志中自动哈希化以防止信息泄露
- 通过 `AuditLogger::log()` 手动记录事件

## 测试指南

### 单元测试位置

- 与实现文件同名并放在同一目录: `module.rs` → `mod.rs` 包含 `#[cfg(test)]` 块
- 集成测试放在 `tests/` 目录

### 测试要求

- 所有新功能必须有测试
- 加密操作必须测试成功和失败场景
- 侧信道防护测试应当验证恒定时间操作

### 运行示例

示例代码在 `examples/` 目录，可通过以下命令运行:

```bash
cargo run --all-features --example symmetric_encryption
cargo run --all-features --example digital_signatures
cargo run --all-features --example fips_compliance
```

## 常见任务

### 添加新算法

1. 在 `types.rs` 中添加算法枚举值
2. 在 `cipher/` 或 `signer/` 中实现提供者
3. 在 `cipher::provider::REGISTRY` 中注册算法
4. 添加 FIPS 合规性检查 (如适用)
5. 添加单元测试和集成测试

### 添加插件

1. 实现 `Plugin` 和所需扩展 trait (如 `CipherPlugin`)
2. 使用 `PluginManager::load()` 加载插件
3. 插件必须实现要求的元数据

### 国际化

- 所有用户可见字符串必须通过 `tr()` 宏或 `translate()` 函数
- 字符串键名格式: `category.message_key`
- 新字符串必须在 `locales/en.json` 和 `locales/zh.json` 中定义

## 安全注意事项

1. **绝不**将密钥记录到日志
2. **绝不**在错误消息中泄露密钥信息
3. 敏感操作必须使用恒定时间实现
4. 所有密钥必须通过 `with_key()` 访问，避免直接暴露
5. 审计日志中的密钥 ID 自动哈希化
6. 涉及内存安全的更改必须经过严格审查

## 性能优化提示

- 大量数据操作使用批量 API (`accelerated_batch_*`)
- 启用 `parallel` 特性以使用多线程
- 硬件加速会自动检测和使用
- 避免频繁创建/销毁密钥管理器和加密器
