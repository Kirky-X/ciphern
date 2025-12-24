# Ciphern 用户指南

欢迎使用 Ciphern！本指南将帮助您从入门到精通，涵盖常见使用场景和最佳实践。

**版本**: v0.1.0  
**更新日期**: 2025-12-22

---

## 目录

1. [安装与配置](#1-安装与配置)
2. [核心概念](#2-核心概念)
3. [基础使用](#3-基础使用)
4. [密钥管理](#4-密钥管理)
5. [高级特性](#5-高级特性)
6. [多语言集成](#6-多语言集成)
7. [生产环境部署](#7-生产环境部署)
8. [故障排查](#8-故障排查)
9. [最佳实践](#9-最佳实践)
10. [常见问题](#10-常见问题)

---

## 1. 安装与配置

### 1.1 快速开始

#### 添加依赖

```toml
# Cargo.toml
[dependencies]
ciphern = "0.1"

# 可选特性
[dependencies]
ciphern = { version = "0.1", features = ["fips"] }
```

#### 可用特性 (Features)

| 特性        | 描述              | 建议场景  |
|-----------|-----------------|-------|
| `default` | 包含 std, fips, hash, encrypt, kdf | 默认全功能版本 |
| `std`     | 启用标准库支持         | 基础依赖  |
| `fips`    | FIPS 140-3 合规支持 | 金融、政府 |
| `hash`    | 启用哈希算法 (SHA/SM3) | 数据完整性校验 |
| `encrypt` | 启用加解密与签名接口   | 核心加密功能 |
| `kdf`     | 启用密钥派生功能      | 密钥管理高级场景 |
| `plugin`  | 启用动态插件加载      | 自定义算法扩展 |

### 1.2 初始化

在使用任何功能前，建议调用 `init()` 函数以确保系统自检（如 FIPS 自检）和审计日志初始化。

```rust
use ciphern::Result;

fn main() -> Result<()> {
    // 初始化系统
    ciphern::init()?;
    Ok(())
}
```

---

## 2. 核心概念

### 2.1 算法 (Algorithm)

Ciphern 支持多种加密算法，分为国际标准和国密标准。

#### 对称加密

| 算法              | 密钥长度    | 性能 | 使用场景   |
|-----------------|---------|----|--------|
| **AES128GCM**   | 128 bit | 极快 | 通用数据加密 |
| **AES192GCM**   | 192 bit | 极快 | 通用数据加密 |
| **AES256GCM**   | 256 bit | 极快 | 通用数据加密 |
| **SM4GCM**      | 128 bit | 快  | 国密合规场景 |

#### 非对称加密与签名

| 算法             | 安全级别    | 性能 | 使用场景   |
|----------------|---------|----|--------|
| **ECDSAP256**  | 128 bit | 快  | 数字签名   |
| **ECDSAP384**  | 192 bit | 快  | 数字签名   |
| **ECDSAP521**  | 256 bit | 快  | 数字签名   |
| **RSA2048**    | 112 bit | 慢  | 兼容性场景  |
| **RSA3072**    | 128 bit | 慢  | 兼容性场景  |
| **RSA4096**    | 152 bit | 慢  | 兼容性场景  |
| **SM2**        | 128 bit | 中  | 国密数字签名 |
| **Ed25519**    | 128 bit | 极快 | 高性能签名  |

#### 哈希函数

| 算法           | 输出长度    | 性能 | 使用场景  |
|--------------|---------|----|-------|
| **SHA256**   | 256 bit | 快  | 通用哈希  |
| **SHA384**   | 384 bit | 快  | 通用哈希  |
| **SHA512**   | 512 bit | 快  | 通用哈希  |
| **SHA3_256** | 256 bit | 快  | 高安全哈希 |
| **SM3**      | 256 bit | 中  | 国密合规  |

### 2.2 密钥管理器 (KeyManager)

在 Ciphern 中，密钥材料受内存保护，不直接暴露。所有操作通过 `KeyManager` 引用 `key_id` 完成。

---

## 3. 基础使用

### 3.1 加密与解密

```rust
use ciphern::{Cipher, Algorithm, KeyManager, Result};

fn main() -> Result<()> {
    // 1. 初始化系统
    ciphern::init()?;

    // 2. 初始化密钥管理器
    let km = KeyManager::new()?;
    
    // 3. 生成密钥并获得 ID
    let key_id = km.generate_key(Algorithm::AES256GCM)?;
    
    // 4. 创建加密器
    let cipher = Cipher::new(Algorithm::AES256GCM)?;
    
    // 5. 执行加密
    let plaintext = b"Sensitive data";
    let ciphertext = cipher.encrypt(&km, &key_id, plaintext)?;
    
    // 6. 执行解密
    let decrypted = cipher.decrypt(&km, &key_id, &ciphertext)?;
    assert_eq!(plaintext, &decrypted[..]);
    
    Ok(())
}
```

### 3.2 数字签名

```rust
use ciphern::{Signer, Algorithm, KeyManager, Result};

fn main() -> Result<()> {
    // 初始化
    ciphern::init()?;
    
    let km = KeyManager::new()?;
    let key_id = km.generate_key(Algorithm::ECDSAP384)?;
    
    let signer = Signer::new(Algorithm::ECDSAP384)?;
    let message = b"Message to sign";
    
    // 签名
    let signature = signer.sign(&km, &key_id, message)?;
    
    // 验证
    let is_valid = signer.verify(&km, &key_id, message, &signature)?;
    assert!(is_valid);
    
    Ok(())
}
```

### 3.3 消息摘要与哈希

Ciphern 支持多种哈希算法，包括国际标准的 SHA 系列和国密标准的 SM3。注意需要启用 `hash` 特性。

#### 计算 SM3 哈希

```rust
use ciphern::{Hash, Result};

fn main() -> Result<()> {
    let data = b"abc";
    let hash = Hash::sm3(data)?;
    println!("SM3: {:x?}", hash);
    Ok(())
}
```

#### 计算 SHA512 哈希

```rust
use ciphern::{Hash, Result};

fn main() -> Result<()> {
    let data = b"abc";
    let hash = Hash::sha512(data)?;
    println!("SHA-512: {:x?}", hash);
    Ok(())
}
```

### 3.4 密钥别名管理

Ciphern 支持为密钥设置易读的别名，方便管理和检索。

```rust
let km = KeyManager::new()?;

// 生成带别名的密钥
let key_id = km.generate_key_with_alias(Algorithm::AES256GCM, "master-key")?;

// 之后可以通过别名获取密钥 ID
let resolved_id = km.resolve_alias("master-key")?;
assert_eq!(key_id, resolved_id);

// 也可以直接通过别名进行加解密
let cipher = Cipher::new(Algorithm::AES256GCM)?;
let ciphertext = cipher.encrypt(&km, "master-key", b"data")?;
```

---

## 4. 密钥管理

### 4.1 密钥生命周期

```rust
use ciphern::{KeyManager, Algorithm, Result};

fn key_lifecycle_example() -> Result<()> {
    let km = KeyManager::new()?;
    
    // 1. 生成密钥
    let key_id = km.generate_key(Algorithm::AES256GCM)?;
    println!("Generated Key ID: {}", key_id);
    
    // 2. 激活密钥 (新生成的密钥默认已激活)
    km.activate_key(&key_id)?;
    
    // 3. 暂停密钥
    km.suspend_key(&key_id)?;
    
    // 4. 获取密钥信息
    let key = km.get_key(&key_id)?;
    println!("Key State: {:?}", key.state());
    
    Ok(())
}
```

### 4.2 密钥保护机制

Ciphern 提供了多层密钥保护：

- **内存擦除**: 密钥材料在使用后会被 `zeroize` 自动擦除。
- **内存锁定**: 防止密钥被交换到磁盘。
- **访问控制**: 必须通过 `KeyManager` 引用 ID 访问密钥。

### 4.3 密钥状态管理

密钥是加密的核心，Ciphern 提供完整的密钥生命周期管理。

#### 密钥状态

```
PENDING → ACTIVE → ROTATING → DEPRECATED → DESTROYED
```

- **PENDING**: 已生成但未激活
- **ACTIVE**: 正常使用中
- **ROTATING**: 轮换中 (新旧密钥并存)
- **DEPRECATED**: 只能解密，不能加密
- **DESTROYED**: 已销毁，密钥材料已擦除

#### 密钥层次结构

```
Root Key (硬件保护)
  ├─ Tenant A Master Key
  │   ├─ App Key: database-encryption
  │   └─ App Key: file-encryption
  └─ Tenant B Master Key
      └─ App Key: api-encryption
```

### 4.4 密钥派生 (KDF)

从主密钥派生应用密钥，隔离风险。

```rust
use ciphern::Algorithm;
use ciphern::key::manager::KeyManager;

let km = KeyManager::new()?;
let key_id = km.generate_key(Algorithm::HKDF)?;
// 实际派生操作通常通过特定 Provider 完成
```

---

## 5. 高级特性

### 5.1 FIPS 140-3 模式

当启用 `fips` 特性时，Ciphern 可以运行在合规模式：

- 只允许 FIPS 批准的算法（如 AES, SHA-256）。
- 启动时执行自检。
- 强制执行连续随机数生成器测试。

```rust
use ciphern::{fips, Result};

fn main() -> Result<()> {
    // 检查 FIPS 模式是否启用
    if fips::is_fips_enabled() {
        println!("Running in FIPS 140-3 mode");
    }
    Ok(())
}
```

### 5.2 侧信道防护

Ciphern 实现了针对侧信道攻击的防护，包括恒定时间操作以防止定时攻击。

```rust
use ciphern::side_channel::constant_time_eq;

// 示例：恒定时间比较
let a = b"password";
let b = b"password";
let is_equal = constant_time_eq(a, b);
```

### 5.3 密钥状态管理

Ciphern 提供完整的密钥生命周期管理。

```rust
use ciphern::key::KeyState;

fn check_key_state(manager: &KeyManager, key_id: &str) -> Result<()> {
    let key = manager.get_key(key_id)?;
    
    // 检查密钥是否处于 ACTIVE 状态
    assert_eq!(key.state(), KeyState::Active);
    
    Ok(())
}
```

#### 密钥销毁

```rust
// 密钥在 KeyManager 内部由 zeroize 自动擦除
// 显式删除密钥
// km.delete_key(key_id)?;
```

### 4.5 多租户密钥隔离

Ciphern 通过 `KeyManager` 支持基于 ID 的密钥生成，便于在多租户环境中隔离密钥。

```rust
fn multi_tenant_example(km: &KeyManager) -> Result<()> {
    // 为租户 A 生成密钥
    let key_id_a = km.generate_key_with_id(Algorithm::AES256GCM, "tenant-a-key-1")?;

    // 为租户 B 生成密钥
    let key_id_b = km.generate_key_with_id(Algorithm::AES256GCM, "tenant-b-key-1")?;

    Ok(())
}
```

#### 租户访问控制

在应用层，您可以根据当前上下文租户 ID 来拼接密钥 ID，从而实现逻辑隔离。

```rust
let tenant_id = "tenant-123";
let key_id = format!("{}-db-key", tenant_id);
let ciphertext = cipher.encrypt(&km, &key_id, plaintext)?;
```

### 4.6 密钥派生与分层

#### HKDF 密钥派生

```rust
use ciphern::KeyManager;
use ciphern::Algorithm;

fn derive_keys_example(km: &KeyManager) -> Result<()> {
    // 主密钥 ID
    let master_key_id = km.generate_key(Algorithm::AES256GCM)?;
    
    // 派生算法示例
    let kdf_key_id = km.generate_key(Algorithm::HKDF)?;
    
    Ok(())
}
```

---

## 5. 高级特性

### 5.1 FIPS 140-3 合规模式

#### 启用 FIPS 模式

在 `Cargo.toml` 中启用 `fips` 特性，并确保在代码中调用了 `ciphern::init()`。

```toml
# Cargo.toml
[dependencies]
ciphern = { version = "0.1", features = ["fips"] }
```

```rust
use ciphern::{fips, Result};

fn main() -> Result<()> {
    // 初始化（将触发 FIPS 自检）
    ciphern::init()?;

    // 检查 FIPS 模式是否启用
    if ciphern::is_fips_enabled() {
        println!("✅ FIPS mode enabled");
    }

    Ok(())
}
```

#### FIPS 批准的算法

| 类别   | 批准算法                                   | 不批准算法        |
|------|----------------------------------------|--------------|
| 对称加密 | AES128GCM, AES192GCM, AES256GCM        | SM4GCM       |
| 非对称  | ECDSAP256, ECDSAP384, ECDSAP521, RSA2048, RSA3072, RSA4096 | SM2, Ed25519 |
| 哈希   | SHA256, SHA384, SHA512, SHA3_256       | SM3          |
| KDF  | HKDF, PBKDF2                           | Sm3Kdf       |

### 5.2 性能优化

#### 自动检测与使用

Ciphern 会自动检测 CPU 特性并使用最优实现（如 AES-NI, AVX2, ARM Crypto Extensions）。

#### 性能监控 (Prometheus)

Ciphern 内部集成了 Prometheus 指标。

```rust
use ciphern::audit::REGISTRY;

// 获取指标
let metrics = REGISTRY.gather();
```

### 5.3 审计日志

#### 启用审计

在 `ciphern::init()` 调用后，审计日志会自动按需记录。

```rust
use ciphern::audit::AuditLogger;

// 记录自定义操作
AuditLogger::log("CUSTOM_OP", Some(Algorithm::AES256GCM), Some("key-1"), Ok(()));
```

### 5.4 侧信道防护

Ciphern 实现了针对侧信道攻击的多层防护机制，核心是通过恒定时间操作防止定时攻击和功耗分析。

#### 恒定时间操作实现

所有敏感比较和数据处理都使用恒定时间算法，避免因分支预测或内存访问模式泄露信息：

```rust
use ciphern::side_channel::constant_time::constant_time_eq;
use ciphern::side_channel::constant_time::constant_time_less_than;

// 示例1：恒定时间比较（防止时序攻击）
let a = b"password";
let b = b"password";
let is_equal = constant_time_eq(a, b);

// 示例2：恒定时间小于比较
let x = 0x12345678u32;
let y = 0x87654321u32;
let is_less = constant_time_less_than(x, y);
```

#### 加密操作的侧信道防护

Ciphern 内部的所有加密操作（如 AES 加解密、ECDSA 签名）都使用恒定时间实现：

```rust
use ciphern::{Cipher, Algorithm, KeyManager};

// 加密操作自动使用恒定时间实现
let km = KeyManager::new()?;
let key_id = km.generate_key(Algorithm::AES256GCM)?;
let cipher = Cipher::new(Algorithm::AES256GCM)?;

// 该加密操作在恒定时间内完成，不会泄露明文或密钥信息
let ciphertext = cipher.encrypt(&km, &key_id, b"sensitive data")?;
```

#### 内存访问模式防护

Ciphern 使用 `SecretBytes` 容器保护敏感数据，确保内存访问模式不会泄露信息：

```rust
use ciphern::memory::SecretBytes;

// 敏感数据存储在受保护的容器中
let secret = SecretBytes::new(b"secret key material".to_vec())?;

// 所有访问都通过恒定时间接口
let data = secret.as_slice();
```

#### 防护范围

- ✅ **定时攻击防护**: 所有比较操作使用恒定时间实现
- ✅ **功耗分析防护**: 内存访问模式恒定
- ✅ **缓存攻击防护**: 避免数据依赖的内存访问
- ✅ **分支预测防护**: 消除基于秘密数据的分支

### 5.5 自定义插件

注意需要启用 `plugin` 特性。

```rust
use ciphern::plugin::{Plugin, CipherPlugin};
use ciphern::provider::SymmetricCipher;
use ciphern::types::Algorithm;
use ciphern::error::Result;
use std::sync::Arc;
use std::any::Any;

struct MyCustomPlugin;

impl Plugin for MyCustomPlugin {
    fn name(&self) -> &str { "my-custom-plugin" }
    fn version(&self) -> &str { "1.0.0" }
    fn initialize(&mut self) -> Result<()> { Ok(()) }
    fn shutdown(&mut self) -> Result<()> { Ok(()) }
    fn health_check(&self) -> Result<bool> { Ok(true) }
    fn as_any(&self) -> &dyn Any { self }
}

impl CipherPlugin for MyCustomPlugin {
    fn as_symmetric_cipher(&self) -> Arc<dyn SymmetricCipher> {
        // 返回您的 SymmetricCipher 实现
        todo!()
    }
    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![Algorithm::AES256GCM]
    }
}

// 注册插件
use ciphern::plugin::manager::PluginManager;

let manager = PluginManager::new();
let my_plugin = Arc::new(MyCustomPlugin);
manager.register_cipher_plugin(my_plugin)?;
```

---

## 6. 多语言集成

### 6.1 Java 集成

#### 编译说明

Java JNI 绑定已完成核心功能实现，支持加密解密和密钥管理。目前需要从源码编译：

```bash
# 编译 JNI 库
cargo build --release --features java
```

#### 基础使用

```java
import com.ciphern.Ciphern;

public class Example {
    public static void main(String[] args) {
        // 初始化
        Ciphern.init();
        
        // 生成密钥
        String keyId = Ciphern.generateKey("AES256GCM");
        
        // 加密
        byte[] plaintext = "Hello, Java!".getBytes();
        byte[] ciphertext = Ciphern.encrypt(keyId, plaintext);
        
        // 解密
        byte[] decrypted = Ciphern.decrypt(keyId, ciphertext);
        
        System.out.println("Decrypted: " + new String(decrypted));
    }
}
```

### 6.2 Python 集成

#### 编译说明

Python PyO3 绑定已完成核心功能实现，支持加密解密、签名验证和哈希计算。目前需要从源码编译：

```bash
# 编译 PyO3 扩展
cargo build --release --features python
```

#### 基础使用

```python
from ciphern_py import KeyManager, Ciphern

# 初始化密钥管理器
km = KeyManager()

# 生成密钥
key_id = km.generate_key("AES256GCM")

# 创建加密器
cipher = Ciphern(km)

# 加密
plaintext = b"Hello, Python!"
ciphertext = cipher.encrypt(key_id, plaintext)

# 解密
decrypted = cipher.decrypt(key_id, ciphertext)
assert plaintext == decrypted
```

---

## 7. 生产环境部署

### 7.1 性能调优

#### 线程池配置

Ciphern 使用 Tokio 作为异步运行时，可以通过环境变量或运行时句柄配置线程池。

```bash
# 设置 Tokio 工作线程数
export TOKIO_WORKER_THREADS=8
```

#### SIMD 优化

```bash
# 编译时启用 CPU 特性以获得最佳性能
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### 7.2 安全加固

#### 内存保护

Ciphern 默认启用多层内存保护机制：

1. **自动内存擦除**: 使用 `zeroize` 自动清理密钥内存
2. **内存锁定**: 使用 `mlock` 防止密钥被交换到磁盘
3. **完整性校验**: 密钥完整性检查防止内存篡改

在 Linux 环境下，确保应用有足够的权限使用 `mlock`：

```bash
# 提升内存锁定限制 (Linux)
# 编辑 /etc/security/limits.conf
* soft memlock unlimited
* hard memlock unlimited
```

#### 敏感数据容器

Ciphern 提供 `SecretBytes` 容器用于存储敏感数据：

```rust
use ciphern::memory::SecretBytes;

// 创建安全容器
let secret = SecretBytes::new(b"sensitive data".to_vec())?;

// 访问数据（自动零化）
let data = secret.as_slice();

// 容器销毁时自动零化内存
```

#### 文件权限

确保密钥存储目录权限正确：

```bash
# 密钥存储目录权限
chmod 700 /path/to/keys
```

### 7.3 监控与告警

#### Prometheus 关键指标

- `crypto_operations_total`: 操作总数 (加密/解密/签名等)
- `crypto_operation_duration_seconds`: 操作延迟
- `crypto_errors_total`: 错误总数

---

## 8. 故障排查

### 8.1 常见错误

#### 错误: `DecryptionFailed`

**原因**:
- 使用了错误的密钥 ID。
- 密文被篡改。
- 算法参数不匹配。

#### 错误: `FipsSelfTestFailed`

**原因**:
- 启用 FIPS 模式时，启动自检失败。
- 环境不满足 FIPS 要求。

### 8.2 调试技巧

#### 启用详细日志

```bash
# 设置日志级别
export RUST_LOG=ciphern=debug
./your_application
```

---

## 9. 最佳实践

### 9.1 安全建议

1. **始终调用 `init()`**: 确保系统正确初始化。
2. **使用别名**: 为关键密钥设置别名，避免在代码中硬编码密钥 ID。
3. **启用审计**: 在生产环境中启用审计日志以满足合规性要求。
4. **定期更新**: 及时更新 Ciphern 以获取最新的安全补丁。

---

## 10. 常见问题 (FAQ)

**Q: 如何选择加密算法？**
A: 推荐使用 `AES256GCM` 处理对称加密，`ECDSAP384` 处理数字签名。

**Q: 是否支持 SM 系列算法？**
A: 是的，Ciphern 支持 SM2, SM3, SM4 算法（注意：非 FIPS 批准）。

**Q: 密钥如何持久化？**
A: 默认情况下，`KeyManager` 会将密钥持久化到配置的存储路径中。

---

## 附录

### A. 完整 API 参考

请参考生成的 Rust 文档：
```bash
cargo doc --open
```

### B. 文档版本

**版本**: v0.1.0
**更新日期**: 2025-12-24
**反馈**: [GitHub Issues](https://github.com/Kirky-X/ciphern/issues)

[⬆ 回到顶部](#ciphern-用户指南)