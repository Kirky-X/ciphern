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

### 1.1 Rust 项目集成

#### 添加依赖

```toml
# Cargo.toml
[dependencies]
ciphern = "0.1"

# 可选特性
[dependencies]
ciphern = { version = "0.1", features = ["simd", "fips"] }
```

#### 可用特性 (Features)

| 特性             | 描述                      | 建议场景     |
| ---------------- | ------------------------- | ------------ |
| `default`        | 标准库 + AES + SM4        | 通用场景     |
| `simd`           | SIMD 优化 (性能提升 3-6x) | 高吞吐量场景 |
| `fips`           | FIPS 140-3 合规模式       | 金融、政府   |
| `audit-log`      | 审计日志                  | 安全审计     |

---

## 2. 核心概念

### 2.1 算法 (Algorithm)

Ciphern 支持多种加密算法，分为国际标准和国密标准。

#### 对称加密

| 算法            | 密钥长度 | 性能 | 使用场景     |
| ---------------- | -------- | ---- | ------------ |
| **AES-256-GCM** | 256 bit  | 极快 | 通用数据加密 |
| **SM4-GCM**     | 128 bit  | 快   | 国密合规场景 |

#### 非对称加密与签名

| 算法           | 安全级别 | 性能 | 使用场景           |
| -------------- | -------- | ---- | ------------------ |
| **ECDSA-P384** | 192 bit  | 快   | 数字签名、密钥协商 |
| **SM2**        | 128 bit  | 中   | 国密数字签名       |
| **Ed25519**    | 128 bit  | 极快 | 高性能签名         |

#### 哈希函数

| 算法        | 输出长度 | 性能 | 使用场景       |
| ----------- | -------- | ---- | -------------- |
| **SHA-256** | 256 bit  | 快   | 通用哈希、HMAC |
| **SM3**     | 256 bit  | 中   | 国密合规       |

### 2.2 密钥管理器 (KeyManager)

在 Ciphern 中，密钥材料受内存保护，不直接暴露。所有操作通过 `KeyManager` 引用 `key_id` 完成。

---

## 3. 基础使用

### 3.1 加密与解密

```rust
use ciphern::{Cipher, Algorithm, KeyManager, Result};

fn main() -> Result<()> {
    // 1. 初始化密钥管理器
    let km = KeyManager::new()?;
    
    // 2. 生成密钥并获得 ID
    let key_id = km.generate_key(Algorithm::AES256GCM)?;
    
    // 3. 创建加密器
    let cipher = Cipher::new(Algorithm::AES256GCM)?;
    
    // 4. 执行加密
    let plaintext = b"Sensitive data";
    let ciphertext = cipher.encrypt(&km, &key_id, plaintext)?;
    
    // 5. 执行解密
    let decrypted = cipher.decrypt(&km, &key_id, &ciphertext)?;
    assert_eq!(plaintext, &decrypted[..]);
    
    Ok(())
}
```

### 3.2 数字签名

```rust
use ciphern::{Signer, Algorithm, KeyManager, Result};

fn main() -> Result<()> {
    let km = KeyManager::new()?;
    let key_id = km.generate_key(Algorithm::ECDSA_P384)?;
    
    let signer = Signer::new(Algorithm::ECDSA_P384)?;
    let message = b"Message to sign";
    
    // 签名
    let signature = signer.sign(&km, &key_id, message)?;
    
    // 验证
    let is_valid = signer.verify(&km, &key_id, message, &signature)?;
    assert!(is_valid);
    
    Ok(())
}
```

### 3.3 哈希计算 (SM3)

```rust
use ciphern::{Hash, Result};

fn main() -> Result<()> {
    let data = b"abc";
    let hash = Hash::sm3(data)?;
    println!("SM3: {:x?}", hash);
    Ok(())
}
```

#### 完整示例

```toml
[dependencies]
securevault = { version = "0.1", features = [
    "simd",           # 性能优化
    "audit-log",      # 审计
    "metrics",        # 监控
] }
```

### 1.2 配置文件

SecureVault 支持通过配置文件自定义行为。

```toml
# securevault.toml

[general]
# 算法优先级 (按顺序尝试)
algorithm_priority = ["AES256GCM", "SM4GCM"]

# 线程池大小 (0 = 自动检测)
thread_pool_size = 0

[keys]
# 默认密钥长度
default_key_size = 32

# 密钥缓存大小
cache_size = 100

# 默认轮换策略
[keys.rotation]
max_age_days = 90
max_operations = 1000000
auto_rotate = true

[random]
# 熵源配置
entropy_source = "hardware"  # hardware, os, hybrid
min_entropy_bits = 256

[memory]
# 内存保护
enable_mlock = true
enable_canary = true
canary_check_interval_ms = 1000

[audit]
enabled = true
log_success = false
log_failure = true
output = "file"  # file, syslog, siem

[audit.file]
path = "/var/log/ciphern/audit.log"
rotation_size_mb = 100

[fips]
# FIPS 模式 (需要编译时启用 fips 特性)
enabled = false
strict_mode = true  # 严格模式禁止非批准算法
```

### 1.3 环境变量

```bash
# 配置文件路径
export CIPHERN_CONFIG=/etc/ciphern/config.toml

# 日志级别
export RUST_LOG=ciphern=info

# FIPS 模式
export CIPHERN_FIPS=1
```

---

## 2. 核心概念

### 2.1 算法 (Algorithm)

SecureVault 支持多种加密算法，分为国际标准和国密标准。

#### 对称加密

| 算法            | 密钥长度 | 性能 | 使用场景     |
| --------------- | -------- | ---- | ------------ |
| **AES-256-GCM** | 256 bit  | 极快 | 通用数据加密 |
| **SM4-GCM**     | 128 bit  | 快   | 国密合规场景 |

#### 非对称加密与签名

| 算法           | 安全级别 | 性能 | 使用场景           |
| -------------- | -------- | ---- | ------------------ |
| **ECDSA-P384** | 192 bit  | 快   | 数字签名、密钥协商 |
| **SM2**        | 128 bit  | 中   | 国密数字签名       |
| **Ed25519**    | 128 bit  | 极快 | 高性能签名         |
| **RSA-4096**   | 112 bit  | 慢   | 兼容性场景         |

#### 哈希函数

| 算法        | 输出长度 | 性能 | 使用场景       |
| ----------- | -------- | ---- | -------------- |
| **SHA-256** | 256 bit  | 快   | 通用哈希、HMAC |
| **SHA-384** | 384 bit  | 快   | 高安全要求     |
| **SHA-512** | 512 bit  | 快   | 高安全要求     |
| **SM3**     | 256 bit  | 中   | 国密合规       |

### 2.2 密钥 (Key)

密钥是加密的核心，SecureVault 提供完整的密钥生命周期管理。

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

### 2.3 密钥派生 (KDF)

从主密钥派生应用密钥，隔离风险。

```rust
use securevault::kdf::{Hkdf, HkdfAlgorithm};

let master_key = Key::generate(Algorithm::AES256GCM)?;
let kdf = Hkdf::new(HkdfAlgorithm::Sha256);

// 派生不同用途的密钥
let db_key = kdf.derive(&master_key, None, b"database", 32)?;
let api_key = kdf.derive(&master_key, None, b"api", 32)?;
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
    
    // 2. 导出密钥 (受控操作)
    // let key_bytes = km.export_key(&key_id)?;
    
    // 3. 删除密钥
    // km.delete_key(&key_id)?;
    
    Ok(())
}
```

### 4.2 密钥保护机制

Ciphern 提供了多层密钥保护：
- **内存擦除**: 密钥材料在使用后会被 `zeroize` 自动擦除。
- **内存锁定**: 防止密钥被交换到磁盘。
- **访问控制**: 必须通过 `KeyManager` 引用 ID 访问密钥。

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
    if fips::is_fips_enabled() {
        println!("Running in FIPS 140-3 mode");
    }
    Ok(())
}
```

### 5.2 侧信道防护

Ciphern 实现了针对功耗分析攻击的防护（如 AES S-box 掩码）：

```rust
use ciphern::{Cipher, Algorithm, SideChannelConfig, RotatingSboxMasking};

// 创建带防护的加密器
// (具体实现取决于 provider 是否支持侧信道防护特性)
```
        manager.get_key_state(old_key_id)?,
        KeyState::Rotating
    );
    
    // 新密钥进入 ACTIVE 状态
    assert_eq!(
        manager.get_key_state(new_key_id)?,
        KeyState::Active
    );
    
    Ok(new_key_id)
}
```

#### 密钥销毁

```rust
// 安全销毁密钥 (内存擦除)
manager.destroy_key(key_id)?;

// 验证密钥已销毁
assert_eq!(
    manager.get_key_state(key_id)?,
    KeyState::Destroyed
);
```

### 4.2 多租户密钥隔离

#### 创建租户

```rust
use securevault::KeyHierarchy;

fn multi_tenant_example() -> Result<(), Box<dyn std::error::Error>> {
    let hierarchy = KeyHierarchy::new()?;
    
    // 创建租户
    let tenant_a = hierarchy.create_tenant("customer-001")?;
    let tenant_b = hierarchy.create_tenant("customer-002")?;
    
    // 租户 A 创建密钥
    let key_a = tenant_a.create_key("database-encryption")?;
    let cipher_a = Cipher::new(Algorithm::AES256GCM, &key_a)?;
    let ciphertext_a = cipher_a.encrypt(b"Tenant A data")?;
    
    // 租户 B 创建密钥
    let key_b = tenant_b.create_key("database-encryption")?;
    let cipher_b = Cipher::new(Algorithm::AES256GCM, &key_b)?;
    
    // ✅ 租户 B 无法解密租户 A 的数据
    assert!(cipher_b.decrypt(&ciphertext_a).is_err());
    
    // ✅ 租户 A 无法访问租户 B 的密钥
    assert!(tenant_a.get_key_by_id(key_b.id()).is_err());
    
    Ok(())
}
```

#### 租户访问控制

```rust
use securevault::{KeyHierarchy, AccessPolicy};

// 创建租户并设置访问策略
let tenant = hierarchy.create_tenant_with_policy(
    "customer-001",
    AccessPolicy {
        allowed_algorithms: vec![Algorithm::AES256GCM, Algorithm::ECDSAP384],
        max_keys: 100,
        require_mfa: true,
    }
)?;
```

### 4.3 密钥派生与分层

#### HKDF 密钥派生

```rust
use securevault::kdf::{Hkdf, HkdfAlgorithm};

fn derive_keys_example() -> Result<(), Box<dyn std::error::Error>> {
    // 主密钥
    let master_key = Key::generate(Algorithm::AES256GCM)?;
    
    // 创建 KDF
    let kdf = Hkdf::new(HkdfAlgorithm::Sha256);
    
    // 派生数据库加密密钥
    let db_key = kdf.derive(
        &master_key,
        Some(b"unique-salt"),
        b"database-encryption",
        32,  // 输出长度
    )?;
    
    // 派生 API 加密密钥
    let api_key = kdf.derive(
        &master_key,
        Some(b"unique-salt"),
        b"api-encryption",
        32,
    )?;
    
    // 不同上下文产生不同密钥
    assert_ne!(db_key.as_bytes(), api_key.as_bytes());
    
    // 相同上下文产生相同密钥 (确定性)
    let db_key2 = kdf.derive(
        &master_key,
        Some(b"unique-salt"),
        b"database-encryption",
        32,
    )?;
    assert_eq!(db_key.as_bytes(), db_key2.as_bytes());
    
    Ok(())
}
```

#### PBKDF2 密码派生

```rust
use securevault::kdf::{Pbkdf2, Pbkdf2Algorithm};

fn password_to_key(password: &str) -> Result<Key, Box<dyn std::error::Error>> {
    let pbkdf2 = Pbkdf2::new(Pbkdf2Algorithm::HmacSha256);
    
    let salt = b"unique-random-salt";  // 应该是随机生成的
    let iterations = 100_000;  // NIST 推荐最小值
    
    let key = pbkdf2.derive(
        password.as_bytes(),
        salt,
        iterations,
        32,  // AES-256 密钥长度
    )?;
    
    Ok(key)
}
```

---

## 5. 高级特性

### 5.1 FIPS 140-3 合规模式

#### 启用 FIPS 模式

```toml
# Cargo.toml
[dependencies]
securevault = { version = "0.1", features = ["fips"] }
```

```rust
use securevault::FipsMode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 检查 FIPS 模式是否启用
    if FipsMode::global().is_enabled() {
        println!("✅ FIPS mode enabled");
        
        // 运行自检
        FipsMode::global().run_self_tests()?;
        println!("✅ Self-tests passed");
    }
    
    // 只能使用 FIPS 批准的算法
    let key = Key::generate(Algorithm::AES256GCM)?;  // ✅ 允许
    
    // 非 FIPS 算法会被拒绝
    let result = Key::generate(Algorithm::SM4GCM);
    assert!(result.is_err());  // ❌ AlgorithmNotFipsApproved
    
    Ok(())
}
```

#### FIPS 批准的算法

| 类别     | 批准算法                               | 不批准算法   |
| -------- | -------------------------------------- | ------------ |
| 对称加密 | AES-128/192/256-GCM                    | SM4          |
| 非对称   | ECDSA-P256/384/521, RSA-2048/3072/4096 | SM2, Ed25519 |
| 哈希     | SHA-256/384/512, SHA3-256/384/512      | SM3          |
| KDF      | HKDF, PBKDF2                           | 自定义 KDF   |

### 5.2 SIMD 性能优化

#### 自动检测与使用

```toml
# Cargo.toml
[dependencies]
securevault = { version = "0.1", features = ["simd"] }
```

```rust
use securevault::Cipher;

// SecureVault 会自动检测 CPU 特性并使用最优实现
// - x86_64: AES-NI + AVX2
// - ARM64: ARM Crypto Extensions
// - Fallback: 纯软件实现

let cipher = Cipher::new(Algorithm::AES256GCM, &key)?;
let ciphertext = cipher.encrypt(&large_data)?;  // 自动使用 SIMD
```

#### 性能对比

```rust
use std::time::Instant;

fn benchmark_simd() {
    let data = vec![0u8; 100 * 1024 * 1024]; // 100MB
    let key = Key::generate(Algorithm::AES256GCM).unwrap();
    let cipher = Cipher::new(Algorithm::AES256GCM, &key).unwrap();
    
    let start = Instant::now();
    let _ = cipher.encrypt(&data).unwrap();
    let duration = start.elapsed();
    
    let throughput = (data.len() as f64 / duration.as_secs_f64()) / (1024.0 * 1024.0);
    println!("Throughput: {:.2} MB/s", throughput);
    
    // 预期: > 3 GB/s (AVX2), > 1.5 GB/s (SSE), > 500 MB/s (Scalar)
}
```

### 5.3 审计日志

#### 启用审计

```toml
# securevault.toml
[audit]
enabled = true
log_success = false  # 只记录失败
log_failure = true
output = "file"

[audit.file]
path = "/var/log/securevault/audit.log"
rotation_size_mb = 100
```

```rust
use securevault::audit::AuditLogger;

// 审计日志会自动记录所有加密操作
let cipher = Cipher::new(Algorithm::AES256GCM, &key)?;
let ciphertext = cipher.encrypt(plaintext)?;  // 自动记录

// 查看最近的审计日志
let logger = AuditLogger::global();
let recent_logs = logger.get_recent_logs(10)?;
for log in recent_logs {
    println!("{}: {} - {}", log.timestamp, log.operation, log.result);
}
```

#### SIEM 集成

```toml
# securevault.toml
[audit.siem]
enabled = true
transport = "syslog-tcp"
endpoint = "siem.company.com:514"
format = "cef"  # CEF, Syslog RFC 5424, JSON
```

```rust
use securevault::audit::{AuditLogger, SiemConfig, SiemTransport};

let siem_config = SiemConfig {
    transport: SiemTransport::SyslogTcp("10.0.1.100:514".parse()?),
    format: LogFormat::CEF,
};

AuditLogger::configure_siem(siem_config)?;
```

### 5.4 性能监控

#### Prometheus 集成

```toml
[dependencies]
securevault = { version = "0.1", features = ["metrics"] }
```

```rust
use securevault::metrics;

// 暴露 Prometheus metrics
let metrics_server = metrics::start_server("0.0.0.0:9090")?;

// 执行加密操作 (自动记录 metrics)
let cipher = Cipher::new(Algorithm::AES256GCM, &key)?;
let _ = cipher.encrypt(data)?;

// 可用的 metrics:
// - crypto_encrypt_total (Counter)
// - crypto_encrypt_duration_seconds (Histogram)
// - crypto_key_cache_hit_ratio (Gauge)
// - crypto_memory_usage_bytes (Gauge)
```

### 5.5 自定义插件

#### 实现自定义算法

```rust
use securevault::plugin::{CipherPlugin, PluginMetadata};

struct MyCustomCipher;

impl CipherPlugin for MyCustomCipher {
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        // 实现您的加密逻辑
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];  // 简化示例
        }
        Ok(ciphertext)
    }
    
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // 对称加密,解密与加密相同
        self.encrypt(key, ciphertext)
    }
    
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "my-custom-cipher",
            version: "1.0.0",
            author: "Your Name",
            algorithm: Algorithm::Custom(1001),
        }
    }
}

// 注册插件
use securevault::plugin::PluginManager;

let manager = PluginManager::global();
manager.register("my-cipher", Box::new(MyCustomCipher))?;

// 使用自定义算法
let cipher = Cipher::new_from_plugin("my-cipher", &key)?;
let ciphertext = cipher.encrypt(plaintext)?;
```

---

## 6. 多语言集成

### 6.1 Java 集成

#### Maven 配置

```xml
<dependency>
    <groupId>dev.ciphern</groupId>
    <artifactId>ciphern-jni</artifactId>
    <version>0.1.0</version>
</dependency>
```

#### 基础使用

```java
import dev.ciphern.*;

public class Example {
    public static void main(String[] args) {
        try (KeyManager km = new KeyManager()) {
            String keyId = km.generateKey(Algorithm.AES256GCM);
            
            try (Cipher cipher = new Cipher(Algorithm.AES256GCM)) {
                byte[] plaintext = "Hello, Java!".getBytes();
                byte[] ciphertext = cipher.encrypt(km, keyId, plaintext);
                byte[] decrypted = cipher.decrypt(km, keyId, ciphertext);
                
                System.out.println("Decrypted: " + new String(decrypted));
            }
        } catch (CryptoException e) {
            e.printStackTrace();
        }
    }
}
```

### 6.2 Python 集成

#### 安装

```bash
pip install ciphern
```

#### 基础使用

```python
from ciphern import Cipher, Algorithm, KeyManager

# 初始化
km = KeyManager()
key_id = km.generate_key(Algorithm.AES256GCM)

# 加密解密
cipher = Cipher(Algorithm.AES256GCM)
plaintext = b"Hello, Python!"
ciphertext = cipher.encrypt(km, key_id, plaintext)
decrypted = cipher.decrypt(km, key_id, ciphertext)
assert plaintext == decrypted
```
    return ciphertext

asyncio.run(encrypt_async())
```

---

## 7. 生产环境部署

### 7.1 性能调优

#### 线程池配置

```toml
# securevault.toml
[general]
thread_pool_size = 8  # 根据 CPU 核心数调整
```

#### 密钥缓存

```toml
[keys]
cache_size = 1000  # 缓存最近使用的 1000 个密钥
cache_ttl_seconds = 300  # 5 分钟 TTL
```

#### SIMD 优化

```bash
# 编译时启用 CPU 特性
RUSTFLAGS="-C target-cpu=native" cargo build --release --features simd
```

### 7.2 安全加固

#### 内存保护

```toml
[memory]
enable_mlock = true  # 防止 swap
enable_canary = true  # 内存篡改检测
canary_check_interval_ms = 1000
```

#### 文件权限

```bash
# 配置文件权限
sudo chmod 600 /etc/ciphern/config.toml
sudo chown root:root /etc/ciphern/config.toml

# 日志目录权限
sudo mkdir -p /var/log/ciphern
sudo chmod 700 /var/log/ciphern
```

### 7.3 监控与告警

#### Prometheus + Grafana

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ciphern'
    static_configs:
      - targets: ['localhost:9090']
```

**关键指标**:

- `crypto_encrypt_duration_seconds`: 加密延迟
- `crypto_key_cache_hit_ratio`: 密钥缓存命中率
- `crypto_memory_usage_bytes`: 内存使用量
- `crypto_error_total`: 错误计数

#### 告警规则

```yaml
# alerts.yml
groups:
  - name: securevault
    rules:
      - alert: HighEncryptionLatency
        expr: histogram_quantile(0.99, crypto_encrypt_duration_seconds) > 0.1
        for: 5m
        annotations:
          summary: "Encryption P99 latency > 100ms"
      
      - alert: FrequentDecryptionFailures
        expr: rate(crypto_error_total{error="decryption_failed"}[5m]) > 10
        for: 2m
        annotations:
          summary: "High rate of decryption failures"
```

---

## 8. 故障排查

### 8.1 常见错误

#### 错误: DecryptionFailed

**原因**:

- 使用了错误的密钥
- 密文被篡改
- 密钥已过期

**解决方案**:

```rust
match cipher.decrypt(&ciphertext) {
    Err(CryptoError::DecryptionFailed(msg)) => {
        eprintln!("Decryption failed: {}", msg);
        
        // 检查密钥状态
        if let Some(key_state) = manager.get_key_state(key_id) {
            if key_state == KeyState::Expired {
                eprintln!("Key has expired, trying previous key...");
                // 尝试使用轮换前的密钥
            }
        }
    }
    Ok(plaintext) => { /* 成功 */ }
    Err(e) => { /* 其他错误 */ }
}
```

#### 错误: InsufficientEntropy

**原因**:

- 熵源不可用 (嵌入式设备)
- 系统启动时熵池未初始化

**解决方案**:

```bash
# Linux: 安装 rng-tools
sudo apt-get install rng-tools
sudo systemctl enable rngd
sudo systemctl start rngd

# 检查可用熵
cat /proc/sys/kernel/random/entropy_avail
```

#### 错误: MemoryProtectionFailed

**原因**:

- 权限不足 (mlock 需要特权)
- 内存限制过低

**解决方案**:

```bash
# 提升内存锁定限制
sudo vi /etc/security/limits.conf
# 添加:
* soft memlock unlimited
* hard memlock unlimited

# 或者在配置中禁用 mlock
# ciphern.toml
[memory]
enable_mlock = false
```

### 8.2 调试技巧

#### 启用详细日志

```bash
export RUST_LOG=ciphern=debug
export RUST_BACKTRACE=1
```
./your_application
```

#### 性能分析

```bash
# 使用 perf 分析热点
perf record -g ./your_application
perf report

# 使用 flamegraph
cargo flamegraph --bin your_application
```

#### 内存泄漏检测

```bash
# Valgrind
valgrind --leak-check=full --show-leak-kinds=all ./your_application

# AddressSanitizer
RUSTFLAGS="-Z sanitizer=address" cargo build
./target/debug/your_application
```

---

## 9. 最佳实践

### 9.1 密钥管理最佳实践

#### ✅ DO: 密钥轮换

```rust
// 定期轮换密钥 (推荐 90 天)
let policy = RotationPolicy {
    max_age: Duration::from_days(90),
    auto_rotate: true,
};
```

#### ✅ DO: 密钥派生

```rust
// 从主密钥派生应用密钥,隔离风险
let db_key = kdf.derive(&master_key, None, b"database", 32)?;
let api_key = kdf.derive(&master_key, None, b"api", 32)?;
```

#### ❌ DON'T: 硬编码密钥

```rust
// ❌ 错误
let key = Key::from_bytes(Algorithm::AES256GCM, b"hardcoded_key_12345678901234567890123456")?;

// ✅ 正确
let key = Key::generate(Algorithm::AES256GCM)?;
// 或从安全的密钥管理系统加载
```

#### ❌ DON'T: 重用 IV/Nonce

```rust
// ❌ 错误 - 永远不要重用 IV
let nonce = [0u8; 12];  // 固定 nonce
for data in dataset {
    cipher.encrypt_with_iv(data, &nonce)?;  // 危险!
}

// ✅ 正确 - Ciphern 自动生成随机 IV
for data in dataset {
    cipher.encrypt(&km, &key_id, data)?;  // 每次加密使用新 IV
}
```

### 9.2 性能最佳实践

#### ✅ DO: 复用 Cipher 实例

```rust
// ✅ 好 - 复用 cipher
let cipher = Cipher::new(Algorithm::AES256GCM)?;
for data in dataset {
    let ciphertext = cipher.encrypt(&km, &key_id, data)?;
}
```

#### ✅ DO: 批量操作

```rust
// 批量加密比单独加密更高效
let ciphertexts: Result<Vec<_>> = plaintexts
    .iter()
    .map(|p| cipher.encrypt(&km, &key_id, p))
    .collect();
```

### 9.3 安全最佳实践

#### ✅ DO: 使用 AEAD 模式

```rust
// ✅ 使用认证加密 (AES-GCM)
let cipher = Cipher::new(Algorithm::AES256GCM)?;

// ❌ 避免仅加密模式 (如 AES-CBC)
```

#### ✅ DO: 验证签名

```rust
// ✅ 始终验证签名
let is_valid = signer.verify(&km, &key_id, message, &signature)?;
if !is_valid {
    return Err("Invalid signature");
}

// ❌ 不要盲目信任未验证的数据
```

#### ✅ DO: 清理敏感数据

```rust
use zeroize::Zeroize;

let mut sensitive_data = vec![0u8; 32];
// ... 使用 sensitive_data ...
sensitive_data.zeroize();  // 显式擦除
```

---

## 10. 常见问题

### Q1: Ciphern 与其他加密库有何不同?

**A**: Ciphern 的独特之处在于:

1. **安全优先**: 内存保护、侧信道防护、FIPS 合规
2. **国密支持**: 同时支持国际和国密标准
3. **企业级**: 统一密钥管理、审计日志
4. **易用性**: 统一接口、丰富文档、多语言支持

### Q2: 如何选择加密算法?

**A**:

- **通用场景**: AES-256-GCM (快速、安全、广泛支持)
- **国密合规**: SM4-GCM (符合中国商用密码标准)
- **数字签名**: ECDSA-P384 (安全性与性能平衡)
- **高性能签名**: Ed25519 (速度最快)

### Q3: 密钥应该存储在哪里?

**A**:

1. **最佳**: 硬件安全模块 (HSM) 或 KMS (如 AWS KMS, Azure Key Vault)
2. **次选**: 加密文件系统,使用主密钥加密
3. **开发环境**: 环境变量 (不要提交到 Git)

### Q4: 如何处理密钥轮换期间的旧数据?

**A**:

```rust
// 轮换后的密钥处于 ROTATING 状态,仍可解密旧数据
let old_cipher = Cipher::new(Algorithm::AES256GCM, &old_key)?;
let decrypted = old_cipher.decrypt(&old_ciphertext)?;

// 用新密钥重新加密
let new_cipher = Cipher::new(Algorithm::AES256GCM, &new_key)?;
let new_ciphertext = new_cipher.encrypt(&decrypted)?;
```

### Q5: FIPS 模式会影响性能吗?

**A**: 略有影响但可接受:

- FIPS 自检在启动时运行一次 (~100ms)
- 运行时仅禁用非批准算法,批准算法性能无影响
- 建议仅在合规要求的环境启用 FIPS

### Q6: 如何在 Docker 容器中使用?

**A**:

```dockerfile
FROM rust:1.75

# 安装依赖
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config

# 复制应用
COPY . /app
WORKDIR /app

# 编译
RUN cargo build --release

# 运行
CMD ["./target/release/your_app"]
```

### Q7: 支持哪些平台?

**A**:

- **Tier 1** (完全支持): Linux x86_64, Windows x86_64, macOS x86_64/ARM64
- **Tier 2** (社区支持): Linux ARM64, Linux ARMv7 (嵌入式)
- **实验性**: WebAssembly (WASM)

### Q8: 如何贡献代码?

**A**: 欢迎贡献!请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 附录

### A. 完整 API 参考

详见 [API Documentation](https://docs.rs/ciphern)

### B. 示例代码索引

- [基础加密](examples/basic_encryption.rs)
- [数字签名](examples/digital_signature.rs)
- [密钥管理](examples/key_management.rs)

### C. 术语表

详见 [GLOSSARY.md](GLOSSARY.md)

### D. 配置参考

完整配置选项见 [ciphern.toml.example](examples/ciphern.toml.example)

------

**文档版本**: v0.1.0
**最后更新**: 2025-12-22
**反馈**: 如有问题或建议,请提交 [Issue](https://github.com/yourorg/ciphern/issues)

[⬆ 回到顶部](#ciphern-用户指南)