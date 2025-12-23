# Ciphern 项目文件结构优化报告

## 1. 现状分析与重复检测

通过对项目文件结构的深度扫描，识别出以下改进点：

### 1.1 重复文件与代码
*   **FFI 模块**: `src/ffi/mod.rs` 承担了过多的实现逻辑，与 `src/ffi/interface.rs` 职责重叠。
*   **侧信道模块**: `src/side_channel/embedded_power/` 目录下的 `struct.rs` 和 `impl.rs` 属于过度拆分，增加了维护成本。
*   **类型定义**: `src/cipher/aes.rs` 中的 `AesKeyLength` 与全局 `Algorithm` 枚举存在逻辑冗余。

### 1.2 结构问题
*   **Provider 目录**: `src/provider` 目录略显单薄，其功能（注册表、接口）更适合作为 `src/cipher` 的一部分或核心基础设施。
*   **测试分散**: 单元测试散落在 `src` 和 `tests/unit` 中，建议统一规范：私有函数测试在源码同文件，公共 API 测试在 `tests/`。

## 2. 优化方案

### 2.1 文件合并建议

| 原文件 | 操作 | 目标位置/新文件 | 说明 |
| :--- | :--- | :--- | :--- |
| `src/side_channel/embedded_power/{struct.rs, impl.rs}` | **合并** | `src/side_channel/embedded_power.rs` | 消除子目录，扁平化结构 |
| `src/ffi/mod.rs` (实现部分) | **移动** | `src/ffi/c_api.rs` | 让 `mod.rs` 专注模块导出 |
| `src/provider/registry.rs` | **移动** | `src/cipher/registry.rs` | 将注册逻辑移至 cipher 模块 |

### 2.2 目录结构重构

推荐采用以下扁平化且功能内聚的目录结构：

```text
src/
├── cipher/           # 核心加密逻辑
│   ├── mod.rs
│   ├── aes.rs
│   ├── sm4.rs
│   └── registry.rs   # 算法注册表 (原 provider)
├── ffi/              # 多语言接口
│   ├── mod.rs
│   ├── c_api.rs      # C 接口实现
│   ├── java_jni.rs
│   ├── python.rs
│   └── utils.rs
├── key/              # 密钥管理
├── side_channel/     # 侧信道防护 (扁平化)
│   ├── mod.rs
│   ├── power.rs      # 原 embedded_power
│   ├── masking.rs
│   └── ...
├── lib.rs
└── ...
```

## 3. 执行计划

1.  **Phase 1**: 合并 `side_channel/embedded_power` 模块。
2.  **Phase 2**: 重构 `ffi` 模块，提取 C API 实现。
3.  **Phase 3**: 迁移 `provider` 逻辑至 `cipher` 模块。
4.  **Phase 4**: 清理冗余类型定义和未使用的文件。

此重构将显著提升代码的可读性和可维护性，同时符合 Rust 社区的最佳实践。
