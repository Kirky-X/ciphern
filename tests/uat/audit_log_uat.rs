// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::audit::{AuditLog, AuditLogger};
use ciphern::key::manager::TenantKeyManager;
use ciphern::Algorithm;
use std::sync::{Arc, Mutex};
use std::time::Duration;

lazy_static::lazy_static! {
    static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
}

/// 测试初始化函数，确保测试间隔离
fn setup_test() -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_MUTEX.lock().unwrap();
    // 确保每个测试都从干净的状态开始
    AuditLogger::clear_logs();
    // 等待一小段时间确保日志缓冲区被清理
    std::thread::sleep(Duration::from_millis(100));
    guard
}

fn get_parsed_logs() -> Vec<AuditLog> {
    AuditLogger::get_logs()
        .iter()
        .map(|s| serde_json::from_str::<AuditLog>(s).unwrap())
        .collect()
}

#[test]
fn debug_audit_logging() {
    let _guard = setup_test();

    // 创建租户管理器
    let tenant_manager = Arc::new(TenantKeyManager::new("debug_tenant").unwrap());

    // 生成密钥
    let key_id = tenant_manager.generate_key(Algorithm::AES256GCM).unwrap();
    println!("生成的密钥ID: {}", key_id);

    // 等待日志记录
    std::thread::sleep(Duration::from_millis(100));

    // 获取并打印所有日志
    let logs = AuditLogger::get_logs();
    println!("\n=== 审计日志 ===");
    for (i, log) in logs.iter().enumerate() {
        println!("日志 {}: {}", i, log);
    }
    println!("=== 日志结束 ===\n");

    // 测试访问自己的密钥
    let result = tenant_manager.get_key(&key_id);
    println!("访问自己密钥的结果: {:?}", result.is_ok());

    // 等待日志记录
    std::thread::sleep(Duration::from_millis(100));

    // 获取新的日志
    let logs = AuditLogger::get_logs();
    println!("\n=== 访问后的审计日志 ===");
    for (i, log) in logs.iter().enumerate() {
        println!("日志 {}: {}", i, log);
    }
    println!("=== 日志结束 ===\n");
}

#[test]
fn debug_cross_tenant_access() {
    let _guard = setup_test();

    // 创建两个租户的管理器
    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());

    // 租户1生成密钥
    let tenant1_key = tenant1_manager.generate_key(Algorithm::AES256GCM).unwrap();
    println!("租户1生成的密钥ID: {}", tenant1_key);

    // 等待日志记录
    std::thread::sleep(Duration::from_millis(100));

    // 租户2尝试访问租户1的密钥
    println!("\n=== 租户2尝试访问租户1的密钥 ===");
    let result = tenant2_manager.get_key(&tenant1_key);
    println!("访问结果: {:?}", result.is_ok());

    // 等待日志记录
    std::thread::sleep(Duration::from_millis(100));

    // 获取所有日志
    let logs = AuditLogger::get_logs();
    println!("\n=== 审计日志 ===");
    for (i, log) in logs.iter().enumerate() {
        println!("日志 {}: {}", i, log);
    }
    println!("=== 日志结束 ===\n");

    // 分析日志
    let unauthorized_logs: Vec<_> = logs
        .iter()
        .filter(|log| log.contains("UNAUTHORIZED"))
        .collect();
    println!("非授权访问记录数量: {}", unauthorized_logs.len());

    let key_access_logs: Vec<_> = logs
        .iter()
        .filter(|log| log.contains("KEY_ACCESS"))
        .collect();
    println!("密钥访问记录数量: {}", key_access_logs.len());
}

#[test]
fn test_unauthorized_access_logging() {
    // 初始化测试环境
    let _guard = setup_test();

    // 创建两个租户的管理器
    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());

    // 租户1生成密钥
    let tenant1_key = tenant1_manager.generate_key(Algorithm::AES256GCM).unwrap();

    // 等待密钥生成日志记录
    std::thread::sleep(Duration::from_millis(100));

    // 再次清空日志，确保只测试非授权访问
    AuditLogger::clear_logs();

    // 租户2尝试访问租户1的密钥（应该失败并记录非授权访问）
    let result = tenant2_manager.get_key(&tenant1_key);
    assert!(result.is_err());

    // 等待日志记录
    std::thread::sleep(Duration::from_millis(500));

    // 验证审计日志中记录了非授权访问
    let logs = get_parsed_logs();

    // 查找非授权访问记录
    let unauthorized_logs: Vec<_> = logs
        .iter()
        .filter(|log| log.status == "UNAUTHORIZED")
        .collect();

    assert_eq!(unauthorized_logs.len(), 1, "应该有一条非授权访问记录");

    let unauthorized_log = &unauthorized_logs[0];
    assert_eq!(
        unauthorized_log.tenant_id.as_deref(),
        Some("tenant2"),
        "日志应该包含尝试访问的租户ID"
    );
    assert!(
        unauthorized_log.details.contains("tenant1"),
        "日志应该包含被访问的租户ID"
    );
    assert_eq!(
        unauthorized_log.operation, "KEY_ACCESS",
        "日志应该包含操作类型"
    );
    assert_eq!(
        unauthorized_log.access_type, "unauthorized",
        "日志应该标记为非授权访问"
    );
}

#[test]
fn test_authorized_access_logging() {
    // 初始化测试环境
    let _guard = setup_test();

    let tenant_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());

    // 生成密钥
    let key_id = tenant_manager.generate_key(Algorithm::AES256GCM).unwrap();

    // 等待密钥生成日志记录
    std::thread::sleep(Duration::from_millis(100));

    // 再次清空日志，确保只测试授权访问
    AuditLogger::clear_logs();

    // 租户访问自己的密钥（应该成功并记录授权访问
    let result = tenant_manager.get_key(&key_id);
    assert!(result.is_ok());

    // 等待日志记录
    std::thread::sleep(Duration::from_millis(500));

    // 验证审计日志中记录了授权访问
    let logs = get_parsed_logs();

    // 查找授权访问记录
    let authorized_logs: Vec<_> = logs
        .iter()
        .filter(|log| log.operation == "KEY_ACCESS" && log.status == "SUCCESS")
        .collect();

    assert_eq!(authorized_logs.len(), 1, "应该有一条授权访问记录");

    let authorized_log = &authorized_logs[0];
    assert_eq!(
        authorized_log.tenant_id.as_deref(),
        Some("tenant1"),
        "日志应该包含租户ID"
    );
    assert_eq!(
        authorized_log.access_type, "authorized",
        "日志应该标记为授权访问"
    );
}

#[test]
fn test_key_operations_audit_logging() {
    // 初始化测试环境
    let _guard = setup_test();

    let tenant_manager = Arc::new(TenantKeyManager::new("audit_test_tenant").unwrap());

    // 测试各种密钥操作的审计记录

    // 1. 生成密钥 (已自动激活)
    let key_id = tenant_manager.generate_key(Algorithm::AES256GCM).unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // 2. 列出密钥
    let _keys = tenant_manager.list_keys().unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // 3. 暂停密钥
    tenant_manager.suspend_key(&key_id).unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // 4. 激活密钥 (从暂停恢复到激活)
    tenant_manager.activate_key(&key_id).unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // 5. 设置最大使用次数
    tenant_manager
        .set_key_max_usage(&key_id, Some(100))
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // 6. 销毁密钥
    tenant_manager.destroy_key(&key_id).unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // 验证审计日志
    let logs = get_parsed_logs();

    // 检查各种操作的记录
    let operations = vec![
        "KEY_GENERATE",
        "KEY_LIST",
        "KEY_ACTIVATE",
        "KEY_SUSPEND",
        "KEY_MAX_USAGE_SET",
        "KEY_DESTROY",
    ];

    for op_name in operations {
        let found = logs.iter().any(|log| log.operation == op_name);
        assert!(found, "应该找到操作 {} 的审计记录", op_name);
    }

    // 验证所有记录都包含租户信息
    let monitored_operations = [
        "KEY_GENERATE",
        "KEY_LIST",
        "KEY_ACTIVATE",
        "KEY_SUSPEND",
        "KEY_MAX_USAGE_SET",
        "KEY_DESTROY",
    ];

    for log in &logs {
        if monitored_operations.contains(&log.operation.as_str()) {
            assert_eq!(
                log.tenant_id.as_deref(),
                Some("audit_test_tenant"),
                "记录 {} 应该包含租户ID",
                log.operation
            );
            assert_eq!(
                log.access_type, "authorized",
                "授权操作应该标记为authorized"
            );
        }
    }
}

#[test]
fn test_tenant_id_extraction_from_key() {
    // 初始化测试环境
    let _guard = setup_test();

    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());

    // 生成一个密钥
    let key_id = tenant1_manager.generate_key(Algorithm::AES256GCM).unwrap();

    // 等待密钥生成日志记录
    std::thread::sleep(Duration::from_millis(100));

    // 再次清空日志，确保只测试非授权访问
    AuditLogger::clear_logs();

    // 租户2尝试使用包含租户前缀的完整密钥ID访问
    let full_key_id = format!("tenant1:{}", key_id);
    let result = tenant2_manager.get_key(&full_key_id);
    assert!(result.is_err());

    // 等待日志记录
    std::thread::sleep(Duration::from_millis(500));

    // 验证审计日志记录了非授权访问
    let logs = get_parsed_logs();
    let unauthorized_logs: Vec<_> = logs
        .iter()
        .filter(|log| log.status == "UNAUTHORIZED")
        .collect();

    assert_eq!(unauthorized_logs.len(), 1, "应该检测到非授权访问");

    let unauthorized_log = &unauthorized_logs[0];
    assert!(
        unauthorized_log
            .details
            .contains("Tenant tenant2 attempted to access key from tenant tenant1"),
        "日志应该包含详细的非授权访问信息"
    );
}

#[test]
fn test_audit_log_security_alerts() {
    // 初始化测试环境
    let _guard = setup_test();

    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());

    // 生成密钥
    let key1 = tenant1_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let key2 = tenant1_manager.generate_key(Algorithm::AES256GCM).unwrap();

    // 等待密钥生成日志记录
    std::thread::sleep(Duration::from_millis(100));

    // 再次清空日志，确保只测试非授权访问
    AuditLogger::clear_logs();

    // 模拟多次非授权访问尝试（潜在攻击模式）
    for _ in 0..10 {
        let _ = tenant2_manager.get_key(&key1);
        let _ = tenant2_manager.get_key(&key2);
        std::thread::sleep(Duration::from_millis(200));
    }

    // 等待所有日志记录
    std::thread::sleep(Duration::from_millis(1500));

    // 验证所有非授权访问都被记录
    let logs = get_parsed_logs();
    let unauthorized_logs: Vec<_> = logs
        .iter()
        .filter(|log| log.status == "UNAUTHORIZED")
        .collect();

    assert!(
        unauthorized_logs.len() >= 20,
        "应该至少有20条非授权访问记录 (10次 * 2个密钥)"
    );

    // 验证所有记录都包含安全警告
    for log in &unauthorized_logs {
        assert!(
            log.details.contains("SECURITY ALERT"),
            "每条非授权访问记录都应该包含安全警告"
        );
        assert_eq!(
            log.tenant_id.as_deref(),
            Some("tenant2"),
            "记录应该包含攻击者租户ID"
        );
        assert!(log.details.contains("tenant1"), "记录应该包含被攻击租户ID");
    }
}

#[test]
fn test_audit_log_persistence() {
    // 初始化测试环境
    let _guard = setup_test();

    let tenant_manager = Arc::new(TenantKeyManager::new("persistence_test").unwrap());

    // 生成一些操作
    let key_id = tenant_manager.generate_key(Algorithm::AES256GCM).unwrap();
    let _ = tenant_manager.get_key(&key_id);
    let _ = tenant_manager.list_keys();

    // 等待日志记录
    std::thread::sleep(Duration::from_millis(500));

    // 获取日志并验证格式
    let logs = get_parsed_logs();
    assert!(!logs.is_empty(), "应该有审计日志记录");

    // 验证每条日志的内容
    for log in &logs {
        // 验证必需的字段不为空
        assert!(!log.operation.is_empty(), "日志应该包含操作类型");
        assert!(!log.status.is_empty(), "日志应该包含状态");
        assert!(log.tenant_id.is_some(), "日志应该包含租户ID");
        assert!(!log.access_type.is_empty(), "日志应该包含访问类型");
    }
}
