// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::{Algorithm};
use ciphern::key::manager::TenantKeyManager;
use ciphern::audit::AuditLogger;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn debug_audit_logging() {
    // 创建租户管理器
    let tenant_manager = Arc::new(TenantKeyManager::new("debug_tenant").unwrap());
    
    // 清空审计日志缓冲区
    AuditLogger::clear_logs();
    
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
    // 创建两个租户的管理器
    let tenant1_manager = Arc::new(TenantKeyManager::new("tenant1").unwrap());
    let tenant2_manager = Arc::new(TenantKeyManager::new("tenant2").unwrap());
    
    // 清空审计日志缓冲区
    AuditLogger::clear_logs();
    
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
    let unauthorized_logs: Vec<_> = logs.iter()
        .filter(|log| log.contains("UNAUTHORIZED"))
        .collect();
    println!("非授权访问记录数量: {}", unauthorized_logs.len());
    
    let key_access_logs: Vec<_> = logs.iter()
        .filter(|log| log.contains("KEY_ACCESS"))
        .collect();
    println!("密钥访问记录数量: {}", key_access_logs.len());
}