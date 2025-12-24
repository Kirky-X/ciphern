// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

//! 测试countermeasure_stats跨测试干扰问题

use crate::side_channel::{SideChannelConfig, SideChannelContext};
use std::sync::{Arc, Mutex};

#[test]
fn test_countermeasure_stats_isolation() {
    // 测试1：创建独立的上下文
    let config1 = SideChannelConfig::default();
    let mut context1 = SideChannelContext::new(config1);

    // 初始统计应该为零
    let initial_stats = context1.get_stats();
    assert_eq!(initial_stats.timing_protections, 0);
    assert_eq!(initial_stats.masking_operations, 0);
    assert_eq!(initial_stats.error_detection_triggers, 0);
    assert_eq!(initial_stats.cache_flush_operations, 0);

    // 模拟一些操作
    context1.increment_timing_protections();
    context1.increment_timing_protections();
    context1.increment_masking_operations();

    let after_ops_stats = context1.get_stats();
    assert_eq!(after_ops_stats.timing_protections, 2);
    assert_eq!(after_ops_stats.masking_operations, 1);

    // 测试2：创建另一个独立的上下文
    let config2 = SideChannelConfig::default();
    let context2 = SideChannelContext::new(config2);

    // 新上下文的统计应该仍然为零
    let new_context_stats = context2.get_stats();
    assert_eq!(new_context_stats.timing_protections, 0);
    assert_eq!(new_context_stats.masking_operations, 0);

    // 第一个上下文的统计应该保持不变
    let context1_final_stats = context1.get_stats();
    assert_eq!(context1_final_stats.timing_protections, 2);
    assert_eq!(context1_final_stats.masking_operations, 1);
}

#[test]
fn test_countermeasure_stats_with_arc_mutex() {
    // 测试3：使用Arc<Mutex<>>的上下文共享
    let config = SideChannelConfig::default();
    let context = Arc::new(Mutex::new(SideChannelContext::new(config)));

    let context_clone1 = Arc::clone(&context);
    let context_clone2 = Arc::clone(&context);

    // 在线程1中增加统计
    let handle1 = std::thread::spawn(move || {
        let mut ctx = context_clone1.lock().unwrap();
        ctx.increment_timing_protections();
        ctx.increment_masking_operations();
        ctx.get_stats()
    });

    // 在线程2中增加统计
    let handle2 = std::thread::spawn(move || {
        let mut ctx = context_clone2.lock().unwrap();
        ctx.increment_timing_protections();
        ctx.increment_cache_flush();
        ctx.get_stats()
    });

    // 等待两个线程完成
    let _stats1 = handle1.join().unwrap();
    let _stats2 = handle2.join().unwrap();

    // 由于共享同一个上下文，统计应该累加
    let final_stats = context.lock().unwrap().get_stats();
    assert_eq!(final_stats.timing_protections, 2); // 两个线程各增加1次
    assert_eq!(final_stats.masking_operations, 1); // 只有线程1增加
    assert_eq!(final_stats.cache_flush_operations, 1); // 只有线程2增加

    // 验证最终状态正确（由于竞态条件，线程看到的中间状态可能不一致）
    assert!(final_stats.timing_protections >= 2); // 至少2次增加
    assert_eq!(final_stats.masking_operations, 1); // 只有线程1增加
    assert_eq!(final_stats.cache_flush_operations, 1); // 只有线程2增加
}

#[test]
fn test_countermeasure_stats_parallel_tests() {
    // 测试4：模拟并行测试场景
    let mut handles = vec![];

    for i in 0..4 {
        let handle = std::thread::spawn(move || {
            // 每个线程创建自己的独立上下文
            let config = SideChannelConfig::default();
            let mut context = SideChannelContext::new(config);

            // 每个线程执行不同的操作次数
            for _ in 0..(i + 1) {
                context.increment_timing_protections();
                context.increment_masking_operations();
            }

            // 返回最终的统计
            context.get_stats()
        });

        handles.push(handle);
    }

    // 收集所有线程的结果
    let mut results = vec![];
    for handle in handles {
        results.push(handle.join().unwrap());
    }

    // 验证每个线程的统计是独立的
    for (i, stats) in results.iter().enumerate() {
        let expected_count = (i + 1) as u64;
        assert_eq!(stats.timing_protections, expected_count);
        assert_eq!(stats.masking_operations, expected_count);
        assert_eq!(stats.error_detection_triggers, 0);
        assert_eq!(stats.cache_flush_operations, 0);
    }

    // 验证统计之间没有交叉污染
    let unique_timing_counts: std::collections::HashSet<_> =
        results.iter().map(|s| s.timing_protections).collect();
    assert_eq!(unique_timing_counts.len(), 4); // 应该有4个不同的计数值
}
