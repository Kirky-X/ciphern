// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use subtle::ConstantTimeEq;

#[test]
fn test_constant_time_comparison() {
    let a = [0x42u8; 32];
    let b_same = [0x42u8; 32];
    let b_diff = [0x43u8; 32];

    // Verify API works
    assert!(bool::from(a.ct_eq(&b_same)));
    assert!(!bool::from(a.ct_eq(&b_diff)));

    // Note: True constant-time verification requires statistical tools like 'dudect'
    // which are typically run as separate benchmarks, not simple unit tests.
}
