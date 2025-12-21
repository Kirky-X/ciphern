// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use crate::side_channel::{RotatingSboxMasking, SideChannelContext};
use std::sync::{Arc, Mutex};

// === AES Providers ===

/// AES-GCM 核心实现结构体
#[derive(Debug, Default, Clone)]
pub struct AesGcmProvider {
    pub side_channel_context: Option<Arc<Mutex<SideChannelContext>>>,
    pub rotating_sbox: Option<Arc<Mutex<RotatingSboxMasking>>>,
}

// === SM4 Providers ===

/// SM4-GCM 核心实现结构体
#[derive(Debug, Default, Clone)]
pub struct Sm4GcmProvider {
    pub side_channel_context: Option<Arc<Mutex<SideChannelContext>>>,
    pub rotating_sbox: Option<Arc<Mutex<RotatingSboxMasking>>>,
}
