/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use std::fs;
use std::path::Path;

fn main() {
    // 获取 `OUT_DIR` 环境变量（构建输出目录）
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir)
        .parent()
        .unwrap() // `target/debug/build/<hash>/` → `target/debug/build/`
        .parent()
        .unwrap() // → `target/debug/`
        .parent()
        .unwrap(); // → `target/`（可选，如果希望直接复制到 `target/debug/`）

    let src = "./resource/config.yaml";

    // 复制文件
    fs::copy(src, target_dir.join("config.yaml")).expect("Failed to copy config.yaml");
}
