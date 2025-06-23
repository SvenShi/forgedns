/*
 * Copyright 2025 Sven Shi
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::fs;
use std::path::Path;

fn main() {
    // 获取 `OUT_DIR` 环境变量（构建输出目录）
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir)
        .parent().unwrap()  // `target/debug/build/<hash>/` → `target/debug/build/`
        .parent().unwrap()  // → `target/debug/`
        .parent().unwrap(); // → `target/`（可选，如果希望直接复制到 `target/debug/`）


    let src = "./resource/config.yaml";

    // 复制文件
    fs::copy(src, target_dir.join("config.yaml")).expect("Failed to copy config.yaml");
}
