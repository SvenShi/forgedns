// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

// use crate::pkg::upstream::upstream::{IpAddrUpStream, UpStreamBuilder};
// use chrono::{DateTime, Local};
// use std::net::IpAddr;
// use tokio::sync::RwLock;
// use tokio::task::yield_now;
//
// #[derive(Clone)]
// enum CacheState {
//     None,
//     Querying,
//     Cached(IpAddr),
//     Failed,
// }
//
// pub(crate) struct Bootstrap {
//     upstream: IpAddrUpStream,
//     next_update: RwLock<DateTime<Local>>,
//     cache_state: RwLock<CacheState>,
// }
//
// impl Bootstrap {
//     pub fn new(ip_addr: &str) -> Bootstrap {
//         Bootstrap {
//             upstream: UpStreamBuilder::build_ip_upstream(ip_addr),
//             next_update: RwLock::new(Local::now()),
//             cache_state: RwLock::new(CacheState::None),
//         }
//     }
//
//     pub async fn get(&self) -> Result<IpAddr, String> {
//         let mut failed_count = 0;
//
//         loop {
//             let state = { self.cache_state.read().await.clone() };
//
//             match state {
//                 CacheState::None => {
//                     self.query().await;
//                 }
//                 CacheState::Querying => {
//                     yield_now().await;
//                 }
//                 CacheState::Cached(result) => {
//                     let next_update = *self.next_update.read().await;
//                     if Local::now() > next_update {
//                         self.query().await;
//                         continue;
//                     }
//                     return Ok(result);
//                 }
//                 CacheState::Failed => {
//                     if failed_count > 3 {
//                         return Err("bootstrap 查询失败".to_string());
//                     }
//                     failed_count += 1;
//                     self.query().await;
//                 }
//             }
//         }
//     }
//
//     async fn query(&self) {
//         let mut state = self.cache_state.write().await;
//         *state = CacheState::Querying;
//
//         // TODO: 这里执行真正的查询逻辑，比如调用 upstream 解析 IP
//         // 假设成功获得 ip:
//         // let ip = self.upstream.query().await.unwrap();
//         // *state = CacheState::Cached(ip);
//         // *self.next_update.write().await = Local::now() + chrono::Duration::minutes(10);
//
//         // 如果失败:
//         *state = CacheState::Failed;
//     }
// }
