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
use crate::core::context::DnsContext;
use crate::plugin::Plugin;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, event_enabled, info, warn, Level};

// dns请求处理
pub struct DnsRequestHandler {
    pub executor: Arc<RwLock<Box<dyn Plugin>>>,
}
//
// // 修改后的handle_request方法
// #[async_trait]
// impl RequestHandler for DnsRequestHandler {
//     async fn handle_request<R: ResponseHandler>(
//         &self,
//         request: &Request,
//         mut response_handle: R,
//     ) -> ResponseInfo {
//         let mut context = DnsContext {
//             request_info: request.request_info().unwrap(),
//             response: None,
//             mark: Vec::new(),
//             attributes: HashMap::new(),
//         };
//         info!("Handling request");
//         if event_enabled!(Level::DEBUG) {
//             debug!(
//                 "dns:request source:{}, query:{}, queryType:{}",
//                 context.request_info.src,
//                 context.request_info.query.name().to_string(),
//                 context.request_info.query.query_type().to_string()
//             );
//         }
//
//         {
//             // 执行程序入口执行
//             self.executor.read().await.execute(&mut context).await;
//         }
//
//         match context.response {
//             None => {
//                 warn!("No response received");
//                 let response = MessageResponseBuilder::from_message_request(request)
//                     .build_no_records(request.header().to_owned());
//                 response_handle.send_response(response).await.unwrap()
//             }
//             Some(res) => {
//                 if event_enabled!(Level::DEBUG) {
//                     debug!(
//                         "Response received: source:{}, query:{},answer:{:?}",
//                         context.request_info.src,
//                         context.request_info.query.name().to_string(),
//                         res.answers()
//                     );
//                 }
//                 let response = MessageResponseBuilder::from_message_request(request).build(
//                     request.header().to_owned(),
//                     res.answers().iter(),
//                     res.name_servers().iter(),
//                     vec![],
//                     res.additionals(),
//                 );
//                 response_handle.send_response(response).await.unwrap()
//             }
//         }
//     }
// }
