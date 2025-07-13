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
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use log::info;
use std::collections::HashMap;
use std::sync::Arc;

// dns请求处理
pub struct DnsRequestHandler {
    pub executor: Arc<Box<dyn Plugin>>,
}

// 修改后的handle_request方法
#[async_trait]
impl RequestHandler for DnsRequestHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        info!("Handling request: {:?}", request);
        let mut context = DnsContext {
            request_info: request.request_info().unwrap(),
            response: None,
            mark: Vec::new(),
            attributes: HashMap::new(),
        };

        info!("................{}", self.executor.tag());

        // 执行程序入口执行
        self.executor.execute(&mut context).await;

        match context.response {
            None => {
                info!("No response received");
                let response = MessageResponseBuilder::from_message_request(request)
                    .build_no_records(request.header().to_owned());
                response_handle.send_response(response).await.unwrap()
            }
            Some(res) => {
                info!("Response received: {:?}", res);
                let response = MessageResponseBuilder::from_message_request(request).build(
                    request.header().to_owned(),
                    res.answers().iter(),
                    res.name_servers().iter(),
                    vec![],
                    res.additionals(),
                );
                response_handle.send_response(response).await.unwrap()
            }
        }
    }
}
