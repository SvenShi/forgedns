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

use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use crate::core::context::DnsContext;
use crate::plugin::executable::Executable;
use crate::plugin::executable::forward::SequentialDnsForwarder;

// dns请求处理
pub struct DnsRequestHandler {
    pub executors: Vec<SequentialDnsForwarder>,
}

// 修改后的handle_request方法
#[async_trait::async_trait]
impl RequestHandler for DnsRequestHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        println!("Handling request: {:?}", request);
        let mut context = DnsContext {
            request_info: request.request_info().unwrap(),
            response: None,
        };

        for x in &self.executors {
            x.execute(&mut context).await;
        }

        match context.response {
            None => {
                let response = MessageResponseBuilder::from_message_request(request)
                    .build_no_records(request.header().to_owned());
                response_handle.send_response(response).await.unwrap()
            }
            Some(res) => {
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