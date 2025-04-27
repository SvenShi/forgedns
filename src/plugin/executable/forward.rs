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

use crate::config::config::PluginConfig;
use crate::core::context::DnsContext;
use crate::plugin::executable::Executable;
use crate::plugin::{Plugin, PluginFactory, PluginMainType};
use hickory_client::client::{Client, ClientHandle};
use log::debug;
use std::sync::{Arc, Mutex};

/// dns请求转发器
pub trait RequestForwarder: Executable {
    fn forward(&self, context: &mut DnsContext<'_>) -> impl Future<Output = ()> + Send;
}

/// 单线程的dns转发器
pub struct SequentialDnsForwarder {
    /// 发送dns请求的客户端
    pub client: Arc<Mutex<Client>>,
}

impl Plugin for SequentialDnsForwarder {
    fn init(&self) {
        todo!()
    }

    fn destroy(&self) {
        todo!()
    }
}

pub struct ForwardFactory;

impl PluginFactory for ForwardFactory {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        todo!()
    }

    fn plugin_type(&self, tag: &str) -> PluginMainType {
        PluginMainType::Executor {
            tag: tag.to_string(),
            type_name: "forward".to_string(),
        }
    }
}

impl Executable for SequentialDnsForwarder {
    async fn execute(&self, context: &mut DnsContext<'_>) {
        self.forward(context).await;
    }
}

impl RequestForwarder for SequentialDnsForwarder {
    async fn forward(&self, context: &mut DnsContext<'_>) {
        let query = context.request_info.query;

        let response = self.client.lock().unwrap().query(
            query.name().into(),
            query.query_class(),
            query.query_type(),
        );

        match response.await {
            Ok(res) => {
                context.response = Some(res);
            }
            Err(e) => {
                debug!("dns request has err: {e}");
                context.response = None;
            }
        }
    }
}
