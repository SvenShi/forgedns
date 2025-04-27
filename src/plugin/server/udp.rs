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
use crate::plugin::{Plugin, PluginFactory, PluginMainType};
use crate::plugin::server::Server;

pub struct UdpServer {}

impl Plugin for UdpServer {
    fn init(&self) {
        todo!()
    }

    fn destroy(&self) {
        todo!()
    }
}

impl Server for UdpServer {
    fn run() {
        todo!()
    }
}

pub struct UdpServerFactory {}

impl PluginFactory for UdpServerFactory {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        todo!()
    }

    fn plugin_type(&self, tag: &str) -> PluginMainType {
        PluginMainType::Server {
            tag: tag.to_string(),
            type_name: "udp".to_string(),
        }
    }
}
