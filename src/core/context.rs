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
use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use hickory_proto::op::{Header, LowerQuery};
use hickory_proto::xfer::{DnsResponse, Protocol};

#[allow(unused)]
pub struct DnsContext {
    /// dns 请求信息
    pub request_info: RequestInfo,

    /// dns 响应信息
    pub response: Option<DnsResponse>,

    pub mark: Vec<String>,

    pub attributes: HashMap<String, Box<dyn Any + Send + Sync>>,
}

#[allow(unused)]
impl DnsContext {
    fn set_attr<T>(&mut self, name: String, value: Box<T>)
    where
        T: Send + Sync + 'static,
    {
        self.attributes.insert(name, value);
    }

    fn get_attr<T>(&mut self, name: String) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.attributes.get(&name).and_then(|a| a.downcast_ref())
    }

    fn remove_attr(&mut self, name: &str) {
        self.attributes.remove(name);
    }
}


pub struct RequestInfo {
    /// The source address from which the request came
    pub src: SocketAddr,
    /// The protocol used for the request
    pub protocol: Protocol,
    /// The header from the original request
    pub header: Header,
    /// The query from the request
    pub query: LowerQuery,
}