// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;

#[allow(unused)]
#[derive(Debug)]
pub struct DnsContext {
    pub src_addr: SocketAddr,

    /// dns 请求信息
    pub request: Message,

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
