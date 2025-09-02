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
/// 上游服务器连接类型
enum ConnectType {
    UDP,
    TCP,
    HTTPS,
    TLS,
    QUIC,
    DOQ,
}
impl ConnectType {
    pub fn default_port(&self) -> u16 {
        match self {
            ConnectType::UDP => 53,
            ConnectType::TCP => 53,
            ConnectType::HTTPS => 443,
            ConnectType::TLS => 853,
            ConnectType::QUIC => 853,
            ConnectType::DOQ => 853,
        }
    }

    pub fn schema(&self) -> &str {
        match self {
            ConnectType::UDP => "udp",
            ConnectType::TCP => "tcp",
            ConnectType::HTTPS => "https",
            ConnectType::TLS => "tls",
            ConnectType::QUIC => "quic",
            ConnectType::DOQ => "doq",
        }
    }
}

///上游服务器
pub struct UpStream {
    pub addr: String,
    pub port: u16,
    pub socks5: Option<String>,
    pub connect_type: ConnectType,
}
