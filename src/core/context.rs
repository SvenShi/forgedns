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

use hickory_client::proto::xfer::DnsResponse;
use hickory_server::server::RequestInfo;

pub struct DnsContext<'a> {
    /// dns 请求信息
    pub request_info: RequestInfo<'a>,

    /// dns 响应信息
    pub response: Option<DnsResponse>,
}
