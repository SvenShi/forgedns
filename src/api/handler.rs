// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Core management API handler types.

use std::convert::Infallible;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::combinators::UnsyncBoxBody;

pub type ApiBody = UnsyncBoxBody<Bytes, Infallible>;
pub type ApiResponse = Response<ApiBody>;

#[async_trait]
pub trait ApiHandler: Send + Sync + 'static {
    async fn handle(&self, request: Request<Bytes>) -> ApiResponse;
}
