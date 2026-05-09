// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Helpers for building management API responses.

use std::convert::Infallible;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Frame;
use serde::Serialize;

use crate::api::ApiResponse;

pub fn simple_response(status: StatusCode, body: Bytes) -> ApiResponse {
    Response::builder()
        .status(status)
        .body(Full::new(body).boxed_unsync())
        .expect("failed to build simple API response")
}

pub fn json_response<T>(status: StatusCode, value: &T) -> ApiResponse
where
    T: Serialize + ?Sized,
{
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut response = simple_response(status, Bytes::from(body));
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(err) => simple_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            Bytes::from(format!("failed to serialize json response: {err}")),
        ),
    }
}

pub fn json_ok<T>(status: StatusCode, value: &T) -> ApiResponse
where
    T: Serialize + ?Sized,
{
    json_response(status, value)
}

pub fn json_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> ApiResponse {
    #[derive(Serialize)]
    struct ErrorBody {
        ok: bool,
        code: &'static str,
        message: String,
    }

    json_response(
        status,
        &ErrorBody {
            ok: false,
            code,
            message: message.into(),
        },
    )
}

pub fn streaming_response<S>(status: StatusCode, stream: S) -> ApiResponse
where
    S: futures::Stream<Item = std::result::Result<Frame<Bytes>, Infallible>> + Send + 'static,
{
    Response::builder()
        .status(status)
        .body(http_body_util::StreamBody::new(stream).boxed_unsync())
        .expect("failed to build streaming API response")
}
