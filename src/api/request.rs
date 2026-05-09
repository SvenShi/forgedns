// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Request body collection and `/api` path normalization.

use bytes::Bytes;
use http::{Request, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;

pub(crate) fn strip_api_prefix(path: &str) -> Option<String> {
    if path == "/api" {
        return Some("/".to_string());
    }
    path.strip_prefix("/api/").map(|path| format!("/{path}"))
}

pub(crate) fn rewrite_request_path(
    request: Request<Bytes>,
    path: &str,
) -> std::result::Result<Request<Bytes>, ()> {
    let query = request.uri().query().map(str::to_string);
    let (mut parts, body) = request.into_parts();
    let path_and_query = match query {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    parts.uri = path_and_query.parse::<Uri>().map_err(|_| ())?;
    Ok(Request::from_parts(parts, body))
}

pub(super) async fn read_hyper_request(
    request: Request<Incoming>,
) -> std::result::Result<Request<Bytes>, StatusCode> {
    let (parts, mut body) = request.into_parts();
    let mut collected = Vec::with_capacity(2048);

    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Ok(data) = frame.into_data() {
            collected.extend_from_slice(&data);
        }
    }

    Ok(Request::from_parts(parts, Bytes::from(collected)))
}
