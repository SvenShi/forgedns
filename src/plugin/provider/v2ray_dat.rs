/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Minimal protobuf models for v2ray-rules-dat files.

use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    pub(crate) entry: Vec<GeoIp>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoIp {
    #[prost(string, tag = "1")]
    pub(crate) country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub(crate) cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub(crate) inverse_match: bool,
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) resource_hash: Vec<u8>,
    #[prost(string, tag = "5")]
    pub(crate) code: String,
    #[prost(string, tag = "68000")]
    pub(crate) file_path: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    pub(crate) entry: Vec<GeoSite>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoSite {
    #[prost(string, tag = "1")]
    pub(crate) country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub(crate) domain: Vec<Domain>,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) resource_hash: Vec<u8>,
    #[prost(string, tag = "4")]
    pub(crate) code: String,
    #[prost(string, tag = "68000")]
    pub(crate) file_path: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    pub(crate) r#type: i32,
    #[prost(string, tag = "2")]
    pub(crate) value: String,
    #[prost(message, repeated, tag = "3")]
    pub(crate) attribute: Vec<Attribute>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
pub(crate) enum DomainType {
    Plain = 0,
    Regex = 1,
    RootDomain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Attribute {
    #[prost(string, tag = "1")]
    pub(crate) key: String,
    #[prost(oneof = "attribute::TypedValue", tags = "2, 3")]
    pub(crate) typed_value: Option<attribute::TypedValue>,
}

pub(crate) mod attribute {
    use prost::Oneof;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum TypedValue {
        #[prost(bool, tag = "2")]
        BoolValue(bool),
        #[prost(int64, tag = "3")]
        IntValue(i64),
    }
}

pub(crate) fn normalized_selectors(selectors: &[String]) -> Vec<String> {
    selectors
        .iter()
        .map(|selector| selector.trim())
        .filter(|selector| !selector.is_empty())
        .map(|selector| selector.to_ascii_lowercase())
        .collect()
}
