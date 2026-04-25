// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Minimal protobuf models for v2ray-rules-dat files.

use std::collections::HashSet;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GeoSiteSelector {
    pub(crate) code: String,
    pub(crate) attr: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ParsedDat {
    GeoSite(GeoSiteList),
    GeoIp(GeoIpList),
}

pub(crate) fn normalized_selectors(selectors: &[String]) -> Vec<String> {
    selectors
        .iter()
        .map(|selector| selector.trim())
        .filter(|selector| !selector.is_empty())
        .map(|selector| selector.to_ascii_lowercase())
        .collect()
}

pub(crate) fn unique_nonempty_selectors(selectors: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for selector in selectors {
        let trimmed = selector.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_ascii_lowercase()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

pub(crate) fn geoip_code(entry: &GeoIp) -> &str {
    if entry.code.is_empty() {
        entry.country_code.as_str()
    } else {
        entry.code.as_str()
    }
}

pub(crate) fn geosite_code(entry: &GeoSite) -> &str {
    if entry.code.is_empty() {
        entry.country_code.as_str()
    } else {
        entry.code.as_str()
    }
}

pub(crate) fn cidr_to_rule(cidr: &Cidr) -> Option<String> {
    match cidr.ip.len() {
        4 => Some(format!(
            "{}.{}.{}.{}/{}",
            cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3], cidr.prefix
        )),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&cidr.ip);
            Some(format!(
                "{}/{}",
                std::net::Ipv6Addr::from(octets),
                cidr.prefix
            ))
        }
        _ => None,
    }
}

pub(crate) fn parse_geosite_selectors(
    raw_selectors: &[String],
) -> Result<Vec<GeoSiteSelector>, String> {
    let mut selectors = Vec::new();
    for raw in raw_selectors {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let (code, attr) = match token.split_once('@') {
            Some((code, attr)) => (code.trim(), Some(attr.trim())),
            None => (token, None),
        };
        if code.is_empty() {
            return Err(format!("invalid empty geosite code selector '{}'", token));
        }
        if attr.is_some_and(str::is_empty) {
            return Err(format!(
                "invalid geosite selector '{}' with empty attribute name",
                token
            ));
        }
        selectors.push(GeoSiteSelector {
            code: code.to_ascii_lowercase(),
            attr: attr.map(|value| value.to_ascii_lowercase()),
        });
    }
    Ok(selectors)
}

pub(crate) fn matched_geosite_selectors<'a>(
    entry: &GeoSite,
    selectors: &'a [GeoSiteSelector],
) -> Vec<&'a GeoSiteSelector> {
    if selectors.is_empty() {
        return Vec::new();
    }
    let code = geosite_code(entry).to_ascii_lowercase();
    selectors
        .iter()
        .filter(|selector| selector.code == code)
        .collect()
}

pub(crate) fn geosite_domain_matches_selectors(
    domain: &Domain,
    selectors: &[&GeoSiteSelector],
) -> bool {
    if selectors.is_empty() {
        return true;
    }
    selectors.iter().any(|selector| match &selector.attr {
        None => true,
        Some(attr) => domain_has_attribute(domain, attr),
    })
}

pub(crate) fn geosite_domain_expression(domain: &Domain) -> Result<String, String> {
    let prefix = match DomainType::try_from(domain.r#type).map_err(|_| {
        format!(
            "unsupported domain type '{}' for '{}'",
            domain.r#type, domain.value
        )
    })? {
        DomainType::Plain => "keyword:",
        DomainType::Regex => "regexp:",
        DomainType::RootDomain => "domain:",
        DomainType::Full => "full:",
    };
    Ok(format!("{}{}", prefix, domain.value))
}

pub(crate) fn geosite_domain_expression_original(domain: &Domain) -> Result<String, String> {
    let prefix = match DomainType::try_from(domain.r#type).map_err(|_| {
        format!(
            "unsupported domain type '{}' for '{}'",
            domain.r#type, domain.value
        )
    })? {
        DomainType::Plain => "plain:",
        DomainType::Regex => "regex:",
        DomainType::RootDomain => "root_domain:",
        DomainType::Full => "full:",
    };
    Ok(format!("{}{}", prefix, domain.value))
}

pub(crate) fn geosite_domain_expression_original_with_attrs(
    domain: &Domain,
) -> Result<String, String> {
    let mut line = geosite_domain_expression_original(domain)?;
    for attribute in &domain.attribute {
        line.push(' ');
        line.push('@');
        line.push_str(attribute.key.as_str());
        match &attribute.typed_value {
            None => {}
            Some(attribute::TypedValue::BoolValue(true)) => {}
            Some(attribute::TypedValue::BoolValue(false)) => line.push_str("=false"),
            Some(attribute::TypedValue::IntValue(value)) => {
                line.push('=');
                line.push_str(value.to_string().as_str());
            }
        }
    }
    Ok(line)
}

pub(crate) fn parse_geosite_dat(data: &[u8]) -> Result<GeoSiteList, String> {
    let list = GeoSiteList::decode(data).map_err(|e| e.to_string())?;
    if is_valid_geosite_list(&list) {
        Ok(list)
    } else {
        Err("decoded geosite payload failed structural validation".to_string())
    }
}

pub(crate) fn parse_geoip_dat(data: &[u8]) -> Result<GeoIpList, String> {
    let list = GeoIpList::decode(data).map_err(|e| e.to_string())?;
    if is_valid_geoip_list(&list) {
        Ok(list)
    } else {
        Err("decoded geoip payload failed structural validation".to_string())
    }
}

pub(crate) fn detect_dat_kind(data: &[u8]) -> Result<ParsedDat, String> {
    let geosite = parse_geosite_dat(data).ok().map(ParsedDat::GeoSite);
    let geoip = parse_geoip_dat(data).ok().map(ParsedDat::GeoIp);

    match (geosite, geoip) {
        (Some(_), Some(_)) => {
            Err("dat kind is ambiguous; please pass --kind geosite or --kind geoip".to_string())
        }
        (Some(parsed), None) | (None, Some(parsed)) => Ok(parsed),
        (None, None) => Err("failed to identify dat kind from file contents".to_string()),
    }
}

fn domain_has_attribute(domain: &Domain, attr: &str) -> bool {
    domain.attribute.iter().any(|attribute| {
        if !attribute.key.eq_ignore_ascii_case(attr) {
            return false;
        }
        match &attribute.typed_value {
            None => true,
            Some(attribute::TypedValue::BoolValue(value)) => *value,
            Some(attribute::TypedValue::IntValue(value)) => *value != 0,
        }
    })
}

fn is_valid_geosite_list(list: &GeoSiteList) -> bool {
    !list.entry.is_empty()
        && list.entry.iter().all(|entry| {
            !geosite_code(entry).trim().is_empty()
                && !entry.domain.is_empty()
                && entry
                    .domain
                    .iter()
                    .all(|domain| !domain.value.trim().is_empty())
        })
}

fn is_valid_geoip_list(list: &GeoIpList) -> bool {
    !list.entry.is_empty()
        && list.entry.iter().all(|entry| {
            !geoip_code(entry).trim().is_empty()
                && !entry.cidr.is_empty()
                && entry
                    .cidr
                    .iter()
                    .all(|cidr| matches!(cidr.ip.len(), 4 | 16))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_geosite_selector_rejects_empty_attribute() {
        let err = parse_geosite_selectors(&["cn@".to_string()]).expect_err("selector should fail");
        assert!(err.contains("empty attribute"));
    }

    #[test]
    fn unique_selectors_keep_first_spelling() {
        let selectors =
            unique_nonempty_selectors(&[" CN ".to_string(), "cn".to_string(), "".to_string()]);
        assert_eq!(selectors, vec!["CN".to_string()]);
    }
}
