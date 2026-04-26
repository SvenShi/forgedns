// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::model::{
    EdnsJson, EdnsOptionJson, PendingRecord, QuestionJson, RecordJson, RecordRow, StepJson,
};
use crate::core::context::{ExecutionPath, ExecutionPathEvent};
use crate::proto::rdata::{
    self, CAA, ClientSubnet, DNSKEY, DS, Edns, EdnsCode, EdnsExtendedDnsError, EdnsOption, NSEC,
    NSEC3, NSEC3PARAM, RRSIG, SOA, SSHFP, SVCB, TLSA, TXT, URI,
};
use crate::proto::{DNSClass, Message, Opcode, Question, RData, Rcode, Record, RecordType};

impl PendingRecord {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        request: Message,
        response: Option<Message>,
        created_at_ms: u64,
        elapsed_ms: u64,
        exec_path: ExecutionPath,
        step_start_index: usize,
        client_ip: SocketAddr,
        error: Option<String>,
    ) -> Self {
        Self {
            request,
            response,
            created_at_ms,
            elapsed_ms,
            exec_path,
            step_start_index,
            client_ip,
            error,
        }
    }

    pub(super) fn take_to_record(self) -> (RecordRow, Vec<StepJson>) {
        let PendingRecord {
            request,
            response,
            created_at_ms,
            elapsed_ms,
            exec_path,
            step_start_index,
            client_ip,
            error,
        } = self;

        let questions_json = request
            .questions()
            .iter()
            .map(question_json)
            .collect::<Vec<_>>();
        let req_edns_json = request.edns().as_ref().map(edns_json);
        let steps = exec_path
            .events_from(step_start_index)
            .iter()
            .enumerate()
            .map(step_json)
            .collect::<Vec<_>>();

        let no_err = error.is_none();

        let mut record = RecordRow {
            id: 0,
            created_at_ms,
            elapsed_ms,
            request_id: request.id(),
            client_ip: client_ip.ip().to_string(),
            questions_json,
            req_rd: request.recursion_desired(),
            req_cd: request.checking_disabled(),
            req_ad: request.authentic_data(),
            req_opcode: opcode_name(request.opcode()),
            req_edns_json,
            error,
            has_response: false,
            rcode: None,
            resp_aa: None,
            resp_tc: None,
            resp_ra: None,
            resp_ad: None,
            resp_cd: None,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            answers_json: Vec::new(),
            authorities_json: Vec::new(),
            additionals_json: Vec::new(),
            signature_json: Vec::new(),
            resp_edns_json: None,
        };

        if no_err && let Some(response) = response {
            record.has_response = true;
            record.rcode = Some(rcode_name(response.rcode()));
            record.resp_aa = Some(response.authoritative());
            record.resp_tc = Some(response.truncated());
            record.resp_ra = Some(response.recursion_available());
            record.resp_ad = Some(response.authentic_data());
            record.resp_cd = Some(response.checking_disabled());
            record.answer_count = response.answers().len() as u32;
            record.authority_count = response.authorities().len() as u32;
            record.additional_count = response.additionals().len() as u32;
            record.answers_json = response
                .answers()
                .iter()
                .map(record_json)
                .collect::<Vec<_>>();
            record.authorities_json = response
                .authorities()
                .iter()
                .map(record_json)
                .collect::<Vec<_>>();
            record.additionals_json = response
                .additionals()
                .iter()
                .map(record_json)
                .collect::<Vec<_>>();
            record.signature_json = response
                .signature()
                .iter()
                .map(record_json)
                .collect::<Vec<_>>();
            record.resp_edns_json = response.edns().as_ref().map(edns_json);
        }

        (record, steps)
    }
}

fn question_json(question: &Question) -> QuestionJson {
    QuestionJson {
        name: question.name().to_fqdn(),
        qtype: record_type_name(question.qtype()),
        qclass: dns_class_name(question.qclass()),
    }
}

fn step_json((event_index, event): (usize, &Arc<ExecutionPathEvent>)) -> StepJson {
    StepJson {
        event_index,
        sequence_tag: event.sequence_tag.clone(),
        node_index: event.node_index,
        kind: event.kind.clone(),
        tag: event.tag.clone(),
        outcome: event.outcome.clone(),
    }
}

fn record_json(record: &Record) -> RecordJson {
    let (payload_kind, payload_text, payload) = rdata_payload(record.data());
    RecordJson {
        name: record.name().to_fqdn(),
        class: dns_class_name(record.class()),
        ttl: record.ttl(),
        rr_type: record_type_name(record.rr_type()),
        payload_kind,
        payload_text,
        payload,
    }
}

fn edns_json(edns: &Edns) -> EdnsJson {
    EdnsJson {
        udp_payload_size: edns.udp_payload_size(),
        ext_rcode: edns.ext_rcode(),
        version: edns.version(),
        dnssec_ok: edns.flags().dnssec_ok,
        z: edns.flags().z,
        options: edns.options().iter().map(edns_option_json).collect(),
    }
}

fn edns_option_json(option: &EdnsOption) -> EdnsOptionJson {
    let code = EdnsCode::from(option);
    let (payload_kind, payload) = match option {
        EdnsOption::Llq(value) => (
            "Llq".to_string(),
            json!({
                "version": value.version(),
                "opcode": value.opcode(),
                "error": value.error(),
                "id": value.id(),
                "lease_life": value.lease_life(),
            }),
        ),
        EdnsOption::UpdateLease(value) => (
            "UpdateLease".to_string(),
            json!({
                "lease": value.lease(),
                "key_lease": value.key_lease(),
            }),
        ),
        EdnsOption::Nsid(value) => (
            "Nsid".to_string(),
            json!({ "nsid_base64": STANDARD.encode(value.nsid()) }),
        ),
        EdnsOption::Esu(value) => (
            "Esu".to_string(),
            utf8_or_base64_payload("uri", value.uri()),
        ),
        EdnsOption::Dau(value) => (
            "Dau".to_string(),
            json!({ "algorithms": value.algorithms() }),
        ),
        EdnsOption::Dhu(value) => (
            "Dhu".to_string(),
            json!({ "algorithms": value.algorithms() }),
        ),
        EdnsOption::N3u(value) => (
            "N3u".to_string(),
            json!({ "algorithms": value.algorithms() }),
        ),
        EdnsOption::Subnet(value) => ("Subnet".to_string(), client_subnet_json(value)),
        EdnsOption::Expire(value) => (
            "Expire".to_string(),
            json!({
                "empty": value.is_empty(),
                "expire": (!value.is_empty()).then_some(value.expire()),
            }),
        ),
        EdnsOption::Cookie(value) => (
            "Cookie".to_string(),
            json!({ "cookie_base64": STANDARD.encode(value.cookie()) }),
        ),
        EdnsOption::TcpKeepalive(value) => (
            "TcpKeepalive".to_string(),
            json!({ "timeout": value.timeout() }),
        ),
        EdnsOption::Padding(value) => (
            "Padding".to_string(),
            json!({ "padding_base64": STANDARD.encode(value.padding()) }),
        ),
        EdnsOption::ExtendedDnsError(value) => (
            "ExtendedDnsError".to_string(),
            extended_dns_error_json(value),
        ),
        EdnsOption::ReportChannel(value) => (
            "ReportChannel".to_string(),
            json!({ "agent_domain": value.agent_domain().to_fqdn() }),
        ),
        EdnsOption::ZoneVersion(value) => (
            "ZoneVersion".to_string(),
            json!({
                "label_count": value.label_count(),
                "version_type": value.version_type(),
                "version_base64": STANDARD.encode(value.version()),
            }),
        ),
        EdnsOption::Local(value) => (
            "Local".to_string(),
            json!({
                "code": value.code(),
                "data_base64": STANDARD.encode(value.data()),
            }),
        ),
    };

    EdnsOptionJson {
        code: u16::from(code),
        name: edns_code_name(code),
        payload_kind,
        payload,
    }
}

fn client_subnet_json(value: &ClientSubnet) -> Value {
    json!({
        "addr": value.addr().to_string(),
        "source_prefix": value.source_prefix(),
        "scope_prefix": value.scope_prefix(),
    })
}

fn extended_dns_error_json(value: &EdnsExtendedDnsError) -> Value {
    let text = std::str::from_utf8(value.extra_text())
        .ok()
        .map(str::to_string);
    json!({
        "info_code": value.info_code(),
        "extra_text": text,
        "extra_text_base64": text.is_none().then(|| STANDARD.encode(value.extra_text())),
    })
}

fn rdata_payload(rdata: &RData) -> (String, String, Value) {
    match rdata {
        RData::A(value) => ip_payload("A", IpAddr::V4(value.0)),
        RData::AAAA(value) => ip_payload("AAAA", IpAddr::V6(value.0)),
        RData::CNAME(value) => name_payload("CNAME", "target", &value.0),
        RData::NS(value) => name_payload("NS", "target", &value.0),
        RData::PTR(value) => name_payload("PTR", "target", &value.0),
        RData::DNAME(value) => name_payload("DNAME", "target", &value.0),
        RData::MD(value) => name_payload("MD", "target", &value.0),
        RData::MF(value) => name_payload("MF", "target", &value.0),
        RData::MB(value) => name_payload("MB", "target", &value.0),
        RData::MG(value) => name_payload("MG", "target", &value.0),
        RData::MR(value) => name_payload("MR", "target", &value.0),
        RData::ANAME(value) => name_payload("ANAME", "target", &value.0),
        RData::NSAPPTR(value) => name_payload("NSAPPTR", "target", &value.0),
        RData::MX(value) => (
            "MX".to_string(),
            format!("{} {}", value.preference(), value.exchange().to_fqdn()),
            json!({
                "preference": value.preference(),
                "exchange": value.exchange().to_fqdn(),
            }),
        ),
        RData::KX(value) => (
            "KX".to_string(),
            format!("{} {}", value.preference(), value.exchanger().to_fqdn()),
            json!({
                "preference": value.preference(),
                "exchange": value.exchanger().to_fqdn(),
            }),
        ),
        RData::SRV(value) => (
            "SRV".to_string(),
            format!(
                "{} {} {} {}",
                value.priority(),
                value.weight(),
                value.port(),
                value.target().to_fqdn()
            ),
            json!({
                "priority": value.priority(),
                "weight": value.weight(),
                "port": value.port(),
                "target": value.target().to_fqdn(),
            }),
        ),
        RData::SOA(value) => soa_payload(value),
        RData::TXT(value) => txt_payload("TXT", value),
        RData::SPF(value) => txt_payload("SPF", &value.0),
        RData::CAA(value) => caa_payload(value),
        RData::URI(value) => uri_payload(value),
        RData::SVCB(value) => svcb_payload("SVCB", value),
        RData::HTTPS(value) => svcb_payload("HTTPS", &value.0),
        RData::RRSIG(value) => rrsig_payload("RRSIG", value),
        RData::SIG(value) => rrsig_payload("SIG", &value.0),
        RData::NSEC(value) => nsec_payload(value),
        RData::NSEC3(value) => nsec3_payload(value),
        RData::NSEC3PARAM(value) => nsec3param_payload(value),
        RData::DNSKEY(value) => dnskey_payload("DNSKEY", value),
        RData::CDNSKEY(value) => dnskey_payload("CDNSKEY", &value.0),
        RData::DS(value) => ds_payload("DS", value),
        RData::CDS(value) => ds_payload("CDS", &value.0),
        RData::DLV(value) => ds_payload("DLV", &value.0),
        RData::TA(value) => ds_payload("TA", &value.0),
        RData::TLSA(value) => tlsa_payload("TLSA", value),
        RData::SMIMEA(value) => tlsa_payload("SMIMEA", &value.0),
        RData::SSHFP(value) => sshfp_payload(value),
        RData::OPENPGPKEY(value) => (
            "OPENPGPKEY".to_string(),
            "OPENPGPKEY".to_string(),
            json!({ "public_key_base64": STANDARD.encode(&value.0) }),
        ),
        RData::NULL(value) => (
            "NULL".to_string(),
            "NULL".to_string(),
            json!({ "data_base64": STANDARD.encode(value.data()) }),
        ),
        RData::OPT(_) => ("OPT".to_string(), "OPT".to_string(), json!({})),
        RData::Unknown { rr_type, data } => (
            format!("TYPE{rr_type}"),
            format!("TYPE{rr_type}"),
            json!({
                "unknown_rr_type": rr_type,
                "data_base64": STANDARD.encode(data),
            }),
        ),
        other => (
            record_type_name(other.rr_type()),
            format!("{other:?}"),
            json!({ "display": format!("{other:?}") }),
        ),
    }
}

fn ip_payload(kind: &str, ip: IpAddr) -> (String, String, Value) {
    let ip = ip.to_string();
    (kind.to_string(), ip.clone(), json!({ "ip": ip }))
}

fn name_payload(kind: &str, field: &str, name: &crate::proto::Name) -> (String, String, Value) {
    let target = name.to_fqdn();
    (kind.to_string(), target.clone(), json!({ field: target }))
}

fn soa_payload(value: &SOA) -> (String, String, Value) {
    (
        "SOA".to_string(),
        format!("{} {}", value.mname().to_fqdn(), value.rname().to_fqdn()),
        json!({
            "mname": value.mname().to_fqdn(),
            "rname": value.rname().to_fqdn(),
            "serial": value.serial(),
            "refresh": value.refresh(),
            "retry": value.retry(),
            "expire": value.expire(),
            "minimum": value.minimum(),
        }),
    )
}

fn txt_payload(kind: &str, value: &TXT) -> (String, String, Value) {
    let mut strings = Vec::new();
    let mut parts = Vec::new();
    let mut all_utf8 = true;
    for part in value.txt_data() {
        match std::str::from_utf8(part) {
            Ok(text) => {
                strings.push(text.to_string());
                parts.push(json!({ "text": text }));
            }
            Err(_) => {
                all_utf8 = false;
                let encoded = STANDARD.encode(part);
                parts.push(json!({ "data_base64": encoded }));
            }
        }
    }

    let payload = if all_utf8 {
        json!({ "strings": strings })
    } else {
        json!({ "parts": parts })
    };

    let payload_text = if strings.is_empty() {
        kind.to_string()
    } else {
        strings.join(" ")
    };

    (kind.to_string(), payload_text, payload)
}

fn caa_payload(value: &CAA) -> (String, String, Value) {
    let tag = bytes_to_text_or_base64(value.tag());
    let caa_value = bytes_to_text_or_base64(value.value());
    (
        "CAA".to_string(),
        format!("{} {}", tag.text, caa_value.text),
        json!({
            "flag": value.flag(),
            "tag": tag.text_value,
            "tag_base64": tag.base64_value,
            "value": caa_value.text_value,
            "value_base64": caa_value.base64_value,
        }),
    )
}

fn uri_payload(value: &URI) -> (String, String, Value) {
    let target = bytes_to_text_or_base64(value.target());
    (
        "URI".to_string(),
        target.text.clone(),
        json!({
            "priority": value.priority(),
            "weight": value.weight(),
            "target": target.text_value,
            "target_base64": target.base64_value,
        }),
    )
}

fn svcb_payload(kind: &str, value: &SVCB) -> (String, String, Value) {
    let params = value
        .params()
        .iter()
        .map(|param| {
            json!({
                "key": param.key(),
                "name": svcb_param_name(param.key()),
                "value_base64": STANDARD.encode(param.value()),
                "parsed": svcb_param_value_json(param.parsed()),
            })
        })
        .collect::<Vec<_>>();

    (
        kind.to_string(),
        value.target().to_fqdn(),
        json!({
            "priority": value.priority(),
            "target": value.target().to_fqdn(),
            "params": params,
        }),
    )
}

fn rrsig_payload(kind: &str, value: &RRSIG) -> (String, String, Value) {
    (
        kind.to_string(),
        value.signer_name().to_fqdn(),
        json!({
            "type_covered": format_record_type_from_u16(value.type_covered()),
            "algorithm": value.algorithm(),
            "labels": value.labels(),
            "orig_ttl": value.orig_ttl(),
            "expiration": value.expiration(),
            "inception": value.inception(),
            "key_tag": value.key_tag(),
            "signer_name": value.signer_name().to_fqdn(),
            "signature_base64": STANDARD.encode(value.signature()),
        }),
    )
}

fn nsec_payload(value: &NSEC) -> (String, String, Value) {
    (
        "NSEC".to_string(),
        value.next_domain().to_fqdn(),
        json!({
            "next_domain": value.next_domain().to_fqdn(),
            "type_bitmap": value.type_bitmap_types().iter().map(|ty| record_type_name(*ty)).collect::<Vec<_>>(),
            "type_bitmap_base64": STANDARD.encode(value.type_bitmap()),
        }),
    )
}

fn nsec3_payload(value: &NSEC3) -> (String, String, Value) {
    (
        "NSEC3".to_string(),
        "NSEC3".to_string(),
        json!({
            "hash": value.hash(),
            "flags": value.flags(),
            "iterations": value.iterations(),
            "salt_base64": STANDARD.encode(value.salt()),
            "next_domain_base64": STANDARD.encode(value.next_domain()),
            "type_bitmap": value.type_bitmap_types().iter().map(|ty| record_type_name(*ty)).collect::<Vec<_>>(),
            "type_bitmap_base64": STANDARD.encode(value.type_bitmap()),
        }),
    )
}

fn nsec3param_payload(value: &NSEC3PARAM) -> (String, String, Value) {
    (
        "NSEC3PARAM".to_string(),
        "NSEC3PARAM".to_string(),
        json!({
            "hash": value.hash(),
            "flags": value.flags(),
            "iterations": value.iterations(),
            "salt_base64": STANDARD.encode(value.salt()),
        }),
    )
}

fn dnskey_payload(kind: &str, value: &DNSKEY) -> (String, String, Value) {
    (
        kind.to_string(),
        kind.to_string(),
        json!({
            "flags": value.flags(),
            "protocol": value.protocol(),
            "algorithm": value.algorithm(),
            "public_key_base64": STANDARD.encode(value.public_key()),
        }),
    )
}

fn ds_payload(kind: &str, value: &DS) -> (String, String, Value) {
    (
        kind.to_string(),
        kind.to_string(),
        json!({
            "key_tag": value.key_tag(),
            "algorithm": value.algorithm(),
            "digest_type": value.digest_type(),
            "digest_base64": STANDARD.encode(value.digest()),
        }),
    )
}

fn tlsa_payload(kind: &str, value: &TLSA) -> (String, String, Value) {
    (
        kind.to_string(),
        kind.to_string(),
        json!({
            "usage": value.usage(),
            "selector": value.selector(),
            "matching_type": value.matching_type(),
            "certificate_base64": STANDARD.encode(value.certificate()),
        }),
    )
}

fn sshfp_payload(value: &SSHFP) -> (String, String, Value) {
    (
        "SSHFP".to_string(),
        "SSHFP".to_string(),
        json!({
            "algorithm": value.algorithm(),
            "fp_type": value.fp_type(),
            "fingerprint_base64": STANDARD.encode(value.fingerprint()),
        }),
    )
}

fn utf8_or_base64_payload(field: &str, bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => json!({ field: text }),
        Err(_) => {
            let mut map = serde_json::Map::new();
            map.insert(
                format!("{field}_base64"),
                Value::String(STANDARD.encode(bytes)),
            );
            Value::Object(map)
        }
    }
}

#[derive(Debug)]
struct TextOrBase64 {
    text: String,
    text_value: Option<String>,
    base64_value: Option<String>,
}

fn bytes_to_text_or_base64(bytes: &[u8]) -> TextOrBase64 {
    match std::str::from_utf8(bytes) {
        Ok(text) => TextOrBase64 {
            text: text.to_string(),
            text_value: Some(text.to_string()),
            base64_value: None,
        },
        Err(_) => {
            let encoded = STANDARD.encode(bytes);
            TextOrBase64 {
                text: encoded.clone(),
                text_value: None,
                base64_value: Some(encoded),
            }
        }
    }
}

fn svcb_param_value_json(value: &rdata::SvcParamValue) -> Value {
    match value {
        rdata::SvcParamValue::Mandatory(values) => json!({ "mandatory": values }),
        rdata::SvcParamValue::Alpn(values) => json!({
            "alpn": values
                .iter()
                .map(|value| std::str::from_utf8(value).ok().map(str::to_string).unwrap_or_else(|| STANDARD.encode(value)))
                .collect::<Vec<_>>()
        }),
        rdata::SvcParamValue::NoDefaultAlpn => json!({ "no_default_alpn": true }),
        rdata::SvcParamValue::Port(port) => json!({ "port": port }),
        rdata::SvcParamValue::Ipv4Hint(values) => json!({
            "ipv4_hint": values.iter().map(ToString::to_string).collect::<Vec<_>>()
        }),
        rdata::SvcParamValue::Ech(value) => json!({ "ech_base64": STANDARD.encode(value) }),
        rdata::SvcParamValue::Ipv6Hint(values) => json!({
            "ipv6_hint": values.iter().map(ToString::to_string).collect::<Vec<_>>()
        }),
        rdata::SvcParamValue::DohPath(value) => match std::str::from_utf8(value) {
            Ok(text) => json!({ "doh_path": text }),
            Err(_) => json!({ "doh_path_base64": STANDARD.encode(value) }),
        },
        rdata::SvcParamValue::Ohttp => json!({ "ohttp": true }),
        rdata::SvcParamValue::Unknown => json!({ "unknown": true }),
    }
}

fn opcode_name(opcode: Opcode) -> String {
    opcode.to_string()
}

fn rcode_name(rcode: Rcode) -> String {
    match rcode {
        Rcode::Unknown(code) => format!("RCODE{code}"),
        _ => rcode.to_string(),
    }
}

fn dns_class_name(class: DNSClass) -> String {
    match class {
        DNSClass::Unknown(value) => format!("CLASS{value}"),
        DNSClass::OPT(value) => format!("OPT({value})"),
        _ => class.to_string(),
    }
}

fn format_record_type_from_u16(value: u16) -> String {
    record_type_name(RecordType::from(value))
}

fn record_type_name(record_type: RecordType) -> String {
    match record_type {
        RecordType::Unknown(value) => format!("TYPE{value}"),
        _ => record_type.to_string(),
    }
}

fn edns_code_name(code: EdnsCode) -> String {
    match code {
        EdnsCode::Reserved => "Reserved".to_string(),
        EdnsCode::Llq => "Llq".to_string(),
        EdnsCode::UpdateLease => "UpdateLease".to_string(),
        EdnsCode::Nsid => "Nsid".to_string(),
        EdnsCode::Esu => "Esu".to_string(),
        EdnsCode::Dau => "Dau".to_string(),
        EdnsCode::Dhu => "Dhu".to_string(),
        EdnsCode::N3u => "N3u".to_string(),
        EdnsCode::Subnet => "Subnet".to_string(),
        EdnsCode::Expire => "Expire".to_string(),
        EdnsCode::Cookie => "Cookie".to_string(),
        EdnsCode::TcpKeepalive => "TcpKeepalive".to_string(),
        EdnsCode::Padding => "Padding".to_string(),
        EdnsCode::Chain => "Chain".to_string(),
        EdnsCode::KeyTag => "KeyTag".to_string(),
        EdnsCode::ExtendedDnsError => "ExtendedDnsError".to_string(),
        EdnsCode::ClientTag => "ClientTag".to_string(),
        EdnsCode::ServerTag => "ServerTag".to_string(),
        EdnsCode::ReportChannel => "ReportChannel".to_string(),
        EdnsCode::ZoneVersion => "ZoneVersion".to_string(),
        EdnsCode::Unknown(value) => format!("Unknown({value})"),
    }
}

fn svcb_param_name(key: u16) -> &'static str {
    match key {
        0 => "mandatory",
        1 => "alpn",
        2 => "no-default-alpn",
        3 => "port",
        4 => "ipv4hint",
        5 => "ech",
        6 => "ipv6hint",
        7 => "dohpath",
        8 => "ohttp",
        _ => "unknown",
    }
}
