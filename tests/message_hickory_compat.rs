use forgedns::message::{
    DNSClass, Message, MessageType, Opcode, Question, RData, Rcode, Record, RecordType,
    rdata::{self, ClientSubnet, EdnsOption},
};
use hickory_proto::{
    op as hp_op, rr as hp_rr,
    serialize::binary::{BinDecodable, BinEncodable},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
struct MessageSnapshot {
    id: u16,
    message_type: u8,
    op_code: u8,
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authentic_data: bool,
    checking_disabled: bool,
    response_code: u16,
    questions: Vec<QuestionSnapshot>,
    answers: Vec<RecordSnapshot>,
    name_servers: Vec<RecordSnapshot>,
    additionals: Vec<RecordSnapshot>,
    edns: Option<EdnsSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuestionSnapshot {
    name: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordSnapshot {
    name: String,
    dns_class: u16,
    ttl: u32,
    data: RDataSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RDataSnapshot {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EdnsSnapshot {
    udp_payload_size: u16,
    ext_rcode: u8,
    version: u8,
    dnssec_ok: bool,
    options: Vec<EdnsOptionSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EdnsOptionSnapshot {
    Subnet {
        addr: IpAddr,
        source_prefix: u8,
        scope_prefix: u8,
    },
    Unknown {
        code: u16,
        data: Vec<u8>,
    },
}

fn fixture_snapshot() -> MessageSnapshot {
    MessageSnapshot {
        id: 0x4242,
        message_type: 1,
        op_code: 5,
        authoritative: true,
        truncated: false,
        recursion_desired: true,
        recursion_available: true,
        authentic_data: true,
        checking_disabled: true,
        response_code: 23,
        questions: vec![QuestionSnapshot {
            name: "example.com.".to_string(),
            qtype: 1,
            qclass: 1,
        }],
        answers: vec![
            RecordSnapshot {
                name: "example.com.".to_string(),
                dns_class: 1,
                ttl: 300,
                data: RDataSnapshot::A(Ipv4Addr::new(1, 1, 1, 1)),
            },
            RecordSnapshot {
                name: "example.com.".to_string(),
                dns_class: 1,
                ttl: 301,
                data: RDataSnapshot::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            },
            RecordSnapshot {
                name: "alias.example.com.".to_string(),
                dns_class: 1,
                ttl: 302,
                data: RDataSnapshot::Cname("target.example.com.".to_string()),
            },
            RecordSnapshot {
                name: "1.0.0.127.in-addr.arpa.".to_string(),
                dns_class: 1,
                ttl: 303,
                data: RDataSnapshot::Ptr("localhost.".to_string()),
            },
        ],
        name_servers: vec![
            RecordSnapshot {
                name: "example.com.".to_string(),
                dns_class: 1,
                ttl: 600,
                data: RDataSnapshot::Ns("ns1.example.com.".to_string()),
            },
            RecordSnapshot {
                name: "example.com.".to_string(),
                dns_class: 1,
                ttl: 601,
                data: RDataSnapshot::Soa {
                    mname: "ns1.example.com.".to_string(),
                    rname: "hostmaster.example.com.".to_string(),
                    serial: 2026031201,
                    refresh: 7200,
                    retry: 3600,
                    expire: 1_209_600,
                    minimum: 300,
                },
            },
        ],
        additionals: vec![
            RecordSnapshot {
                name: "example.com.".to_string(),
                dns_class: 1,
                ttl: 120,
                data: RDataSnapshot::Mx {
                    preference: 10,
                    exchange: "mail.example.com.".to_string(),
                },
            },
            RecordSnapshot {
                name: "version.bind.".to_string(),
                dns_class: 3,
                ttl: 0,
                data: RDataSnapshot::Txt(vec!["ForgeDNS".to_string(), "compat".to_string()]),
            },
        ],
        edns: Some(EdnsSnapshot {
            udp_payload_size: 1400,
            ext_rcode: 1,
            version: 0,
            dnssec_ok: true,
            options: vec![
                EdnsOptionSnapshot::Subnet {
                    addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                    source_prefix: 24,
                    scope_prefix: 0,
                },
                EdnsOptionSnapshot::Unknown {
                    code: 65001,
                    data: vec![1, 2, 3, 4],
                },
            ],
        }),
    }
}

fn forgedns_name(raw: &str) -> forgedns::message::Name {
    forgedns::message::Name::from_ascii(raw).expect("fixture name should be valid")
}

fn hickory_name(raw: &str) -> hp_rr::Name {
    hp_rr::Name::from_ascii(raw).expect("fixture name should be valid")
}

fn build_forgedns_fixture() -> Message {
    let mut message = Message::new();
    message.set_id(0x4242);
    message.set_message_type(MessageType::Response);
    message.set_opcode(Opcode::Update);
    message.set_authoritative(true);
    message.set_recursion_desired(true);
    message.set_recursion_available(true);
    message.set_authentic_data(true);
    message.set_checking_disabled(true);
    message.add_question(Question::new(
        forgedns_name("example.com."),
        RecordType::A,
        DNSClass::IN,
    ));

    message.add_answer(Record::from_rdata(
        forgedns_name("example.com."),
        300,
        RData::A(rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
    ));
    message.add_answer(Record::from_rdata(
        forgedns_name("example.com."),
        301,
        RData::AAAA(rdata::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
    ));
    message.add_answer(Record::from_rdata(
        forgedns_name("alias.example.com."),
        302,
        RData::CNAME(rdata::CNAME(forgedns_name("target.example.com."))),
    ));
    message.add_answer(Record::from_rdata(
        forgedns_name("1.0.0.127.in-addr.arpa."),
        303,
        RData::PTR(rdata::PTR(forgedns_name("localhost."))),
    ));

    message.add_authority(Record::from_rdata(
        forgedns_name("example.com."),
        600,
        RData::NS(rdata::NS(forgedns_name("ns1.example.com."))),
    ));
    message.add_authority(Record::from_rdata(
        forgedns_name("example.com."),
        601,
        RData::SOA(rdata::SOA::new(
            forgedns_name("ns1.example.com."),
            forgedns_name("hostmaster.example.com."),
            2026031201,
            7200,
            3600,
            1_209_600,
            300,
        )),
    ));

    message.add_additional(Record::from_rdata(
        forgedns_name("example.com."),
        120,
        RData::MX(rdata::MX::new(10, forgedns_name("mail.example.com."))),
    ));
    let mut chaos_txt = Record::from_rdata(
        forgedns_name("version.bind."),
        0,
        RData::TXT(rdata::TXT::new(txt_wire(&["ForgeDNS", "compat"]))),
    );
    chaos_txt.set_class(DNSClass::CH);
    message.add_additional(chaos_txt);

    let mut edns = rdata::Edns::new();
    edns.set_udp_payload_size(1400);
    edns.set_dnssec_ok(true);
    edns.insert(EdnsOption::Subnet(ClientSubnet::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        24,
        0,
    )));
    edns.insert(EdnsOption::Unknown(65001, vec![1, 2, 3, 4]));
    message.set_edns(edns);
    message.set_rcode(Rcode::BADCOOKIE);

    message
}

fn build_hickory_fixture() -> hp_op::Message {
    let mut message = hp_op::Message::new();
    message
        .set_id(0x4242)
        .set_message_type(hp_op::MessageType::Response)
        .set_op_code(hp_op::OpCode::Update)
        .set_authoritative(true)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_authentic_data(true)
        .set_checking_disabled(true)
        .set_response_code(hp_op::ResponseCode::BADCOOKIE)
        .add_query(hp_op::Query::query(
            hickory_name("example.com."),
            hp_rr::RecordType::A,
        ));

    message.add_answer(hp_rr::Record::from_rdata(
        hickory_name("example.com."),
        300,
        hp_rr::RData::A(hp_rr::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
    ));
    message.add_answer(hp_rr::Record::from_rdata(
        hickory_name("example.com."),
        301,
        hp_rr::RData::AAAA(hp_rr::rdata::AAAA(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
        ))),
    ));
    message.add_answer(hp_rr::Record::from_rdata(
        hickory_name("alias.example.com."),
        302,
        hp_rr::RData::CNAME(hp_rr::rdata::CNAME(hickory_name("target.example.com."))),
    ));
    message.add_answer(hp_rr::Record::from_rdata(
        hickory_name("1.0.0.127.in-addr.arpa."),
        303,
        hp_rr::RData::PTR(hp_rr::rdata::PTR(hickory_name("localhost."))),
    ));

    message.add_name_server(hp_rr::Record::from_rdata(
        hickory_name("example.com."),
        600,
        hp_rr::RData::NS(hp_rr::rdata::NS(hickory_name("ns1.example.com."))),
    ));
    message.add_name_server(hp_rr::Record::from_rdata(
        hickory_name("example.com."),
        601,
        hp_rr::RData::SOA(hp_rr::rdata::SOA::new(
            hickory_name("ns1.example.com."),
            hickory_name("hostmaster.example.com."),
            2026031201,
            7200,
            3600,
            1_209_600,
            300,
        )),
    ));

    message.add_additional(hp_rr::Record::from_rdata(
        hickory_name("example.com."),
        120,
        hp_rr::RData::MX(hp_rr::rdata::MX::new(10, hickory_name("mail.example.com."))),
    ));
    let mut chaos_txt = hp_rr::Record::from_rdata(
        hickory_name("version.bind."),
        0,
        hp_rr::RData::TXT(hp_rr::rdata::TXT::new(vec![
            "ForgeDNS".to_string(),
            "compat".to_string(),
        ])),
    );
    chaos_txt.set_dns_class(hp_rr::DNSClass::CH);
    message.add_additional(chaos_txt);

    let mut edns = hp_op::Edns::new();
    edns.set_max_payload(1400);
    edns.set_dnssec_ok(true);
    edns.set_rcode_high(hp_op::ResponseCode::BADCOOKIE.high());
    edns.options_mut()
        .insert(hp_rr::rdata::opt::EdnsOption::Subnet(
            hp_rr::rdata::opt::ClientSubnet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 0),
        ));
    edns.options_mut()
        .insert(hp_rr::rdata::opt::EdnsOption::Unknown(
            65001,
            vec![1, 2, 3, 4],
        ));
    message.set_edns(edns);

    message
}

fn snapshot_forgedns_message(message: &Message) -> MessageSnapshot {
    MessageSnapshot {
        id: message.id(),
        message_type: match message.message_type() {
            MessageType::Query => 0,
            MessageType::Response => 1,
        },
        op_code: u8::from(message.opcode()),
        authoritative: message.authoritative(),
        truncated: message.truncated(),
        recursion_desired: message.recursion_desired(),
        recursion_available: message.recursion_available(),
        authentic_data: message.authentic_data(),
        checking_disabled: message.checking_disabled(),
        response_code: u16::from(message.rcode()),
        questions: message
            .questions()
            .iter()
            .map(|question| QuestionSnapshot {
                name: question.name().to_fqdn(),
                qtype: u16::from(question.qtype()),
                qclass: u16::from(question.qclass()),
            })
            .collect(),
        answers: message
            .answers()
            .iter()
            .map(snapshot_forgedns_record)
            .collect(),
        name_servers: message
            .authorities()
            .iter()
            .map(snapshot_forgedns_record)
            .collect(),
        additionals: message
            .additionals()
            .iter()
            .map(snapshot_forgedns_record)
            .collect(),
        edns: message.edns().as_ref().map(snapshot_forgedns_edns),
    }
}

fn snapshot_forgedns_record(record: &Record) -> RecordSnapshot {
    RecordSnapshot {
        name: record.name().to_fqdn(),
        dns_class: u16::from(record.class()),
        ttl: record.ttl(),
        data: snapshot_forgedns_rdata(record.data()),
    }
}

fn snapshot_forgedns_rdata(data: &RData) -> RDataSnapshot {
    match data {
        RData::A(rdata::A(addr)) => RDataSnapshot::A(*addr),
        RData::AAAA(rdata::AAAA(addr)) => RDataSnapshot::Aaaa(*addr),
        RData::CNAME(value) => RDataSnapshot::Cname(value.0.to_fqdn()),
        RData::NS(value) => RDataSnapshot::Ns(value.0.to_fqdn()),
        RData::PTR(value) => RDataSnapshot::Ptr(value.0.to_fqdn()),
        RData::MX(value) => RDataSnapshot::Mx {
            preference: value.preference(),
            exchange: value.exchange().to_fqdn(),
        },
        RData::TXT(value) => RDataSnapshot::Txt(
            value
                .txt_data_utf8()
                .map(|part| part.expect("fixture txt chunk should be utf-8").to_string())
                .collect(),
        ),
        RData::SOA(value) => RDataSnapshot::Soa {
            mname: value.mname().to_fqdn(),
            rname: value.rname().to_fqdn(),
            serial: value.serial(),
            refresh: value.refresh(),
            retry: value.retry(),
            expire: value.expire(),
            minimum: value.minimum(),
        },
        other => panic!("unexpected forgedns rdata in fixture: {other:?}"),
    }
}

fn snapshot_forgedns_edns(edns: &rdata::Edns) -> EdnsSnapshot {
    EdnsSnapshot {
        udp_payload_size: edns.udp_payload_size(),
        ext_rcode: edns.ext_rcode(),
        version: edns.version(),
        dnssec_ok: edns.flags().dnssec_ok,
        options: edns
            .options()
            .iter()
            .map(snapshot_forgedns_edns_option)
            .collect(),
    }
}

fn snapshot_forgedns_edns_option(option: &EdnsOption) -> EdnsOptionSnapshot {
    match option {
        EdnsOption::Subnet(value) => EdnsOptionSnapshot::Subnet {
            addr: value.addr(),
            source_prefix: value.source_prefix(),
            scope_prefix: value.scope_prefix(),
        },
        EdnsOption::Unknown(code, data) => EdnsOptionSnapshot::Unknown {
            code: *code,
            data: data.clone(),
        },
    }
}

fn snapshot_hickory_message(message: &hp_op::Message) -> MessageSnapshot {
    MessageSnapshot {
        id: message.id(),
        message_type: match message.message_type() {
            hp_op::MessageType::Query => 0,
            hp_op::MessageType::Response => 1,
        },
        op_code: u8::from(message.op_code()),
        authoritative: message.authoritative(),
        truncated: message.truncated(),
        recursion_desired: message.recursion_desired(),
        recursion_available: message.recursion_available(),
        authentic_data: message.authentic_data(),
        checking_disabled: message.checking_disabled(),
        response_code: u16::from(message.response_code()),
        questions: message
            .queries()
            .iter()
            .map(|question| QuestionSnapshot {
                name: question.name().to_ascii(),
                qtype: u16::from(question.query_type()),
                qclass: u16::from(question.query_class()),
            })
            .collect(),
        answers: message
            .answers()
            .iter()
            .map(snapshot_hickory_record)
            .collect(),
        name_servers: message
            .name_servers()
            .iter()
            .map(snapshot_hickory_record)
            .collect(),
        additionals: message
            .additionals()
            .iter()
            .map(snapshot_hickory_record)
            .collect(),
        edns: message.extensions().as_ref().map(snapshot_hickory_edns),
    }
}

fn snapshot_hickory_record(record: &hp_rr::Record) -> RecordSnapshot {
    RecordSnapshot {
        name: record.name().to_ascii(),
        dns_class: u16::from(record.dns_class()),
        ttl: record.ttl(),
        data: snapshot_hickory_rdata(record.data()),
    }
}

fn snapshot_hickory_rdata(data: &hp_rr::RData) -> RDataSnapshot {
    match data {
        hp_rr::RData::A(value) => RDataSnapshot::A(value.0),
        hp_rr::RData::AAAA(value) => RDataSnapshot::Aaaa(value.0),
        hp_rr::RData::CNAME(value) => RDataSnapshot::Cname(value.0.to_ascii()),
        hp_rr::RData::NS(value) => RDataSnapshot::Ns(value.0.to_ascii()),
        hp_rr::RData::PTR(value) => RDataSnapshot::Ptr(value.0.to_ascii()),
        hp_rr::RData::MX(value) => RDataSnapshot::Mx {
            preference: value.preference(),
            exchange: value.exchange().to_ascii(),
        },
        hp_rr::RData::TXT(value) => RDataSnapshot::Txt(
            value
                .iter()
                .map(|part| {
                    String::from_utf8(part.to_vec()).expect("fixture txt chunk should be utf-8")
                })
                .collect(),
        ),
        hp_rr::RData::SOA(value) => RDataSnapshot::Soa {
            mname: value.mname().to_ascii(),
            rname: value.rname().to_ascii(),
            serial: value.serial(),
            refresh: value.refresh(),
            retry: value.retry(),
            expire: value.expire(),
            minimum: value.minimum(),
        },
        other => panic!("unexpected hickory rdata in fixture: {other:?}"),
    }
}

fn snapshot_hickory_edns(edns: &hp_op::Edns) -> EdnsSnapshot {
    EdnsSnapshot {
        udp_payload_size: edns.max_payload(),
        ext_rcode: edns.rcode_high(),
        version: edns.version(),
        dnssec_ok: edns.flags().dnssec_ok,
        options: edns
            .options()
            .as_ref()
            .iter()
            .map(|(_, option)| snapshot_hickory_edns_option(option))
            .collect(),
    }
}

fn snapshot_hickory_edns_option(option: &hp_rr::rdata::opt::EdnsOption) -> EdnsOptionSnapshot {
    match option {
        hp_rr::rdata::opt::EdnsOption::Subnet(value) => EdnsOptionSnapshot::Subnet {
            addr: value.addr(),
            source_prefix: value.source_prefix(),
            scope_prefix: value.scope_prefix(),
        },
        hp_rr::rdata::opt::EdnsOption::Unknown(code, data) => EdnsOptionSnapshot::Unknown {
            code: *code,
            data: data.clone(),
        },
        other => panic!("unexpected hickory edns option in fixture: {other:?}"),
    }
}

fn txt_wire(parts: &[&str]) -> Box<[u8]> {
    let mut wire = Vec::new();
    for part in parts {
        let bytes = part.as_bytes();
        wire.push(u8::try_from(bytes.len()).expect("fixture txt chunk should fit in u8"));
        wire.extend_from_slice(bytes);
    }
    wire.into_boxed_slice()
}

#[test]
fn forgedns_fixture_roundtrip_matches_hickory_decode() {
    let message = build_forgedns_fixture();
    let expected = fixture_snapshot();

    assert_eq!(snapshot_forgedns_message(&message), expected);

    let bytes = message.to_bytes().expect("forgedns fixture should encode");
    let hickory = hp_op::Message::from_bytes(&bytes).expect("hickory should decode forgedns bytes");
    let decoded = Message::from_bytes(&bytes).expect("forgedns should decode its own bytes");

    assert_eq!(snapshot_hickory_message(&hickory), fixture_snapshot());
    assert_eq!(snapshot_forgedns_message(&decoded), fixture_snapshot());
}

#[test]
fn hickory_fixture_roundtrip_matches_forgedns_decode() {
    let hickory = build_hickory_fixture();
    let bytes = hickory.to_bytes().expect("hickory fixture should encode");
    let decoded = Message::from_bytes(&bytes).expect("forgedns should decode hickory bytes");

    assert_eq!(snapshot_hickory_message(&hickory), fixture_snapshot());
    assert_eq!(snapshot_forgedns_message(&decoded), fixture_snapshot());
    assert_eq!(decoded.question_count(), 1);
    assert_eq!(decoded.max_payload(), 1400);
}

#[test]
fn hickory_fixture_reencode_preserves_semantics() {
    let hickory = build_hickory_fixture();
    let bytes = hickory.to_bytes().expect("hickory fixture should encode");
    let decoded = Message::from_bytes(&bytes).expect("forgedns should decode hickory bytes");
    let reencoded = decoded
        .to_bytes()
        .expect("forgedns should re-encode fixture");

    let hickory_roundtrip =
        hp_op::Message::from_bytes(&reencoded).expect("hickory should decode forgedns bytes");
    let decoded_roundtrip =
        Message::from_bytes(&reencoded).expect("forgedns should decode its own re-encoding");

    assert_eq!(
        snapshot_hickory_message(&hickory_roundtrip),
        fixture_snapshot()
    );
    assert_eq!(
        snapshot_forgedns_message(&decoded_roundtrip),
        fixture_snapshot()
    );
}
