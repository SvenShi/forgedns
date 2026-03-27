use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use forgedns::proto::{
    DNSClass, EdnsCode, EdnsOption, Message, MessageType, Opcode, Question, RData, Rcode, Record,
    RecordType,
    rdata::{self},
};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

fn forgedns_name(raw: &str) -> forgedns::proto::Name {
    forgedns::proto::Name::from_ascii(raw).expect("fixture name should be valid")
}

fn txt_wire(parts: &[&[u8]]) -> Box<[u8]> {
    let mut wire = Vec::new();
    for part in parts {
        assert!(
            part.len() <= u8::MAX as usize,
            "txt chunk must fit in one segment"
        );
        wire.push(part.len() as u8);
        wire.extend_from_slice(part);
    }
    wire.into_boxed_slice()
}

fn build_base_response(qname: &str, qtype: RecordType) -> Message {
    let mut message = Message::new();
    message.set_id(0x4242);
    message.set_message_type(MessageType::Response);
    message.set_opcode(Opcode::Query);
    message.set_authoritative(true);
    message.set_recursion_desired(true);
    message.set_recursion_available(true);
    message.set_authentic_data(true);
    message.set_checking_disabled(true);
    message.set_compress(true);
    message.add_question(Question::new(forgedns_name(qname), qtype, DNSClass::IN));
    message
}

fn add_standard_edns(message: &mut Message, payload_size: u16) {
    let mut edns = rdata::Edns::new();
    edns.set_udp_payload_size(payload_size);
    edns.set_dnssec_ok(true);
    edns.insert(rdata::EdnsOption::Subnet(rdata::ClientSubnet::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        24,
        0,
    )));

    edns.insert(rdata::EdnsOption::Local(rdata::EdnsLocal::new(
        65001,
        vec![1, 2, 3, 4],
    )));
    message.set_edns(edns);
}

fn build_small_response_message() -> Message {
    let mut message = build_base_response("example.com.", RecordType::A);
    message.add_answer(Record::from_rdata(
        forgedns_name("example.com."),
        300,
        RData::A(rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
    ));
    message
}

fn build_compression_heavy_message() -> Message {
    let mut message = build_base_response("service.prod.example.com.", RecordType::A);

    for idx in 0..12u8 {
        let owner = format!("edge-{idx}.service.prod.example.com.");
        let target = format!("pool-{idx}.service.prod.example.com.");
        message.add_answer(Record::from_rdata(
            forgedns_name(&owner),
            60,
            RData::CNAME(rdata::CNAME(forgedns_name(&target))),
        ));
        message.add_answer(Record::from_rdata(
            forgedns_name(&target),
            60,
            RData::A(rdata::A(Ipv4Addr::new(10, 0, 1, idx + 1))),
        ));
    }

    message.add_authority(Record::from_rdata(
        forgedns_name("prod.example.com."),
        300,
        RData::SOA(rdata::SOA::new(
            forgedns_name("ns1.prod.example.com."),
            forgedns_name("hostmaster.prod.example.com."),
            2026031901,
            7200,
            3600,
            1_209_600,
            300,
        )),
    ));

    add_standard_edns(&mut message, 1232);
    message.set_rcode(Rcode::NoError);
    message
}

fn build_large_payload_message() -> Message {
    let mut message = build_base_response("bulk.example.com.", RecordType::TXT);

    for idx in 0..8u8 {
        let owner = format!("chunk-{idx}.bulk.example.com.");
        message.add_answer(Record::from_rdata(
            forgedns_name(&owner),
            120,
            RData::TXT(rdata::TXT::new(txt_wire(&[
                b"forge-benchmark-payload-segment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                b"forge-benchmark-payload-segment-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                b"forge-benchmark-payload-segment-cccccccccccccccccccccccccccccccc",
            ]))),
        ));
    }

    message.add_answer(Record::from_rdata(
        forgedns_name("bulk.example.com."),
        120,
        RData::AAAA(rdata::AAAA(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42,
        ))),
    ));

    message.add_additional(Record::from_rdata(
        forgedns_name("bulk.example.com."),
        60,
        RData::MX(rdata::MX::new(10, forgedns_name("mail.bulk.example.com."))),
    ));

    add_standard_edns(&mut message, 4096);
    message.set_rcode(Rcode::BADCOOKIE);
    message
}

fn build_compat_fixture_message() -> Message {
    let mut message = build_base_response("example.com.", RecordType::A);
    message.set_opcode(Opcode::Update);

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
        RData::TXT(rdata::TXT::new(txt_wire(&[b"ForgeDNS", b"benchmark"]))),
    );
    chaos_txt.set_class(DNSClass::CH);
    message.add_additional(chaos_txt);

    add_standard_edns(&mut message, 1400);
    message.set_rcode(Rcode::BADCOOKIE);
    message
}

fn bench_case(c: &mut Criterion, name: &str, message: Message) {
    let encoded = message
        .to_bytes()
        .expect("fixture message should encode for decode benchmark");

    let mut group = c.benchmark_group(name);
    group.bench_with_input(
        BenchmarkId::new("encode", encoded.len()),
        &message,
        |b, message| {
            b.iter(|| {
                let bytes = message
                    .to_bytes()
                    .expect("message should encode during benchmark");
                black_box(bytes);
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("decode", encoded.len()),
        &encoded,
        |b, encoded| {
            b.iter(|| {
                let decoded = Message::from_bytes(black_box(encoded))
                    .expect("message should decode during benchmark");
                black_box(decoded);
            })
        },
    );
    group.finish();
}

fn build_query_with_edns() -> Message {
    let mut query = Message::new();
    query.set_id(0x5151);
    query.set_opcode(Opcode::Query);
    query.set_recursion_desired(true);
    query.add_question(Question::new(
        forgedns_name("bench.example.com."),
        RecordType::A,
        DNSClass::IN,
    ));

    let mut edns = rdata::Edns::new();
    edns.set_udp_payload_size(1400);
    edns.set_dnssec_ok(true);
    edns.insert(EdnsOption::Subnet(rdata::ClientSubnet::new(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
        24,
        0,
    )));
    edns.insert(EdnsOption::Local(rdata::EdnsLocal::new(
        65001,
        vec![1, 2, 3, 4, 5, 6],
    )));
    query.set_edns(edns);
    query
}

fn build_query_without_edns() -> Message {
    let mut query = Message::new();
    query.set_id(0x5152);
    query.set_opcode(Opcode::Query);
    query.set_recursion_desired(true);
    query.add_question(Question::new(
        forgedns_name("bench.example.com."),
        RecordType::A,
        DNSClass::IN,
    ));
    query
}

fn build_question(qname: &str, qtype: RecordType) -> Question {
    Question::new(forgedns_name(qname), qtype, DNSClass::IN)
}

fn bench_response_builders(c: &mut Criterion) {
    let query = build_query_with_edns();
    let query_without_edns = build_query_without_edns();
    let question_v4 = build_question("bench.example.com.", RecordType::A);
    let question_v6 = build_question("bench.example.com.", RecordType::AAAA);
    let v4_one = [Ipv4Addr::new(192, 0, 2, 10)];
    let v4_eight = [
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(192, 0, 2, 12),
        Ipv4Addr::new(192, 0, 2, 13),
        Ipv4Addr::new(192, 0, 2, 14),
        Ipv4Addr::new(192, 0, 2, 15),
        Ipv4Addr::new(192, 0, 2, 16),
        Ipv4Addr::new(192, 0, 2, 17),
    ];
    let v6_one = [Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)];
    let v6_eight = [
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x11),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x12),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x13),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x14),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x15),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x16),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x17),
    ];
    let v4_one_rdata = v4_one.map(|addr| Arc::new(RData::A(rdata::A(addr))));
    let v4_eight_rdata = v4_eight.map(|addr| Arc::new(RData::A(rdata::A(addr))));
    let v6_one_rdata = v6_one.map(|addr| Arc::new(RData::AAAA(rdata::AAAA(addr))));
    let v6_eight_rdata = v6_eight.map(|addr| Arc::new(RData::AAAA(rdata::AAAA(addr))));

    let mut group = c.benchmark_group("message_response_builders");
    group.bench_function("response_no_edns_single_question", |b| {
        b.iter(|| {
            let response = query_without_edns.response(Rcode::NoError);
            black_box(response);
        })
    });

    group.bench_function("response_with_edns_copy_only", |b| {
        b.iter(|| {
            let response = query.response(Rcode::NoError);
            black_box(response);
        })
    });

    group.bench_function("response_with_edns_copy_and_mutate", |b| {
        b.iter(|| {
            let mut response = query.response(Rcode::NoError);
            let edns = response.ensure_edns_mut();
            edns.set_udp_payload_size(4096);
            edns.flags_mut().z = 3;
            edns.remove(EdnsCode::Unknown(65001));
            edns.insert(EdnsOption::Local(rdata::EdnsLocal::new(
                65001,
                vec![9, 9, 9],
            )));
            black_box(response);
        })
    });

    group.bench_function("address_response_v4_1", |b| {
        b.iter(|| {
            let response = query
                .address_response_rdata(&question_v4, 60, &v4_one_rdata)
                .expect("address response should build");
            black_box(response);
        })
    });

    group.bench_function("address_response_v4_8", |b| {
        b.iter(|| {
            let response = query
                .address_response_rdata(&question_v4, 60, &v4_eight_rdata)
                .expect("address response should build");
            black_box(response);
        })
    });

    group.bench_function("address_response_v6_1", |b| {
        b.iter(|| {
            let response = query
                .address_response_rdata(&question_v6, 60, &v6_one_rdata)
                .expect("address response should build");
            black_box(response);
        })
    });

    group.bench_function("address_response_v6_8", |b| {
        b.iter(|| {
            let response = query
                .address_response_rdata(&question_v6, 60, &v6_eight_rdata)
                .expect("address response should build");
            black_box(response);
        })
    });

    group.bench_function("response_then_encode_a", |b| {
        b.iter(|| {
            let response = query
                .address_response_rdata(&question_v4, 60, &v4_one_rdata)
                .expect("address response should build");
            let encoded = response.to_bytes().expect("address response should encode");
            black_box(encoded);
        })
    });

    group.bench_function("response_then_encode_txt", |b| {
        b.iter(|| {
            let mut response = query.response(Rcode::NoError);
            response.add_answer(Record::from_rdata(
                forgedns_name("bench.example.com."),
                60,
                RData::TXT(rdata::TXT::new(txt_wire(&[
                    b"forge-benchmark-payload-segment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    b"forge-benchmark-payload-segment-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ]))),
            ));
            let encoded = response.to_bytes().expect("txt response should encode");
            black_box(encoded);
        })
    });
    group.finish();
}

fn bench_message_encode_decode(c: &mut Criterion) {
    bench_case(c, "message_small_response", build_small_response_message());
    bench_case(
        c,
        "message_compression_heavy",
        build_compression_heavy_message(),
    );
    bench_case(c, "message_large_payload", build_large_payload_message());
    bench_case(c, "message_compat_fixture", build_compat_fixture_message());
    bench_response_builders(c);
}

criterion_group!(message_codec, bench_message_encode_decode);
criterion_main!(message_codec);
