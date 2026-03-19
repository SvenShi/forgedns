use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use forgedns::message::{
    DNSClass, Message, MessageType, Opcode, Question, RData, Rcode, Record, RecordType,
    rdata::{self},
};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn forgedns_name(raw: &str) -> forgedns::message::Name {
    forgedns::message::Name::from_ascii(raw).expect("fixture name should be valid")
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
    edns.insert(rdata::EdnsOption::Unknown(65001, vec![1, 2, 3, 4]));
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

fn bench_message_encode_decode(c: &mut Criterion) {
    bench_case(c, "message_small_response", build_small_response_message());
    bench_case(
        c,
        "message_compression_heavy",
        build_compression_heavy_message(),
    );
    bench_case(c, "message_large_payload", build_large_payload_message());
    bench_case(c, "message_compat_fixture", build_compat_fixture_message());
}

criterion_group!(message_codec, bench_message_encode_decode);
criterion_main!(message_codec);
