// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tempfile::NamedTempFile;

use super::model::{ListQuery, PendingRecord, QueryRecorderConfig};
use super::store::{query_records, table_names};
use super::{QueryRecorder, QueryRecorderFactory, resolve_config};
use crate::core::app_clock::AppClock;
use crate::core::context::{DnsContext, ExecutionPathEvent};
use crate::core::error::DnsError;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::test_utils::{test_context, test_registry};
use crate::plugin::{Plugin, PluginFactory};
use crate::proto::rdata::{A, CNAME};
use crate::proto::{DNSClass, Message, Name, Question, RData, Rcode, Record, RecordType};

#[test]
fn test_table_names_include_tag_hash_and_version() {
    let tables = table_names("Recorder.Main");
    assert!(tables.records.starts_with("qr_recorder_main_"));
    assert!(tables.records.ends_with("_v1_records"));
    assert!(tables.steps.ends_with("_v1_steps"));
}

#[test]
fn test_record_capture_without_response_uses_empty_sections() {
    let mut ctx = test_context();
    let mut request = Message::new();
    request.set_id(7);
    request.set_recursion_desired(true);
    request.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
        DNSClass::IN,
    ));

    ctx.enable_execution_path();
    ctx.push_execution_path_event(ExecutionPathEvent::new(
        "seq",
        Some(0),
        "executor",
        Some("query_recorder"),
        "entered",
    ));

    let pending = PendingRecord::new(
        request,
        ctx.response.clone(),
        100,
        10,
        ctx.execution_path.clone(),
        0,
        ctx.peer_addr(),
        Some(DnsError::plugin("boom").to_string()),
    );
    let (record, steps) = pending.take_to_record();

    assert!(!record.has_response);
    assert_eq!(record.answer_count, 0);
    assert!(record.answers_json.is_empty());
    assert!(
        record
            .error
            .as_deref()
            .is_some_and(|value| value.contains("boom"))
    );
    assert_eq!(steps.len(), 1);
}

#[test]
fn test_record_capture_with_structured_response() {
    let mut ctx = test_context();
    let mut request = Message::new();
    request.set_id(9);
    request.add_question(Question::new(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
        DNSClass::IN,
    ));

    let mut response = request.response(Rcode::NoError);
    response.set_authoritative(true);
    response.set_recursion_available(true);
    response.add_answer(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        300,
        RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
    ));
    response.add_authority(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        60,
        RData::CNAME(CNAME(Name::from_ascii("alias.example.com.").unwrap())),
    ));
    ctx.set_response(response);
    ctx.enable_execution_path();

    let pending = PendingRecord::new(
        request,
        ctx.response.clone(),
        100,
        12,
        ctx.execution_path.clone(),
        0,
        ctx.peer_addr(),
        None,
    );
    let (record, _) = pending.take_to_record();

    assert!(record.has_response);
    assert_eq!(record.answer_count, 1);
    assert_eq!(record.authority_count, 1);
    assert_eq!(record.answers_json[0].payload_kind, "A");
    assert_eq!(record.authorities_json[0].payload_kind, "CNAME");
}

#[tokio::test]
async fn test_query_recorder_execute_enqueues_record() {
    AppClock::start();

    let temp = NamedTempFile::new().unwrap();
    let config = resolve_config(Some(
        serde_yaml_ng::to_value(QueryRecorderConfig {
            path: temp.path().display().to_string(),
            queue_size: Some(16),
            batch_size: Some(1),
            flush_interval_ms: Some(10),
            memory_tail: Some(8),
            retention_days: Some(7),
            cleanup_interval_hours: Some(1),
        })
        .unwrap(),
    ))
    .unwrap();

    let mut plugin = QueryRecorder::new("rec".to_string(), config.clone(), None);
    plugin.init().await.unwrap();

    let mut ctx = DnsContext::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
        Message::new(),
        test_registry(),
    );
    let step = plugin.execute_with_next(&mut ctx, None).await.unwrap();
    assert_eq!(step, ExecStep::Next);

    tokio::time::sleep(Duration::from_millis(30)).await;
    let backend = plugin.backend.as_ref().unwrap().clone();
    let records = tokio::task::spawn_blocking(move || {
        query_records(
            backend,
            ListQuery {
                cursor: None,
                limit: 10,
                since_ms: None,
                until_ms: None,
            },
        )
    })
    .await
    .unwrap()
    .unwrap()
    .0;
    assert_eq!(records.len(), 1);

    plugin.destroy().await.unwrap();
}

#[tokio::test]
async fn test_query_recorder_list_cursor_only_when_more_records_exist() {
    AppClock::start();

    let temp = NamedTempFile::new().unwrap();
    let config = resolve_config(Some(
        serde_yaml_ng::to_value(QueryRecorderConfig {
            path: temp.path().display().to_string(),
            queue_size: Some(16),
            batch_size: Some(1),
            flush_interval_ms: Some(10),
            memory_tail: Some(8),
            retention_days: Some(7),
            cleanup_interval_hours: Some(1),
        })
        .unwrap(),
    ))
    .unwrap();

    let mut plugin = QueryRecorder::new("rec".to_string(), config.clone(), None);
    plugin.init().await.unwrap();

    for request_id in 1..=3 {
        let mut request = Message::new();
        request.set_id(request_id);
        let mut ctx = DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        );
        plugin.execute_with_next(&mut ctx, None).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(30)).await;
    let backend = plugin.backend.as_ref().unwrap().clone();
    let (first_page, first_cursor) = tokio::task::spawn_blocking(move || {
        query_records(
            backend,
            ListQuery {
                cursor: None,
                limit: 2,
                since_ms: None,
                until_ms: None,
            },
        )
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(first_page.len(), 2);
    assert!(first_cursor.is_some());

    let cursor_record = first_page.last().unwrap();
    let backend = plugin.backend.as_ref().unwrap().clone();
    let (second_page, second_cursor) = tokio::task::spawn_blocking({
        let cursor = super::model::ListCursor {
            created_at_ms: cursor_record.created_at_ms,
            id: cursor_record.id,
        };
        move || {
            query_records(
                backend,
                ListQuery {
                    cursor: Some(cursor),
                    limit: 2,
                    since_ms: None,
                    until_ms: None,
                },
            )
        }
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(second_page.len(), 1);
    assert!(second_cursor.is_none());

    plugin.destroy().await.unwrap();
}

#[test]
fn test_factory_rejects_quick_setup() {
    let factory = QueryRecorderFactory;
    let err = match factory.quick_setup("rec", None, test_registry()) {
        Ok(_) => panic!("quick setup should be rejected"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("quick setup"));
}

#[test]
fn test_resolve_config_rejects_zero_limits() {
    let config = serde_yaml_ng::to_value(QueryRecorderConfig {
        path: "test.db".to_string(),
        queue_size: Some(0),
        batch_size: Some(1),
        flush_interval_ms: Some(1),
        memory_tail: Some(1),
        retention_days: Some(1),
        cleanup_interval_hours: Some(1),
    })
    .unwrap();
    assert!(resolve_config(Some(config)).is_err());
}
