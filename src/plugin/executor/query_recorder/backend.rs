// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{error, warn};

use super::model::{PendingRecord, RecordDetail, ResolvedRecorderConfig, TableNames};
use super::store::{create_schema, open_database, run_writer_thread, table_names};
use crate::core::error::{DnsError, Result};

#[derive(Debug)]
pub(super) struct RecorderBackend {
    pub(super) tag: String,
    pub(super) path: PathBuf,
    pub(super) tables: TableNames,
    pub(super) queue_tx: SyncSender<WriterCommand>,
    pub(super) stop_requested: Arc<AtomicBool>,
    pub(super) writer_handle: Mutex<Option<JoinHandle<()>>>,
    pub(super) tail: Arc<Mutex<VecDeque<RecordDetail>>>,
    pub(super) memory_tail: usize,
    pub(super) broadcaster: broadcast::Sender<RecordDetail>,
    pub(super) dropped_total: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
pub(super) enum WriterCommand {
    Insert(Box<PendingRecord>),
    Cleanup { cutoff_ms: u64 },
}

#[derive(Debug)]
pub(super) struct WriterThreadContext {
    pub(super) tables: TableNames,
    pub(super) stop_requested: Arc<AtomicBool>,
    pub(super) tail: Arc<Mutex<VecDeque<RecordDetail>>>,
    pub(super) memory_tail: usize,
    pub(super) broadcaster: broadcast::Sender<RecordDetail>,
    pub(super) batch_size: usize,
    pub(super) flush_interval: Duration,
}

impl RecorderBackend {
    pub(super) fn run(tag: String, config: ResolvedRecorderConfig) -> Result<Arc<Self>> {
        if let Some(parent) = config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|err| {
                DnsError::plugin(format!(
                    "failed to create query_recorder directory '{}': {}",
                    parent.display(),
                    err
                ))
            })?;
        }

        let mut conn = open_database(&config.path).map_err(|err| {
            format!(
                "failed to open database '{}': {}",
                config.path.display(),
                err
            )
        })?;

        let tables = table_names(&tag);
        create_schema(&mut conn, &tables)?;

        let (queue_tx, queue_rx) = sync_channel(config.queue_size);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(
            config.memory_tail.max(1),
        )));
        let (broadcaster, _) = broadcast::channel(config.memory_tail.max(16));
        let dropped_total = Arc::new(AtomicU64::new(0));

        let writer_tables = tables.clone();
        let writer_stop = stop_requested.clone();
        let writer_tail = tail.clone();
        let writer_broadcaster = broadcaster.clone();
        let memory_tail = config.memory_tail.max(1);
        let batch_size = config.batch_size;
        let flush_interval = Duration::from_millis(config.flush_interval_ms);
        let writer_handle = thread::Builder::new()
            .name(format!("query-recorder-{}", tag))
            .spawn(move || {
                if let Err(err) = run_writer_thread(
                    WriterThreadContext {
                        tables: writer_tables,
                        stop_requested: writer_stop,
                        tail: writer_tail,
                        memory_tail,
                        broadcaster: writer_broadcaster,
                        batch_size,
                        flush_interval,
                    },
                    queue_rx,
                    conn,
                ) {
                    error!("query_recorder writer stopped: {}", err);
                }
            })?;

        Ok(Arc::new(Self {
            tag,
            path: config.path,
            tables,
            queue_tx,
            stop_requested,
            writer_handle: Mutex::new(Some(writer_handle)),
            tail,
            memory_tail,
            broadcaster,
            dropped_total,
        }))
    }

    pub(super) fn enqueue(&self, pending: PendingRecord) {
        if let Err(err) = self
            .queue_tx
            .try_send(WriterCommand::Insert(Box::new(pending)))
        {
            self.dropped_total.fetch_add(1, Ordering::Relaxed);
            warn!("query_recorder dropped record: {}", err);
        }
    }

    pub(super) fn cleanup(&self, cutoff_ms: u64) {
        if let Err(err) = self.queue_tx.try_send(WriterCommand::Cleanup { cutoff_ms }) {
            warn!("query_recorder cleanup skipped: {}", err);
        }
    }
}
