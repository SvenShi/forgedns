/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Global periodic task center.
//!
//! Unlike per-task ticker loops, this center uses one scheduler task to drive
//! all periodic jobs. This reduces long-lived task overhead and keeps lifecycle
//! control centralized in runtime.

use futures::stream::{FuturesUnordered, StreamExt};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};
use tracing::{error, warn};

type TaskFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type TaskFn = Arc<dyn Fn() -> TaskFuture + Send + Sync + 'static>;

enum Command {
    Register {
        id: u64,
        name: String,
        interval: Duration,
        task: TaskFn,
    },
    Remove {
        id: u64,
        ack: oneshot::Sender<()>,
    },
    RemoveDetached {
        id: u64,
    },
    StopAll {
        ack: oneshot::Sender<()>,
    },
}

struct ScheduledTask {
    name: String,
    interval: Duration,
    next_run: Instant,
    task: TaskFn,
    running: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ScheduledTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduledTask")
            .field("name", &self.name)
            .field("interval", &self.interval)
            .field("next_run", &self.next_run)
            .finish_non_exhaustive()
    }
}

/// Runtime-wide center for periodic background tasks.
#[derive(Debug)]
pub struct TaskCenter {
    next_id: AtomicU64,
    tx: mpsc::UnboundedSender<Command>,
}

impl TaskCenter {
    fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(run_scheduler(rx));
        Self {
            next_id: AtomicU64::new(1),
            tx,
        }
    }

    /// Register a fixed-interval task into the global scheduler.
    ///
    /// The first run happens after one full interval, and missed ticks use
    /// Skip behavior semantics (no burst catch-up).
    pub fn spawn_fixed<F, Fut>(&self, name: impl Into<String>, interval: Duration, task: F) -> u64
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let name = name.into();
        let task: TaskFn = Arc::new(move || Box::pin(task()));
        let _ = self.tx.send(Command::Register {
            id,
            name,
            interval,
            task,
        });
        id
    }

    /// Stop a previously registered task.
    pub async fn stop_task(&self, id: u64) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(Command::Remove { id, ack: ack_tx }).is_err() {
            return;
        }
        let _ = ack_rx.await;
    }

    /// Request task removal without waiting for acknowledgement.
    ///
    /// This is useful from synchronous drop paths where awaiting is impossible.
    pub fn stop_task_detached(&self, id: u64) {
        let _ = self.tx.send(Command::RemoveDetached { id });
    }

    /// Stop all managed tasks.
    pub async fn stop_all(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(Command::StopAll { ack: ack_tx }).is_err() {
            return;
        }
        let _ = ack_rx.await;
    }
}

async fn run_scheduler(mut rx: mpsc::UnboundedReceiver<Command>) {
    let mut tasks: HashMap<u64, ScheduledTask> = HashMap::new();
    let mut deadlines: BinaryHeap<Reverse<(Instant, u64)>> = BinaryHeap::new();

    loop {
        if tasks.is_empty() {
            let Some(cmd) = rx.recv().await else {
                break;
            };
            handle_command(cmd, &mut tasks, &mut deadlines).await;
            continue;
        }

        let Some(next_deadline) = next_deadline(&tasks, &mut deadlines) else {
            rebuild_deadlines(&tasks, &mut deadlines);
            continue;
        };

        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else {
                    break;
                };
                handle_command(cmd, &mut tasks, &mut deadlines).await;
            }
            _ = sleep_until(next_deadline) => {
                run_due_tasks(&mut tasks, &mut deadlines).await;
            }
        }
    }

    let mut running = Vec::new();
    for (_, mut task) in tasks.drain() {
        if let Some(handle) = task.running.take() {
            running.push((task.name, handle));
        }
    }
    stop_handles(running).await;
}

async fn handle_command(
    cmd: Command,
    tasks: &mut HashMap<u64, ScheduledTask>,
    deadlines: &mut BinaryHeap<Reverse<(Instant, u64)>>,
) {
    match cmd {
        Command::Register {
            id,
            name,
            interval,
            task,
        } => {
            let next_run = Instant::now() + interval;
            deadlines.push(Reverse((next_run, id)));
            tasks.insert(
                id,
                ScheduledTask {
                    name,
                    interval,
                    next_run,
                    task,
                    running: None,
                },
            );
        }
        Command::Remove { id, ack } => {
            if let Some(mut task) = tasks.remove(&id) {
                stop_running_task(&mut task).await;
            }
            let _ = ack.send(());
        }
        Command::RemoveDetached { id } => {
            if let Some(mut task) = tasks.remove(&id) {
                stop_running_task(&mut task).await;
            }
        }
        Command::StopAll { ack } => {
            let mut running = Vec::new();
            for (_, mut task) in tasks.drain() {
                if let Some(handle) = task.running.take() {
                    running.push((task.name, handle));
                }
            }
            deadlines.clear();
            stop_handles(running).await;
            let _ = ack.send(());
        }
    }
}

async fn run_due_tasks(
    tasks: &mut HashMap<u64, ScheduledTask>,
    deadlines: &mut BinaryHeap<Reverse<(Instant, u64)>>,
) {
    let now = Instant::now();
    let mut finished = Vec::new();
    let mut to_spawn = Vec::new();

    while let Some(deadline) = next_deadline(tasks, deadlines) {
        if deadline > now {
            break;
        }
        let Some(Reverse((_, id))) = deadlines.pop() else {
            break;
        };

        let mut spawn_entry: Option<(u64, TaskFn)> = None;
        if let Some(task) = tasks.get_mut(&id) {
            let mut next_run = task.next_run;
            while next_run <= now {
                next_run += task.interval;
            }
            task.next_run = next_run;
            deadlines.push(Reverse((task.next_run, id)));

            if task
                .running
                .as_ref()
                .is_some_and(|handle| handle.is_finished())
            {
                if let Some(handle) = task.running.take() {
                    finished.push((task.name.clone(), handle));
                }
            }

            if task.running.is_none() {
                spawn_entry = Some((id, task.task.clone()));
            }
        }

        if let Some(spawn_entry) = spawn_entry {
            to_spawn.push(spawn_entry);
        }
    }

    reap_finished_handles(finished).await;
    for (id, run) in to_spawn {
        if let Some(task) = tasks.get_mut(&id) {
            task.running = Some(tokio::spawn(async move {
                run().await;
            }));
        }
    }
}

fn next_deadline(
    tasks: &HashMap<u64, ScheduledTask>,
    deadlines: &mut BinaryHeap<Reverse<(Instant, u64)>>,
) -> Option<Instant> {
    loop {
        let Reverse((deadline, id)) = deadlines.peek()?.clone();
        match tasks.get(&id) {
            Some(task) if task.next_run == deadline => return Some(deadline),
            _ => {
                deadlines.pop();
            }
        }
    }
}

fn rebuild_deadlines(
    tasks: &HashMap<u64, ScheduledTask>,
    deadlines: &mut BinaryHeap<Reverse<(Instant, u64)>>,
) {
    deadlines.clear();
    for (id, task) in tasks {
        deadlines.push(Reverse((task.next_run, *id)));
    }
}

async fn reap_finished_handles(handles: Vec<(String, JoinHandle<()>)>) {
    for (name, handle) in handles {
        await_finished_handle(name, handle).await;
    }
}

async fn await_finished_handle(name: String, handle: JoinHandle<()>) {
    match handle.await {
        Ok(()) => {}
        Err(err) if err.is_cancelled() => {}
        Err(err) if err.is_panic() => {
            error!(task = %name, error = %err, "Periodic task panicked");
        }
        Err(err) => {
            warn!(task = %name, error = %err, "Periodic task exited unexpectedly");
        }
    }
}

async fn stop_running_task(task: &mut ScheduledTask) {
    if let Some(handle) = task.running.take() {
        stop_handle(task.name.clone(), handle).await;
    }
}

async fn stop_handle(name: String, handle: JoinHandle<()>) {
    handle.abort();
    await_finished_handle(name, handle).await;
}

async fn stop_handles(handles: Vec<(String, JoinHandle<()>)>) {
    if handles.is_empty() {
        return;
    }

    let mut waits = FuturesUnordered::new();
    for (name, handle) in handles {
        handle.abort();
        waits.push(async move {
            await_finished_handle(name, handle).await;
        });
    }

    while waits.next().await.is_some() {}
}

static GLOBAL_TASK_CENTER: OnceLock<TaskCenter> = OnceLock::new();

#[inline]
fn global_task_center() -> &'static TaskCenter {
    GLOBAL_TASK_CENTER.get_or_init(TaskCenter::new)
}

/// Register a fixed-interval task into the global runtime task center.
#[inline]
pub fn spawn_fixed<F, Fut>(name: impl Into<String>, interval: Duration, task: F) -> u64
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    global_task_center().spawn_fixed(name, interval, task)
}

/// Stop a previously registered global task.
#[inline]
pub async fn stop_task(id: u64) {
    global_task_center().stop_task(id).await;
}

/// Stop a previously registered global task from a synchronous path.
#[inline]
pub fn stop_task_detached(id: u64) {
    global_task_center().stop_task_detached(id);
}

/// Stop all tasks registered in the global runtime task center.
#[inline]
pub async fn stop_all() {
    global_task_center().stop_all().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::{Notify, oneshot};

    async fn wait_until(label: &str, condition: impl Fn() -> bool) {
        for _ in 0..128 {
            if condition() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("timed out waiting for {label}");
    }

    async fn flush_tasks() {
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    async fn advance_and_flush(duration: Duration) {
        tokio::time::advance(duration).await;
        flush_tasks().await;
    }

    #[tokio::test]
    async fn stop_task_waits_for_running_future_to_abort() {
        let center = TaskCenter::new();
        let (started_tx, started_rx) = oneshot::channel();
        let released = Arc::new(AtomicBool::new(false));
        let release_flag = released.clone();
        let started_tx = Arc::new(Mutex::new(Some(started_tx)));
        let started_tx_task = started_tx.clone();
        let blocker = Arc::new(Notify::new());
        let blocker_task = blocker.clone();

        let task_id = center.spawn_fixed("test", Duration::from_millis(10), move || {
            let blocker_task = blocker_task.clone();
            let release_flag = release_flag.clone();
            let started_tx_task = started_tx_task.clone();
            async move {
                struct DropFlag(Arc<AtomicBool>);
                impl Drop for DropFlag {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }

                let _drop_flag = DropFlag(release_flag);
                if let Some(started_tx) = started_tx_task
                    .lock()
                    .expect("started_tx mutex poisoned")
                    .take()
                {
                    let _ = started_tx.send(());
                }
                blocker_task.notified().await;
            }
        });

        started_rx.await.expect("task should start");
        center.stop_task(task_id).await;

        assert!(
            released.load(Ordering::Acquire),
            "running task should be aborted before stop_task returns"
        );
        blocker.notify_waiters();
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_task_does_not_overlap_and_skips_missed_ticks() {
        let center = TaskCenter::new();
        let overlap = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let blocker = Arc::new(Notify::new());
        let blocker_task = blocker.clone();
        let overlap_task = overlap.clone();
        let running_task = running.clone();
        let started_task = started.clone();

        let task_id = center.spawn_fixed("skip-test", Duration::from_millis(10), move || {
            let blocker_task = blocker_task.clone();
            let overlap_task = overlap_task.clone();
            let running_task = running_task.clone();
            let started_task = started_task.clone();
            async move {
                if running_task.fetch_add(1, Ordering::AcqRel) != 0 {
                    overlap_task.store(true, Ordering::Release);
                }
                started_task.fetch_add(1, Ordering::AcqRel);
                blocker_task.notified().await;
                running_task.fetch_sub(1, Ordering::AcqRel);
            }
        });

        flush_tasks().await;
        advance_and_flush(Duration::from_millis(10)).await;
        wait_until("first task start", || started.load(Ordering::Acquire) == 1).await;

        advance_and_flush(Duration::from_millis(100)).await;
        assert_eq!(
            started.load(Ordering::Acquire),
            1,
            "blocked periodic task should skip missed ticks instead of overlapping"
        );
        assert!(
            !overlap.load(Ordering::Acquire),
            "periodic task should never overlap with itself"
        );

        blocker.notify_waiters();
        wait_until("first task release", || {
            running.load(Ordering::Acquire) == 0
        })
        .await;

        advance_and_flush(Duration::from_millis(10)).await;
        wait_until("second task start", || started.load(Ordering::Acquire) == 2).await;

        center.stop_task(task_id).await;
        assert!(
            !overlap.load(Ordering::Acquire),
            "stop_task should not introduce overlapping executions"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stop_all_aborts_all_running_tasks_and_center_can_be_reused() {
        let center = TaskCenter::new();
        let blocker = Arc::new(Notify::new());
        let blocker_task_a = blocker.clone();
        let blocker_task_b = blocker.clone();
        let started = Arc::new(AtomicUsize::new(0));
        let started_task_a = started.clone();
        let started_task_b = started.clone();
        let released_a = Arc::new(AtomicBool::new(false));
        let released_b = Arc::new(AtomicBool::new(false));
        let released_task_a = released_a.clone();
        let released_task_b = released_b.clone();

        center.spawn_fixed("task-a", Duration::from_millis(10), move || {
            let blocker_task_a = blocker_task_a.clone();
            let started_task_a = started_task_a.clone();
            let released_task_a = released_task_a.clone();
            async move {
                struct DropFlag(Arc<AtomicBool>);
                impl Drop for DropFlag {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }

                let _drop_flag = DropFlag(released_task_a);
                started_task_a.fetch_add(1, Ordering::AcqRel);
                blocker_task_a.notified().await;
            }
        });
        center.spawn_fixed("task-b", Duration::from_millis(10), move || {
            let blocker_task_b = blocker_task_b.clone();
            let started_task_b = started_task_b.clone();
            let released_task_b = released_task_b.clone();
            async move {
                struct DropFlag(Arc<AtomicBool>);
                impl Drop for DropFlag {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }

                let _drop_flag = DropFlag(released_task_b);
                started_task_b.fetch_add(1, Ordering::AcqRel);
                blocker_task_b.notified().await;
            }
        });

        flush_tasks().await;
        advance_and_flush(Duration::from_millis(10)).await;
        wait_until("both tasks start", || started.load(Ordering::Acquire) == 2).await;

        center.stop_all().await;
        assert!(
            released_a.load(Ordering::Acquire) && released_b.load(Ordering::Acquire),
            "stop_all should abort every running task before returning"
        );

        let rerun_count = Arc::new(AtomicUsize::new(0));
        let rerun_count_task = rerun_count.clone();
        let rerun_id = center.spawn_fixed("task-c", Duration::from_millis(10), move || {
            let rerun_count_task = rerun_count_task.clone();
            async move {
                rerun_count_task.fetch_add(1, Ordering::AcqRel);
            }
        });

        flush_tasks().await;
        advance_and_flush(Duration::from_millis(10)).await;
        wait_until("task center reuse", || {
            rerun_count.load(Ordering::Acquire) == 1
        })
        .await;
        center.stop_task(rerun_id).await;
        blocker.notify_waiters();
    }

    #[tokio::test(start_paused = true)]
    async fn stop_task_detached_removes_only_target_task() {
        let center = TaskCenter::new();
        let stopped_count = Arc::new(AtomicUsize::new(0));
        let kept_count = Arc::new(AtomicUsize::new(0));
        let stopped_count_task = stopped_count.clone();
        let kept_count_task = kept_count.clone();

        let stopped_id = center.spawn_fixed("stopped", Duration::from_millis(10), move || {
            let stopped_count_task = stopped_count_task.clone();
            async move {
                stopped_count_task.fetch_add(1, Ordering::AcqRel);
            }
        });
        let kept_id = center.spawn_fixed("kept", Duration::from_millis(10), move || {
            let kept_count_task = kept_count_task.clone();
            async move {
                kept_count_task.fetch_add(1, Ordering::AcqRel);
            }
        });

        flush_tasks().await;
        advance_and_flush(Duration::from_millis(10)).await;
        wait_until("initial task runs", || {
            stopped_count.load(Ordering::Acquire) == 1 && kept_count.load(Ordering::Acquire) == 1
        })
        .await;

        center.stop_task_detached(stopped_id);
        flush_tasks().await;
        for expected in 2..=4 {
            advance_and_flush(Duration::from_millis(10)).await;
            wait_until("surviving task run", || {
                kept_count.load(Ordering::Acquire) == expected
            })
            .await;
            assert_eq!(
                stopped_count.load(Ordering::Acquire),
                1,
                "detached stop should remove only the targeted task"
            );
        }

        center.stop_task(kept_id).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stop_task_before_first_run_prevents_execution() {
        let center = TaskCenter::new();
        let started = Arc::new(AtomicUsize::new(0));
        let started_task = started.clone();

        let task_id = center.spawn_fixed("pending", Duration::from_millis(10), move || {
            let started_task = started_task.clone();
            async move {
                started_task.fetch_add(1, Ordering::AcqRel);
            }
        });

        flush_tasks().await;
        center.stop_task(task_id).await;
        advance_and_flush(Duration::from_millis(100)).await;

        assert_eq!(
            started.load(Ordering::Acquire),
            0,
            "stop_task should remove a pending task before its first scheduled run"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn panicked_task_is_reaped_and_rescheduled_on_next_tick() {
        let center = TaskCenter::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let successes = Arc::new(AtomicUsize::new(0));
        let attempts_task = attempts.clone();
        let successes_task = successes.clone();

        let task_id = center.spawn_fixed("panic-once", Duration::from_millis(10), move || {
            let attempts_task = attempts_task.clone();
            let successes_task = successes_task.clone();
            async move {
                let attempt = attempts_task.fetch_add(1, Ordering::AcqRel) + 1;
                if attempt == 1 {
                    panic!("intentional panic for scheduler recovery test");
                }
                successes_task.fetch_add(1, Ordering::AcqRel);
            }
        });

        flush_tasks().await;
        advance_and_flush(Duration::from_millis(10)).await;
        wait_until("first task attempt", || {
            attempts.load(Ordering::Acquire) == 1
        })
        .await;

        advance_and_flush(Duration::from_millis(10)).await;
        wait_until("second task attempt", || {
            attempts.load(Ordering::Acquire) == 2
        })
        .await;
        wait_until("successful rerun after panic", || {
            successes.load(Ordering::Acquire) == 1
        })
        .await;

        center.stop_task(task_id).await;
    }
}
