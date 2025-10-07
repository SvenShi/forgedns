/*
 * Copyright 2025 Sven Shi
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use dashmap::DashMap;
use hickory_proto::op::Message;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::sync::oneshot::Sender;

/// the dns request map
#[derive(Debug)]
pub(crate) struct RequestMap {
    current_id: AtomicU16,
    requests: DashMap<u16, Sender<Message>>,
}

#[allow(unused)]
impl RequestMap {
    pub fn new() -> Self {
        Self {
            current_id: AtomicU16::new(0),
            requests: DashMap::with_capacity(65535),
        }
    }

    pub fn store(&self, tx: Sender<Message>) -> u16 {
        let query_id = self.next_id();
        self.requests.insert(query_id, tx);
        query_id
    }

    pub fn next_id(&self) -> u16 {
        for _ in 0..65535 {
            let id = self
                .current_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if !self.requests.contains_key(&id) {
                return id;
            }
        }
        panic!("RequestMap exhausted all IDs");
    }

    pub fn current_id(&self) -> u16 {
        self.current_id.load(Ordering::Relaxed)
    }

    pub fn insert(&self, id: u16, tx: Sender<Message>) {
        self.requests.insert(id, tx);
    }

    pub fn remove(&self, id: &u16) -> Option<(u16, Sender<Message>)> {
        self.requests.remove(id)
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }
}
