use hickory_proto::xfer::DnsResponse;
use rand::random;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU16, Ordering};
use tokio::sync::oneshot::Sender;

const MAX_IDS: usize = u16::MAX as usize;

#[derive(Debug)]
pub struct RequestMap {
    slots: Vec<AtomicPtr<Sender<DnsResponse>>>,
    size: AtomicU16,
}

impl RequestMap {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(MAX_IDS);
        for _ in 0..MAX_IDS + 1 {
            slots.push(AtomicPtr::new(ptr::null_mut()));
        }
        Self {
            slots,
            size: AtomicU16::new(0),
        }
    }

    #[inline(always)]
    pub fn store(&self, tx: Sender<DnsResponse>) -> u16 {
        let ptr = Box::into_raw(Box::new(tx));

        loop {
            let id = random::<u16>() as usize;
            // 尝试 CAS 插入空槽
            if self.slots[id]
                .compare_exchange(ptr::null_mut(), ptr, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.size.fetch_add(1, Ordering::Relaxed);
                return id as u16;
            }
        }
    }

    #[inline(always)]
    pub fn take(&self, id: u16) -> Option<Sender<DnsResponse>> {
        let slot = &self.slots[id as usize];
        let ptr = slot.swap(ptr::null_mut(), Ordering::AcqRel);
        if ptr.is_null() {
            None
        } else {
            self.size.fetch_sub(1, Ordering::Relaxed);
            unsafe { Some(*Box::from_raw(ptr)) }
        }
    }

    pub fn size(&self) -> u16 {
        self.size.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.size.load(Ordering::Relaxed) == 0
    }
}

#[cfg(test)]
mod test {
    use crate::pkg::upstream::request_map::RequestMap;
    use hickory_proto::xfer::DnsResponse;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::task::JoinSet;
    use tokio::time::{Instant, sleep};

    #[tokio::test]
    async fn test() {
        for i in 0..5 {
            let map = Arc::new(RequestMap::new());
            let mut set = JoinSet::new();
            for _ in 0..1000 {
                let map = map.clone();
                set.spawn(async move {
                    let mut nanos = 0;
                    for _ in 0..100 {
                        let sender = tokio::sync::oneshot::channel::<DnsResponse>();
                        let instant = Instant::now();
                        let id = map.store(sender.0);
                        nanos += instant.elapsed().as_nanos();
                        sleep(Duration::from_millis(30)).await;
                        map.take(id);
                    }
                    nanos / 100
                });
            }
            println!(
                "avg store using time {}ns",
                set.join_all().await.iter().sum::<u128>() / 1000
            )
        }

        for i in 0..5 {
            let map = Arc::new(RequestMap::new());
            let mut set = JoinSet::new();
            for _ in 0..1000 {
                let map = map.clone();
                set.spawn(async move {
                    let mut nanos = 0;
                    for _ in 0..100 {
                        let sender = tokio::sync::oneshot::channel::<DnsResponse>();
                        let id = map.store(sender.0);
                        sleep(Duration::from_millis(30)).await;
                        let instant = Instant::now();
                        map.take(id);
                        nanos += instant.elapsed().as_nanos();
                    }
                    nanos / 100
                });
            }
            println!(
                "avg take using time {}ns",
                set.join_all().await.iter().sum::<u128>() / 1000
            )
        }
    }
}
