use anyhow::Context;
use lru::LruCache;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use state::InitCell;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::sync::{Mutex, MutexGuard, Notify};

pub struct StoreItem {
    pub ip: Ipv4Packet<'static>,
    pub tcp: TcpPacket<'static>,
}

type K = String;
type V = Arc<(Notify, Mutex<Option<StoreItem>>)>;

static GLOBAL_STORE: InitCell<Mutex<LruCache<K, V>>> = InitCell::new();

fn store_size() -> NonZeroUsize {
    let size = std::env::var("TCPFP_STORE_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(128);

    NonZeroUsize::new(size).unwrap_or(NonZeroUsize::new(128).unwrap())
}

async fn lock_store<'a>() -> MutexGuard<'a, LruCache<K, V>> {
    GLOBAL_STORE
        .get_or_init(|| Mutex::new(LruCache::new(store_size())))
        .lock()
        .await
}

async fn entry_by_key(key: &String) -> V {
    let mut store = lock_store().await;

    store
        .get_or_insert_ref(key, || Arc::new((Notify::new(), Mutex::new(None))))
        .clone()
}

pub async fn publish(ip: String, port: u16, value: StoreItem) {
    let key = format!("{}:{}", ip, port);
    let (notify, mutex) = &*entry_by_key(&key).await;
    *mutex.lock().await = Some(value);
    notify.notify_one();
}

pub async fn consume(ip: String, port: u16) -> anyhow::Result<StoreItem> {
    let key = format!("{}:{}", ip, port);
    let notify = entry_by_key(&key).await;

    tokio::time::timeout(Duration::from_millis(1000), notify.0.notified())
        .await
        .context("timed out waiting for store publish")?;

    let entry = lock_store()
        .await
        .pop(&key)
        .context("store entry evicted before it was read")?;

    let item = entry.1.lock().await.take();
    item.context("store entry was empty")
}
