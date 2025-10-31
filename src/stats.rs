use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

use chrono::{DateTime, Local};
use tracing::info;
use num_format::{Locale, ToFormattedString};


pub struct Stats {
    pub total_bytes_sent: AtomicUsize,
    pub total_bytes_received: AtomicUsize,
    pub total_packets_sent: AtomicUsize,
    pub total_packets_received: AtomicUsize,
    pub total_reconnections: AtomicUsize,
    pub last_reconnection_time: RwLock<Option<DateTime<Local>>>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            total_bytes_sent: AtomicUsize::new(0),
            total_bytes_received: AtomicUsize::new(0),
            total_packets_sent: AtomicUsize::new(0),
            total_packets_received: AtomicUsize::new(0),
            total_reconnections: AtomicUsize::new(0),
            last_reconnection_time: RwLock::new(None),
        }
    }

    pub fn increment_bytes_sent(&self, bytes: u64) {
        self.total_bytes_sent
            .fetch_add(bytes as usize, Ordering::Relaxed);
    }

    pub fn increment_bytes_received(&self, bytes: u64) {
        self.total_bytes_received
            .fetch_add(bytes as usize, Ordering::Relaxed);
    }

    pub fn increment_packets_sent(&self, packets: u64) {
        self.total_packets_sent
            .fetch_add(packets as usize, Ordering::Relaxed);
    }

    pub fn increment_packets_received(&self, packets: u64) {
        self.total_packets_received
            .fetch_add(packets as usize, Ordering::Relaxed);
    }

    pub fn increment_reconnections(&self) {
        self.total_reconnections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_last_reconnection_time(&self, time: DateTime<Local>) {
        self.last_reconnection_time.write().unwrap().replace(time);
    }

    pub fn get_last_reconnection_time(&self) -> Option<DateTime<Local>> {
        self.last_reconnection_time.read().unwrap().clone()
    }
    pub fn get_total_bytes_sent(&self) -> usize {
        self.total_bytes_sent.load(Ordering::Relaxed)
    }
    pub fn get_total_bytes_received(&self) -> usize {
        self.total_bytes_received.load(Ordering::Relaxed)
    }
    pub fn get_total_packets_sent(&self) -> usize {
        self.total_packets_sent.load(Ordering::Relaxed)
    }
    pub fn get_total_packets_received(&self) -> usize {
        self.total_packets_received.load(Ordering::Relaxed)
    }
    pub fn get_total_reconnections(&self) -> usize {
        self.total_reconnections.load(Ordering::Relaxed)
    }
}

pub async fn start_stats_reporting(context: &mut tokio_tree_context::Context, stats: Arc<Stats>) {
    info!("Starting stats reporting (every 30 seconds)");
    context.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let bytes_sent = humansize::format_size(
                stats.get_total_bytes_sent() as u64, 
                humansize::BINARY);
            let bytes_received = humansize::format_size(
                stats.get_total_bytes_received() as u64,
                humansize::BINARY);
            let packets_sent = stats.get_total_packets_sent()
                .to_formatted_string(&Locale::en);
            let packets_received = stats.get_total_packets_received()
                .to_formatted_string(&Locale::en);
            let reconnections = stats.get_total_reconnections()
                .to_formatted_string(&Locale::en);
            info!("Stats: bytes_sent={}, bytes_received={}, packets_sent={}, packets_received={}, reconnections={}", bytes_sent, bytes_received, packets_sent, packets_received, reconnections);
        }
    });
}
