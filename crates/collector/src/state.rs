use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::{Mutex, RwLock};

use datasabi_protocol::{Event, LiveSnapshot};
use tokio::sync::broadcast;

use crate::store::Store;

/// State shared between the capture engine (plain threads) and the IPC server (tokio).
pub struct Shared {
    pub store: Mutex<Store>,
    pub live: RwLock<LiveSnapshot>,
    pub events: broadcast::Sender<Event>,
    pub shutdown: AtomicBool,
    /// Set by the IPC handler when alert rules change; cleared by the engine on reload.
    pub rules_dirty: AtomicBool,
    /// Unix timestamp until which alerts are silenced; 0 means no quiet mode.
    pub quiet_until: AtomicI64,
}

impl Shared {
    pub fn new(store: Store) -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            store: Mutex::new(store),
            live: RwLock::new(LiveSnapshot::default()),
            events,
            shutdown: AtomicBool::new(false),
            rules_dirty: AtomicBool::new(false),
            quiet_until: AtomicI64::new(0),
        }
    }

    /// Sends an event to subscribers; having none is fine.
    pub fn publish(&self, event: Event) {
        let _ = self.events.send(event);
    }
}
