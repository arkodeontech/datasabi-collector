//! Windows capture: ETW events (bytes per process) → app and network → the shared
//! engine (`crate::engine`), which totals usage, checks alerts and saves to SQLite.
//! The Windows counterpart of `linux/`.

pub mod adapters;
pub mod etw;
pub mod procs;

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use datasabi_protocol::Metered;

use crate::addr::is_local_only;
use crate::config::Config;
use crate::engine::{now_unix, Engine};
use crate::state::Shared;
use crate::winrules::{app_info, local_and_remote, lost_from_logman, SYSTEM_PID};

use adapters::Adapters;
use etw::{Counts, Msg};

/// The ETW session's name (one per computer).
const SESSION: &str = "DataSabiCollector";
const CHANNEL_CAPACITY: usize = 65_536;
const HOUSEKEEPING: Duration = Duration::from_secs(5);
/// How often each interface's network is re-checked (as on Linux).
const NET_REFRESH: Duration = Duration::from_secs(5);
/// The adapter list is re-read at most this often when an address isn't known yet.
const ADAPTERS_MISS_GAP: Duration = Duration::from_secs(1);
const SERVICES_EVERY: Duration = Duration::from_secs(60);
const LOST_EVERY: Duration = Duration::from_secs(60);

pub fn run(cfg: Config, shared: Arc<Shared>) -> Result<()> {
    if cfg.socket_group.is_some() {
        tracing::warn!(
            "--socket-group is ignored on Windows: the pipe's access list decides who connects"
        );
    }
    let (tx, rx) = mpsc::sync_channel::<Msg>(CHANNEL_CAPACITY);
    let counts = Arc::new(Counts::default());
    let session = etw::start(SESSION, tx, counts.clone())?;

    let mut capture = Capture::new(Engine::new(shared.clone())?, cfg.interfaces.clone());
    let mut last_housekeeping = Instant::now();
    let mut last_lost = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(msg) => capture.handle(msg),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_housekeeping.elapsed() >= HOUSEKEEPING {
            last_housekeeping = Instant::now();
            capture.housekeeping();
        }
        if last_lost.elapsed() >= LOST_EVERY {
            last_lost = Instant::now();
            capture.check_lost(&counts);
        }
        capture.engine.run_due();
        if shared.shutdown.load(Ordering::Relaxed) {
            break;
        }
    }
    session.stop();
    capture.engine.flush();
    tracing::info!("capture engine stopped");
    Ok(())
}

/// The Windows side: finds each event's app and network and feeds the bytes into the
/// shared engine.
struct Capture {
    engine: Engine,
    only: Vec<String>,
    adapters: Adapters,
    adapters_read: Instant,
    /// Program file per process: from start events, or asked of Windows.
    images: HashMap<u32, String>,
    services: HashMap<u32, Vec<String>>,
    services_read: Instant,
    services_dirty: bool,
    app_ids: HashMap<u32, i64>,
    net_checked: HashMap<Arc<str>, Instant>,
    /// Events with no address of ours, counted for the logs.
    not_ours: u64,
    /// The lost and dropped totals last logged.
    lost_seen: (u64, u64, u64),
}

impl Capture {
    fn new(engine: Engine, only: Vec<String>) -> Self {
        let adapters = Adapters::read(&only).unwrap_or_else(|e| {
            tracing::warn!("{e:#}");
            Adapters::default()
        });
        Self {
            engine,
            only,
            adapters,
            adapters_read: Instant::now(),
            images: HashMap::new(),
            services: procs::services_by_pid(),
            services_read: Instant::now(),
            services_dirty: false,
            app_ids: HashMap::new(),
            net_checked: HashMap::new(),
            not_ours: 0,
            lost_seen: (0, 0, 0),
        }
    }

    fn handle(&mut self, msg: Msg) {
        match msg {
            Msg::Net {
                pid,
                size,
                dir,
                a,
                b,
            } => self.on_net(pid, size, dir, a, b),
            Msg::Start { pid, image } => {
                if image.to_ascii_lowercase().ends_with("svchost.exe") {
                    self.services_dirty = true;
                }
                self.images.insert(pid, image);
                self.app_ids.remove(&pid);
            }
            Msg::Stop { pid } => {
                self.images.remove(&pid);
                self.app_ids.remove(&pid);
                self.services.remove(&pid);
            }
        }
    }

    fn on_net(
        &mut self,
        pid: u32,
        size: u32,
        dir: crate::aggregate::Direction,
        a: std::net::IpAddr,
        b: std::net::IpAddr,
    ) {
        let mut pair = local_and_remote(a, b, |ip| self.adapters.contains(ip));
        if pair.is_none() && self.adapters_read.elapsed() >= ADAPTERS_MISS_GAP {
            self.read_adapters();
            pair = local_and_remote(a, b, |ip| self.adapters.contains(ip));
        }
        let Some((local, remote)) = pair else {
            self.not_ours += 1;
            return;
        };
        if is_local_only(remote) {
            return;
        }
        let Some(adapter) = self.adapters.get(&local).cloned() else {
            return;
        };
        if adapter.vpn {
            // Counted once, encrypted, on the physical network under the VPN app.
            return;
        }
        let Some((net_id, metered)) = self.network(&adapter.name) else {
            return;
        };
        let Some(app_id) = self.app_id(pid) else {
            return;
        };
        self.engine
            .add(app_id, net_id, metered, dir, u64::from(size), now_unix());
    }

    fn read_adapters(&mut self) {
        match Adapters::read(&self.only) {
            Ok(a) => self.adapters = a,
            Err(e) => tracing::warn!("{e:#}"),
        }
        self.adapters_read = Instant::now();
    }

    fn housekeeping(&mut self) {
        self.read_adapters();
        if self.services_dirty || self.services_read.elapsed() >= SERVICES_EVERY {
            self.services = procs::services_by_pid();
            self.services_read = Instant::now();
            self.services_dirty = false;
            // svchost names depend on the services; work them out again.
            let svchosts: Vec<u32> = self.services.keys().copied().collect();
            for pid in svchosts {
                self.app_ids.remove(&pid);
            }
        }
        self.engine.reload_rules_if_changed();
    }

    /// Logs events lost by the ETW session or dropped by the queue: data never counted.
    fn check_lost(&mut self, counts: &Counts) {
        let out = std::process::Command::new("logman")
            .args(["query", SESSION, "-ets"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let lost = lost_from_logman(&out);
        let dropped = counts.dropped.load(Ordering::Relaxed);
        let unparsed = counts.unparsed.load(Ordering::Relaxed);
        if (lost, dropped, unparsed) != self.lost_seen {
            tracing::warn!(
                "events not counted so far: {lost} lost by ETW, {dropped} dropped (queue \
                 full), {unparsed} unreadable; {} with no address of ours",
                self.not_ours
            );
            self.lost_seen = (lost, dropped, unparsed);
        }
    }

    /// Network id and metered flag for an adapter, re-checked every few seconds. The
    /// network's name and Windows' cost setting come in the next PR; until then the
    /// adapter's name is used and the cost is unknown (treated as metered).
    fn network(&mut self, iface: &Arc<str>) -> Option<(i64, bool)> {
        if let (Some(checked), Some(net)) = (
            self.net_checked.get(iface),
            self.engine.cached_network(iface),
        ) {
            if checked.elapsed() < NET_REFRESH {
                return Some(net);
            }
        }
        let net = self.engine.network(iface, None, Metered::Unknown)?;
        self.net_checked.insert(iface.clone(), Instant::now());
        Some(net)
    }

    fn app_id(&mut self, pid: u32) -> Option<i64> {
        if let Some(id) = self.app_ids.get(&pid) {
            return Some(*id);
        }
        // The Win32 path while the process runs; the start event's path if it has exited.
        let image = procs::image_path(pid).or_else(|| self.images.get(&pid).cloned());
        let id = match image {
            // Exited before it was seen, and no start event: counted, as on Linux.
            None if pid != SYSTEM_PID => self.engine.unknown_app_id()?,
            _ => {
                let services = self.services.get(&pid).cloned().unwrap_or_default();
                self.engine
                    .app_id(&app_info(pid, image.as_deref(), &services))?
            }
        };
        self.app_ids.insert(pid, id);
        Some(id)
    }
}
