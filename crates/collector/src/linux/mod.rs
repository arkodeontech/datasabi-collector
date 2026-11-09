//! Linux capture: pcap packets -> socket owner -> app, fed into the shared engine
//! (`crate::engine`), which totals usage, checks alerts and saves to SQLite.

pub mod apps;
pub mod capture;
pub mod network;
pub mod packet;
pub mod sockets;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::aggregate::Direction;
use crate::config::Config;
use crate::engine::{now_unix, Engine};
use crate::state::Shared;

use apps::AppResolver;
use capture::Msg;
use network::NetworkManager;
use packet::is_local_only;
use sockets::{Proto, SocketTable, MISS_REFRESH_GAP};

const NET_REFRESH: Duration = Duration::from_secs(5);
const HOUSEKEEPING: Duration = Duration::from_secs(5);
const CHANNEL_CAPACITY: usize = 65_536;

type FlowKey = (Proto, SocketAddr, SocketAddr);

/// Traffic of a flow whose owner was not in the socket table yet. Settled on the
/// next refresh (at most [`MISS_REFRESH_GAP`] later) so short, fast transfers that
/// start right after a refresh are still attributed to the right app.
struct Pending {
    net_id: i64,
    metered: bool,
    bytes_in: u64,
    bytes_out: u64,
    ts: i64,
}

pub fn run(cfg: Config, shared: Arc<Shared>) -> Result<()> {
    let (tx, rx) = mpsc::sync_channel::<Msg>(CHANNEL_CAPACITY);
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    capture::spawn_manager(cfg.interfaces.clone(), tx, shutdown.clone());

    let mut capture = Capture::new(Engine::new(shared.clone())?);
    let mut last_housekeeping = Instant::now();

    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(Msg::Packet { iface, packet }) => capture.handle(&iface, packet),
            Ok(Msg::Locals(l)) => capture.locals = l,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        capture.settle_pending();
        if last_housekeeping.elapsed() >= HOUSEKEEPING {
            last_housekeeping = Instant::now();
            capture.housekeeping();
        }
        capture.engine.run_due();
        if shared.shutdown.load(Ordering::Relaxed) {
            break;
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    capture.settle_pending_now();
    capture.engine.flush();
    tracing::info!("capture engine stopped");
    Ok(())
}

/// The Linux side: finds which app owns each packet's connection and feeds the bytes
/// into the shared engine.
struct Capture {
    engine: Engine,
    locals: HashSet<IpAddr>,
    sockets: SocketTable,
    resolver: AppResolver,
    nm: NetworkManager,
    /// When each interface's network was last asked of NetworkManager.
    net_checked: HashMap<Arc<str>, Instant>,
    pending: HashMap<FlowKey, Pending>,
    /// Flows confirmed to have no visible owner; cleared during housekeeping.
    unknown_flows: HashSet<FlowKey>,
}

impl Capture {
    fn new(engine: Engine) -> Self {
        Self {
            engine,
            locals: HashSet::new(),
            sockets: SocketTable::new(),
            resolver: AppResolver::new(),
            nm: NetworkManager::new(),
            net_checked: HashMap::new(),
            pending: HashMap::new(),
            unknown_flows: HashSet::new(),
        }
    }

    fn handle(&mut self, iface: &Arc<str>, p: packet::Parsed) {
        let src_local = self.locals.contains(&p.src.ip());
        let dst_local = self.locals.contains(&p.dst.ip());
        let (dir, local, remote) = match (src_local, dst_local) {
            (true, false) => (Direction::Out, p.src, p.dst),
            (false, true) => (Direction::In, p.dst, p.src),
            // Both local (hairpin) or neither (forwarded/hotspot clients): not ours.
            _ => return,
        };
        if is_local_only(remote.ip()) {
            return;
        }
        let Some((net_id, metered)) = self.network(iface) else {
            return;
        };
        let key = (p.proto, local, remote);
        let bytes = p.len as u64;
        let ts = now_unix();
        let app_id = if let Some(pid) = self.sockets.find(p.proto, local, remote) {
            self.app_id(pid)
        } else if self.unknown_flows.contains(&key) {
            self.engine.unknown_app_id()
        } else {
            let e = self.pending.entry(key).or_insert(Pending {
                net_id,
                metered,
                bytes_in: 0,
                bytes_out: 0,
                ts,
            });
            match dir {
                Direction::In => e.bytes_in += bytes,
                Direction::Out => e.bytes_out += bytes,
            }
            return;
        };
        let Some(app_id) = app_id else { return };
        self.engine.add(app_id, net_id, metered, dir, bytes, ts);
    }

    /// Settles queued flows once the socket table can be refreshed again.
    fn settle_pending(&mut self) {
        if !self.pending.is_empty() && self.sockets.refresh_if_older(MISS_REFRESH_GAP) {
            self.attribute_pending();
        }
    }

    fn settle_pending_now(&mut self) {
        if !self.pending.is_empty() {
            self.sockets.refresh();
            self.attribute_pending();
        }
    }

    fn attribute_pending(&mut self) {
        let pending: Vec<(FlowKey, Pending)> = self.pending.drain().collect();
        for ((proto, local, remote), f) in pending {
            let app_id = match self.sockets.find(proto, local, remote) {
                Some(pid) => self.app_id(pid),
                None => {
                    tracing::trace!("no owner for {proto:?} {local} <-> {remote}");
                    self.unknown_flows.insert((proto, local, remote));
                    self.engine.unknown_app_id()
                }
            };
            let Some(app_id) = app_id else { continue };
            if f.bytes_in > 0 {
                self.engine
                    .add(app_id, f.net_id, f.metered, Direction::In, f.bytes_in, f.ts);
            }
            if f.bytes_out > 0 {
                self.engine.add(
                    app_id,
                    f.net_id,
                    f.metered,
                    Direction::Out,
                    f.bytes_out,
                    f.ts,
                );
            }
        }
    }

    /// Periodic refresh: expire per-pid caches and give unknown flows another chance.
    fn housekeeping(&mut self) {
        self.sockets.maybe_refresh();
        self.resolver.retain_pids(self.sockets.alive_pids());
        self.unknown_flows.clear();
        self.engine.reload_rules_if_changed();
    }

    /// Network id and metered flag for an interface, re-checked every few seconds.
    fn network(&mut self, iface: &Arc<str>) -> Option<(i64, bool)> {
        if let (Some(checked), Some(net)) = (
            self.net_checked.get(iface),
            self.engine.cached_network(iface),
        ) {
            if checked.elapsed() < NET_REFRESH {
                return Some(net);
            }
        }
        let info = self.nm.query(iface);
        let net = self.engine.network(iface, info.name, info.detected)?;
        self.net_checked.insert(iface.clone(), Instant::now());
        Some(net)
    }

    fn app_id(&mut self, pid: u32) -> Option<i64> {
        let info = self.resolver.resolve(pid);
        self.engine.app_id(&info)
    }
}
