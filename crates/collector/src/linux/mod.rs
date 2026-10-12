//! Linux capture engine: pcap packets -> socket owner -> app -> aggregator -> SQLite.

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
use datasabi_protocol::{Alert, Event};

use crate::aggregate::{Aggregator, Direction};
use crate::config::Config;
use crate::state::Shared;
use crate::store::treated_as_metered;

use apps::{AppInfo, AppResolver};
use capture::Msg;
use network::NetworkManager;
use packet::is_local_only;
use sockets::{Proto, SocketTable, MISS_REFRESH_GAP};

const TICK: Duration = Duration::from_secs(1);
const FLUSH: Duration = Duration::from_secs(5);
const NET_REFRESH: Duration = Duration::from_secs(5);
const HOUSEKEEPING: Duration = Duration::from_secs(5);
const ROLLUP: Duration = Duration::from_secs(3600);
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

struct NetEntry {
    id: i64,
    name: Option<String>,
    metered: bool,
    checked: Instant,
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn run(cfg: Config, shared: Arc<Shared>) -> Result<()> {
    let (tx, rx) = mpsc::sync_channel::<Msg>(CHANNEL_CAPACITY);
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    capture::spawn_manager(cfg.interfaces.clone(), tx, shutdown.clone());

    let mut engine = Engine::new(shared.clone())?;
    let mut last_tick = Instant::now();
    let mut last_flush = Instant::now();
    let mut last_housekeeping = Instant::now();
    let mut last_rollup = Instant::now();

    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(Msg::Packet { iface, packet }) => engine.handle(&iface, packet),
            Ok(Msg::Locals(l)) => engine.locals = l,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        engine.settle_pending();
        if last_housekeeping.elapsed() >= HOUSEKEEPING {
            last_housekeeping = Instant::now();
            engine.housekeeping();
        }
        if last_tick.elapsed() >= TICK {
            let elapsed = last_tick.elapsed().as_secs_f64();
            last_tick = Instant::now();
            engine.tick(elapsed);
        }
        if last_flush.elapsed() >= FLUSH {
            last_flush = Instant::now();
            engine.flush();
        }
        if last_rollup.elapsed() >= ROLLUP {
            last_rollup = Instant::now();
            engine.rollup();
        }
        if shared.shutdown.load(Ordering::Relaxed) {
            break;
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    engine.settle_pending_now();
    engine.flush();
    tracing::info!("capture engine stopped");
    Ok(())
}

struct Engine {
    shared: Arc<Shared>,
    locals: HashSet<IpAddr>,
    sockets: SocketTable,
    resolver: AppResolver,
    nm: NetworkManager,
    nets: HashMap<Arc<str>, NetEntry>,
    app_ids: HashMap<String, i64>,
    unknown_app: Option<i64>,
    pending: HashMap<FlowKey, Pending>,
    /// Flows confirmed to have no visible owner; cleared during housekeeping.
    unknown_flows: HashSet<FlowKey>,
    agg: Aggregator,
}

impl Engine {
    fn new(shared: Arc<Shared>) -> Result<Self> {
        // Load alert rules and quiet mode from store before starting the engine.
        let now = now_unix();
        let (rules, quiet_until_val) = {
            let store = shared.store.lock().unwrap();
            let rules = store.get_active_rules()?;
            let quiet = store.get_quiet_until()?.unwrap_or(0);
            (rules, quiet)
        };
        shared
            .quiet_until
            .store(quiet_until_val, std::sync::atomic::Ordering::Relaxed);

        let mut agg = Aggregator::new(rules);
        // Rebuild alert windows from the last hour so a restart does not reset them.
        {
            let store = shared.store.lock().unwrap();
            let metered: HashSet<i64> = store
                .networks(now)?
                .into_iter()
                .filter(|n| n.treated_as_metered)
                .map(|n| n.id)
                .collect();
            for ((app, net), points) in store.recent_usage(now - 3600)? {
                if metered.contains(&net) {
                    for (ts, bytes) in points {
                        agg.seed_metered(app, ts, bytes);
                    }
                }
            }
        }
        Ok(Self {
            shared,
            locals: HashSet::new(),
            sockets: SocketTable::new(),
            resolver: AppResolver::new(),
            nm: NetworkManager::new(),
            nets: HashMap::new(),
            app_ids: HashMap::new(),
            unknown_app: None,
            pending: HashMap::new(),
            unknown_flows: HashSet::new(),
            agg,
        })
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
            let info = self.resolver.resolve(pid);
            self.app_id(&info)
        } else if self.unknown_flows.contains(&key) {
            self.unknown_app_id()
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
        self.agg.add(app_id, net_id, metered, dir, bytes, ts);
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
                Some(pid) => {
                    let info = self.resolver.resolve(pid);
                    self.app_id(&info)
                }
                None => {
                    tracing::trace!("no owner for {proto:?} {local} <-> {remote}");
                    self.unknown_flows.insert((proto, local, remote));
                    self.unknown_app_id()
                }
            };
            let Some(app_id) = app_id else { continue };
            if f.bytes_in > 0 {
                self.agg
                    .add(app_id, f.net_id, f.metered, Direction::In, f.bytes_in, f.ts);
            }
            if f.bytes_out > 0 {
                self.agg.add(
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
        // Reload alert rules when the IPC handler has changed them.
        if self
            .shared
            .rules_dirty
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            match self.shared.store.lock().unwrap().get_active_rules() {
                Ok(rules) => self.agg.set_rules(rules),
                Err(e) => tracing::error!("reloading alert rules: {e:#}"),
            }
        }
    }

    fn app_id(&mut self, info: &AppInfo) -> Option<i64> {
        if let Some(id) = self.app_ids.get(&info.key) {
            return Some(*id);
        }
        let res = self.shared.store.lock().unwrap().upsert_app(
            &info.key,
            &info.name,
            info.exe.as_deref(),
            now_unix(),
        );
        match res {
            Ok(id) => {
                tracing::debug!("new app {} ({}) -> {id}", info.name, info.key);
                self.app_ids.insert(info.key.clone(), id);
                self.agg.set_name(id, &info.name);
                Some(id)
            }
            Err(e) => {
                tracing::error!("saving app {}: {e:#}", info.key);
                None
            }
        }
    }

    fn unknown_app_id(&mut self) -> Option<i64> {
        if self.unknown_app.is_none() {
            self.unknown_app = self.app_id(&AppInfo::unknown());
        }
        self.unknown_app
    }

    /// Network id and metered flag for an interface, re-checked every few seconds.
    fn network(&mut self, iface: &Arc<str>) -> Option<(i64, bool)> {
        if let Some(n) = self.nets.get(iface) {
            if n.checked.elapsed() < NET_REFRESH {
                return Some((n.id, n.metered));
            }
        }
        let info = self.nm.query(iface);
        let store = self.shared.store.lock().unwrap();
        let now = now_unix();
        let id = match store.upsert_network(iface, info.name.as_deref(), info.detected, now) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("saving network {iface}: {e:#}");
                return None;
            }
        };
        let user_override = store.network_override(id).unwrap_or(None);
        drop(store);
        let metered = treated_as_metered(info.detected, user_override);
        let changed = self
            .nets
            .get(iface)
            .is_none_or(|n| n.id != id || n.metered != metered);
        if changed {
            tracing::info!(
                "network on {iface}: {} (detected {:?}, treated as {})",
                info.name.as_deref().unwrap_or("unnamed"),
                info.detected,
                if metered { "metered" } else { "unlimited" }
            );
        }
        self.nets.insert(
            iface.clone(),
            NetEntry {
                id,
                name: info.name,
                metered,
                checked: Instant::now(),
            },
        );
        Some((id, metered))
    }

    fn network_name(&self, id: i64) -> Option<String> {
        self.nets
            .iter()
            .find(|(_, n)| n.id == id)
            .map(|(iface, n)| n.name.clone().unwrap_or_else(|| iface.to_string()))
    }

    fn tick(&mut self, elapsed: f64) {
        let now = now_unix();
        let (snapshot, fired) = self.agg.tick(elapsed, now);
        *self.shared.live.write().unwrap() = snapshot.clone();
        self.shared.publish(Event::Live(snapshot));
        let quiet_until = self
            .shared
            .quiet_until
            .load(std::sync::atomic::Ordering::Relaxed);
        if quiet_until > 0 && now < quiet_until {
            return;
        }
        for f in fired {
            let network = f.network_id.and_then(|id| self.network_name(id));
            tracing::info!(
                "alert: {} used {} in {} min",
                f.app_name,
                datasabi_protocol::format_bytes(f.fired.bytes),
                f.fired.window_minutes
            );
            if let Err(e) = self.shared.store.lock().unwrap().log_alert(
                f.fired.app_id,
                f.network_id,
                now,
                f.fired.bytes,
                f.fired.window_minutes,
            ) {
                tracing::error!("logging alert: {e:#}");
            }
            self.shared.publish(Event::AlertFired(Alert {
                app_id: f.fired.app_id,
                app_name: f.app_name,
                bytes: f.fired.bytes,
                window_minutes: f.fired.window_minutes,
                network,
                at_unix: now,
            }));
        }
    }

    fn rollup(&mut self) {
        let now = now_unix();
        let mut store = self.shared.store.lock().unwrap();
        if let Err(e) = store.rollup_minutes(now) {
            tracing::error!("minute rollup: {e:#}");
        }
        if let Err(e) = store.rollup_hours(now) {
            tracing::error!("hour rollup: {e:#}");
        }
    }

    fn flush(&mut self) {
        let rows = self.agg.take_rows();
        if rows.is_empty() {
            return;
        }
        if let Err(e) = self.shared.store.lock().unwrap().add_usage(&rows) {
            tracing::error!("saving {} usage rows: {e:#}", rows.len());
        }
    }
}
