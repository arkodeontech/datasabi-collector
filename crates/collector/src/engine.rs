//! The part of the collector every platform shares. Platform code (`linux/`, and later
//! Windows) works out which app sent how many bytes on which network interface and feeds
//! that in here. The engine turns apps and networks into database ids, totals usage,
//! checks alert rules, saves usage every few seconds and rolls minutes up into hours and
//! days.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use datasabi_protocol::{Alert, Event, Metered};

use crate::aggregate::{Aggregator, Direction};
use crate::state::Shared;
use crate::store::treated_as_metered;

const TICK: Duration = Duration::from_secs(1);
const FLUSH: Duration = Duration::from_secs(5);
const ROLLUP: Duration = Duration::from_secs(3600);

/// An app's identity: a stable key, a friendly name and the executable, if known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInfo {
    pub key: String,
    pub name: String,
    pub exe: Option<String>,
}

impl AppInfo {
    pub fn unknown() -> Self {
        Self {
            key: "unknown".into(),
            name: "Unknown / system".into(),
            exe: None,
        }
    }
}

/// The network last seen on an interface.
struct NetEntry {
    id: i64,
    name: Option<String>,
    metered: bool,
}

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub struct Engine {
    shared: Arc<Shared>,
    nets: HashMap<String, NetEntry>,
    app_ids: HashMap<String, i64>,
    unknown_app: Option<i64>,
    agg: Aggregator,
    last_tick: Instant,
    last_flush: Instant,
    last_rollup: Instant,
}

impl Engine {
    pub fn new(shared: Arc<Shared>) -> Result<Self> {
        // Load alert rules and quiet mode from store before starting the engine.
        let now = now_unix();
        let (rules, quiet_until_val) = {
            let store = shared.store.lock().unwrap();
            let rules = store.get_active_rules()?;
            let quiet = store.get_quiet_until()?.unwrap_or(0);
            (rules, quiet)
        };
        shared.quiet_until.store(quiet_until_val, Ordering::Relaxed);

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
        let start = Instant::now();
        Ok(Self {
            shared,
            nets: HashMap::new(),
            app_ids: HashMap::new(),
            unknown_app: None,
            agg,
            last_tick: start,
            last_flush: start,
            last_rollup: start,
        })
    }

    /// Records bytes an app sent or received on a network at `ts` (unix seconds).
    pub fn add(
        &mut self,
        app_id: i64,
        net_id: i64,
        metered: bool,
        dir: Direction,
        bytes: u64,
        ts: i64,
    ) {
        self.agg.add(app_id, net_id, metered, dir, bytes, ts);
    }

    pub fn app_id(&mut self, info: &AppInfo) -> Option<i64> {
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

    pub fn unknown_app_id(&mut self) -> Option<i64> {
        if self.unknown_app.is_none() {
            self.unknown_app = self.app_id(&AppInfo::unknown());
        }
        self.unknown_app
    }

    /// The network last seen on `iface`, without asking the system again.
    pub fn cached_network(&self, iface: &str) -> Option<(i64, bool)> {
        self.nets.get(iface).map(|n| (n.id, n.metered))
    }

    /// Network id and metered flag for what the system reports on `iface`: its connection
    /// name and whether it says the connection is metered. The user's override wins.
    pub fn network(
        &mut self,
        iface: &str,
        name: Option<String>,
        detected: Metered,
    ) -> Option<(i64, bool)> {
        let store = self.shared.store.lock().unwrap();
        let now = now_unix();
        let id = match store.upsert_network(iface, name.as_deref(), detected, now) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("saving network {iface}: {e:#}");
                return None;
            }
        };
        let user_override = store.network_override(id).unwrap_or(None);
        drop(store);
        let metered = treated_as_metered(detected, user_override);
        let changed = self
            .nets
            .get(iface)
            .is_none_or(|n| n.id != id || n.metered != metered);
        if changed {
            tracing::info!(
                "network on {iface}: {} (detected {:?}, treated as {})",
                name.as_deref().unwrap_or("unnamed"),
                detected,
                if metered { "metered" } else { "unlimited" }
            );
        }
        self.nets
            .insert(iface.to_string(), NetEntry { id, name, metered });
        Some((id, metered))
    }

    fn network_name(&self, id: i64) -> Option<String> {
        self.nets
            .iter()
            .find(|(_, n)| n.id == id)
            .map(|(iface, n)| n.name.clone().unwrap_or_else(|| iface.to_string()))
    }

    /// Reloads alert rules when the IPC handler has changed them.
    pub fn reload_rules_if_changed(&mut self) {
        if self.shared.rules_dirty.swap(false, Ordering::Relaxed) {
            match self.shared.store.lock().unwrap().get_active_rules() {
                Ok(rules) => self.agg.set_rules(rules),
                Err(e) => tracing::error!("reloading alert rules: {e:#}"),
            }
        }
    }

    /// Runs whatever is due: the live snapshot and alerts every second, saving usage
    /// every few seconds and the rollups every hour. Call it often.
    pub fn run_due(&mut self) {
        if self.last_tick.elapsed() >= TICK {
            let elapsed = self.last_tick.elapsed().as_secs_f64();
            self.last_tick = Instant::now();
            self.tick(elapsed);
        }
        if self.last_flush.elapsed() >= FLUSH {
            self.last_flush = Instant::now();
            self.flush();
        }
        if self.last_rollup.elapsed() >= ROLLUP {
            self.last_rollup = Instant::now();
            self.rollup();
        }
    }

    fn tick(&mut self, elapsed: f64) {
        let now = now_unix();
        let (snapshot, fired) = self.agg.tick(elapsed, now);
        *self.shared.live.write().unwrap() = snapshot.clone();
        self.shared.publish(Event::Live(snapshot));
        let quiet_until = self.shared.quiet_until.load(Ordering::Relaxed);
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

    /// Saves the usage counted since the last save.
    pub fn flush(&mut self) {
        let rows = self.agg.take_rows();
        if rows.is_empty() {
            return;
        }
        if let Err(e) = self.shared.store.lock().unwrap().add_usage(&rows) {
            tracing::error!("saving {} usage rows: {e:#}", rows.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Local;
    use datasabi_protocol::{Range, BYTES_PER_MB};

    use crate::store::Store;

    fn engine() -> (tempfile::TempDir, Arc<Shared>, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        let shared = Arc::new(Shared::new(store));
        let engine = Engine::new(shared.clone()).unwrap();
        (dir, shared, engine)
    }

    fn app(key: &str, name: &str) -> AppInfo {
        AppInfo {
            key: key.into(),
            name: name.into(),
            exe: None,
        }
    }

    #[test]
    fn usage_fed_in_is_saved() {
        let (_d, shared, mut e) = engine();
        let (net, metered) = e
            .network("wlan0", Some("Test MiFi".into()), Metered::Yes)
            .unwrap();
        assert!(metered);
        assert_eq!(e.cached_network("wlan0"), Some((net, true)));
        let curl = e.app_id(&app("/usr/bin/curl", "curl")).unwrap();
        assert_eq!(e.app_id(&app("/usr/bin/curl", "curl")), Some(curl));
        let unknown = e.unknown_app_id().unwrap();
        assert_eq!(e.unknown_app_id(), Some(unknown));
        assert_ne!(curl, unknown);

        e.add(curl, net, metered, Direction::In, 1000, now_unix());
        e.add(curl, net, metered, Direction::Out, 100, now_unix());
        e.add(unknown, net, metered, Direction::In, 50, now_unix());
        e.flush();

        let sum = shared
            .store
            .lock()
            .unwrap()
            .summary(Range::Today, Local::now())
            .unwrap();
        assert_eq!(sum.total_in, 1050);
        assert_eq!(sum.total_out, 100);
        assert_eq!(sum.apps[0].name, "curl");
        assert_eq!(sum.apps[0].bytes_in, 1000);
    }

    #[test]
    fn user_override_decides_metered() {
        let (_d, shared, mut e) = engine();
        let (net, metered) = e.network("wlan0", None, Metered::Yes).unwrap();
        assert!(metered);
        shared
            .store
            .lock()
            .unwrap()
            .set_network_override(net, Some(false))
            .unwrap();
        assert_eq!(e.network("wlan0", None, Metered::Yes), Some((net, false)));
    }

    #[test]
    fn metered_use_over_a_rule_fires_an_alert() {
        let (_d, shared, mut e) = engine();
        let mut events = shared.events.subscribe();
        let (net, metered) = e
            .network("wlan0", Some("Test MiFi".into()), Metered::Yes)
            .unwrap();
        let curl = e.app_id(&app("/usr/bin/curl", "curl")).unwrap();
        // The default 15-minute rule is 50 MB.
        e.add(
            curl,
            net,
            metered,
            Direction::In,
            60 * BYTES_PER_MB,
            now_unix(),
        );
        e.tick(1.0);

        let mut alert = None;
        while let Ok(ev) = events.try_recv() {
            if let Event::AlertFired(a) = ev {
                alert = Some(a);
            }
        }
        let alert = alert.expect("an alert was published");
        assert_eq!(alert.app_id, curl);
        assert_eq!(alert.network.as_deref(), Some("Test MiFi"));
    }
}
