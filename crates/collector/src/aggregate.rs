//! Turns attributed traffic into per-minute rows, live rates and alerts.
//! Platform independent: the capture engine feeds it already-attributed bytes.

use std::collections::{HashMap, HashSet};

use datasabi_protocol::{AppRate, LiveSnapshot};

use crate::alerts::{AlertEngine, Fired, Rule};
use crate::store::UsageRow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Download.
    In,
    /// Upload.
    Out,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiredAlert {
    pub fired: Fired,
    pub app_name: String,
    /// Network the app was last seen using on a metered connection.
    pub network_id: Option<i64>,
}

pub struct Aggregator {
    /// (app, network, minute) -> (in, out), drained by [`Aggregator::take_rows`].
    buckets: HashMap<(i64, i64, i64), (u64, u64)>,
    /// app -> (in, out) since the last tick.
    second: HashMap<i64, (u64, u64)>,
    names: HashMap<i64, String>,
    alerts: AlertEngine,
    metered_active: HashSet<i64>,
    last_metered_net: HashMap<i64, i64>,
}

impl Aggregator {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            buckets: HashMap::new(),
            second: HashMap::new(),
            names: HashMap::new(),
            alerts: AlertEngine::new(rules),
            metered_active: HashSet::new(),
            last_metered_net: HashMap::new(),
        }
    }

    pub fn set_name(&mut self, app_id: i64, name: &str) {
        if self.names.get(&app_id).map(String::as_str) != Some(name) {
            self.names.insert(app_id, name.to_string());
        }
    }

    pub fn name(&self, app_id: i64) -> &str {
        self.names
            .get(&app_id)
            .map(String::as_str)
            .unwrap_or("Unknown")
    }

    /// Replaces alert rules without clearing window data.
    pub fn set_rules(&mut self, rules: Vec<Rule>) {
        self.alerts.set_rules(rules);
    }

    /// Seeds alert windows (e.g. from the database after a restart).
    pub fn seed_metered(&mut self, app_id: i64, ts: i64, bytes: u64) {
        self.alerts.record(app_id, ts, bytes);
    }

    pub fn add(
        &mut self,
        app_id: i64,
        network_id: i64,
        metered: bool,
        dir: Direction,
        bytes: u64,
        ts: i64,
    ) {
        let minute = ts - ts.rem_euclid(60);
        let b = self
            .buckets
            .entry((app_id, network_id, minute))
            .or_default();
        let s = self.second.entry(app_id).or_default();
        match dir {
            Direction::In => {
                b.0 += bytes;
                s.0 += bytes;
            }
            Direction::Out => {
                b.1 += bytes;
                s.1 += bytes;
            }
        }
        if metered {
            self.alerts.record(app_id, ts, bytes);
            self.metered_active.insert(app_id);
            self.last_metered_net.insert(app_id, network_id);
        }
    }

    /// Rows to persist since the last call.
    pub fn take_rows(&mut self) -> Vec<UsageRow> {
        self.buckets
            .drain()
            .map(
                |((app_id, network_id, minute_ts), (bytes_in, bytes_out))| UsageRow {
                    app_id,
                    network_id,
                    minute_ts,
                    bytes_in,
                    bytes_out,
                },
            )
            .collect()
    }

    /// Called about once a second: produces the live snapshot and any new alerts.
    pub fn tick(&mut self, elapsed_secs: f64, now: i64) -> (LiveSnapshot, Vec<FiredAlert>) {
        let secs = elapsed_secs.max(0.001);
        let mut apps: Vec<AppRate> = self
            .second
            .drain()
            .filter(|(_, (i, o))| i + o > 0)
            .map(|(app_id, (i, o))| AppRate {
                app_id,
                name: self
                    .names
                    .get(&app_id)
                    .cloned()
                    .unwrap_or_else(|| "Unknown".into()),
                rx_bps: (i as f64 / secs).round() as u64,
                tx_bps: (o as f64 / secs).round() as u64,
            })
            .collect();
        apps.sort_by_key(|a| std::cmp::Reverse(a.rx_bps + a.tx_bps));
        let snapshot = LiveSnapshot {
            at_unix: now,
            total_rx_bps: apps.iter().map(|a| a.rx_bps).sum(),
            total_tx_bps: apps.iter().map(|a| a.tx_bps).sum(),
            apps,
        };

        let mut fired = Vec::new();
        let active: Vec<i64> = self.metered_active.drain().collect();
        for app_id in active {
            if let Some(f) = self.alerts.check(app_id, now) {
                fired.push(FiredAlert {
                    fired: f,
                    app_name: self.name(app_id).to_string(),
                    network_id: self.last_metered_net.get(&app_id).copied(),
                });
            }
        }
        if now % 60 == 0 {
            self.alerts.prune(now);
        }
        (snapshot, fired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::DEFAULT_RULES;
    use datasabi_protocol::BYTES_PER_MB;

    #[test]
    fn buckets_rates_and_alerts() {
        let mut agg = Aggregator::new(DEFAULT_RULES.to_vec());
        agg.set_name(1, "Chrome");
        agg.set_name(2, "Spotify");
        let t = 1_700_000_040;
        agg.add(1, 10, true, Direction::In, 2000, t);
        agg.add(1, 10, true, Direction::Out, 500, t);
        agg.add(2, 10, true, Direction::In, 100, t);

        let (snap, alerts) = agg.tick(1.0, t);
        assert!(alerts.is_empty());
        assert_eq!(snap.apps[0].name, "Chrome");
        assert_eq!(snap.apps[0].rx_bps, 2000);
        assert_eq!(snap.total_tx_bps, 500);

        // Same minute merges into one row per app/network.
        agg.add(1, 10, true, Direction::In, 1000, t + 5);
        let mut rows = agg.take_rows();
        rows.sort_by_key(|r| r.app_id);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].bytes_in, 3000);
        assert_eq!(rows[0].minute_ts, t - t % 60);
        assert!(agg.take_rows().is_empty());

        // Unmetered traffic never alerts.
        agg.add(2, 11, false, Direction::In, 500 * BYTES_PER_MB, t + 6);
        assert!(agg.tick(1.0, t + 6).1.is_empty());

        agg.add(1, 10, true, Direction::In, 60 * BYTES_PER_MB, t + 7);
        let (_, alerts) = agg.tick(1.0, t + 7);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].app_name, "Chrome");
        assert_eq!(alerts[0].network_id, Some(10));
        assert_eq!(alerts[0].fired.window_minutes, 15);
    }
}
