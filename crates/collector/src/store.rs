//! SQLite storage. Only byte counts per app, per network, per minute are stored:
//! never packet contents, URLs or domains.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Local, NaiveTime, TimeZone};
use datasabi_protocol::{
    AlertRule, AppHistory, AppUsage, Metered, NetworkInfo, Range, Summary, UsagePoint,
};
use rusqlite::{params, Connection, OptionalExtension};

/// Longest alert window accepted (24 hours); the alert engine keeps per-minute
/// history for the longest rule.
pub const MAX_ALERT_WINDOW_MINUTES: u32 = 1440;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS apps (
    id          INTEGER PRIMARY KEY,
    key         TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    exe         TEXT,
    first_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS networks (
    id            INTEGER PRIMARY KEY,
    interface     TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    detected      TEXT NOT NULL DEFAULT 'unknown',
    user_override INTEGER,
    last_seen     INTEGER NOT NULL,
    UNIQUE (interface, name)
);
CREATE TABLE IF NOT EXISTS usage_minute (
    app_id     INTEGER NOT NULL,
    network_id INTEGER NOT NULL,
    minute_ts  INTEGER NOT NULL,
    bytes_in   INTEGER NOT NULL,
    bytes_out  INTEGER NOT NULL,
    PRIMARY KEY (app_id, network_id, minute_ts)
);
CREATE INDEX IF NOT EXISTS idx_usage_minute_ts ON usage_minute (minute_ts);
CREATE TABLE IF NOT EXISTS alerts_log (
    id             INTEGER PRIMARY KEY,
    app_id         INTEGER NOT NULL,
    network_id     INTEGER,
    ts             INTEGER NOT NULL,
    bytes          INTEGER NOT NULL,
    window_minutes INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_rules (
    id              INTEGER PRIMARY KEY,
    window_minutes  INTEGER NOT NULL UNIQUE,
    threshold_bytes INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_hour (
    app_id     INTEGER NOT NULL,
    network_id INTEGER NOT NULL,
    hour_ts    INTEGER NOT NULL,
    bytes_in   INTEGER NOT NULL,
    bytes_out  INTEGER NOT NULL,
    PRIMARY KEY (app_id, network_id, hour_ts)
);
CREATE INDEX IF NOT EXISTS idx_usage_hour_ts ON usage_hour (hour_ts);
CREATE TABLE IF NOT EXISTS usage_day (
    app_id     INTEGER NOT NULL,
    network_id INTEGER NOT NULL,
    day_ts     INTEGER NOT NULL,
    bytes_in   INTEGER NOT NULL,
    bytes_out  INTEGER NOT NULL,
    PRIMARY KEY (app_id, network_id, day_ts)
);
CREATE INDEX IF NOT EXISTS idx_usage_day_ts ON usage_day (day_ts);
"#;

/// One row to add to `usage_minute`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageRow {
    pub app_id: i64,
    pub network_id: i64,
    pub minute_ts: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Per (app, network): (minute start, bytes) points.
pub type RecentUsage = HashMap<(i64, i64), Vec<(i64, u64)>>;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        let store = Self { conn };
        store.seed_default_rules_if_empty()?;
        Ok(store)
    }

    fn seed_default_rules_if_empty(&self) -> Result<()> {
        use crate::alerts::DEFAULT_RULES;
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM alert_rules", [], |r| r.get(0))?;
        if count == 0 {
            for rule in &DEFAULT_RULES {
                self.conn.execute(
                    "INSERT OR IGNORE INTO alert_rules (window_minutes, threshold_bytes) VALUES (?1, ?2)",
                    params![rule.window_minutes, rule.bytes as i64],
                )?;
            }
        }
        Ok(())
    }

    pub fn get_alert_rules(&self) -> Result<Vec<AlertRule>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, window_minutes, threshold_bytes FROM alert_rules ORDER BY window_minutes",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AlertRule {
                    id: r.get(0)?,
                    window_minutes: r.get::<_, u32>(1)?,
                    threshold_bytes: r.get::<_, i64>(2)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Returns active rules as the alert engine's internal type.
    pub fn get_active_rules(&self) -> Result<Vec<crate::alerts::Rule>> {
        let rules = self.get_alert_rules()?;
        Ok(rules
            .into_iter()
            .map(|r| crate::alerts::Rule {
                window_minutes: r.window_minutes,
                bytes: r.threshold_bytes,
            })
            .collect())
    }

    /// Upsert a rule keyed by `window_minutes`. Returns the row id.
    pub fn set_alert_rule(&self, window_minutes: u32, threshold_bytes: u64) -> Result<i64> {
        if !(1..=MAX_ALERT_WINDOW_MINUTES).contains(&window_minutes) {
            anyhow::bail!(
                "alert window must be between 1 and {MAX_ALERT_WINDOW_MINUTES} minutes, got {window_minutes}"
            );
        }
        if threshold_bytes == 0 {
            anyhow::bail!("alert threshold must be more than 0 bytes");
        }
        let id = self.conn.query_row(
            "INSERT INTO alert_rules (window_minutes, threshold_bytes) VALUES (?1, ?2)
             ON CONFLICT(window_minutes) DO UPDATE SET threshold_bytes = excluded.threshold_bytes
             RETURNING id",
            params![window_minutes, threshold_bytes as i64],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    pub fn delete_alert_rule(&self, id: i64) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM alert_rules WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    pub fn get_quiet_until(&self) -> Result<Option<i64>> {
        let v: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'quiet_until'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v.and_then(|s| s.parse::<i64>().ok()).filter(|&t| t > 0))
    }

    pub fn set_quiet_until(&self, until: Option<i64>) -> Result<()> {
        match until {
            Some(t) => {
                self.conn.execute(
                    "INSERT INTO settings (key, value) VALUES ('quiet_until', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![t.to_string()],
                )?;
            }
            None => {
                self.conn
                    .execute("DELETE FROM settings WHERE key = 'quiet_until'", [])?;
            }
        }
        Ok(())
    }

    pub fn upsert_app(&self, key: &str, name: &str, exe: Option<&str>, now: i64) -> Result<i64> {
        let id = self.conn.query_row(
            "INSERT INTO apps (key, name, exe, first_seen) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET name = excluded.name, exe = COALESCE(excluded.exe, apps.exe)
             RETURNING id",
            params![key, name, exe, now],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    pub fn upsert_network(
        &self,
        interface: &str,
        name: Option<&str>,
        detected: Metered,
        now: i64,
    ) -> Result<i64> {
        let id = self.conn.query_row(
            "INSERT INTO networks (interface, name, detected, last_seen) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(interface, name) DO UPDATE SET detected = excluded.detected, last_seen = excluded.last_seen
             RETURNING id",
            params![interface, name.unwrap_or(""), metered_to_str(detected), now],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    /// Adds byte counts; rows for the same app/network/minute are summed.
    pub fn add_usage(&mut self, rows: &[UsageRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO usage_minute (app_id, network_id, minute_ts, bytes_in, bytes_out)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(app_id, network_id, minute_ts) DO UPDATE SET
                    bytes_in = bytes_in + excluded.bytes_in,
                    bytes_out = bytes_out + excluded.bytes_out",
            )?;
            for r in rows {
                stmt.execute(params![
                    r.app_id,
                    r.network_id,
                    r.minute_ts,
                    r.bytes_in as i64,
                    r.bytes_out as i64
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Aggregate `usage_minute` rows older than 7 days into `usage_hour` and delete them.
    pub fn rollup_minutes(&mut self, now: i64) -> Result<()> {
        let cutoff = now - 7 * 86_400;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO usage_hour (app_id, network_id, hour_ts, bytes_in, bytes_out)
             SELECT app_id, network_id,
                    minute_ts - (minute_ts % 3600),
                    SUM(bytes_in), SUM(bytes_out)
             FROM usage_minute WHERE minute_ts < ?1
             GROUP BY app_id, network_id, minute_ts - (minute_ts % 3600)
             ON CONFLICT(app_id, network_id, hour_ts) DO UPDATE SET
                bytes_in  = bytes_in  + excluded.bytes_in,
                bytes_out = bytes_out + excluded.bytes_out",
            params![cutoff],
        )?;
        tx.execute(
            "DELETE FROM usage_minute WHERE minute_ts < ?1",
            params![cutoff],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Aggregate `usage_hour` rows older than 90 days into `usage_day` and delete them.
    pub fn rollup_hours(&mut self, now: i64) -> Result<()> {
        let cutoff = now - 90 * 86_400;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO usage_day (app_id, network_id, day_ts, bytes_in, bytes_out)
             SELECT app_id, network_id,
                    hour_ts - (hour_ts % 86400),
                    SUM(bytes_in), SUM(bytes_out)
             FROM usage_hour WHERE hour_ts < ?1
             GROUP BY app_id, network_id, hour_ts - (hour_ts % 86400)
             ON CONFLICT(app_id, network_id, day_ts) DO UPDATE SET
                bytes_in  = bytes_in  + excluded.bytes_in,
                bytes_out = bytes_out + excluded.bytes_out",
            params![cutoff],
        )?;
        tx.execute("DELETE FROM usage_hour WHERE hour_ts < ?1", params![cutoff])?;
        tx.commit()?;
        Ok(())
    }

    pub fn log_alert(
        &self,
        app_id: i64,
        network_id: Option<i64>,
        ts: i64,
        bytes: u64,
        window_minutes: u32,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO alerts_log (app_id, network_id, ts, bytes, window_minutes) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![app_id, network_id, ts, bytes as i64, window_minutes],
        )?;
        Ok(())
    }

    pub fn summary(&self, range: Range, now: DateTime<Local>) -> Result<Summary> {
        let since = range_start(range, now);
        let mut stmt = self.conn.prepare_cached(
            "SELECT a.id, a.name, a.key, SUM(u.bi), SUM(u.bo)
             FROM (
               SELECT app_id, bytes_in as bi, bytes_out as bo FROM usage_minute WHERE minute_ts >= ?1
               UNION ALL
               SELECT app_id, bytes_in, bytes_out FROM usage_hour WHERE hour_ts >= ?1
               UNION ALL
               SELECT app_id, bytes_in, bytes_out FROM usage_day WHERE day_ts >= ?1
             ) u
             JOIN apps a ON a.id = u.app_id
             GROUP BY a.id
             ORDER BY SUM(u.bi) + SUM(u.bo) DESC",
        )?;
        let apps = stmt
            .query_map(params![since], |r| {
                Ok(AppUsage {
                    app_id: r.get(0)?,
                    name: r.get(1)?,
                    key: r.get(2)?,
                    bytes_in: r.get::<_, i64>(3)? as u64,
                    bytes_out: r.get::<_, i64>(4)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Summary {
            range,
            since_unix: since,
            total_in: apps.iter().map(|a| a.bytes_in).sum(),
            total_out: apps.iter().map(|a| a.bytes_out).sum(),
            apps,
        })
    }

    pub fn app_history(
        &self,
        app_id: i64,
        range: Range,
        now: DateTime<Local>,
    ) -> Result<AppHistory> {
        let since = range_start(range, now);
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, SUM(bi), SUM(bo) FROM (
               SELECT minute_ts as ts, bytes_in as bi, bytes_out as bo
               FROM usage_minute WHERE app_id = ?1 AND minute_ts >= ?2
               UNION ALL
               SELECT hour_ts, bytes_in, bytes_out
               FROM usage_hour WHERE app_id = ?1 AND hour_ts >= ?2
               UNION ALL
               SELECT day_ts, bytes_in, bytes_out
               FROM usage_day WHERE app_id = ?1 AND day_ts >= ?2
             ) GROUP BY ts ORDER BY ts",
        )?;
        let points = stmt
            .query_map(params![app_id, since], |r| {
                Ok(UsagePoint {
                    minute_unix: r.get(0)?,
                    bytes_in: r.get::<_, i64>(1)? as u64,
                    bytes_out: r.get::<_, i64>(2)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(AppHistory {
            app_id,
            range,
            points,
        })
    }

    pub fn networks(&self, now: i64) -> Result<Vec<NetworkInfo>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, interface, name, detected, user_override, last_seen FROM networks ORDER BY last_seen DESC",
        )?;
        let mut rows = stmt
            .query_map([], |r| {
                let name: String = r.get(2)?;
                let detected = metered_from_str(&r.get::<_, String>(3)?);
                let user_override: Option<bool> = r.get::<_, Option<i64>>(4)?.map(|v| v != 0);
                let last_seen: i64 = r.get(5)?;
                Ok(NetworkInfo {
                    id: r.get(0)?,
                    interface: r.get(1)?,
                    name: if name.is_empty() { None } else { Some(name) },
                    detected,
                    user_override,
                    treated_as_metered: treated_as_metered(detected, user_override),
                    active: now - last_seen <= 300,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Rows are newest first. An interface is on one network at a time, so only
        // its most recent row can be active; an older row seen moments ago (e.g. the
        // same connection before it was renamed) is not.
        let mut seen_interfaces = std::collections::HashSet::new();
        for n in &mut rows {
            if !seen_interfaces.insert(n.interface.clone()) {
                n.active = false;
            }
        }
        Ok(rows)
    }

    pub fn set_network_override(&self, id: i64, metered: Option<bool>) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE networks SET user_override = ?2 WHERE id = ?1",
            params![id, metered.map(|m| m as i64)],
        )?;
        Ok(n > 0)
    }

    pub fn network_override(&self, id: i64) -> Result<Option<bool>> {
        let v: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT user_override FROM networks WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v.flatten().map(|v| v != 0))
    }

    /// Per-app totals per minute since `since` (used to rebuild alert windows after a restart).
    pub fn recent_usage(&self, since: i64) -> Result<RecentUsage> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT app_id, network_id, minute_ts, bytes_in + bytes_out FROM usage_minute WHERE minute_ts >= ?1",
        )?;
        let mut out = RecentUsage::new();
        let rows = stmt.query_map(params![since], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)? as u64,
            ))
        })?;
        for row in rows {
            let (app, net, ts, bytes) = row?;
            out.entry((app, net)).or_default().push((ts, bytes));
        }
        Ok(out)
    }
}

/// Alerts use metered thresholds unless the user (or the OS, explicitly) says the
/// network is unlimited. Unknown counts as metered: MiFi routers rarely announce
/// themselves as metered, and they are exactly the networks we care about.
pub fn treated_as_metered(detected: Metered, user_override: Option<bool>) -> bool {
    user_override.unwrap_or(detected != Metered::No)
}

pub fn metered_to_str(m: Metered) -> &'static str {
    match m {
        Metered::Yes => "yes",
        Metered::No => "no",
        Metered::Unknown => "unknown",
    }
}

pub fn metered_from_str(s: &str) -> Metered {
    match s {
        "yes" => Metered::Yes,
        "no" => Metered::No,
        _ => Metered::Unknown,
    }
}

/// Start of a calendar range in local time, as Unix seconds.
pub fn range_start(range: Range, now: DateTime<Local>) -> i64 {
    let today = now.date_naive();
    let date = match range {
        Range::Today => today,
        Range::Week => {
            today - chrono::Duration::days(today.weekday().num_days_from_monday() as i64)
        }
        Range::Month => today.with_day(1).unwrap_or(today),
    };
    let naive = date.and_time(NaiveTime::MIN);
    Local
        .from_local_datetime(&naive)
        .earliest()
        .map(|d| d.timestamp())
        .unwrap_or_else(|| naive.and_utc().timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("t.db")).unwrap();
        (dir, s)
    }

    #[test]
    fn invalid_alert_rules_are_rejected() {
        let (_d, s) = store();
        assert!(s.set_alert_rule(0, 50 * 1024 * 1024).is_err());
        assert!(s
            .set_alert_rule(MAX_ALERT_WINDOW_MINUTES + 1, 50 * 1024 * 1024)
            .is_err());
        assert!(s.set_alert_rule(15, 0).is_err());
        assert!(s.set_alert_rule(MAX_ALERT_WINDOW_MINUTES, 1).is_ok());
    }

    #[test]
    fn only_latest_network_per_interface_is_active() {
        let (_d, s) = store();
        s.upsert_network("wlan0", Some("Old name"), Metered::Yes, 100)
            .unwrap();
        s.upsert_network("eth0", Some("Office"), Metered::No, 150)
            .unwrap();
        s.upsert_network("wlan0", Some("MiFi"), Metered::Yes, 200)
            .unwrap();
        let active: Vec<(String, bool)> = s
            .networks(250)
            .unwrap()
            .into_iter()
            .map(|n| (n.name.unwrap(), n.active))
            .collect();
        assert_eq!(
            active,
            vec![
                ("MiFi".to_string(), true),
                ("Office".to_string(), true),
                ("Old name".to_string(), false),
            ]
        );
    }

    #[test]
    fn upsert_app_refreshes_stored_name() {
        let (_d, s) = store();
        let key = "/usr/share/code/code";
        let id = s
            .upsert_app(key, "Visual Studio Code - URL Handler", None, 0)
            .unwrap();
        assert_eq!(
            s.upsert_app(key, "Visual Studio Code", None, 1).unwrap(),
            id
        );
        let name: String = s
            .conn
            .query_row("SELECT name FROM apps WHERE id = ?1", [id], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "Visual Studio Code");
    }

    #[test]
    fn usage_is_summed_and_summarised() {
        let (_d, mut s) = store();
        let now = Local::now();
        let ts = now.timestamp() / 60 * 60;
        let chrome = s
            .upsert_app("/opt/google/chrome/chrome", "Google Chrome", None, ts)
            .unwrap();
        let apt = s
            .upsert_app("/usr/lib/apt/methods/http", "APT", None, ts)
            .unwrap();
        assert_eq!(
            s.upsert_app("/opt/google/chrome/chrome", "Google Chrome", None, ts)
                .unwrap(),
            chrome
        );
        let net = s
            .upsert_network("wlan0", Some("MTN MiFi"), Metered::Unknown, ts)
            .unwrap();

        s.add_usage(&[
            UsageRow {
                app_id: chrome,
                network_id: net,
                minute_ts: ts,
                bytes_in: 1000,
                bytes_out: 100,
            },
            UsageRow {
                app_id: apt,
                network_id: net,
                minute_ts: ts,
                bytes_in: 5000,
                bytes_out: 10,
            },
        ])
        .unwrap();
        s.add_usage(&[UsageRow {
            app_id: chrome,
            network_id: net,
            minute_ts: ts,
            bytes_in: 9000,
            bytes_out: 0,
        }])
        .unwrap();

        let sum = s.summary(Range::Today, now).unwrap();
        assert_eq!(sum.apps.len(), 2);
        assert_eq!(sum.apps[0].name, "Google Chrome");
        assert_eq!(sum.apps[0].bytes_in, 10_000);
        assert_eq!(sum.total_in, 15_000);
        assert_eq!(sum.total_out, 110);

        let hist = s.app_history(chrome, Range::Today, now).unwrap();
        assert_eq!(hist.points.len(), 1);
        assert_eq!(hist.points[0].bytes_in, 10_000);
    }

    #[test]
    fn network_override_controls_metering() {
        let (_d, s) = store();
        let id = s
            .upsert_network("wlan0", Some("Home fibre"), Metered::Unknown, 100)
            .unwrap();
        assert!(s.networks(100).unwrap()[0].treated_as_metered);
        s.set_network_override(id, Some(false)).unwrap();
        let n = &s.networks(100).unwrap()[0];
        assert!(!n.treated_as_metered);
        assert_eq!(n.user_override, Some(false));
        assert_eq!(s.network_override(id).unwrap(), Some(false));
        s.set_network_override(id, None).unwrap();
        assert_eq!(s.network_override(id).unwrap(), None);
    }

    #[test]
    fn range_starts_are_ordered() {
        let now = Local::now();
        let t = range_start(Range::Today, now);
        let w = range_start(Range::Week, now);
        let m = range_start(Range::Month, now);
        assert!(t <= now.timestamp());
        assert!(w <= t);
        assert!(now.timestamp() - t < 86_400 + 3_600);
        let _ = m;
    }

    #[test]
    fn rollup_moves_data_across_tiers() {
        let (_d, mut s) = store();
        let now = Local::now();
        // Write a minute row 10 days ago (older than 7-day minute retention).
        let old_ts = now.timestamp() - 10 * 86_400;
        let old_minute = old_ts - old_ts.rem_euclid(60);
        let app = s.upsert_app("app", "App", None, old_ts).unwrap();
        let net = s
            .upsert_network("eth0", None, Metered::Yes, old_ts)
            .unwrap();
        s.add_usage(&[UsageRow {
            app_id: app,
            network_id: net,
            minute_ts: old_minute,
            bytes_in: 100,
            bytes_out: 50,
        }])
        .unwrap();

        // Before rollup the summary (month) should see the data.
        let sum_before = s.summary(Range::Month, now).unwrap();
        assert_eq!(sum_before.apps[0].bytes_in, 100);

        // Run rollup: minute → hour.
        s.rollup_minutes(now.timestamp()).unwrap();

        // usage_minute row should be gone; hour row should exist.
        let min_count: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM usage_minute", [], |r| r.get(0))
            .unwrap();
        let hr_count: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM usage_hour", [], |r| r.get(0))
            .unwrap();
        assert_eq!(min_count, 0);
        assert_eq!(hr_count, 1);

        // Summary should still show the same total (now read from usage_hour).
        let sum_after = s.summary(Range::Month, now).unwrap();
        assert_eq!(sum_after.apps[0].bytes_in, 100);
    }
}
