//! "This app is eating your data" alerts.
//!
//! Only traffic on networks treated as metered is recorded here. An app triggers an
//! alert when it crosses any rule inside a sliding window; after that it stays quiet
//! for [`COOLDOWN_SECS`] so the user is not nagged.

use std::collections::{HashMap, VecDeque};

use datasabi_protocol::BYTES_PER_MB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub window_minutes: u32,
    pub bytes: u64,
}

/// Defaults from the PRD: 50 MB in 15 minutes, or 150 MB in an hour.
pub const DEFAULT_RULES: [Rule; 2] = [
    Rule {
        window_minutes: 15,
        bytes: 50 * BYTES_PER_MB,
    },
    Rule {
        window_minutes: 60,
        bytes: 150 * BYTES_PER_MB,
    },
];

pub const COOLDOWN_SECS: i64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fired {
    pub app_id: i64,
    pub bytes: u64,
    pub window_minutes: u32,
}

pub struct AlertEngine {
    rules: Vec<Rule>,
    max_window_secs: i64,
    /// Per app: (minute start, bytes) oldest first.
    usage: HashMap<i64, VecDeque<(i64, u64)>>,
    last_fired: HashMap<i64, i64>,
}

fn minute_of(ts: i64) -> i64 {
    ts - ts.rem_euclid(60)
}

impl AlertEngine {
    pub fn new(mut rules: Vec<Rule>) -> Self {
        rules.sort_by_key(|r| r.window_minutes);
        let max_window_secs = rules
            .iter()
            .map(|r| r.window_minutes as i64 * 60)
            .max()
            .unwrap_or(0);
        Self {
            rules,
            max_window_secs,
            usage: HashMap::new(),
            last_fired: HashMap::new(),
        }
    }

    /// Records metered bytes used by `app_id` at time `ts` (Unix seconds).
    pub fn record(&mut self, app_id: i64, ts: i64, bytes: u64) {
        let minute = minute_of(ts);
        let q = self.usage.entry(app_id).or_default();
        match q.back_mut() {
            Some((m, b)) if *m == minute => *b += bytes,
            _ => {
                // Keep the deque ordered even if a late record arrives.
                let pos = q.iter().position(|(m, _)| *m > minute).unwrap_or(q.len());
                if pos > 0 && q[pos - 1].0 == minute {
                    q[pos - 1].1 += bytes;
                } else {
                    q.insert(pos, (minute, bytes));
                }
            }
        }
        let oldest = minute - self.max_window_secs;
        while q.front().is_some_and(|(m, _)| *m <= oldest) {
            q.pop_front();
        }
    }

    /// Bytes used by the app in the last `window_minutes` minutes (current minute included).
    pub fn window_bytes(&self, app_id: i64, now: i64, window_minutes: u32) -> u64 {
        let start = minute_of(now) - window_minutes as i64 * 60;
        self.usage
            .get(&app_id)
            .map(|q| q.iter().filter(|(m, _)| *m > start).map(|(_, b)| b).sum())
            .unwrap_or(0)
    }

    /// Returns an alert if the app crossed a rule and is not cooling down.
    pub fn check(&mut self, app_id: i64, now: i64) -> Option<Fired> {
        if let Some(last) = self.last_fired.get(&app_id) {
            if now - last < COOLDOWN_SECS {
                return None;
            }
        }
        for rule in &self.rules {
            let used = self.window_bytes(app_id, now, rule.window_minutes);
            if used >= rule.bytes {
                self.last_fired.insert(app_id, now);
                return Some(Fired {
                    app_id,
                    bytes: used,
                    window_minutes: rule.window_minutes,
                });
            }
        }
        None
    }

    /// Replaces rules without clearing the usage ring buffers or cooldown state.
    pub fn set_rules(&mut self, mut rules: Vec<Rule>) {
        rules.sort_by_key(|r| r.window_minutes);
        self.max_window_secs = rules
            .iter()
            .map(|r| r.window_minutes as i64 * 60)
            .max()
            .unwrap_or(0);
        self.rules = rules;
    }

    /// Drops apps with no usage left in any window.
    pub fn prune(&mut self, now: i64) {
        let oldest = minute_of(now) - self.max_window_secs;
        self.usage
            .retain(|_, q| q.back().is_some_and(|(m, _)| *m > oldest));
        self.last_fired.retain(|_, t| now - *t < COOLDOWN_SECS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = BYTES_PER_MB;
    const T0: i64 = 1_700_000_000 - 1_700_000_000 % 60;

    #[test]
    fn fires_on_short_burst() {
        let mut a = AlertEngine::new(DEFAULT_RULES.to_vec());
        for i in 0..10 {
            a.record(1, T0 + i * 60, 4 * MB);
        }
        assert_eq!(a.check(1, T0 + 9 * 60), None); // 40 MB
        a.record(1, T0 + 9 * 60, 10 * MB);
        let f = a.check(1, T0 + 9 * 60).expect("should fire");
        assert_eq!(f.window_minutes, 15);
        assert_eq!(f.bytes, 50 * MB);
    }

    #[test]
    fn slow_usage_hits_hourly_rule_only() {
        let mut a = AlertEngine::new(DEFAULT_RULES.to_vec());
        // 3 MB per minute: 45 MB per 15 min, 150 MB after 50 minutes.
        let mut fired = None;
        for i in 0..60 {
            let t = T0 + i * 60;
            a.record(7, t, 3 * MB);
            if let Some(f) = a.check(7, t) {
                fired = Some((i, f));
                break;
            }
        }
        let (minute, f) = fired.expect("hourly rule should fire");
        assert_eq!(minute, 49);
        assert_eq!(f.window_minutes, 60);
    }

    #[test]
    fn old_usage_leaves_the_window() {
        let mut a = AlertEngine::new(DEFAULT_RULES.to_vec());
        a.record(2, T0, 45 * MB);
        a.record(2, T0 + 20 * 60, 10 * MB);
        assert_eq!(a.check(2, T0 + 20 * 60), None);
        assert_eq!(a.window_bytes(2, T0 + 20 * 60, 60), 55 * MB);
    }

    #[test]
    fn cooldown_suppresses_repeat_alerts() {
        let mut a = AlertEngine::new(DEFAULT_RULES.to_vec());
        a.record(3, T0, 60 * MB);
        assert!(a.check(3, T0).is_some());
        a.record(3, T0 + 120, 60 * MB);
        assert!(a.check(3, T0 + 120).is_none());
        a.record(3, T0 + COOLDOWN_SECS + 60, 60 * MB);
        assert!(a.check(3, T0 + COOLDOWN_SECS + 60).is_some());
    }
}
