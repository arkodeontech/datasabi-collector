//! Wire protocol between the DataSabi collector (privileged service) and its clients
//! (the desktop app, `dsctl`).
//!
//! Transport: a local stream socket (Unix socket on Linux, named pipe on Windows).
//! Framing: newline-delimited JSON. Each line is one message.
//!
//! * Client -> collector: [`ClientMessage`] (`{"id":1,"request":{"type":"ping"}}`)
//! * Collector -> client: [`ServerMessage`], either a `response` to a request id or an
//!   unsolicited `event` (only after the client sent [`Request::Subscribe`]).

use serde::{Deserialize, Serialize};

/// Bumped whenever a breaking change is made to the messages below.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default socket path used by the Linux collector.
pub const DEFAULT_SOCKET_PATH: &str = "/run/datasabi/collector.sock";

/// Bytes per megabyte as displayed to users (decision: 1 GB = 1024 MB).
pub const BYTES_PER_MB: u64 = 1024 * 1024;

/// Time range for summaries and history. Ranges are calendar based in local time:
/// today since midnight, week since Monday, month since the 1st.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Range {
    Today,
    Week,
    Month,
}

/// A request sent by a client. `id` is echoed back in the matching response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientMessage {
    pub id: u64,
    pub request: Request,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Health check; returns [`Response::Pong`].
    Ping,
    /// Totals and per-app usage for a range; returns [`Response::Summary`].
    GetSummary { range: Range },
    /// Current per-app transfer rates; returns [`Response::Live`].
    GetLive,
    /// Per-minute usage of one app; returns [`Response::AppHistory`].
    GetAppHistory { app_id: i64, range: Range },
    /// Known networks and whether they are treated as metered; returns [`Response::Networks`].
    GetNetworks,
    /// Mark a network as metered (`Some(true)`), unlimited (`Some(false)`) or back to
    /// automatic detection (`None`). Returns [`Response::Ok`].
    SetNetworkOverride {
        network_id: i64,
        metered: Option<bool>,
    },
    /// Start receiving [`Event`]s on this connection. Returns [`Response::Ok`].
    Subscribe,
    /// Retrieve current alert rules and quiet-mode state; returns [`Response::AlertConfig`].
    GetAlertConfig,
    /// Add or update an alert rule keyed by `window_minutes`. Returns [`Response::Ok`].
    SetAlertRule {
        window_minutes: u32,
        threshold_bytes: u64,
    },
    /// Remove an alert rule by id. Returns [`Response::Ok`] or [`Response::Error`].
    DeleteAlertRule { rule_id: i64 },
    /// Silence alerts until `until_unix` (Unix seconds); `None` clears quiet mode.
    /// Returns [`Response::Ok`].
    SetQuietMode { until_unix: Option<i64> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerMessage {
    Response { id: u64, body: Response },
    Event { body: Event },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong {
        version: String,
        protocol: u32,
    },
    Summary(Summary),
    Live(LiveSnapshot),
    AppHistory(AppHistory),
    Networks {
        networks: Vec<NetworkInfo>,
    },
    AlertConfig {
        rules: Vec<AlertRule>,
        /// When set, alerts are silenced until this Unix timestamp.
        quiet_until: Option<i64>,
    },
    Ok,
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Sent about once a second to subscribers.
    Live(LiveSnapshot),
    /// An app crossed an alert threshold on a metered network.
    AlertFired(Alert),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppUsage {
    pub app_id: i64,
    pub name: String,
    /// Executable path, Flatpak ID or Snap name used to group processes.
    pub key: String,
    /// Bytes received (download).
    pub bytes_in: u64,
    /// Bytes sent (upload).
    pub bytes_out: u64,
}

impl AppUsage {
    pub fn total(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    pub range: Range,
    /// Start of the range, Unix seconds.
    pub since_unix: i64,
    pub total_in: u64,
    pub total_out: u64,
    /// Sorted by total usage, largest first.
    pub apps: Vec<AppUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRate {
    pub app_id: i64,
    pub name: String,
    /// Download rate, bytes per second.
    pub rx_bps: u64,
    /// Upload rate, bytes per second.
    pub tx_bps: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveSnapshot {
    pub at_unix: i64,
    pub total_rx_bps: u64,
    pub total_tx_bps: u64,
    /// Sorted by total rate, largest first. Idle apps are omitted.
    pub apps: Vec<AppRate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsagePoint {
    /// Start of the minute, Unix seconds.
    pub minute_unix: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppHistory {
    pub app_id: i64,
    pub range: Range,
    pub points: Vec<UsagePoint>,
}

/// Metered status as reported by the operating system.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Metered {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInfo {
    pub id: i64,
    /// Interface name, e.g. `wlp2s0`, `usb0`.
    pub interface: String,
    /// Connection name or Wi-Fi SSID when known.
    pub name: Option<String>,
    /// What the OS reports.
    pub detected: Metered,
    /// Set by the user; overrides detection.
    pub user_override: Option<bool>,
    /// The value the collector actually uses for alerts.
    pub treated_as_metered: bool,
    /// Whether the network carried traffic in the last few minutes.
    pub active: bool,
}

/// One persisted alert rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertRule {
    pub id: i64,
    pub window_minutes: u32,
    /// Alert fires when an app exceeds this many bytes in `window_minutes`.
    pub threshold_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    pub app_id: i64,
    pub app_name: String,
    /// Bytes used by the app inside the window.
    pub bytes: u64,
    pub window_minutes: u32,
    pub network: Option<String>,
    pub at_unix: i64,
}

/// Encode a message as one line of JSON (with trailing newline).
pub fn encode_line<T: Serialize>(msg: &T) -> serde_json::Result<String> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    Ok(s)
}

/// Decode one line of JSON (trailing whitespace allowed).
pub fn decode_line<'a, T: Deserialize<'a>>(line: &'a str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim_end())
}

/// Human-friendly size using 1024-based units, e.g. `420 MB`, `1.4 GB`.
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < KB * KB {
        format!("{:.0} KB", b / KB)
    } else if b < KB * KB * KB {
        format!("{:.0} MB", b / (KB * KB))
    } else {
        format!("{:.1} GB", b / (KB * KB * KB))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let msg = ClientMessage {
            id: 7,
            request: Request::GetSummary {
                range: Range::Today,
            },
        };
        let line = encode_line(&msg).unwrap();
        assert_eq!(
            line,
            "{\"id\":7,\"request\":{\"type\":\"get_summary\",\"range\":\"today\"}}\n"
        );
        let back: ClientMessage = decode_line(&line).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn response_and_event_shapes() {
        let resp = ServerMessage::Response {
            id: 1,
            body: Response::Pong {
                version: "0.1.0".into(),
                protocol: PROTOCOL_VERSION,
            },
        };
        let line = encode_line(&resp).unwrap();
        assert!(line.contains("\"kind\":\"response\""));
        assert!(line.contains("\"type\":\"pong\""));
        assert_eq!(decode_line::<ServerMessage>(&line).unwrap(), resp);

        let ev = ServerMessage::Event {
            body: Event::AlertFired(Alert {
                app_id: 3,
                app_name: "Chrome".into(),
                bytes: 420 * BYTES_PER_MB,
                window_minutes: 60,
                network: Some("MTN MiFi".into()),
                at_unix: 1_700_000_000,
            }),
        };
        let line = encode_line(&ev).unwrap();
        assert!(line.contains("\"type\":\"alert_fired\""));
        assert_eq!(decode_line::<ServerMessage>(&line).unwrap(), ev);
    }

    #[test]
    fn formats_sizes_with_1024_units() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(420 * BYTES_PER_MB), "420 MB");
        assert_eq!(format_bytes(1536 * BYTES_PER_MB), "1.5 GB");
    }
}
