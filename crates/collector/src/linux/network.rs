//! Asks NetworkManager (over D-Bus) whether an interface's connection is metered
//! and what it is called. Without NetworkManager everything is `Unknown`.

use std::time::{Duration, Instant};

use datasabi_protocol::Metered;
use zbus::blocking::{proxy::Builder, Connection, Proxy};
use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedObjectPath;

const NM: &str = "org.freedesktop.NetworkManager";
const RETRY_CONNECT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetInfo {
    pub detected: Metered,
    /// Connection name (usually the Wi-Fi SSID).
    pub name: Option<String>,
}

impl NetInfo {
    fn unknown() -> Self {
        Self {
            detected: Metered::Unknown,
            name: None,
        }
    }
}

/// NetworkManager's NMMetered: 0 unknown, 1 yes, 2 no, 3 guess-yes, 4 guess-no.
pub fn metered_from_nm(v: u32) -> Metered {
    match v {
        1 | 3 => Metered::Yes,
        2 | 4 => Metered::No,
        _ => Metered::Unknown,
    }
}

pub struct NetworkManager {
    conn: Option<Connection>,
    last_attempt: Option<Instant>,
    warned: bool,
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            conn: None,
            last_attempt: None,
            warned: false,
        }
    }

    fn connection(&mut self) -> Option<&Connection> {
        if self.conn.is_none()
            && self
                .last_attempt
                .is_none_or(|t| t.elapsed() >= RETRY_CONNECT)
        {
            self.last_attempt = Some(Instant::now());
            match Connection::system() {
                Ok(c) => self.conn = Some(c),
                Err(e) => {
                    if !self.warned {
                        tracing::warn!("system D-Bus unavailable, metered detection off: {e}");
                        self.warned = true;
                    }
                }
            }
        }
        self.conn.as_ref()
    }

    pub fn query(&mut self, iface: &str) -> NetInfo {
        let Some(conn) = self.connection() else {
            return NetInfo::unknown();
        };
        match query_nm(conn, iface) {
            Ok(info) => info,
            Err(e) => {
                tracing::debug!("NetworkManager query for {iface} failed: {e}");
                NetInfo::unknown()
            }
        }
    }
}

fn proxy<'a>(conn: &Connection, path: &'a str, iface: &'a str) -> zbus::Result<Proxy<'a>> {
    Builder::new(conn)
        .destination(NM)?
        .path(path)?
        .interface(iface)?
        .cache_properties(CacheProperties::No)
        .build()
}

fn query_nm(conn: &Connection, iface: &str) -> zbus::Result<NetInfo> {
    let nm = proxy(conn, "/org/freedesktop/NetworkManager", NM)?;
    let device: OwnedObjectPath = nm.call("GetDeviceByIpIface", &(iface,))?;
    let dev = proxy(
        conn,
        device.as_str(),
        "org.freedesktop.NetworkManager.Device",
    )?;
    let detected = metered_from_nm(dev.get_property::<u32>("Metered")?);
    let active: OwnedObjectPath = dev.get_property("ActiveConnection")?;
    let name = if active.as_str() == "/" {
        None
    } else {
        let ac = proxy(
            conn,
            active.as_str(),
            "org.freedesktop.NetworkManager.Connection.Active",
        )?;
        ac.get_property::<String>("Id")
            .ok()
            .filter(|s| !s.is_empty())
    };
    Ok(NetInfo { detected, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_nm_values() {
        assert_eq!(metered_from_nm(0), Metered::Unknown);
        assert_eq!(metered_from_nm(1), Metered::Yes);
        assert_eq!(metered_from_nm(3), Metered::Yes);
        assert_eq!(metered_from_nm(2), Metered::No);
        assert_eq!(metered_from_nm(4), Metered::No);
    }
}
