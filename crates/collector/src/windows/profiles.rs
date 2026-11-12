//! Connection profiles (Windows.Networking.Connectivity): each connected adapter's
//! network name ("Isaac's Galaxy A12", the Wi-Fi name) and Windows' cost setting for it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use datasabi_protocol::Metered;
use windows::Foundation::EventRegistrationToken;
use windows::Networking::Connectivity::{
    NetworkConnectivityLevel, NetworkInformation, NetworkStatusChangedEventHandler,
};

use crate::winrules::{cost_metered, guid_text};

/// A connected adapter's network.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub name: Option<String>,
    pub detected: Metered,
}

/// The connected profiles, by their adapter's GUID. Errors on one profile skip it.
pub fn read() -> HashMap<String, Profile> {
    let mut out = HashMap::new();
    let profiles = match NetworkInformation::GetConnectionProfiles() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("reading connection profiles failed: {e}");
            return out;
        }
    };
    let count = profiles.Size().unwrap_or(0);
    for i in 0..count {
        let Ok(p) = profiles.GetAt(i) else { continue };
        let connected = p
            .GetNetworkConnectivityLevel()
            .map(|l| l != NetworkConnectivityLevel::None)
            .unwrap_or(false);
        if !connected {
            continue;
        }
        let Ok(id) = p.NetworkAdapter().and_then(|a| a.NetworkAdapterId()) else {
            continue;
        };
        let name = p
            .ProfileName()
            .ok()
            .map(|n| n.to_string())
            .filter(|n| !n.is_empty());
        let detected = p
            .GetConnectionCost()
            .and_then(|c| c.NetworkCostType())
            .map(|t| cost_metered(t.0))
            .unwrap_or(Metered::Unknown);
        out.insert(
            guid_text(id.data1, id.data2, id.data3, id.data4),
            Profile { name, detected },
        );
    }
    out
}

/// Sets `changed` whenever Windows reports a network change (connect, disconnect, a
/// cost or profile change), so the capture re-reads the profiles at once instead of
/// waiting for its next periodic read. Stops watching when dropped.
pub struct Watch {
    token: Option<EventRegistrationToken>,
}

impl Watch {
    pub fn start(changed: Arc<AtomicBool>) -> Self {
        let handler = NetworkStatusChangedEventHandler::new(move |_| {
            changed.store(true, Ordering::Relaxed);
            Ok(())
        });
        match NetworkInformation::NetworkStatusChanged(&handler) {
            Ok(token) => Self { token: Some(token) },
            Err(e) => {
                tracing::warn!("network change notifications unavailable: {e}; reading every few seconds instead");
                Self { token: None }
            }
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        if let Some(t) = self.token.take() {
            let _ = NetworkInformation::RemoveNetworkStatusChanged(t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::adapters::counters;

    /// Every connected profile belongs to a real adapter (its GUID is in the counter
    /// table), and at least one is connected. Needs a network: ignored by default, run
    /// on Windows CI with `--ignored`.
    #[test]
    #[ignore]
    fn connected_profiles_belong_to_adapters() {
        let profiles = read();
        let counters = counters().unwrap();
        assert!(!profiles.is_empty(), "no connected profile");
        for id in profiles.keys() {
            assert!(
                counters.contains_key(id),
                "profile for unknown adapter {id}"
            );
        }
    }
}
