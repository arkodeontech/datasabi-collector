//! libpcap capture: one thread per interface, plus a manager thread that picks up
//! interfaces as they come and go (USB tethering, MiFi over USB, Wi-Fi reconnects).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use pcap::{Capture, Device};

use super::packet::{self, Parsed};

pub enum Msg {
    Packet {
        iface: Arc<str>,
        packet: Parsed,
    },
    /// All local addresses (every interface), refreshed periodically.
    Locals(HashSet<IpAddr>),
}

const RESCAN: Duration = Duration::from_secs(5);

/// Virtual interfaces whose traffic is also seen on a physical one (counting both
/// would double usage). VPN tunnels are skipped too: their traffic is counted on
/// the physical interface (with that network's metered setting) and attributed to
/// the VPN client. Tunnels with other names are caught by [`is_vpn_tunnel`].
const SKIP_PREFIXES: &[&str] = &[
    "lo",
    "any",
    "docker",
    "veth",
    "br-",
    "virbr",
    "vnet",
    "vboxnet",
    "vmnet",
    "tun",
    "tap",
    "wg",
    "tailscale",
    "zt",
    "nflog",
    "nfqueue",
    "dbus",
    "bluetooth",
    "usbmon",
    "lxc",
    "lxd",
    "cni",
    "flannel",
    "podman",
    // VPN apps that name their own interfaces (Proton's tunnel and kill switch,
    // NordVPN, Mullvad, PIA, Cisco AnyConnect, GlobalProtect).
    "proton",
    "pvpn",
    "ipv6leak",
    "nordlynx",
    "nordtun",
    "mullvad",
    "wgpia",
    "cscotun",
    "gpd",
];

pub fn eligible(dev: &Device, filter: &[String]) -> bool {
    if !filter.is_empty() {
        return filter.iter().any(|f| f == &dev.name);
    }
    !dev.flags.is_loopback()
        && dev.flags.is_up()
        && !SKIP_PREFIXES.iter().any(|p| dev.name.starts_with(p))
        && !is_vpn_tunnel(&LinkInfo::read(&dev.name))
}

/// `ARPHRD_NONE`: layer-3 links without a hardware header (WireGuard, tun).
const ARPHRD_NONE: u32 = 65534;

/// What sysfs says about an interface, enough to tell a VPN tunnel apart.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct LinkInfo {
    /// `/sys/class/net/<if>/type` (ARPHRD_*).
    pub link_type: Option<u32>,
    /// `DEVTYPE=` from `uevent` (e.g. "wireguard", "wlan").
    pub devtype: Option<String>,
    /// `tun_flags` exists: a tun/tap device (OpenVPN and most VPN apps).
    pub tun: bool,
    /// Backed by hardware (`device` link exists): Wi-Fi, Ethernet, USB modems.
    pub physical: bool,
}

impl LinkInfo {
    pub fn read(iface: &str) -> Self {
        let dir = std::path::Path::new("/sys/class/net").join(iface);
        let devtype = std::fs::read_to_string(dir.join("uevent"))
            .ok()
            .and_then(|u| {
                u.lines()
                    .find_map(|l| l.strip_prefix("DEVTYPE=").map(str::to_string))
            });
        Self {
            link_type: std::fs::read_to_string(dir.join("type"))
                .ok()
                .and_then(|t| t.trim().parse().ok()),
            devtype,
            tun: dir.join("tun_flags").exists(),
            physical: dir.join("device").exists(),
        }
    }
}

/// A VPN tunnel whatever its name: a virtual tun/tap device, a WireGuard link, or
/// another headerless layer-3 link. Hardware never counts: a USB modem in raw-IP
/// mode is also `ARPHRD_NONE` but carries the real (often metered) traffic.
pub fn is_vpn_tunnel(link: &LinkInfo) -> bool {
    if link.physical {
        return false;
    }
    link.tun || link.devtype.as_deref() == Some("wireguard") || link.link_type == Some(ARPHRD_NONE)
}

pub fn spawn_manager(filter: Vec<String>, tx: SyncSender<Msg>, shutdown: Arc<AtomicBool>) {
    let running: Arc<Mutex<HashSet<String>>> = Arc::default();
    let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
    thread::Builder::new()
        .name("capture-manager".into())
        .spawn(move || {
            let mut warned_empty = false;
            while !shutdown.load(Ordering::Relaxed) {
                match Device::list() {
                    Ok(devices) => {
                        let locals: HashSet<IpAddr> = devices
                            .iter()
                            .flat_map(|d| d.addresses.iter().map(|a| a.addr))
                            .collect();
                        if tx.send(Msg::Locals(locals)).is_err() {
                            return;
                        }
                        let mut started = 0;
                        for dev in devices.into_iter().filter(|d| eligible(d, &filter)) {
                            let mut r = running.lock().unwrap();
                            if r.contains(&dev.name) {
                                started += 1;
                                continue;
                            }
                            r.insert(dev.name.clone());
                            drop(r);
                            started += 1;
                            spawn_capture(
                                dev,
                                tx.clone(),
                                shutdown.clone(),
                                running.clone(),
                                dropped.clone(),
                            );
                        }
                        if started == 0 && !warned_empty {
                            tracing::warn!("no network interfaces to capture yet");
                            warned_empty = true;
                        }
                    }
                    Err(e) => tracing::error!("listing interfaces failed: {e}"),
                }
                let d = dropped.swap(0, Ordering::Relaxed);
                if d > 0 {
                    tracing::warn!("dropped {d} packets: engine is falling behind");
                }
                thread::sleep(RESCAN);
            }
        })
        .expect("spawn capture manager");
}

fn spawn_capture(
    dev: Device,
    tx: SyncSender<Msg>,
    shutdown: Arc<AtomicBool>,
    running: Arc<Mutex<HashSet<String>>>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
) {
    let name = dev.name.clone();
    let _ = thread::Builder::new()
        .name(format!("cap-{name}"))
        .spawn(move || {
            if let Err(e) = capture_loop(dev, &tx, &shutdown, &dropped) {
                tracing::warn!("capture on {name} stopped: {e}");
            }
            running.lock().unwrap().remove(&name);
        });
}

fn capture_loop(
    dev: Device,
    tx: &SyncSender<Msg>,
    shutdown: &AtomicBool,
    dropped: &std::sync::atomic::AtomicU64,
) -> anyhow::Result<()> {
    let iface: Arc<str> = Arc::from(dev.name.as_str());
    let mut cap = Capture::from_device(dev)?
        .promisc(false)
        .snaplen(128)
        .timeout(500)
        .immediate_mode(true)
        .open()?;
    if let Err(e) = cap.filter("ip or ip6", true) {
        tracing::debug!("BPF filter on {iface} not applied: {e}");
    }
    let linktype = cap.get_datalink().0;
    tracing::info!("capturing on {iface} (link type {linktype})");
    while !shutdown.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(p) => {
                if let Some(parsed) = packet::parse(linktype, p.data, p.header.len) {
                    let msg = Msg::Packet {
                        iface: iface.clone(),
                        packet: parsed,
                    };
                    match tx.try_send(msg) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(TrySendError::Disconnected(_)) => return Ok(()),
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(link_type: u32, devtype: Option<&str>, tun: bool, physical: bool) -> LinkInfo {
        LinkInfo {
            link_type: Some(link_type),
            devtype: devtype.map(str::to_string),
            tun,
            physical,
        }
    }

    #[test]
    fn vpn_tunnels_are_skipped_whatever_their_name() {
        // ProtonVPN / NordVPN (kernel WireGuard): headerless, virtual.
        assert!(is_vpn_tunnel(&link(65534, Some("wireguard"), false, false)));
        // OpenVPN tun (layer 3) and tap (layer 2, Ethernet type).
        assert!(is_vpn_tunnel(&link(65534, None, true, false)));
        assert!(is_vpn_tunnel(&link(1, None, true, false)));
    }

    #[test]
    fn real_networks_are_kept() {
        // Wi-Fi and Ethernet.
        assert!(!is_vpn_tunnel(&link(1, Some("wlan"), false, true)));
        assert!(!is_vpn_tunnel(&link(1, None, false, true)));
        // USB modem in raw-IP mode: also ARPHRD_NONE, but hardware — must be counted.
        assert!(!is_vpn_tunnel(&link(65534, Some("wwan"), false, true)));
        // PPP mobile modem (ARPHRD_PPP).
        assert!(!is_vpn_tunnel(&link(512, None, false, false)));
    }

    #[test]
    fn named_vpn_interfaces_are_on_the_skip_list() {
        for name in [
            "proton0",
            "ipv6leakintrf0",
            "pvpn-ks",
            "nordlynx",
            "tun0",
            "wg0",
        ] {
            assert!(
                SKIP_PREFIXES.iter().any(|p| name.starts_with(p)),
                "{name} should be skipped"
            );
        }
        for name in ["wlp2s0", "enp3s0", "usb0", "wwan0", "ppp0"] {
            assert!(
                !SKIP_PREFIXES.iter().any(|p| name.starts_with(p)),
                "{name} must be captured"
            );
        }
    }
}
