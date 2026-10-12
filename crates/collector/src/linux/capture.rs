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
/// the physical interface and attributed to the VPN client.
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
];

pub fn eligible(dev: &Device, filter: &[String]) -> bool {
    if !filter.is_empty() {
        return filter.iter().any(|f| f == &dev.name);
    }
    !dev.flags.is_loopback()
        && dev.flags.is_up()
        && !SKIP_PREFIXES.iter().any(|p| dev.name.starts_with(p))
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
