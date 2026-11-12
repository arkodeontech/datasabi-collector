//! The Windows capture's rules, kept apart from the Windows API so they build and are
//! tested on every platform: which way an ETW network event goes, which adapters are
//! VPN tunnels, how a process is named, and how lost events are read.

// Only the tests use these on other platforms.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use datasabi_protocol::Metered;

use crate::aggregate::Direction;
use crate::engine::AppInfo;

/// Microsoft-Windows-Kernel-Network: TCP and UDP sends and receives, IPv4 and IPv6.
pub const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
/// KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6.
pub const KERNEL_NETWORK_KEYWORDS: u64 = 0x10 | 0x20;
/// Microsoft-Windows-Kernel-Process: process start and stop, for names of programs
/// that exit quickly.
pub const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
/// WINEVENT_KEYWORD_PROCESS.
pub const KERNEL_PROCESS_KEYWORDS: u64 = 0x10;
/// Kernel-Process event ids.
pub const PROCESS_START: u16 = 1;
pub const PROCESS_STOP: u16 = 2;

/// Which way a Kernel-Network event goes: sends (TCP and UDP, IPv4 and IPv6) are
/// uploads, receives downloads. Other events (connect, disconnect, retransmit…) carry
/// no new data and are ignored. Same ids as the B2 test program.
pub fn net_direction(event_id: u16) -> Option<Direction> {
    match event_id {
        10 | 26 | 42 | 58 => Some(Direction::Out),
        11 | 27 | 43 | 59 => Some(Direction::In),
        _ => None,
    }
}

/// Which of an event's two addresses is this computer's: the one an adapter has.
/// Returns (local, remote), or `None` when neither (or both, a hairpin) is ours.
/// Deciding it this way doesn't depend on how the event labels source and destination.
pub fn local_and_remote(
    a: IpAddr,
    b: IpAddr,
    is_ours: impl Fn(&IpAddr) -> bool,
) -> Option<(IpAddr, IpAddr)> {
    match (is_ours(&a), is_ours(&b)) {
        (true, false) => Some((a, b)),
        (false, true) => Some((b, a)),
        _ => None,
    }
}

/// Words in an adapter's description that mark a VPN tunnel whatever its type.
const VPN_WORDS: &[&str] = &[
    "tap-windows",
    "tap-protonvpn",
    "wintun",
    "wireguard",
    "openvpn",
    "nordlynx",
    "protonvpn",
    "mullvad",
    "anyconnect",
    "fortinet",
    "pangp",
    "globalprotect",
];

/// A VPN tunnel adapter: its traffic is also seen, encrypted, on the physical adapter,
/// so counting both would double it. As on Linux (collector PR #2) the tunnel is
/// skipped and the VPN client's own traffic on the physical network is counted.
/// IF_TYPE_TUNNEL (131) and IF_TYPE_PROP_VIRTUAL (53, WireGuard/Wintun) by type; TAP
/// adapters report Ethernet (6), so they're caught by their description. Hyper-V's
/// virtual switch also reports Ethernet and isn't a VPN: an external switch carries the
/// computer's own traffic, so "virtual" alone isn't a reason to skip.
pub fn is_vpn_adapter(if_type: u32, description: &str) -> bool {
    const IF_TYPE_PROP_VIRTUAL: u32 = 53;
    const IF_TYPE_TUNNEL: u32 = 131;
    if if_type == IF_TYPE_TUNNEL || if_type == IF_TYPE_PROP_VIRTUAL {
        return true;
    }
    let d = description.to_ascii_lowercase();
    VPN_WORDS.iter().any(|w| d.contains(w))
}

/// An IP address from the bytes of a Windows SOCKADDR (as in SOCKET_ADDRESS):
/// AF_INET (2) has the address at bytes 4..8, AF_INET6 (23) at 8..24.
pub fn sockaddr_ip(bytes: &[u8]) -> Option<IpAddr> {
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 23;
    let family = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
    match family {
        AF_INET => {
            let a: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(a)))
        }
        AF_INET6 => {
            let a: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// Process 4: the kernel (file sharing, some drivers, kernel-mode VPN tunnels).
pub const SYSTEM_PID: u32 = 4;

/// File names too generic to tell apps apart: many vendors ship an `updater.exe`.
const GENERIC_FILES: &[&str] = &[
    "updater.exe",
    "update.exe",
    "setup.exe",
    "install.exe",
    "installer.exe",
    "launcher.exe",
    "helper.exe",
    "service.exe",
    "uninstall.exe",
];

/// Folders that hold vendors' folders rather than being one (`Program Files`,
/// `AppData\Local`, …): never used as an app's folder.
const ROOT_FOLDERS: &[&str] = &[
    "program files",
    "program files (x86)",
    "programdata",
    "appdata",
    "local",
    "roaming",
    "users",
    "windows",
    "system32",
    "syswow64",
];

/// A version folder: "1.2.3", "v120", or Squirrel's "app-1.0.9".
fn is_version(folder: &str) -> bool {
    let f = folder.to_ascii_lowercase();
    let f = f.strip_prefix("app-").unwrap_or(&f);
    let f = f.strip_prefix('v').unwrap_or(f);
    !f.is_empty()
        && f.chars().all(|c| c.is_ascii_digit() || c == '.')
        && f.contains(|c: char| c.is_ascii_digit())
}

/// The vendor or product folder of a program: the nearest folder above the file that
/// isn't a version number, a root like `Program Files`, or a drive.
fn app_folder(image: &str) -> Option<&str> {
    let mut parts: Vec<&str> = image.split(['\\', '/']).filter(|p| !p.is_empty()).collect();
    parts.pop(); // the file itself
    parts.into_iter().rev().find(|f| {
        let lower = f.to_ascii_lowercase();
        !is_version(f) && !ROOT_FOLDERS.contains(&lower.as_str()) && !lower.ends_with(':')
    })
}

/// An app's identity from its process: the kernel, a svchost by the services it runs,
/// or a program by its file.
///
/// Programs are keyed by **file name**, not full path as on Linux: Windows apps often
/// update into new version folders (Squirrel's `app-1.0.9`, Chrome's and WebView2's
/// version folders), and a path key would make each update a new app with its history
/// split. Generic file names ([`GENERIC_FILES`], e.g. `updater.exe`) would merge
/// different vendors, so they're keyed with their vendor or product folder
/// (`exe:<folder>\<file>`, the nearest folder that isn't a version or a root). Friendly
/// names (file descriptions, "Windows Update and Store") come in a later PR; until then
/// the file name is shown, with the folder for generic ones.
pub fn app_info(pid: u32, image: Option<&str>, services: &[String]) -> AppInfo {
    if pid == SYSTEM_PID {
        return AppInfo {
            key: "windows:system".into(),
            name: "Windows (system)".into(),
            exe: None,
        };
    }
    let Some(image) = image.filter(|i| !i.is_empty()) else {
        return AppInfo::unknown();
    };
    let file = image.rsplit(['\\', '/']).next().unwrap_or(image);
    let lower = file.to_ascii_lowercase();
    if lower == "svchost.exe" && !services.is_empty() {
        let mut s = services.to_vec();
        s.sort_unstable_by_key(|x| x.to_ascii_lowercase());
        let list = s.join(",");
        return AppInfo {
            key: format!("svchost:{}", list.to_ascii_lowercase()),
            name: format!("svchost.exe [{list}]"),
            exe: Some(image.to_string()),
        };
    }
    if GENERIC_FILES.contains(&lower.as_str()) {
        if let Some(folder) = app_folder(image) {
            return AppInfo {
                key: format!("exe:{}\\{lower}", folder.to_ascii_lowercase()),
                name: format!("{file} ({folder})"),
                exe: Some(image.to_string()),
            };
        }
    }
    AppInfo {
        key: format!("exe:{lower}"),
        name: file.to_string(),
        exe: Some(image.to_string()),
    }
}

/// Events and buffers the ETW session lost, from `logman query <session> -ets`
/// ("Events Lost:   0", "Buffers Lost: 0"). Lost events are data never counted.
pub fn lost_from_logman(text: &str) -> u64 {
    text.lines()
        .filter_map(|line| {
            let (label, value) = line.split_once(':')?;
            if !label.to_ascii_lowercase().contains("lost") {
                return None;
            }
            value.trim().parse::<u64>().ok()
        })
        .sum()
}

/// Windows' cost setting for a connection (NetworkCostType) → metered. Unrestricted is
/// unlimited; Fixed (a data cap) and Variable (pay per use) are metered; Unknown stays
/// unknown, which the store treats as metered. A MiFi or phone hotspot often reads
/// Unrestricted (B4, B2), so the user's own choice (FR-21) still wins, in the store.
pub fn cost_metered(cost_type: i32) -> Metered {
    match cost_type {
        1 => Metered::No,
        2 | 3 => Metered::Yes,
        _ => Metered::Unknown,
    }
}

/// A GUID as Windows writes it, upper case without braces: the key that joins an
/// adapter (GetAdaptersAddresses), its counters (GetIfTable2) and its connection profile.
pub fn guid_text(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> String {
    format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        data4[0], data4[1], data4[2], data4[3], data4[4], data4[5], data4[6], data4[7]
    )
}

/// The same key from a GUID's text, as GetAdaptersAddresses gives it ("{6b29fc40-…}").
pub fn normalize_guid(text: &str) -> String {
    text.trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_uppercase()
}

/// MIB_IF_ROW2's FilterInterface flag (bit 1): a filter driver's layer over a real
/// adapter (e.g. "Wi-Fi-WFP Native MAC Layer LightWeight Filter"), which repeats that
/// adapter's counters. Skipped, or the adapter would be counted twice.
pub fn is_filter_layer(flags: u8) -> bool {
    flags & 0b10 != 0
}

/// An adapter's counters at one reading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
}

impl Counters {
    fn is_zero(&self) -> bool {
        *self == Counters::default()
    }

    /// `self` − `last`, or `None` if any counter went down (the counters restarted).
    fn since(&self, last: &Counters) -> Option<Counters> {
        Some(Counters {
            bytes_in: self.bytes_in.checked_sub(last.bytes_in)?,
            bytes_out: self.bytes_out.checked_sub(last.bytes_out)?,
            packets_in: self.packets_in.checked_sub(last.packets_in)?,
            packets_out: self.packets_out.checked_sub(last.packets_out)?,
        })
    }

    fn add(&mut self, other: &Counters) {
        self.bytes_in += other.bytes_in;
        self.bytes_out += other.bytes_out;
        self.packets_in += other.packets_in;
        self.packets_out += other.packets_out;
    }
}

/// One reading of an adapter: its counters, and whether it was up (connected).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reading {
    pub counters: Counters,
    pub up: bool,
}

/// Each adapter's traffic since the collector started, from repeated readings of its
/// counters (B2's lessons, `windows-plan.md` §7):
///
/// - The first reading at start is the baseline: what an adapter carried before the
///   collector ran isn't counted.
/// - When an adapter goes down (the connection dropped, or the Wi-Fi was off), Windows
///   starts its counters again from zero when it's back. So a reading while it's down
///   marks it restarted, and its first reading once up counts **in full**, even if the
///   new counter has already passed the old one (B2 run 1+3: 2.2 MB before a drop, up
///   to 3 MB/s after; comparing with the old value would lose up to that much).
/// - Counters that go down while it stays up also mean a restart: the new reading
///   counts in full.
/// - An adapter that appears after start counts its first reading in full. (The probe
///   skipped it, and lost the first seconds after the Wi-Fi came on.)
/// - A brief all-zero reading while an adapter stays up is ignored, so the old total
///   coming back isn't counted twice.
///
/// It relies on Windows restarting the counters across a down/up, as seen on the
/// desktop and laptop in B2; D4 checks it on more machines.
#[derive(Debug, Default)]
pub struct AdapterTally {
    last: HashMap<String, Counters>,
    total: HashMap<String, Counters>,
    restarted: HashSet<String>,
    restarts_by: HashMap<String, u64>,
    pub restarts: u64,
}

impl AdapterTally {
    /// Adds a reading (adapter key → reading). `baseline`: the first reading at start.
    pub fn update(&mut self, readings: HashMap<String, Reading>, baseline: bool) {
        for (key, Reading { counters: now, up }) in readings {
            if !up {
                self.restarted.insert(key);
                continue;
            }
            if now.is_zero() {
                // Up at zero at start: a baseline of zero, so the next reading counts.
                if baseline {
                    self.last.entry(key).or_default();
                }
                continue;
            }
            let grew = if self.restarted.remove(&key) {
                self.restarts += 1;
                *self.restarts_by.entry(key.clone()).or_default() += 1;
                Some(now)
            } else {
                match self.last.get(&key) {
                    None if baseline => None,
                    None => Some(now),
                    Some(last) => match now.since(last) {
                        Some(g) => Some(g),
                        None => {
                            self.restarts += 1;
                            *self.restarts_by.entry(key.clone()).or_default() += 1;
                            Some(now)
                        }
                    },
                }
            };
            if let Some(g) = grew {
                self.total.entry(key.clone()).or_default().add(&g);
            }
            self.last.insert(key, now);
        }
    }

    /// Traffic since the collector started, per adapter key (the tests' view; the
    /// capture uses [`Self::snapshot`]).
    #[cfg(test)]
    pub fn totals(&self) -> &HashMap<String, Counters> {
        &self.total
    }

    /// Each adapter's traffic since start and how many times its counters restarted:
    /// a minute in which they restarted isn't trusted for reconciliation.
    pub fn snapshot(&self) -> HashMap<String, (Counters, u64)> {
        self.total
            .iter()
            .map(|(k, c)| {
                (
                    k.clone(),
                    (*c, self.restarts_by.get(k).copied().unwrap_or(0)),
                )
            })
            .collect()
    }
}

/// The most an app's count grows when it's matched to the adapter: headers are about
/// 3–5% (B2: 39.6–47.4 bytes a packet), so anything beyond this is something else.
pub const RECONCILE_CAP_PERCENT: u64 = 12;
/// What each app gets when the adapter's reading can't be trusted that minute (missing,
/// or the counters restarted): B2's headers, roughly.
pub const RECONCILE_FALLBACK_PERCENT: u64 = 4;

/// One minute's reconciliation on one adapter, one direction (DataSabi TODO D1, decided
/// 12 Nov 2026). ETW counts what's inside each packet, the operator bills the packets,
/// and the adapter's counters are what left the card (B2: adapter ÷ the phone's bill
/// 99.6%). So the apps are topped up to the adapter:
///
/// - `adapter`: the adapter's internet bytes that minute (its growth minus the local
///   traffic the apps skipped), or `None` when its reading is missing or restarted.
/// - `apps`: each app's internet bytes that minute.
///
/// Returns each app's extra bytes (same order) and the bytes for "Other (Windows)":
/// - overhead = adapter − apps (never negative: an adapter below the apps adds nothing);
/// - spread over the apps by their bytes, at most [`RECONCILE_CAP_PERCENT`] of each;
/// - whatever is left goes to "Other (Windows)", visible rather than hidden in apps;
///   with no apps that minute, all of it does;
/// - with no trustworthy reading, each app gets [`RECONCILE_FALLBACK_PERCENT`] and
///   "Other (Windows)" nothing.
///
/// The extras and the other add up to the overhead exactly.
pub fn reconcile(adapter: Option<u64>, apps: &[u64]) -> (Vec<u64>, u64) {
    let Some(adapter) = adapter else {
        let extras = apps
            .iter()
            .map(|b| percent(*b, RECONCILE_FALLBACK_PERCENT))
            .collect();
        return (extras, 0);
    };
    let total: u64 = apps.iter().sum();
    let overhead = adapter.saturating_sub(total);
    if total == 0 {
        return (vec![0; apps.len()], overhead);
    }
    let extras: Vec<u64> = apps
        .iter()
        .map(|b| {
            let share = (u128::from(overhead) * u128::from(*b) / u128::from(total)) as u64;
            share.min(percent(*b, RECONCILE_CAP_PERCENT))
        })
        .collect();
    let spread: u64 = extras.iter().sum();
    (extras, overhead - spread)
}

/// One minute on one adapter, as [`reconcile_minute`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinuteMatch {
    /// Each app's extra bytes (in, out), in the order given.
    pub extras: Vec<(u64, u64)>,
    /// "Other (Windows)" (in, out).
    pub other: (u64, u64),
    /// The apps' lead over the adapter, carried into the next minute.
    pub carry: u64,
}

/// One minute's reconciliation on one adapter, by each app's **total** (in + out), then
/// split by direction (reviewer, 13 Nov 2026). Matching each direction on its own is
/// wrong: a download makes the computer send acknowledgements, upload bytes on the
/// adapter that no app's upload shows (B2 run 1+3: apps sent 14.1 MB, the adapter 70.1
/// MB), so the upload side would look far short and push most of it into "Other".
///
/// - `adapter`: the adapter's internet bytes that minute (in, out), after the local
///   traffic is taken off; `None` when its reading is missing or restarted.
/// - `apps`: each app's (in, out) bytes that minute.
/// - `carry`: last minute's shortfall (the apps ahead of the adapter, because the
///   adapter is read every 5 s and minute edges don't line up). It's taken off this
///   minute's overhead, so a burst's catch-up isn't mistaken for "Other".
///
/// The total overhead is shared by [`reconcile`] (capped per app, the rest to Other).
/// Each extra, and Other, is then split into in and out in proportion to the adapter's
/// own overhead per direction (if one direction's is zero or less, all goes to the
/// other). With no trustworthy reading: +[`RECONCILE_FALLBACK_PERCENT`] per direction,
/// nothing to Other, and the carry starts again.
pub fn reconcile_minute(
    adapter: Option<(u64, u64)>,
    apps: &[(u64, u64)],
    carry: u64,
) -> MinuteMatch {
    let Some((a_in, a_out)) = adapter else {
        return MinuteMatch {
            extras: apps
                .iter()
                .map(|(i, o)| {
                    (
                        percent(*i, RECONCILE_FALLBACK_PERCENT),
                        percent(*o, RECONCILE_FALLBACK_PERCENT),
                    )
                })
                .collect(),
            other: (0, 0),
            carry: 0,
        };
    };
    let apps_in: u64 = apps.iter().map(|(i, _)| i).sum();
    let apps_out: u64 = apps.iter().map(|(_, o)| o).sum();
    let apps_total = apps_in + apps_out;
    let adapter_total = a_in + a_out;
    // The adapter catching up on last minute's lead isn't overhead.
    let behind = apps_total + carry;
    let new_carry = behind.saturating_sub(adapter_total);
    let adapter_for_apps = adapter_total.saturating_sub(carry);
    let totals: Vec<u64> = apps.iter().map(|(i, o)| i + o).collect();
    let (extras, other) = reconcile(Some(adapter_for_apps), &totals);

    // Split by the adapter's own overhead per direction.
    let o_in = a_in.saturating_sub(apps_in);
    let o_out = a_out.saturating_sub(apps_out);
    let split = |x: u64| -> (u64, u64) {
        if o_in + o_out == 0 {
            return (x, 0);
        }
        let x_in = (u128::from(x) * u128::from(o_in) / u128::from(o_in + o_out)) as u64;
        (x_in, x - x_in)
    };
    MinuteMatch {
        extras: extras.into_iter().map(split).collect(),
        other: split(other),
        carry: new_carry,
    }
}

/// `bytes` × `pct` / 100, rounded to the nearest byte.
fn percent(bytes: u64, pct: u64) -> u64 {
    ((u128::from(bytes) * u128::from(pct) + 50) / 100) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_are_uploads_and_receives_downloads() {
        for id in [10, 26, 42, 58] {
            assert_eq!(net_direction(id), Some(Direction::Out));
        }
        for id in [11, 27, 43, 59] {
            assert_eq!(net_direction(id), Some(Direction::In));
        }
        // TCP connect, disconnect, retransmit: no new data.
        for id in [12, 13, 14, 15] {
            assert_eq!(net_direction(id), None);
        }
    }

    #[test]
    fn the_local_side_is_the_one_an_adapter_has() {
        let ours: IpAddr = "192.168.43.10".parse().unwrap();
        let theirs: IpAddr = "142.250.1.1".parse().unwrap();
        let is_ours = |ip: &IpAddr| *ip == ours;
        assert_eq!(
            local_and_remote(ours, theirs, is_ours),
            Some((ours, theirs))
        );
        assert_eq!(
            local_and_remote(theirs, ours, is_ours),
            Some((ours, theirs))
        );
        // Hairpin or a stranger's packet: not counted.
        assert_eq!(local_and_remote(ours, ours, is_ours), None);
        assert_eq!(local_and_remote(theirs, theirs, is_ours), None);
    }

    #[test]
    fn vpn_tunnels_are_found_by_type_or_name() {
        // WireGuard/Wintun (ProtonVPN, NordVPN's NordLynx, Mullvad): prop-virtual.
        assert!(is_vpn_adapter(53, "ProtonVPN Tunnel"));
        assert!(is_vpn_adapter(131, "Teredo Tunneling Pseudo-Interface"));
        // OpenVPN's TAP reports Ethernet.
        assert!(is_vpn_adapter(6, "TAP-Windows Adapter V9"));
        assert!(is_vpn_adapter(6, "TAP-ProtonVPN Windows Adapter V9"));
        assert!(is_vpn_adapter(6, "PANGP Virtual Ethernet Adapter Secure"));
        // Real networks, and Hyper-V's switch, are kept.
        assert!(!is_vpn_adapter(71, "Intel(R) Wi-Fi 6 AX201 160MHz"));
        assert!(!is_vpn_adapter(6, "Realtek PCIe GbE Family Controller"));
        assert!(!is_vpn_adapter(6, "Hyper-V Virtual Ethernet Adapter"));
        assert!(!is_vpn_adapter(
            6,
            "Remote NDIS based Internet Sharing Device"
        ));
    }

    #[test]
    fn sockaddr_bytes_become_addresses() {
        let v4 = [2, 0, 0x01, 0xbb, 192, 168, 43, 10, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(sockaddr_ip(&v4), Some("192.168.43.10".parse().unwrap()));
        let mut v6 = [0u8; 28];
        v6[0] = 23;
        v6[8..24].copy_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(sockaddr_ip(&v6), Some("fe80::1".parse().unwrap()));
        assert_eq!(sockaddr_ip(&[2, 0, 0]), None);
        assert_eq!(sockaddr_ip(&[17, 0, 0, 0, 1, 2, 3, 4]), None);
    }

    #[test]
    fn processes_get_names() {
        let chrome = app_info(
            1234,
            Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            &[],
        );
        assert_eq!(chrome.key, "exe:chrome.exe");
        assert_eq!(chrome.name, "chrome.exe");
        // The same program from another folder is the same app.
        let other = app_info(9, Some(r"D:\Apps\CHROME.EXE"), &[]);
        assert_eq!(other.key, "exe:chrome.exe");
        // A svchost is known by the services it runs, in a stable order.
        let svc = app_info(
            800,
            Some(r"C:\Windows\System32\svchost.exe"),
            &["wuauserv".into(), "DoSvc".into()],
        );
        assert_eq!(svc.key, "svchost:dosvc,wuauserv");
        assert_eq!(svc.name, "svchost.exe [DoSvc,wuauserv]");
        assert_eq!(app_info(4, None, &[]).name, "Windows (system)");
        assert_eq!(app_info(77, None, &[]), AppInfo::unknown());
        assert_eq!(app_info(77, Some(""), &[]), AppInfo::unknown());
    }

    #[test]
    fn a_program_is_one_app_across_version_folders() {
        let a = app_info(
            1,
            Some(r"C:\Program Files\Google\Chrome\Application\130.0.6723.70\chrome.exe"),
            &[],
        );
        let b = app_info(
            2,
            Some(r"C:\Program Files\Google\Chrome\Application\131.0.6778.86\chrome.exe"),
            &[],
        );
        assert_eq!(a.key, b.key);
        assert_eq!(a.key, "exe:chrome.exe");
    }

    #[test]
    fn generic_files_are_kept_apart_by_their_folder() {
        let firefox = app_info(
            101,
            Some(r"C:\Program Files\Mozilla Firefox\updater.exe"),
            &[],
        );
        let vendor = app_info(
            102,
            Some(r"C:\Program Files\Acme\Tool\2.4.1\updater.exe"),
            &[],
        );
        assert_eq!(firefox.key, r"exe:mozilla firefox\updater.exe");
        assert_eq!(firefox.name, "updater.exe (Mozilla Firefox)");
        // The version folder is skipped: the product folder names it.
        assert_eq!(vendor.key, r"exe:tool\updater.exe");
        assert_ne!(firefox.key, vendor.key);
        // Squirrel apps (Discord, Slack, Teams): Update.exe beside versioned app folders.
        let discord = app_info(
            103,
            Some(r"C:\Users\a\AppData\Local\Discord\Update.exe"),
            &[],
        );
        assert_eq!(discord.key, r"exe:discord\update.exe");
        let slack = app_info(
            104,
            Some(r"C:\Users\a\AppData\Local\Slack\app-4.41.97\Update.exe"),
            &[],
        );
        assert_eq!(slack.key, r"exe:slack\update.exe");
        // Straight under a root: nothing to name it by, so the file alone.
        assert_eq!(
            app_info(105, Some(r"C:\Program Files\setup.exe"), &[]).key,
            "exe:setup.exe"
        );
    }

    #[test]
    fn version_folders_are_recognised() {
        for v in ["1.2.3", "130.0.6723.70", "v120", "app-1.0.9", "2024"] {
            assert!(is_version(v), "{v}");
        }
        for f in ["Chrome", "Application", "v", "app-", "Win64", "x64"] {
            assert!(!is_version(f), "{f}");
        }
    }

    #[test]
    fn lost_events_are_read_from_logman() {
        let out = "Name: DataSabiCollector\nEvents Lost:   3\nBuffers Lost: 2\nBuffer Size: 64\n";
        assert_eq!(lost_from_logman(out), 5);
        assert_eq!(lost_from_logman("no session"), 0);
    }

    #[test]
    fn windows_cost_settings_become_metered() {
        assert_eq!(cost_metered(1), Metered::No);
        assert_eq!(cost_metered(2), Metered::Yes);
        assert_eq!(cost_metered(3), Metered::Yes);
        assert_eq!(cost_metered(0), Metered::Unknown);
        assert_eq!(cost_metered(9), Metered::Unknown);
    }

    #[test]
    fn guids_are_one_key_whatever_their_source() {
        let from_struct = guid_text(
            0x6B29_FC40,
            0xCA47,
            0x1067,
            [0xB3, 0x1D, 0x00, 0xDD, 0x01, 0x06, 0x62, 0xDA],
        );
        assert_eq!(from_struct, "6B29FC40-CA47-1067-B31D-00DD010662DA");
        assert_eq!(
            normalize_guid("{6b29fc40-ca47-1067-b31d-00dd010662da}"),
            from_struct
        );
    }

    #[test]
    fn filter_layers_are_skipped() {
        assert!(is_filter_layer(0b0000_0010));
        assert!(is_filter_layer(0b0000_0011));
        assert!(!is_filter_layer(0b0000_0101)); // hardware, connector present
    }

    fn c(bytes_in: u64, bytes_out: u64) -> Counters {
        Counters {
            bytes_in,
            bytes_out,
            packets_in: bytes_in / 1000,
            packets_out: bytes_out / 1000,
        }
    }

    /// Readings of adapters that are up.
    fn reading(pairs: &[(&str, Counters)]) -> HashMap<String, Reading> {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    Reading {
                        counters: *v,
                        up: true,
                    },
                )
            })
            .collect()
    }

    /// One adapter that's down.
    fn down(key: &str) -> HashMap<String, Reading> {
        HashMap::from([(key.to_string(), Reading::default())])
    }

    #[test]
    fn the_tally_counts_only_what_happens_after_start() {
        let mut t = AdapterTally::default();
        // Wi-Fi had carried 1.2 GB before the collector started: not counted.
        t.update(reading(&[("wifi", c(1_200_000_000, 50_000_000))]), true);
        assert_eq!(t.totals().get("wifi"), None);
        t.update(reading(&[("wifi", c(1_200_500_000, 50_020_000))]), false);
        assert_eq!(t.totals()["wifi"], c(500_000, 20_000));
    }

    #[test]
    fn a_restart_counts_the_new_reading_in_full() {
        let mut t = AdapterTally::default();
        t.update(reading(&[("wifi", c(9_000_000, 100_000))]), true);
        t.update(reading(&[("wifi", c(9_400_000, 120_000))]), false);
        // The hotspot dropped and came back: counters started again.
        t.update(reading(&[("wifi", c(300_000, 10_000))]), false);
        assert_eq!(t.totals()["wifi"], c(700_000, 30_000));
        assert_eq!(t.restarts, 1);
    }

    #[test]
    fn a_drop_then_a_quick_climb_counts_the_new_reading_in_full() {
        // B2 run 1+3: 2.2 MB before the hotspot dropped; within the 5 s between readings
        // the new counter already passed it (up to 3 MB/s).
        let mut t = AdapterTally::default();
        t.update(reading(&[("wifi", c(1_000_000, 50_000))]), true);
        t.update(reading(&[("wifi", c(2_200_000, 60_000))]), false);
        t.update(down("wifi"), false);
        t.update(reading(&[("wifi", c(5_000_000, 90_000))]), false);
        assert_eq!(
            t.totals()["wifi"],
            c(1_200_000 + 5_000_000, 10_000 + 90_000)
        );
        assert_eq!(t.restarts, 1);
        // The restart is counted for that adapter, so that minute isn't reconciled.
        assert_eq!(t.snapshot()["wifi"].1, 1);
        // Then ordinary growth again.
        t.update(reading(&[("wifi", c(5_100_000, 90_000))]), false);
        assert_eq!(t.totals()["wifi"].bytes_in, 6_300_000);
    }

    #[test]
    fn a_brief_zero_isnt_a_restart() {
        let mut t = AdapterTally::default();
        t.update(reading(&[("wifi", c(9_000_000, 100_000))]), true);
        t.update(reading(&[("wifi", c(0, 0))]), false);
        // The old total comes back: only the growth since is counted.
        t.update(reading(&[("wifi", c(9_100_000, 100_000))]), false);
        assert_eq!(t.totals()["wifi"], c(100_000, 0));
        assert_eq!(t.restarts, 0);
    }

    #[test]
    fn an_adapter_that_comes_up_later_counts_its_first_reading() {
        let mut t = AdapterTally::default();
        // Wi-Fi off at start (down), and a USB tether not there at all.
        t.update(down("wifi"), true);
        t.update(reading(&[("wifi", c(5_186, 0))]), false);
        t.update(
            reading(&[("wifi", c(800_000, 20_000)), ("usb", c(42_000, 1_000))]),
            false,
        );
        assert_eq!(t.totals()["wifi"], c(800_000, 20_000));
        assert_eq!(t.totals()["usb"], c(42_000, 1_000));
    }

    /// B2 run 1+3 (desktop, hotspot): apps 2,485.6 MB, adapter 2,600.6 MB. The 4.6%
    /// overhead is under the cap, so it's all spread over the apps and the total
    /// matches the adapter exactly.
    #[test]
    fn b2_desktop_run_is_topped_up_to_the_adapter() {
        // DoSvc, Chrome and the rest, as in the report.
        let apps = [
            1_326_856_043,
            1_150_933_423,
            2_485_568_692 - 1_326_856_043 - 1_150_933_423,
        ];
        let adapter = 2_600_580_597;
        let (extras, other) = reconcile(Some(adapter), &apps);
        assert_eq!(other + extras.iter().sum::<u64>(), adapter - 2_485_568_692);
        assert!(other <= 2, "only rounding is left over, got {other}");
        let after: u64 = apps.iter().zip(&extras).map(|(a, e)| a + e).sum::<u64>() + other;
        assert_eq!(after, adapter);
        // Each app grows by the same share, about 4.63%.
        for (a, e) in apps.iter().zip(&extras) {
            let pct = *e as f64 * 100.0 / *a as f64;
            assert!((pct - 4.627).abs() < 0.01, "{pct}");
        }
    }

    /// B2 run 2 (laptop, hotspot, metered): apps 869.5 MB, adapter 902.0 MB: 3.7%.
    #[test]
    fn b2_laptop_run_is_topped_up_to_the_adapter() {
        let apps = [
            640_400_000,
            188_000_000,
            869_533_767 - 640_400_000 - 188_000_000,
        ];
        let (extras, other) = reconcile(Some(901_998_823), &apps);
        let after: u64 = apps.iter().sum::<u64>() + extras.iter().sum::<u64>() + other;
        assert_eq!(after, 901_998_823);
        assert!(other <= 2);
    }

    #[test]
    fn beyond_the_cap_goes_to_other() {
        // 1,000 bytes of apps, 1,500 on the adapter: 120 (12%) to the app, 380 to Other.
        assert_eq!(reconcile(Some(1_500), &[1_000]), (vec![120], 380));
        // Spread by bytes, each capped: 600 and 400 bytes, 300 overhead → 72 and 48
        // (their 12%), 180 to Other.
        assert_eq!(reconcile(Some(1_300), &[600, 400]), (vec![72, 48], 180));
    }

    #[test]
    fn no_apps_that_minute_means_all_to_other() {
        assert_eq!(reconcile(Some(5_000), &[]), (vec![], 5_000));
        assert_eq!(reconcile(Some(5_000), &[0, 0]), (vec![0, 0], 5_000));
    }

    #[test]
    fn an_adapter_below_the_apps_adds_nothing() {
        assert_eq!(reconcile(Some(900), &[600, 400]), (vec![0, 0], 0));
    }

    #[test]
    fn a_restarted_or_missing_reading_gives_four_percent() {
        assert_eq!(reconcile(None, &[1_000, 250]), (vec![40, 10], 0));
        assert_eq!(reconcile(None, &[]), (vec![], 0));
    }

    /// B2 run 1+3, per direction as the report has it. Download: apps 2,471,437,785,
    /// adapter 2,530,501,132. Upload: apps 14,130,907, adapter 70,079,465 (the download's
    /// acknowledgements). By total, every app grows ~4.63% and nothing goes to Other;
    /// each direction then adds up to the adapter's.
    #[test]
    fn b2_desktop_run_by_total_then_split_by_direction() {
        let apps = [
            (1_323_108_693, 3_747_350),  // DoSvc
            (1_140_680_728, 10_252_695), // Chrome
            (7_648_364, 130_862),        // the rest
        ];
        let m = reconcile_minute(Some((2_530_501_132, 70_079_465)), &apps, 0);
        assert!(m.other.0 + m.other.1 <= 2, "Other got {:?}", m.other);
        for ((i, o), (ei, eo)) in apps.iter().zip(&m.extras) {
            let pct = (ei + eo) as f64 * 100.0 / (i + o) as f64;
            assert!((pct - 4.627).abs() < 0.01, "{pct}");
        }
        let total_in: u64 = apps.iter().map(|a| a.0).sum::<u64>()
            + m.extras.iter().map(|e| e.0).sum::<u64>()
            + m.other.0;
        let total_out: u64 = apps.iter().map(|a| a.1).sum::<u64>()
            + m.extras.iter().map(|e| e.1).sum::<u64>()
            + m.other.1;
        assert!(total_in.abs_diff(2_530_501_132) <= 3, "{total_in}");
        assert!(total_out.abs_diff(70_079_465) <= 3, "{total_out}");
        assert_eq!(m.carry, 0);
    }

    /// The v1 bug: per direction, the upload side was ~56 MB short and capped at 12%,
    /// so ~54 MB/hour went to Other. By total, it doesn't.
    #[test]
    fn download_acknowledgements_dont_land_in_other() {
        let (_, other_out) = reconcile(Some(70_079_465), &[3_747_350, 10_252_695, 130_862]);
        assert!(
            other_out > 50_000_000,
            "per direction, Other got {other_out}"
        );
        let m = reconcile_minute(
            Some((2_530_501_132, 70_079_465)),
            &[
                (1_323_108_693, 3_747_350),
                (1_140_680_728, 10_252_695),
                (7_648_364, 130_862),
            ],
            0,
        );
        assert!(m.other.0 + m.other.1 <= 2);
    }

    /// B2 run 2 (laptop, metered): download apps 849,781,327 / adapter 875,835,963;
    /// upload 19,752,440 / 26,162,860.
    #[test]
    fn b2_laptop_run_by_total_then_split_by_direction() {
        let apps = [(640_000_000, 15_000_000), (209_781_327, 4_752_440)];
        let m = reconcile_minute(Some((875_835_963, 26_162_860)), &apps, 0);
        let total = apps.iter().map(|(i, o)| i + o).sum::<u64>()
            + m.extras.iter().map(|(i, o)| i + o).sum::<u64>()
            + m.other.0
            + m.other.1;
        assert_eq!(total, 875_835_963 + 26_162_860);
        assert!(m.other.0 + m.other.1 <= 2);
    }

    /// Minute edges: the adapter (read every 5 s) lags a burst's start, then catches
    /// up. The shortfall is carried, so nothing spills into Other.
    #[test]
    fn a_minute_edge_lag_is_carried_not_spilled() {
        let m1 = reconcile_minute(Some((1_900, 0)), &[(2_000, 0)], 0);
        assert_eq!(m1.extras, vec![(0, 0)]);
        assert_eq!(m1.other, (0, 0));
        assert_eq!(m1.carry, 100);
        let m2 = reconcile_minute(Some((1_150, 0)), &[(1_000, 0)], m1.carry);
        assert_eq!(m2.other, (0, 0));
        assert_eq!(m2.extras, vec![(50, 0)]);
        assert_eq!(m2.carry, 0);
    }

    #[test]
    fn a_direction_with_no_overhead_gets_none_of_it() {
        // Download: the adapter is below the apps; upload: 100 over. All extra is upload.
        let m = reconcile_minute(Some((900, 1_200)), &[(1_000, 1_000)], 0);
        assert_eq!(m.extras, vec![(0, 100)]);
    }

    #[test]
    fn an_untrusted_minute_gives_four_percent_and_resets_the_carry() {
        let m = reconcile_minute(None, &[(1_000, 250)], 500);
        assert_eq!(m.extras, vec![(40, 10)]);
        assert_eq!(m.other, (0, 0));
        assert_eq!(m.carry, 0);
    }
}
