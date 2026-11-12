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
                Some(now)
            } else {
                match self.last.get(&key) {
                    None if baseline => None,
                    None => Some(now),
                    Some(last) => match now.since(last) {
                        Some(g) => Some(g),
                        None => {
                            self.restarts += 1;
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

    /// Traffic since the collector started, per adapter key.
    pub fn totals(&self) -> &HashMap<String, Counters> {
        &self.total
    }
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
}
