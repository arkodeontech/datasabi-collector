//! The Windows capture's rules, kept apart from the Windows API so they build and are
//! tested on every platform: which way an ETW network event goes, which adapters are
//! VPN tunnels, how a process is named, and how lost events are read.

// Only the tests use these on other platforms.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
}
