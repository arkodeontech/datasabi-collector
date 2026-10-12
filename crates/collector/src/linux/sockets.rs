//! Maps a packet's address tuple to the process that owns the socket, using
//! /proc/net/{tcp,tcp6,udp,udp6} (tuple -> inode) and /proc/<pid>/fd (inode -> pid).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Minimum gap between refreshes triggered by unknown packets.
pub const MISS_REFRESH_GAP: Duration = Duration::from_millis(100);
/// Background refresh interval.
const PERIODIC_REFRESH: Duration = Duration::from_secs(5);

const TCP_LISTEN: u8 = 0x0A;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockEntry {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub inode: u64,
}

pub struct SocketTable {
    by_tuple: HashMap<(Proto, SocketAddr, SocketAddr), u64>,
    by_port: HashMap<(Proto, u16), u64>,
    inode_pid: HashMap<u64, u32>,
    alive_pids: HashSet<u32>,
    last_refresh: Option<Instant>,
}

impl Default for SocketTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketTable {
    pub fn new() -> Self {
        Self {
            by_tuple: HashMap::new(),
            by_port: HashMap::new(),
            inode_pid: HashMap::new(),
            alive_pids: HashSet::new(),
            last_refresh: None,
        }
    }

    /// Pids seen during the last refresh (used to expire caches).
    pub fn alive_pids(&self) -> &HashSet<u32> {
        &self.alive_pids
    }

    /// Refreshes if the periodic interval elapsed. Returns true if it refreshed.
    pub fn maybe_refresh(&mut self) -> bool {
        if self
            .last_refresh
            .is_none_or(|t| t.elapsed() >= PERIODIC_REFRESH)
        {
            self.refresh();
            true
        } else {
            false
        }
    }

    /// Refreshes when the last refresh is at least `gap` old. Returns true if it did.
    pub fn refresh_if_older(&mut self, gap: Duration) -> bool {
        if self.last_refresh.is_none_or(|t| t.elapsed() >= gap) {
            self.refresh();
            true
        } else {
            false
        }
    }

    /// Lookup without refreshing.
    pub fn find(&self, proto: Proto, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
        let inode = self
            .by_tuple
            .get(&(proto, local, remote))
            .or_else(|| self.by_port.get(&(proto, local.port())))?;
        self.inode_pid.get(inode).copied()
    }

    pub fn refresh(&mut self) {
        self.last_refresh = Some(Instant::now());
        self.by_tuple.clear();
        self.by_port.clear();
        for (proto, file) in [
            (Proto::Tcp, "/proc/net/tcp"),
            (Proto::Tcp, "/proc/net/tcp6"),
            (Proto::Udp, "/proc/net/udp"),
            (Proto::Udp, "/proc/net/udp6"),
        ] {
            let Ok(text) = fs::read_to_string(file) else {
                continue;
            };
            for e in parse_proc_net(&text) {
                if e.inode == 0 {
                    continue;
                }
                let connected = !e.remote.ip().is_unspecified();
                if connected {
                    self.by_tuple.insert((proto, e.local, e.remote), e.inode);
                }
                // Port fallback: unconnected UDP sockets and listeners; connected
                // sockets only fill gaps.
                let key = (proto, e.local.port());
                if !connected || (proto == Proto::Tcp && e.state == TCP_LISTEN) {
                    self.by_port.insert(key, e.inode);
                } else {
                    self.by_port.entry(key).or_insert(e.inode);
                }
            }
        }
        self.scan_fds();
    }

    fn scan_fds(&mut self) {
        self.inode_pid.clear();
        self.alive_pids.clear();
        let Ok(proc_dir) = fs::read_dir("/proc") else {
            return;
        };
        for entry in proc_dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            self.alive_pids.insert(pid);
            let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(target) = fs::read_link(fd.path()) {
                    if let Some(inode) = socket_inode(target.to_str().unwrap_or("")) {
                        // First owner wins; forked children share sockets with the parent.
                        self.inode_pid.entry(inode).or_insert(pid);
                    }
                }
            }
        }
    }
}

/// Parses `socket:[12345]`.
fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Parses the body of /proc/net/{tcp,tcp6,udp,udp6}.
pub fn parse_proc_net(text: &str) -> Vec<SockEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            Some(SockEntry {
                local: parse_addr(f[1])?,
                remote: parse_addr(f[2])?,
                state: u8::from_str_radix(f[3], 16).ok()?,
                inode: f[9].parse().ok()?,
            })
        })
        .collect()
}

/// Parses `0100007F:0035` (IPv4) or a 32-hex-digit IPv6 address with port. The kernel
/// prints each 32-bit word in host byte order.
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(addr, 16).ok()?.to_ne_bytes(),
        )),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&addr[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
            }
            let v6 = Ipv6Addr::from(bytes);
            // Dual-stack sockets report IPv4 peers as ::ffff:a.b.c.d; packets carry plain IPv4.
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(all(test, target_endian = "little"))]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_tcp() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 22541 1 0000000000000000 100 0 0 10 0\n   1: 6408A8C0:C738 0101FA8E:01BB 01 00000000:00000000 02:000A7B2E 00000000  1000        0 98765 2 0000000000000000 20 4 30 10 -1\n";
        let e = parse_proc_net(text);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].local, "127.0.0.53:53".parse().unwrap());
        assert_eq!(e[0].state, TCP_LISTEN);
        assert_eq!(e[1].local, "192.168.8.100:51000".parse().unwrap());
        assert_eq!(e[1].remote, "142.250.1.1:443".parse().unwrap());
        assert_eq!(e[1].inode, 98765);
    }

    #[test]
    fn parses_ipv6_and_mapped() {
        // ::1 port 631
        let a = parse_addr("00000000000000000000000001000000:0277").unwrap();
        assert_eq!(a, "[::1]:631".parse().unwrap());
        // ::ffff:142.250.1.1 port 443
        let m = parse_addr("0000000000000000FFFF00000101FA8E:01BB").unwrap();
        assert_eq!(m, "142.250.1.1:443".parse().unwrap());
    }

    #[test]
    fn socket_link_parsing() {
        assert_eq!(socket_inode("socket:[4242]"), Some(4242));
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("anon_inode:[eventfd]"), None);
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    #[test]
    fn finds_own_tcp_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut t = SocketTable::new();
        let (local, peer) = (client.local_addr().unwrap(), client.peer_addr().unwrap());
        assert_eq!(t.find(Proto::Tcp, local, peer), None);
        assert!(t.refresh_if_older(MISS_REFRESH_GAP));
        assert_eq!(t.find(Proto::Tcp, local, peer), Some(std::process::id()));
        // A fresh refresh is not repeated inside the gap.
        assert!(!t.refresh_if_older(MISS_REFRESH_GAP));
    }
}
