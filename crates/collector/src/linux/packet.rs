//! Minimal header parsing: just enough to get addresses, ports and the IP length.
//! Only the first ~128 bytes of each packet are captured.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::sockets::Proto;

/// libpcap link types we understand.
pub const DLT_EN10MB: i32 = 1;
pub const DLT_RAW: i32 = 12;
pub const DLT_RAW_ALT: i32 = 14;
pub const LINKTYPE_RAW: i32 = 101;
pub const LINKTYPE_LINUX_SLL: i32 = 113;
pub const LINKTYPE_LINUX_SLL2: i32 = 276;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    pub proto: Proto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// Bytes on the IP layer (headers included).
    pub len: u32,
}

const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86DD;
const ETH_VLAN: u16 = 0x8100;
const ETH_QINQ: u16 = 0x88A8;

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

/// Parses one captured frame. `wire_len` is the original frame length.
pub fn parse(linktype: i32, data: &[u8], wire_len: u32) -> Option<Parsed> {
    let (ethertype, offset) = match linktype {
        DLT_EN10MB => {
            let mut et = be16(data, 12)?;
            let mut off = 14;
            while et == ETH_VLAN || et == ETH_QINQ {
                et = be16(data, off + 2)?;
                off += 4;
            }
            (Some(et), off)
        }
        LINKTYPE_LINUX_SLL => (Some(be16(data, 14)?), 16),
        LINKTYPE_LINUX_SLL2 => (Some(be16(data, 0)?), 20),
        DLT_RAW | DLT_RAW_ALT | LINKTYPE_RAW => (None, 0),
        _ => return None,
    };
    let ip = data.get(offset..)?;
    let fallback_len = wire_len.saturating_sub(offset as u32);
    match ethertype {
        Some(ETH_IPV4) => parse_ipv4(ip, fallback_len),
        Some(ETH_IPV6) => parse_ipv6(ip, fallback_len),
        Some(_) => None,
        None => match ip.first()? >> 4 {
            4 => parse_ipv4(ip, fallback_len),
            6 => parse_ipv6(ip, fallback_len),
            _ => None,
        },
    }
}

fn ports(proto: u8, l4: &[u8]) -> Option<(Proto, u16, u16)> {
    let p = match proto {
        6 => Proto::Tcp,
        17 => Proto::Udp,
        _ => return None,
    };
    Some((p, be16(l4, 0)?, be16(l4, 2)?))
}

fn parse_ipv4(ip: &[u8], fallback_len: u32) -> Option<Parsed> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    let total = be16(ip, 2)? as u32;
    let frag_offset = be16(ip, 6)? & 0x1FFF;
    if frag_offset != 0 {
        return None; // later fragments carry no ports
    }
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let (proto, sp, dp) = ports(ip[9], ip.get(ihl..)?)?;
    Some(Parsed {
        proto,
        src: SocketAddr::new(IpAddr::V4(src), sp),
        dst: SocketAddr::new(IpAddr::V4(dst), dp),
        len: if total == 0 { fallback_len } else { total },
    })
}

fn parse_ipv6(ip: &[u8], fallback_len: u32) -> Option<Parsed> {
    if ip.len() < 40 || ip[0] >> 4 != 6 {
        return None;
    }
    let payload = be16(ip, 4)? as u32;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?);
    let mut next = ip[6];
    let mut off = 40;
    // Walk common extension headers.
    for _ in 0..4 {
        match next {
            0 | 43 | 60 => {
                next = *ip.get(off)?;
                off += (*ip.get(off + 1)? as usize + 1) * 8;
            }
            44 => {
                let frag = be16(ip, off + 2)? >> 3;
                if frag != 0 {
                    return None;
                }
                next = *ip.get(off)?;
                off += 8;
            }
            _ => break,
        }
    }
    let (proto, sp, dp) = ports(next, ip.get(off..)?)?;
    Some(Parsed {
        proto,
        src: SocketAddr::new(IpAddr::V6(src), sp),
        dst: SocketAddr::new(IpAddr::V6(dst), dp),
        len: if payload == 0 {
            fallback_len
        } else {
            payload + 40
        },
    })
}

/// True for addresses whose traffic does not touch the data plan:
/// loopback, LAN/private, link-local, multicast and broadcast.
pub fn is_local_only(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local_only(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (first & 0xFFC0) == 0xFE80 // link-local
                || (first & 0xFE00) == 0xFC00 // unique local
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(total_len: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&total_len.to_be_bytes());
        p[9] = 6;
        p[12..16].copy_from_slice(&[192, 168, 8, 100]);
        p[16..20].copy_from_slice(&[142, 250, 1, 1]);
        p[20..22].copy_from_slice(&51000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p
    }

    #[test]
    fn parses_ethernet_ipv4_tcp() {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ETH_IPV4.to_be_bytes());
        frame.extend(ipv4_tcp(1500));
        let p = parse(DLT_EN10MB, &frame, 1514).unwrap();
        assert_eq!(p.proto, Proto::Tcp);
        assert_eq!(p.src, "192.168.8.100:51000".parse().unwrap());
        assert_eq!(p.dst, "142.250.1.1:443".parse().unwrap());
        assert_eq!(p.len, 1500);
    }

    #[test]
    fn parses_vlan_and_raw_and_sll() {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ETH_VLAN.to_be_bytes());
        frame.extend_from_slice(&[0, 5]);
        frame.extend_from_slice(&ETH_IPV4.to_be_bytes());
        frame.extend(ipv4_tcp(60));
        assert_eq!(parse(DLT_EN10MB, &frame, 78).unwrap().len, 60);

        assert_eq!(parse(LINKTYPE_RAW, &ipv4_tcp(80), 80).unwrap().len, 80);

        let mut sll = vec![0u8; 14];
        sll.extend_from_slice(&ETH_IPV4.to_be_bytes());
        sll.extend(ipv4_tcp(90));
        assert_eq!(parse(LINKTYPE_LINUX_SLL, &sll, 106).unwrap().len, 90);
    }

    #[test]
    fn parses_ipv6_udp_with_hop_by_hop() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(8u16 + 8).to_be_bytes());
        p[6] = 0; // hop-by-hop
        p[8..24].copy_from_slice(&"2c0f:f8f0::10".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"2a00:1450::1".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]); // ext header -> UDP
        p.extend_from_slice(&5353u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&[0, 8, 0, 0]);
        let parsed = parse(LINKTYPE_RAW, &p, p.len() as u32).unwrap();
        assert_eq!(parsed.proto, Proto::Udp);
        assert_eq!(parsed.dst.port(), 443);
        assert_eq!(parsed.len, 56);
    }

    #[test]
    fn ignores_non_ip_and_icmp() {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // ARP
        frame.extend_from_slice(&[0; 28]);
        assert!(parse(DLT_EN10MB, &frame, 42).is_none());
        let mut icmp = ipv4_tcp(60);
        icmp[9] = 1;
        assert!(parse(LINKTYPE_RAW, &icmp, 60).is_none());
    }

    #[test]
    fn local_only_addresses() {
        for a in [
            "192.168.0.1",
            "10.1.2.3",
            "127.0.0.1",
            "224.0.0.251",
            "fe80::1",
            "fd00::1",
            "::1",
        ] {
            assert!(is_local_only(a.parse().unwrap()), "{a}");
        }
        for a in [
            "142.250.1.1",
            "100.64.1.1",
            "2a00:1450::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_local_only(a.parse().unwrap()), "{a}");
        }
    }
}
