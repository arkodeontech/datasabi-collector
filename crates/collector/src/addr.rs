//! Address rules shared by every platform's capture.

use std::net::IpAddr;

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
