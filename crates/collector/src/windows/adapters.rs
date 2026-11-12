//! This computer's network adapters: their addresses (GetAdaptersAddresses), to find
//! which adapter an address belongs to and whether it's a VPN tunnel; and their byte
//! counters (GetIfTable2), for the adapter thread.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIfTable2, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
    MIB_IF_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;

use crate::winrules::{
    guid_text, is_filter_layer, is_vpn_adapter, normalize_guid, sockaddr_ip, Counters, Reading,
};

/// One adapter: its GUID (the key shared with its counters and connection profile),
/// its name as Windows shows it ("Wi-Fi") and whether it's a VPN tunnel.
#[derive(Debug, Clone)]
pub struct Adapter {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub vpn: bool,
}

/// Address → adapter, for every adapter that has an address.
#[derive(Debug, Default)]
pub struct Adapters {
    by_addr: HashMap<IpAddr, Adapter>,
}

impl Adapters {
    pub fn get(&self, ip: &IpAddr) -> Option<&Adapter> {
        self.by_addr.get(ip)
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.by_addr.contains_key(ip)
    }

    /// Reads the adapters now. `only`: if not empty, adapters with other names are left
    /// out (`--interface`), as on Linux.
    pub fn read(only: &[String]) -> Result<Self> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        for _ in 0..4 {
            // u64 elements keep the buffer aligned for IP_ADAPTER_ADDRESSES_LH.
            buf.resize((size as usize).div_ceil(8), 0);
            // SAFETY: `buf` holds `size` bytes; Windows writes the list into it.
            let err = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut size,
                )
            };
            if err == ERROR_SUCCESS {
                // SAFETY: on success the buffer starts with a valid linked list whose
                // pointers stay inside `buf`, which outlives the walk.
                return Ok(Self::walk(
                    buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH,
                    only,
                ));
            }
            if err != ERROR_BUFFER_OVERFLOW {
                bail!("GetAdaptersAddresses failed (Windows error {err})");
            }
        }
        bail!("GetAdaptersAddresses kept asking for a bigger buffer")
    }

    /// `first` must be the start of a list written by GetAdaptersAddresses, still alive.
    fn walk(first: *const IP_ADAPTER_ADDRESSES_LH, only: &[String]) -> Self {
        let mut by_addr = HashMap::new();
        let mut a = first;
        // SAFETY (this loop): every pointer comes from the list GetAdaptersAddresses wrote
        // into the caller's buffer, which is alive for the whole walk.
        while let Some(adapter) = unsafe { a.as_ref() } {
            let name = wide(adapter.FriendlyName);
            let description = wide(adapter.Description);
            let wanted = only.is_empty() || only.iter().any(|o| o == &name);
            if wanted {
                let entry = Adapter {
                    id: Arc::from(normalize_guid(&narrow(adapter.AdapterName)).as_str()),
                    name: Arc::from(name.as_str()),
                    vpn: is_vpn_adapter(adapter.IfType, &description),
                };
                let mut u = adapter.FirstUnicastAddress;
                while let Some(addr) = unsafe { u.as_ref() } {
                    let sa = addr.Address;
                    if !sa.lpSockaddr.is_null() && sa.iSockaddrLength > 0 {
                        let bytes = unsafe {
                            std::slice::from_raw_parts(
                                sa.lpSockaddr as *const u8,
                                sa.iSockaddrLength as usize,
                            )
                        };
                        if let Some(ip) = sockaddr_ip(bytes) {
                            by_addr.insert(ip, entry.clone());
                        }
                    }
                    u = addr.Next;
                }
            }
            a = adapter.Next;
        }
        Self { by_addr }
    }
}

/// Every adapter's counters and whether it's up, by GUID, without filter-driver layers
/// (they repeat their adapter's counters).
pub fn counters() -> Result<HashMap<String, Reading>> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: Windows allocates the table; it's freed with FreeMibTable below.
    let err = unsafe { GetIfTable2(&mut table) };
    if err != ERROR_SUCCESS || table.is_null() {
        bail!("GetIfTable2 failed (Windows error {err})");
    }
    let mut out = HashMap::new();
    // SAFETY: the table holds NumEntries rows laid out from its `Table` field on.
    unsafe {
        let n = (*table).NumEntries as usize;
        let rows = std::ptr::addr_of!((*table).Table) as *const MIB_IF_ROW2;
        for i in 0..n {
            let r = &*rows.add(i);
            if is_filter_layer(r.InterfaceAndOperStatusFlags._bitfield) {
                continue;
            }
            let g = r.InterfaceGuid;
            out.insert(
                guid_text(g.data1, g.data2, g.data3, g.data4),
                Reading {
                    counters: Counters {
                        bytes_in: r.InOctets,
                        bytes_out: r.OutOctets,
                        packets_in: r.InUcastPkts + r.InNUcastPkts,
                        packets_out: r.OutUcastPkts + r.OutNUcastPkts,
                    },
                    up: r.OperStatus == IfOperStatusUp,
                },
            );
        }
        FreeMibTable(table as *const _);
    }
    Ok(out)
}

/// A NUL-terminated 8-bit string from Windows (AdapterName, a GUID), or "" for null.
fn narrow(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: Windows strings end with a NUL.
    unsafe { std::ffi::CStr::from_ptr(p as *const std::ffi::c_char) }
        .to_string_lossy()
        .into_owned()
}

/// A NUL-terminated UTF-16 string from Windows, or "" for null. `p` must be null or
/// point at a NUL-terminated UTF-16 string.
fn wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: Windows strings end with a NUL, so reading up to it stays in bounds.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` characters before the NUL were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    /// The adapter list and the counter table use the same key (the adapter's GUID).
    #[test]
    fn adapters_and_counters_share_keys() {
        let adapters = Adapters::read(&[]).unwrap();
        let counters = counters().unwrap();
        assert!(
            adapters
                .by_addr
                .values()
                .any(|a| counters.contains_key(a.id.as_ref())),
            "no adapter's GUID found among the counters"
        );
    }

    /// A download makes the counters grow by at least what was received. Needs the
    /// internet: ignored by default, run on Windows CI with `--ignored`.
    #[test]
    #[ignore]
    fn counters_grow_with_a_download() {
        let mut tally = crate::winrules::AdapterTally::default();
        tally.update(counters().unwrap(), true);
        let mut stream = std::net::TcpStream::connect("example.com:80").unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        tally.update(counters().unwrap(), false);
        let grew: u64 = tally.totals().values().map(|c| c.bytes_in).sum();
        assert!(
            grew * 10 >= response.len() as u64 * 9,
            "adapters grew {grew} bytes for a {}-byte response",
            response.len()
        );
    }
}
