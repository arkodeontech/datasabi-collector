//! This computer's network adapters and their addresses, from GetAdaptersAddresses:
//! which adapter an address belongs to, and whether it's a VPN tunnel.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use crate::winrules::{is_vpn_adapter, sockaddr_ip};

/// One adapter: its name as Windows shows it ("Wi-Fi") and whether it's a VPN tunnel.
#[derive(Debug, Clone)]
pub struct Adapter {
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
