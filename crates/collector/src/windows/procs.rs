//! Process names: the program file of each process id, and the services each svchost
//! runs.

use std::collections::HashMap;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_MORE_DATA};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The full path of a running process's program file, or `None` if it has exited or
/// can't be opened. Used when a process sends data before its start event was seen
/// (it was already running when the collector started).
pub fn image_path(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess returns null on failure, checked; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` UTF-16 units; Windows writes at most that and sets `len`.
    let ok = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
    };
    // SAFETY: opened above.
    unsafe { CloseHandle(handle) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// The running Win32 services per process id (svchost processes run several).
pub fn services_by_pid() -> HashMap<u32, Vec<String>> {
    let mut out: HashMap<u32, Vec<String>> = HashMap::new();
    // SAFETY: null machine and database names mean this computer's active database.
    let scm = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    if scm.is_null() {
        tracing::warn!("could not open the service list; svchost processes won't be split");
        return out;
    }
    let mut buf: Vec<u64> = vec![0; 64 * 1024 / 8];
    let mut resume: u32 = 0;
    loop {
        let mut needed: u32 = 0;
        let mut count: u32 = 0;
        // SAFETY: `buf` holds `buf.len() * 8` bytes, aligned for the structures written.
        let ok = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                buf.as_mut_ptr() as *mut u8,
                (buf.len() * 8) as u32,
                &mut needed,
                &mut count,
                &mut resume,
                std::ptr::null(),
            )
        };
        // SAFETY: plain call.
        let more = ok == 0 && unsafe { GetLastError() } == ERROR_MORE_DATA;
        if ok == 0 && !more {
            tracing::warn!("listing services failed; svchost processes won't be split");
            break;
        }
        let entries = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
        for i in 0..count as usize {
            // SAFETY: Windows wrote `count` entries at the start of `buf`; their name
            // pointers point inside `buf`.
            let e = unsafe { &*entries.add(i) };
            let name = wide(e.lpServiceName);
            let pid = e.ServiceStatusProcess.dwProcessId;
            if pid != 0 && !name.is_empty() {
                out.entry(pid).or_default().push(name);
            }
        }
        if !more {
            break;
        }
        if needed as usize > buf.len() * 8 {
            buf.resize((needed as usize).div_ceil(8), 0);
        }
    }
    // SAFETY: opened above.
    unsafe { CloseServiceHandle(scm) };
    out
}

/// A NUL-terminated UTF-16 string from Windows, or "" for null.
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
