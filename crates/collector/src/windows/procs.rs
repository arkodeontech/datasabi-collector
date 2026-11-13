//! Process names: the program file of each process id, what that file says about
//! itself (its version information), and the services each svchost runs.

use std::collections::HashMap;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_MORE_DATA};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
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

use std::path::PathBuf;

use crate::winrules::{plain_drive_path, version_info_size_ok, FileNames, Service};

/// The running Win32 services per process id (svchost processes run several), with
/// their display names.
pub fn services_by_pid() -> HashMap<u32, Vec<Service>> {
    let mut out: HashMap<u32, Vec<Service>> = HashMap::new();
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
            let display = wide(e.lpDisplayName);
            let pid = e.ServiceStatusProcess.dwProcessId;
            if pid != 0 && !name.is_empty() {
                out.entry(pid).or_default().push(Service { name, display });
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

/// The file description and product name from a program file's version information,
/// in the file's own language (its first translation), or US English if it lists none.
/// Empty when the file has no version information or can't be read.
pub fn file_names(path: &str) -> FileNames {
    let wide_path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut ignored = 0;
    // SAFETY: `wide_path` is NUL-terminated.
    let size = unsafe { GetFileVersionInfoSizeW(wide_path.as_ptr(), &mut ignored) };
    // A program file chooses this size; anything beyond a real one's isn't read.
    if !version_info_size_ok(size) {
        return FileNames::default();
    }
    // u64s, so the values Windows points to inside it are aligned for u16 reads.
    let mut block = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: `block` holds at least `size` bytes.
    let ok = unsafe { GetFileVersionInfoW(wide_path.as_ptr(), 0, size, block.as_mut_ptr().cast()) };
    if ok == 0 {
        return FileNames::default();
    }
    let block = &block[..];
    let mut tables: Vec<String> = Vec::new();
    if let Some(pairs) = query(block, r"\VarFileInfo\Translation") {
        // (language, code page) pairs.
        let mut rest = pairs.as_slice();
        while let [lang, code_page, tail @ ..] = rest {
            tables.push(format!("{lang:04x}{code_page:04x}"));
            rest = tail;
        }
    }
    tables.extend(["040904b0".to_string(), "040904e4".to_string()]);
    for table in &tables {
        let value = |field: &str| {
            query(block, &format!(r"\StringFileInfo\{table}\{field}"))
                .map(|v| {
                    String::from_utf16_lossy(&v)
                        .trim_end_matches('\0')
                        .to_string()
                })
                .filter(|v| !v.trim().is_empty())
        };
        let names = FileNames {
            description: value("FileDescription"),
            product: value("ProductName"),
        };
        if names != FileNames::default() {
            return names;
        }
    }
    FileNames::default()
}

/// The real Store app folder, `%ProgramFiles%\WindowsApps` (only Windows can write
/// there), as process paths show it: resolved and without the `\\?\` prefix. `None`
/// if Program Files can't be resolved, and then no program counts as a Store app.
pub fn store_root() -> Option<PathBuf> {
    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    let resolved = std::fs::canonicalize(program_files).ok()?;
    Some(plain_drive_path(&resolved)?.join("WindowsApps"))
}

/// A value from a version information block, as UTF-16 units (strings) or u16 pairs
/// (the translation list).
fn query(block: &[u64], sub_block: &str) -> Option<Vec<u16>> {
    let wide_sub: Vec<u16> = sub_block.encode_utf16().chain(Some(0)).collect();
    let mut value: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut len: u32 = 0;
    // SAFETY: `block` is a block GetFileVersionInfoW filled; `wide_sub` is
    // NUL-terminated; Windows points `value` inside `block`.
    let ok = unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            wide_sub.as_ptr(),
            &mut value,
            &mut len,
        )
    };
    if ok == 0 || value.is_null() || len == 0 {
        return None;
    }
    let start = value as usize;
    let block_start = block.as_ptr() as usize;
    let block_end = block_start + std::mem::size_of_val(block);
    // Strings come back in characters, the translation list in bytes; read whichever
    // is smaller, and never past the block.
    let units = if sub_block.contains("Translation") {
        len as usize / 2
    } else {
        len as usize
    };
    let aligned = (value as *const u16).is_aligned();
    if start < block_start || !aligned || start + units * 2 > block_end {
        return None;
    }
    // SAFETY: checked above: inside `block`, aligned for u16, `units` long.
    Some(unsafe { std::slice::from_raw_parts(value as *const u16, units) }.to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// On a real Windows (CI): Windows' own program files describe themselves, a missing
    /// file gives nothing, and running services come with display names.
    #[test]
    fn windows_programs_and_services_have_names() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let explorer = file_names(&format!(r"{root}\explorer.exe"));
        assert!(
            explorer
                .description
                .as_deref()
                .is_some_and(|d| !d.trim().is_empty()),
            "{explorer:?}"
        );
        assert_eq!(file_names(r"C:\no\such\file.exe"), FileNames::default());
        let store = store_root().expect("Program Files resolves");
        assert!(
            store.ends_with("WindowsApps") && store.is_absolute(),
            "{store:?}"
        );
        let services = services_by_pid();
        assert!(
            services.values().flatten().any(|s| !s.display.is_empty()),
            "no service has a display name"
        );
    }
}
