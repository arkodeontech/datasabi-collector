//! The data folder, `%ProgramData%\DataSabi` (the usage history and the logs), made
//! safe for a LocalSystem service to write in.
//!
//! Any signed-in user can create folders in `%ProgramData%`. A folder made before
//! DataSabi was installed stays owned by whoever made it, and an owner can always
//! reopen its access list; and a folder that is really a junction or symlink would
//! send the service's writes wherever it points: a known way to take over a PC. So
//! the folder, `logs\`, and each file the collector writes are checked before use:
//! not a link, no extra hard links, owned by SYSTEM or Administrators. Anything else
//! is moved aside (`<name>.untrusted-<unix time>`; folders are then made fresh).
//! Checks and changes go through a handle opened on the item itself, never following
//! a link, and nothing is changed by name (which could walk into a link inside).

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsWellKnownSid,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};

use crate::config::data_dir;
use crate::ipc::pipe::SecurityDescriptor;
use crate::winrules::aside_name;

/// Folders: owner Administrators; a protected access list (nothing inherited from
/// above): SYSTEM and Administrators full control, passed on to what's made inside.
const DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// Files: the same, without passing anything on.
const FILE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Database files the collector writes (SQLite makes the others next to `usage.db`).
const DB_FILES: [&str; 4] = [
    "usage.db",
    "usage.db-wal",
    "usage.db-shm",
    "usage.db-journal",
];

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Folder,
    File,
}

/// Makes the data folder, `logs\` and the collector's files safe (see the module
/// notes) and returns what was moved aside, for the log. `log_keep`: how many old
/// logs the rolling log keeps.
pub fn prepare(log_keep: usize) -> Result<Vec<PathBuf>> {
    let dir_sd = SecurityDescriptor::from_sddl(DIR_SDDL)?;
    let file_sd = SecurityDescriptor::from_sddl(FILE_SDDL)?;
    let mut moved = Vec::new();
    let dir = data_dir();
    let logs = dir.join("logs");
    secure(&dir, Kind::Folder, &dir_sd, &mut moved)?;
    secure(&logs, Kind::Folder, &dir_sd, &mut moved)?;
    let mut files: Vec<PathBuf> = DB_FILES.iter().map(|f| dir.join(f)).collect();
    files.push(logs.join("collector.log"));
    files.extend((1..=log_keep).map(|n| logs.join(format!("collector.log.{n}"))));
    for file in &files {
        secure(file, Kind::File, &file_sd, &mut moved)?;
    }
    Ok(moved)
}

/// Keeps `path` if it qualifies (and gives it `sd`'s owner and access list),
/// otherwise moves it aside. A missing folder is made; a missing file is left for the
/// collector to make inside the now-safe folder.
fn secure(
    path: &Path,
    kind: Kind,
    sd: &SecurityDescriptor,
    moved: &mut Vec<PathBuf>,
) -> Result<()> {
    // Another program could swap the item between steps; a few rounds, then give up.
    for _ in 0..3 {
        match kind {
            Kind::Folder => {
                if let Err(e) = create_dir_secure(path, sd) {
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(e).with_context(|| {
                            format!(
                                "creating {} owned by Administrators (run as administrator)",
                                path.display()
                            )
                        });
                    }
                }
            }
            Kind::File => {
                if let Err(e) = std::fs::symlink_metadata(path) {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        return Ok(());
                    }
                }
            }
        }
        // Opened on the item itself (not what a link points to), with the rights to
        // read and set its owner and access list. If even that is refused, or its
        // owner can't be read, someone locked it against us: not ours.
        if let Ok(item) = open_no_follow(path) {
            if is_trusted(&item, kind).unwrap_or(false) {
                return lock_down(&item, sd, path);
            }
        } // The handle is closed here, before the move.
        moved.push(move_aside(path)?);
    }
    bail!("{} keeps being replaced by another program", path.display())
}

/// Makes a folder that is owned by Administrators and has `sd`'s protected access
/// list from the start, whatever the token's default owner. Git Bash, and the "Object
/// creator" default-owner policy some organisations set, make it the user's own
/// account, which [`is_trusted`] rightly refuses (a program running as that user
/// without admin rights has the same account). Only an administrator or SYSTEM may
/// set Administrators as the owner.
fn create_dir_secure(path: &Path, sd: &SecurityDescriptor) -> std::io::Result<()> {
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: `wide` is NUL-terminated; `attributes` and the descriptor it points to
    // live through the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn open_no_follow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// No junction or symlink, the expected kind, a single name (no hard link to some
/// other file), owned by SYSTEM or Administrators.
fn is_trusted(item: &File, kind: Kind) -> Result<bool> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open for FILE_READ_ATTRIBUTES; `info` is a plain struct.
    if unsafe { GetFileInformationByHandle(item.as_raw_handle(), &mut info) } == 0 {
        bail!("reading attributes: {}", std::io::Error::last_os_error());
    }
    let is_folder = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || is_folder != (kind == Kind::Folder)
        || (kind == Kind::File && info.nNumberOfLinks != 1)
    {
        return Ok(false);
    }
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is open for READ_CONTROL; `owner` points into `descriptor`,
    // which Windows allocates and we free below, after the last use of `owner`.
    let err = unsafe {
        GetSecurityInfo(
            item.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if err != ERROR_SUCCESS {
        bail!("reading the owner failed (Windows error {err})");
    }
    // SAFETY: `owner` is valid until `descriptor` is freed.
    let trusted = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid) != 0
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
    };
    // SAFETY: allocated by GetSecurityInfo with LocalAlloc; freed once.
    unsafe { LocalFree(descriptor) };
    Ok(trusted)
}

/// Sets `sd`'s owner (Administrators) and protected access list, through the handle.
fn lock_down(item: &File, sd: &SecurityDescriptor, path: &Path) -> Result<()> {
    let (mut owner, mut dacl): (PSID, *mut ACL) = (std::ptr::null_mut(), std::ptr::null_mut());
    let (mut defaulted, mut present) = (0, 0);
    // SAFETY: `sd` is a valid descriptor; both pointers point into it, and it lives
    // past the SetSecurityInfo call below.
    let ok = unsafe {
        GetSecurityDescriptorOwner(sd.as_ptr(), &mut owner, &mut defaulted) != 0
            && GetSecurityDescriptorDacl(sd.as_ptr(), &mut present, &mut dacl, &mut defaulted) != 0
    };
    if !ok || owner.is_null() || present == 0 {
        bail!("the data folder's access list is incomplete");
    }
    // SAFETY: the handle is open for WRITE_DAC and WRITE_OWNER; see above for the rest.
    let err = unsafe {
        SetSecurityInfo(
            item.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if err != ERROR_SUCCESS {
        bail!("securing {} failed (Windows error {err})", path.display());
    }
    Ok(())
}

/// Renames `path` (itself, never what a link points to) to `<name>.untrusted-<time>`.
fn move_aside(path: &Path) -> Result<PathBuf> {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let aside = aside_name(path, unix);
    std::fs::rename(path, &aside).with_context(|| {
        format!(
            "moving the untrusted {} aside to {}",
            path.display(),
            aside.display()
        )
    })?;
    Ok(aside)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder this process makes is owned by Administrators, so the check trusts it
    /// whatever this process's default owner is. Windows CI runs it from PowerShell
    /// and from Git Bash (whose programs default to the user's own account).
    #[test]
    #[ignore = "sets Administrators as owner, which needs administrator rights"]
    fn a_new_folder_is_owned_by_administrators() {
        let dir = std::env::temp_dir().join(format!("datasabi-owner-test-{}", std::process::id()));
        let _ = std::fs::remove_dir(&dir);
        let sd = SecurityDescriptor::from_sddl(DIR_SDDL).unwrap();
        create_dir_secure(&dir, &sd).unwrap();
        let item = open_no_follow(&dir).unwrap();
        let trusted = is_trusted(&item, Kind::Folder).unwrap();
        drop(item);
        std::fs::remove_dir(&dir).unwrap();
        assert!(
            trusted,
            "a folder made by the collector itself must be trusted"
        );
    }
}
