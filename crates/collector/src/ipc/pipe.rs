//! The Windows transport: a named pipe (`\\.\pipe\datasabi-collector` by default),
//! Windows' counterpart of the group-owned Unix socket. The collector runs with full
//! system rights, so anything that can talk to it is a target; the pipe is hardened
//! (DataSabi TODO D1, decided 12 Nov 2026):
//!
//! - **Remote clients refused** (`PIPE_REJECT_REMOTE_CLIENTS`): only programs on this
//!   computer can connect, never another machine over the network.
//! - **First instance only** (`FILE_FLAG_FIRST_PIPE_INSTANCE`): if another program
//!   already holds the name, the collector refuses to start instead of sharing a pipe
//!   someone else controls.
//! - **An access list** ([`PIPE_SDDL`]): SYSTEM and Administrators full control;
//!   signed-in (interactive) users read, and write data only (not create instances);
//!   nobody else, and not inherited.
//! - **Serving never stops on one error**: a failed accept or a failed new instance is
//!   logged and retried with a capped backoff, instead of ending the server.
//!
//! Clients check the other side too: `first_pipe_instance` protects the collector, not
//! its clients, so if the service isn't running any program could create a pipe with
//! this name. `dsctl` (and the app, D2) only talk to a pipe owned by SYSTEM.
//! - **A maximum line length**: [`super::MAX_LINE`], enforced in `handle_client`.

use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use super::handle_client;
use crate::state::Shared;

/// The pipe's access list: a protected DACL (`P`, so nothing is inherited) allowing
/// SYSTEM (`SY`) and Administrators (`BA`) full access (`GA`), and interactive users
/// (`IU`, anyone signed in at this computer, including over Remote Desktop) exactly
/// [`CLIENT_ACCESS`]: read, and write data. Not generic write (`GW`): on a pipe that
/// includes FILE_CREATE_PIPE_INSTANCE, which would let any signed-in program create
/// its own instance of this pipe and intercept clients of a fully privileged service.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;IU)";

/// What a client asks for when it opens the pipe: FILE_GENERIC_READ (0x120089) |
/// FILE_WRITE_DATA (0x2). A client asking for GENERIC_WRITE would be refused to
/// signed-in users, since the access list doesn't give them that.
// Read by the tests here; dsctl (a separate binary) keeps its own copy.
#[allow(dead_code)]
pub const CLIENT_ACCESS: u32 = 0x0012_0089 | 0x0002;

/// A security descriptor built from SDDL by Windows, freed when dropped.
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is a block of memory owned only by this value and never
// changed after it's built, so it can be shared and moved between threads.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `sd` receives a
        // descriptor allocated with LocalAlloc, freed in `Drop`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("building the pipe's access list from {sddl:?}"));
        }
        Ok(Self(sd))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

/// One instance of the pipe with the hardening above. `first` is true only for the
/// collector's first instance.
fn create(name: &str, first: bool, sd: &SecurityDescriptor) -> Result<NamedPipeServer> {
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first).reject_remote_clients(true);
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES for the whole call, and its
    // descriptor (`sd`) outlives it; Windows copies the descriptor into the pipe.
    unsafe { opts.create_with_security_attributes_raw(name, &mut attrs as *mut _ as *mut c_void) }
        .with_context(|| {
            if first {
                format!("creating the pipe {name} (is another collector, or another program, already using it?)")
            } else {
                format!("creating another instance of the pipe {name}")
            }
        })
}

/// The pipe, ready to accept its first client.
pub struct Listener {
    name: String,
    sd: SecurityDescriptor,
    next: NamedPipeServer,
}

/// Creates the pipe's first instance. Fails if the name is already taken. Must run
/// inside a Tokio runtime.
pub fn bind(name: &str) -> Result<Listener> {
    let sd = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
    let next = create(name, true, &sd)?;
    tracing::info!("listening on {name}");
    Ok(Listener {
        name: name.to_string(),
        sd,
        next,
    })
}

/// The longest wait between attempts to create a new instance.
const RETRY_MAX: Duration = Duration::from_secs(30);

/// A new instance of the pipe, retried with a growing wait (1 s, 2 s, … up to
/// [`RETRY_MAX`]) until Windows gives one: a passing failure mustn't stop the service
/// from listening until someone restarts it.
async fn next_instance(name: &str, sd: &SecurityDescriptor) -> NamedPipeServer {
    let mut wait = Duration::from_secs(1);
    loop {
        match create(name, false, sd) {
            Ok(server) => return server,
            Err(e) => {
                tracing::warn!("{e:#}; trying again in {} s", wait.as_secs());
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(RETRY_MAX);
            }
        }
    }
}

/// Serves clients for ever: each connected instance is handed to `handle_client`, and
/// a new instance is created at once, so a client can always connect. Errors are
/// logged and served past, never returned.
pub async fn serve(listener: Listener, shared: Arc<Shared>) -> Result<()> {
    let Listener { name, sd, mut next } = listener;
    loop {
        match next.connect().await {
            Ok(()) => {
                let client = next;
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client, shared).await {
                        tracing::debug!("client disconnected: {e:#}");
                    }
                });
                next = next_instance(&name, &sd).await;
            }
            Err(e) => {
                // For example a client that connected and left before it was accepted
                // (ERROR_NO_DATA). The new instance is made before this one is dropped,
                // so the pipe's name never goes free.
                tracing::warn!("accepting a client on {name} failed: {e}; carrying on");
                next = next_instance(&name, &sd).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::store::Store;
    use datasabi_protocol::{
        decode_line, encode_line, ClientMessage, Request, Response, ServerMessage,
    };
    use std::io::{BufRead, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

    /// ERROR_PIPE_BUSY: every instance is taken for the moment.
    const PIPE_BUSY: i32 = 231;

    fn unique_name() -> String {
        static N: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\datasabi-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn shared() -> (tempfile::TempDir, Arc<Shared>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        (dir, Arc::new(Shared::new(store)))
    }

    async fn connect(name: &str) -> NamedPipeClient {
        for _ in 0..50 {
            match ClientOptions::new().open(name) {
                Ok(c) => return c,
                Err(e) if e.raw_os_error() == Some(PIPE_BUSY) => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(e) => panic!("connecting to {name}: {e}"),
            }
        }
        panic!("{name} stayed busy");
    }

    async fn ping(client: NamedPipeClient, id: u64) {
        let (r, mut w) = tokio::io::split(client);
        let line = encode_line(&ClientMessage {
            id,
            request: Request::Ping,
        })
        .unwrap();
        w.write_all(line.as_bytes()).await.unwrap();
        let mut lines = BufReader::new(r).lines();
        let l = lines.next_line().await.unwrap().unwrap();
        assert!(matches!(
            decode_line::<ServerMessage>(&l).unwrap(),
            ServerMessage::Response { id: got, body: Response::Pong { .. } } if got == id
        ));
    }

    #[test]
    fn the_access_list_builds_and_bad_sddl_is_refused() {
        assert!(SecurityDescriptor::from_sddl(PIPE_SDDL).is_ok());
        assert!(SecurityDescriptor::from_sddl("not an access list").is_err());
    }

    /// Two clients at once both get answers: a new instance is ready while the first
    /// one is busy.
    #[tokio::test]
    async fn clients_are_answered_over_the_pipe() {
        let (_dir, shared) = shared();
        let name = unique_name();
        let listener = bind(&name).unwrap();
        tokio::spawn(serve(listener, shared));
        let a = connect(&name).await;
        let b = connect(&name).await;
        ping(a, 1).await;
        ping(b, 2).await;
    }

    /// The access list's own constant matches what clients ask for.
    #[test]
    fn signed_in_users_get_exactly_what_clients_ask_for() {
        assert!(PIPE_SDDL.contains(&format!("(A;;{:#x};;;IU)", CLIENT_ACCESS)));
    }

    /// A client asking only for CLIENT_ACCESS (as dsctl and the app do) can talk to
    /// the collector: read and write data are enough for the protocol.
    #[tokio::test]
    async fn a_client_with_only_read_and_write_data_is_answered() {
        let (_dir, shared) = shared();
        let name = unique_name();
        let listener = bind(&name).unwrap();
        tokio::spawn(serve(listener, shared));
        let pipe_name = name.clone();
        let line = tokio::task::spawn_blocking(move || {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .access_mode(CLIENT_ACCESS)
                .open(&pipe_name)
                .unwrap();
            let mut w = file.try_clone().unwrap();
            let ping = encode_line(&ClientMessage {
                id: 9,
                request: Request::Ping,
            })
            .unwrap();
            w.write_all(ping.as_bytes()).unwrap();
            let mut line = String::new();
            std::io::BufReader::new(file).read_line(&mut line).unwrap();
            line
        })
        .await
        .unwrap();
        assert!(matches!(
            decode_line::<ServerMessage>(&line).unwrap(),
            ServerMessage::Response {
                id: 9,
                body: Response::Pong { .. }
            }
        ));
    }

    /// Clients that open the pipe and leave at once (before or just after being accepted)
    /// don't stop the server: a normal client is still answered afterwards.
    #[tokio::test]
    async fn clients_that_leave_at_once_dont_stop_the_server() {
        let (_dir, shared) = shared();
        let name = unique_name();
        let listener = bind(&name).unwrap();
        tokio::spawn(serve(listener, shared));
        for _ in 0..20 {
            drop(connect(&name).await);
        }
        ping(connect(&name).await, 3).await;
    }

    /// Name squatting: if the name is already held (by another collector or any other
    /// program), `bind` fails instead of joining someone else's pipe.
    #[tokio::test]
    async fn a_taken_name_is_refused() {
        let name = unique_name();
        let _first = bind(&name).unwrap();
        // `Listener` has no Debug, so no `expect_err`.
        match bind(&name) {
            Ok(_) => panic!("a second first instance must fail"),
            Err(err) => assert!(format!("{err:#}").contains("already using it")),
        }
    }
}
