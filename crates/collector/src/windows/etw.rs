//! The ETW session: Kernel-Network (bytes per process) and Kernel-Process (names of
//! processes as they start), in one real-time session. The callbacks only parse and
//! queue; everything else happens on the capture thread.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use anyhow::Result;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;

use crate::aggregate::Direction;
use crate::winrules::{
    net_direction, KERNEL_NETWORK, KERNEL_NETWORK_KEYWORDS, KERNEL_PROCESS,
    KERNEL_PROCESS_KEYWORDS, PROCESS_START, PROCESS_STOP,
};

/// What the callbacks hand to the capture thread.
pub enum Msg {
    /// `size` bytes sent or received by process `pid`; one of `a`, `b` is ours.
    Net {
        pid: u32,
        size: u32,
        dir: Direction,
        a: IpAddr,
        b: IpAddr,
    },
    Start {
        pid: u32,
        image: String,
    },
    Stop {
        pid: u32,
    },
}

/// Counters the callbacks keep, read by the capture thread.
#[derive(Default)]
pub struct Counts {
    /// Events dropped because the capture thread's queue was full.
    pub dropped: AtomicU64,
    /// Network events that couldn't be read (no schema, or missing fields).
    pub unparsed: AtomicU64,
}

/// A running session; stopped when dropped.
pub struct Session {
    trace: Option<UserTrace>,
}

impl Session {
    pub fn stop(mut self) {
        if let Some(t) = self.trace.take() {
            let _ = t.stop();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(t) = self.trace.take() {
            let _ = t.stop();
        }
    }
}

/// Starts the session `name`. A session left behind by a crashed run would stop a new
/// one from starting, so it's stopped first. Needs administrator rights.
pub fn start(name: &str, tx: SyncSender<Msg>, counts: Arc<Counts>) -> Result<Session> {
    let _ = std::process::Command::new("logman")
        .args(["stop", name, "-ets"])
        .output();

    let net_tx = tx.clone();
    let net_counts = counts.clone();
    let network = Provider::by_guid(KERNEL_NETWORK)
        .any(KERNEL_NETWORK_KEYWORDS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            on_network(record, locator, &net_tx, &net_counts);
        })
        .build();

    let proc_counts = counts;
    let process = Provider::by_guid(KERNEL_PROCESS)
        .any(KERNEL_PROCESS_KEYWORDS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            on_process(record, locator, &tx, &proc_counts);
        })
        .build();

    let trace = UserTrace::new()
        .named(name.to_string())
        .enable(network)
        .enable(process)
        .start_and_process()
        .map_err(|e| {
            anyhow::anyhow!(
                "could not start the ETW session {name} ({e:?}); the collector needs \
                 administrator rights"
            )
        })?;
    tracing::info!("ETW session {name} started");
    Ok(Session { trace: Some(trace) })
}

fn send(tx: &SyncSender<Msg>, counts: &Counts, msg: Msg) {
    if tx.try_send(msg).is_err() {
        counts.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn on_network(
    record: &EventRecord,
    locator: &SchemaLocator,
    tx: &SyncSender<Msg>,
    counts: &Counts,
) {
    let Some(dir) = net_direction(record.event_id()) else {
        return;
    };
    let Ok(schema) = locator.event_schema(record) else {
        counts.unparsed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let parser = Parser::create(record, &schema);
    let pid: Result<u32, _> = parser.try_parse("PID");
    let size: Result<u32, _> = parser.try_parse("size");
    let a: Result<IpAddr, _> = parser.try_parse("saddr");
    let b: Result<IpAddr, _> = parser.try_parse("daddr");
    let (Ok(pid), Ok(size), Ok(a), Ok(b)) = (pid, size, a, b) else {
        counts.unparsed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    send(
        tx,
        counts,
        Msg::Net {
            pid,
            size,
            dir,
            a,
            b,
        },
    );
}

fn on_process(
    record: &EventRecord,
    locator: &SchemaLocator,
    tx: &SyncSender<Msg>,
    counts: &Counts,
) {
    let id = record.event_id();
    if id != PROCESS_START && id != PROCESS_STOP {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let Ok(pid) = parser.try_parse::<u32>("ProcessID") else {
        return;
    };
    if id == PROCESS_STOP {
        send(tx, counts, Msg::Stop { pid });
        return;
    }
    if let Ok(image) = parser.try_parse::<String>("ImageName") {
        send(tx, counts, Msg::Start { pid, image });
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::*;

    /// A real session counts this process's download. Needs administrator rights and the
    /// internet, so it's ignored by default; the Windows CI job runs it with `--ignored`.
    #[test]
    #[ignore]
    fn etw_counts_this_process_download() {
        let (tx, rx) = mpsc::sync_channel(65_536);
        let counts = Arc::new(Counts::default());
        let session = start("DataSabiCollectorTest", tx, counts.clone()).unwrap();
        std::thread::sleep(Duration::from_secs(2));

        let mut stream = std::net::TcpStream::connect("example.com:80").unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let expected = response.len() as u64;

        let me = std::process::id();
        let mut received = 0u64;
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline && received < expected {
            if let Ok(Msg::Net {
                pid,
                size,
                dir: Direction::In,
                ..
            }) = rx.recv_timeout(Duration::from_millis(200))
            {
                if pid == me {
                    received += u64::from(size);
                }
            }
        }
        session.stop();
        assert!(
            received * 10 >= expected * 9,
            "ETW counted {received} of the {expected} bytes this process received \
             ({} dropped, {} unreadable)",
            counts.dropped.load(Ordering::Relaxed),
            counts.unparsed.load(Ordering::Relaxed)
        );
    }
}
