//! Local connection server speaking the newline-delimited JSON protocol from
//! `datasabi-protocol`. The protocol handling here works over any stream; how
//! clients connect is per platform: a group-owned Unix socket on Linux (`unix`),
//! and a hardened named pipe on Windows (`pipe`).

use std::sync::Arc;

use anyhow::Result;
use datasabi_protocol::{
    decode_line, encode_line, ClientMessage, NetworkUsage, Request, Response, ServerMessage,
    PROTOCOL_VERSION,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc};

use crate::state::Shared;

#[cfg(windows)]
pub mod pipe;
#[cfg(target_os = "linux")]
pub mod unix;

/// Longest request line accepted; anything bigger closes the connection.
const MAX_LINE: usize = 64 * 1024;

/// Serves one client until it disconnects: requests in, responses and (after
/// `Subscribe`) events out, over any stream (a Unix socket, a named pipe, a test pipe).
pub async fn handle_client<S>(stream: S, shared: Arc<Shared>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read, mut write) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<String>(256);
    let writer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if write.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    let mut reader = BufReader::new(read);
    let mut line = String::new();
    let mut subscription: Option<tokio::task::JoinHandle<()>> = None;
    let result = loop {
        line.clear();
        let n = (&mut reader)
            .take(MAX_LINE as u64 + 1)
            .read_line(&mut line)
            .await?;
        if n == 0 {
            break Ok(());
        }
        if line.len() > MAX_LINE {
            break Err(anyhow::anyhow!("request too large"));
        }
        if line.trim().is_empty() {
            continue;
        }
        let (id, body) = match decode_line::<ClientMessage>(&line) {
            Ok(msg) => {
                let body = if matches!(msg.request, Request::Subscribe) {
                    if subscription.is_none() {
                        subscription = Some(spawn_forwarder(shared.events.subscribe(), tx.clone()));
                    }
                    Response::Ok
                } else {
                    let shared = shared.clone();
                    tokio::task::spawn_blocking(move || handle_request(&shared, msg.request))
                        .await
                        .unwrap_or_else(|e| Response::Error {
                            message: e.to_string(),
                        })
                };
                (msg.id, body)
            }
            Err(e) => (
                0,
                Response::Error {
                    message: format!("bad request: {e}"),
                },
            ),
        };
        let out = encode_line(&ServerMessage::Response { id, body })?;
        if tx.send(out).await.is_err() {
            break Ok(());
        }
    };
    if let Some(s) = subscription {
        s.abort();
    }
    drop(tx);
    let _ = writer.await;
    result
}

fn spawn_forwarder(
    mut events: broadcast::Receiver<datasabi_protocol::Event>,
    tx: mpsc::Sender<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(body) => {
                    let Ok(line) = encode_line(&ServerMessage::Event { body }) else {
                        continue;
                    };
                    if tx.send(line).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

pub fn handle_request(shared: &Shared, req: Request) -> Response {
    let result: Result<Response> = (|| {
        Ok(match req {
            Request::Ping => Response::Pong {
                version: env!("CARGO_PKG_VERSION").to_string(),
                protocol: PROTOCOL_VERSION,
            },
            Request::GetSummary { range } => Response::Summary(
                shared
                    .store
                    .lock()
                    .unwrap()
                    .summary(range, chrono::Local::now())?,
            ),
            Request::GetLive => Response::Live(shared.live.read().unwrap().clone()),
            Request::GetAppHistory { app_id, range } => {
                Response::AppHistory(shared.store.lock().unwrap().app_history(
                    app_id,
                    range,
                    chrono::Local::now(),
                )?)
            }
            Request::GetNetworks => Response::Networks {
                networks: shared
                    .store
                    .lock()
                    .unwrap()
                    .networks(chrono::Utc::now().timestamp())?,
            },
            Request::SetNetworkOverride {
                network_id,
                metered,
            } => {
                if shared
                    .store
                    .lock()
                    .unwrap()
                    .set_network_override(network_id, metered)?
                {
                    Response::Ok
                } else {
                    Response::Error {
                        message: format!("no network with id {network_id}"),
                    }
                }
            }
            Request::Subscribe => Response::Ok,
            Request::GetAlertConfig => {
                let store = shared.store.lock().unwrap();
                Response::AlertConfig {
                    rules: store.get_alert_rules()?,
                    quiet_until: store.get_quiet_until()?,
                }
            }
            Request::SetAlertRule {
                window_minutes,
                threshold_bytes,
            } => {
                shared
                    .store
                    .lock()
                    .unwrap()
                    .set_alert_rule(window_minutes, threshold_bytes)?;
                shared
                    .rules_dirty
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                Response::Ok
            }
            Request::DeleteAlertRule { rule_id } => {
                if shared.store.lock().unwrap().delete_alert_rule(rule_id)? {
                    shared
                        .rules_dirty
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    Response::Ok
                } else {
                    Response::Error {
                        message: format!("no alert rule with id {rule_id}"),
                    }
                }
            }
            Request::GetUsage {
                networks,
                from_unix,
                to_unix,
            } => {
                let (bytes_in, bytes_out) = shared
                    .store
                    .lock()
                    .unwrap()
                    .usage_between(&networks, from_unix, to_unix)?;
                Response::Usage(NetworkUsage {
                    bytes_in,
                    bytes_out,
                    day_boundary: crate::store::DAY_BOUNDARY,
                })
            }
            Request::SetQuietMode { until_unix } => {
                let v = until_unix.unwrap_or(0);
                shared.store.lock().unwrap().set_quiet_until(until_unix)?;
                shared
                    .quiet_until
                    .store(v, std::sync::atomic::Ordering::Relaxed);
                Response::Ok
            }
        })
    })();
    result.unwrap_or_else(|e| Response::Error {
        message: format!("{e:#}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use tokio::io::AsyncBufReadExt;

    fn shared() -> (tempfile::TempDir, Arc<Shared>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        (dir, Arc::new(Shared::new(store)))
    }

    /// The protocol over an in-memory stream, so it runs on every platform (the socket
    /// test is in `unix`): a request is answered, and a line over `MAX_LINE` closes the
    /// connection instead of growing a buffer.
    #[tokio::test]
    async fn any_stream_is_served_and_a_huge_line_is_refused() {
        let (_dir, shared) = shared();
        let (client, server) = tokio::io::duplex(256 * 1024);
        let served = tokio::spawn(handle_client(server, shared));
        let (r, mut w) = tokio::io::split(client);
        let mut lines = BufReader::new(r).lines();

        let ping = encode_line(&ClientMessage {
            id: 7,
            request: Request::Ping,
        })
        .unwrap();
        w.write_all(ping.as_bytes()).await.unwrap();
        let l = lines.next_line().await.unwrap().unwrap();
        assert!(matches!(
            decode_line::<ServerMessage>(&l).unwrap(),
            ServerMessage::Response {
                id: 7,
                body: Response::Pong { .. }
            }
        ));

        let huge = format!("{}\n", "x".repeat(MAX_LINE + 10));
        w.write_all(huge.as_bytes()).await.unwrap();
        let result = served.await.unwrap();
        assert!(result.unwrap_err().to_string().contains("too large"));
    }
}
