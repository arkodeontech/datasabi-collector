//! Local socket server speaking the newline-delimited JSON protocol from
//! `datasabi-protocol`.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use datasabi_protocol::{
    decode_line, encode_line, ClientMessage, Request, Response, ServerMessage, PROTOCOL_VERSION,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};

use crate::state::Shared;

/// Longest request line accepted; anything bigger closes the connection.
const MAX_LINE: usize = 64 * 1024;

pub fn bind(path: &Path, group: Option<&str>) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    if path.exists() {
        std::fs::remove_file(path).with_context(|| format!("removing stale {}", path.display()))?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    let mode = match group {
        Some(name) => {
            let g = nix::unistd::Group::from_name(name)?
                .with_context(|| format!("group {name} does not exist"))?;
            nix::unistd::chown(path, None, Some(g.gid))
                .with_context(|| format!("giving {} to group {name}", path.display()))?;
            0o660
        }
        None => {
            tracing::warn!("no --socket-group given: socket is open to every local user");
            0o666
        }
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    tracing::info!("listening on {}", path.display());
    Ok(listener)
}

pub async fn serve(listener: UnixListener, shared: Arc<Shared>) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, shared).await {
                tracing::debug!("client disconnected: {e:#}");
            }
        });
    }
}

async fn handle_client(stream: UnixStream, shared: Arc<Shared>) -> Result<()> {
    let (read, mut write) = stream.into_split();
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
                if shared
                    .store
                    .lock()
                    .unwrap()
                    .delete_alert_rule(rule_id)?
                {
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
    use datasabi_protocol::{Range, Request};

    #[tokio::test]
    async fn ping_summary_and_subscribe_over_socket() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        let shared = Arc::new(Shared::new(store));
        let sock = dir.path().join("c.sock");
        let listener = bind(&sock, None).unwrap();
        tokio::spawn(serve(listener, shared.clone()));

        let stream = UnixStream::connect(&sock).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        for (id, request) in [
            (1, Request::Ping),
            (
                2,
                Request::GetSummary {
                    range: Range::Today,
                },
            ),
            (3, Request::Subscribe),
        ] {
            let line = encode_line(&ClientMessage { id, request }).unwrap();
            w.write_all(line.as_bytes()).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in 0..3 {
            let l = lines.next_line().await.unwrap().unwrap();
            got.push(decode_line::<ServerMessage>(&l).unwrap());
        }
        assert!(matches!(
            got[0],
            ServerMessage::Response {
                id: 1,
                body: Response::Pong { .. }
            }
        ));
        assert!(matches!(
            got[1],
            ServerMessage::Response {
                id: 2,
                body: Response::Summary(_)
            }
        ));
        assert!(matches!(
            got[2],
            ServerMessage::Response {
                id: 3,
                body: Response::Ok
            }
        ));

        shared.publish(datasabi_protocol::Event::Live(Default::default()));
        let l = lines.next_line().await.unwrap().unwrap();
        assert!(matches!(
            decode_line::<ServerMessage>(&l).unwrap(),
            ServerMessage::Event { .. }
        ));

        w.write_all(b"not json\n").await.unwrap();
        let l = lines.next_line().await.unwrap().unwrap();
        assert!(matches!(
            decode_line::<ServerMessage>(&l).unwrap(),
            ServerMessage::Response {
                id: 0,
                body: Response::Error { .. }
            }
        ));
    }
}
