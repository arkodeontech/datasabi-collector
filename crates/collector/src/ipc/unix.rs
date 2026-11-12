//! The Linux transport: a Unix socket, owned by a group so only its members (and root)
//! can connect (`--socket-group`).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UnixListener;

use super::handle_client;
use crate::state::Shared;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use datasabi_protocol::{
        decode_line, encode_line, ClientMessage, Range, Request, Response, ServerMessage,
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

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
