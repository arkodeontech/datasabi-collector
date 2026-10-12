//! DataSabi collector: a small privileged service that measures how much internet
//! data each app uses and serves the numbers to the DataSabi app over a local socket.

#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

mod aggregate;
mod alerts;
mod config;
#[cfg(target_os = "linux")]
mod ipc;
#[cfg(target_os = "linux")]
mod linux;
mod state;
mod store;

use anyhow::Result;
use clap::Parser;

use config::Config;

fn main() -> Result<()> {
    let cfg = Config::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
    run(cfg)
}

#[cfg(not(target_os = "linux"))]
fn run(_cfg: Config) -> Result<()> {
    anyhow::bail!("datasabi-collector does not support this OS yet (Windows support is planned)")
}

#[cfg(target_os = "linux")]
fn run(cfg: Config) -> Result<()> {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    tracing::info!("DataSabi collector {} starting", env!("CARGO_PKG_VERSION"));
    let store = store::Store::open(&cfg.db)?;
    let shared = Arc::new(state::Shared::new(store));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<()>>();
    let engine = {
        let cfg = cfg.clone();
        let shared = shared.clone();
        std::thread::Builder::new()
            .name("engine".into())
            .spawn(move || {
                let r = linux::run(cfg, shared);
                let _ = done_tx.send(r);
            })?
    };

    let result = rt.block_on(async {
        let listener = ipc::bind(&cfg.socket, cfg.socket_group.as_deref())?;
        tokio::select! {
            r = ipc::serve(listener, shared.clone()) => r,
            r = done_rx => match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e.context("capture engine failed")),
                Err(_) => Err(anyhow::anyhow!("capture engine panicked")),
            },
            _ = shutdown_signal() => {
                tracing::info!("shutting down");
                Ok(())
            }
        }
    });

    shared.shutdown.store(true, Ordering::Relaxed);
    let _ = engine.join();
    let _ = std::fs::remove_file(&cfg.socket);
    result
}

#[cfg(target_os = "linux")]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
