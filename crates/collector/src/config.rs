use std::path::PathBuf;

use clap::Parser;
use datasabi_protocol::DEFAULT_ENDPOINT;

/// Where the usage history is kept by default.
#[cfg(not(windows))]
const DEFAULT_DB: &str = "/var/lib/datasabi/usage.db";
/// Where the usage history is kept by default (the service PR may move it with
/// %ProgramData%).
#[cfg(windows)]
const DEFAULT_DB: &str = r"C:\ProgramData\DataSabi\usage.db";

/// DataSabi collector: measures how much internet data each app uses.
#[derive(Parser, Debug, Clone)]
#[command(name = "datasabi-collector", version, about)]
pub struct Config {
    /// Where the DataSabi app connects: the local socket's path on Linux, the named
    /// pipe's name on Windows.
    #[arg(long, default_value = DEFAULT_ENDPOINT)]
    pub socket: PathBuf,

    /// SQLite database holding usage history.
    #[arg(long, default_value = DEFAULT_DB)]
    pub db: PathBuf,

    /// Group allowed to use the socket (mode 0660). Without it the socket is
    /// world-accessible (0666), which is only meant for development.
    #[arg(long)]
    pub socket_group: Option<String>,

    /// Capture only these interfaces (repeatable). Default: every physical
    /// interface, picked up automatically as it appears (Wi-Fi, USB tethering, ...).
    #[arg(long = "interface", short = 'i')]
    pub interfaces: Vec<String>,
}
