use std::path::PathBuf;

use clap::Parser;
use datasabi_protocol::DEFAULT_ENDPOINT;

/// Where the collector keeps its data on Windows: `%ProgramData%\DataSabi` (usually
/// `C:\ProgramData\DataSabi`), readable only by SYSTEM and Administrators.
#[cfg(windows)]
pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(base).join("DataSabi")
}

/// Where the usage history is kept by default.
fn default_db() -> PathBuf {
    #[cfg(windows)]
    return data_dir().join("usage.db");
    #[cfg(not(windows))]
    PathBuf::from("/var/lib/datasabi/usage.db")
}

/// DataSabi collector: measures how much internet data each app uses.
#[derive(Parser, Debug, Clone)]
#[command(name = "datasabi-collector", version, about)]
pub struct Config {
    /// Where the DataSabi app connects: the local socket's path on Linux, the named
    /// pipe's name on Windows.
    #[arg(long, default_value = DEFAULT_ENDPOINT)]
    pub socket: PathBuf,

    /// SQLite database holding usage history.
    #[arg(long, default_value_os_t = default_db())]
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
