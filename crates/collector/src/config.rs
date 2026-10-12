use std::path::PathBuf;

use clap::Parser;
use datasabi_protocol::DEFAULT_SOCKET_PATH;

/// DataSabi collector: measures how much internet data each app uses.
#[derive(Parser, Debug, Clone)]
#[command(name = "datasabi-collector", version, about)]
pub struct Config {
    /// Path of the local socket that the DataSabi app connects to.
    #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
    pub socket: PathBuf,

    /// SQLite database holding usage history.
    #[arg(long, default_value = "/var/lib/datasabi/usage.db")]
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
