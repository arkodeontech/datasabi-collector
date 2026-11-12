//! `dsctl`: talk to the DataSabi collector from a terminal.
//!
//!   dsctl ping
//!   dsctl summary [today|week|month]
//!   dsctl live
//!   dsctl networks
//!   dsctl set-network <id> metered|unlimited|auto
//!   dsctl watch            # stream live rates and alerts

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use datasabi_protocol::{Range, DEFAULT_ENDPOINT};

#[derive(Parser)]
#[command(name = "dsctl", version, about = "Query the DataSabi collector")]
struct Cli {
    /// The collector's socket (Linux) or named pipe (Windows).
    #[arg(long, default_value = DEFAULT_ENDPOINT)]
    socket: PathBuf,
    /// Print raw JSON responses.
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check that the collector is running.
    Ping,
    /// Data used per app.
    Summary {
        #[arg(value_enum, default_value_t = RangeArg::Today)]
        range: RangeArg,
    },
    /// Current transfer rates.
    Live,
    /// Known networks and how they are treated.
    Networks,
    /// Mark a network as metered, unlimited, or back to automatic.
    SetNetwork { id: i64, mode: NetMode },
    /// Stream live rates and alerts until Ctrl+C.
    Watch,
    /// Show current alert rules and quiet-mode status.
    AlertConfig,
    /// Add or update an alert rule (threshold in MB, window in minutes).
    SetAlert { mb: u64, minutes: u32 },
    /// Remove an alert rule by id.
    DeleteAlert { id: i64 },
    /// Silence alerts for N hours (0 = clear quiet mode).
    Quiet { hours: u32 },
    /// Bytes used on some networks (ids from `dsctl networks`) between two Unix times.
    Usage {
        /// Network ids, comma separated.
        #[arg(value_delimiter = ',', required = true)]
        networks: Vec<i64>,
        /// Start, Unix seconds (included).
        #[arg(long)]
        from: i64,
        /// End, Unix seconds (excluded); now if left out.
        #[arg(long)]
        to: Option<i64>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RangeArg {
    Today,
    Week,
    Month,
}

#[derive(Clone, Copy, ValueEnum)]
enum NetMode {
    Metered,
    Unlimited,
    Auto,
}

impl From<RangeArg> for Range {
    fn from(r: RangeArg) -> Self {
        match r {
            RangeArg::Today => Range::Today,
            RangeArg::Week => Range::Week,
            RangeArg::Month => Range::Month,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    imp::run(cli)
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub fn run(_cli: super::Cli) -> anyhow::Result<()> {
        anyhow::bail!("dsctl does not support this OS yet")
    }
}

#[cfg(any(unix, windows))]
mod imp {
    use std::io::{BufRead, BufReader, Write};

    use anyhow::{bail, Context, Result};
    use datasabi_protocol::{
        decode_line, encode_line, format_bytes, ClientMessage, Event, LiveSnapshot, Request,
        Response, ServerMessage, BYTES_PER_MB,
    };

    use super::{Cli, Cmd, NetMode};

    #[cfg(unix)]
    type Stream = std::os::unix::net::UnixStream;
    /// A named pipe client is opened like a file.
    #[cfg(windows)]
    type Stream = std::fs::File;

    #[cfg(unix)]
    fn open(cli: &Cli) -> Result<Stream> {
        Stream::connect(&cli.socket).with_context(|| {
            format!(
                "cannot reach the collector at {} (is it running, and are you in the datasabi group?)",
                cli.socket.display()
            )
        })
    }

    #[cfg(windows)]
    fn open(cli: &Cli) -> Result<Stream> {
        /// ERROR_PIPE_BUSY: every instance is taken for the moment; the collector
        /// makes a new one at once, so try again shortly.
        const PIPE_BUSY: i32 = 231;
        /// FILE_GENERIC_READ | FILE_WRITE_DATA: what the pipe's access list gives
        /// signed-in users (the collector's `ipc::pipe::CLIENT_ACCESS`).
        const CLIENT_ACCESS: u32 = 0x0012_0089 | 0x0002;
        use std::os::windows::fs::OpenOptionsExt;
        let mut tries = 0;
        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .access_mode(CLIENT_ACCESS)
                .open(&cli.socket)
            {
                Ok(f) => {
                    check_server(&f, cli)?;
                    return Ok(f);
                }
                Err(e) if e.raw_os_error() == Some(PIPE_BUSY) && tries < 50 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "cannot reach the collector at {} (is the DataSabi service running?)",
                            cli.socket.display()
                        )
                    })
                }
            }
        }
    }

    /// Talk only to the real service. The collector refuses to start if its pipe's name
    /// is taken, but that protects it, not its clients: if the service isn't running,
    /// any program can create a pipe with this name. The service runs as SYSTEM, so its
    /// pipe is owned by SYSTEM (S-1-5-18); anything else is refused before a word is sent.
    #[cfg(windows)]
    fn check_server(pipe: &Stream, cli: &Cli) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
        use windows_sys::Win32::Security::{
            IsWellKnownSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID,
        };

        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: the handle is open for the call (it has READ_CONTROL through
        // CLIENT_ACCESS); `owner` points into `sd`, which Windows allocates and we free.
        let err = unsafe {
            GetSecurityInfo(
                pipe.as_raw_handle(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if err != ERROR_SUCCESS {
            bail!(
                "cannot check who runs {} (Windows error {err}); not sending anything",
                cli.socket.display()
            );
        }
        // SAFETY: `owner` is valid until `sd` is freed just below.
        let system = unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } != 0;
        // SAFETY: allocated by GetSecurityInfo.
        unsafe { LocalFree(sd) };
        if !system {
            bail!(
                "{} isn't owned by the system, so it isn't the DataSabi service: another \
                 program may be posing as it. Not sending anything.",
                cli.socket.display()
            );
        }
        Ok(())
    }

    struct Client {
        reader: BufReader<Stream>,
        writer: Stream,
        next_id: u64,
    }

    impl Client {
        fn connect(cli: &Cli) -> Result<Self> {
            let s = open(cli)?;
            Ok(Self {
                reader: BufReader::new(s.try_clone()?),
                writer: s,
                next_id: 1,
            })
        }

        fn request(&mut self, request: Request) -> Result<Response> {
            let id = self.next_id;
            self.next_id += 1;
            self.writer
                .write_all(encode_line(&ClientMessage { id, request })?.as_bytes())?;
            loop {
                match self.read()? {
                    ServerMessage::Response { id: rid, body } if rid == id || rid == 0 => {
                        return Ok(body)
                    }
                    _ => continue,
                }
            }
        }

        fn read(&mut self) -> Result<ServerMessage> {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                bail!("collector closed the connection");
            }
            Ok(decode_line(&line)?)
        }
    }

    fn rate(bps: u64) -> String {
        format!("{}/s", format_bytes(bps))
    }

    fn print_live(l: &LiveSnapshot) {
        println!("down {}  up {}", rate(l.total_rx_bps), rate(l.total_tx_bps));
        for a in l.apps.iter().take(10) {
            println!(
                "  {:<32} down {:>10}  up {:>10}",
                a.name,
                rate(a.rx_bps),
                rate(a.tx_bps)
            );
        }
    }

    pub fn run(cli: Cli) -> Result<()> {
        let mut c = Client::connect(&cli)?;
        let req = match &cli.cmd {
            Cmd::Ping => Request::Ping,
            Cmd::Summary { range } => Request::GetSummary {
                range: (*range).into(),
            },
            Cmd::Live => Request::GetLive,
            Cmd::Networks => Request::GetNetworks,
            Cmd::SetNetwork { id, mode } => Request::SetNetworkOverride {
                network_id: *id,
                metered: match mode {
                    NetMode::Metered => Some(true),
                    NetMode::Unlimited => Some(false),
                    NetMode::Auto => None,
                },
            },
            Cmd::Watch => Request::Subscribe,
            Cmd::AlertConfig => Request::GetAlertConfig,
            Cmd::SetAlert { mb, minutes } => Request::SetAlertRule {
                window_minutes: *minutes,
                threshold_bytes: mb * BYTES_PER_MB,
            },
            Cmd::DeleteAlert { id } => Request::DeleteAlertRule { rule_id: *id },
            Cmd::Usage { networks, from, to } => Request::GetUsage {
                networks: networks.clone(),
                from_unix: *from,
                to_unix: to.unwrap_or_else(|| chrono::Utc::now().timestamp()),
            },
            Cmd::Quiet { hours } => Request::SetQuietMode {
                until_unix: if *hours == 0 {
                    None
                } else {
                    Some(chrono::Utc::now().timestamp() + *hours as i64 * 3600)
                },
            },
        };
        let resp = c.request(req)?;
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            if !matches!(cli.cmd, Cmd::Watch) {
                return Ok(());
            }
        }
        match resp {
            Response::Error { message } => bail!("collector error: {message}"),
            Response::Pong { version, protocol } => {
                println!("collector {version} (protocol {protocol}) is running")
            }
            Response::Summary(s) if !cli.json => {
                println!(
                    "Total: {}  (down {}, up {})",
                    format_bytes(s.total_in + s.total_out),
                    format_bytes(s.total_in),
                    format_bytes(s.total_out)
                );
                for a in &s.apps {
                    println!(
                        "  {:>4}  {:<32} {:>9}",
                        a.app_id,
                        a.name,
                        format_bytes(a.total())
                    );
                }
            }
            Response::Live(l) if !cli.json => print_live(&l),
            Response::Networks { networks } if !cli.json => {
                for n in networks {
                    println!(
                        "  {:>3}  {:<10} {:<24} detected {:<8} override {:<9} => {}{}",
                        n.id,
                        n.interface,
                        n.name.as_deref().unwrap_or("-"),
                        format!("{:?}", n.detected).to_lowercase(),
                        match n.user_override {
                            Some(true) => "metered",
                            Some(false) => "unlimited",
                            None => "auto",
                        },
                        if n.treated_as_metered {
                            "metered"
                        } else {
                            "unlimited"
                        },
                        if n.active { "  (active)" } else { "" }
                    );
                }
            }
            Response::Ok if matches!(cli.cmd, Cmd::Watch) => loop {
                match c.read()? {
                    ServerMessage::Event { body } if cli.json => {
                        println!("{}", serde_json::to_string(&body)?)
                    }
                    ServerMessage::Event {
                        body: Event::Live(l),
                    } => {
                        if !l.apps.is_empty() {
                            print_live(&l);
                        }
                    }
                    ServerMessage::Event {
                        body: Event::AlertFired(a),
                    } => println!(
                        "ALERT: {} used {} in the last {} minutes{}",
                        a.app_name,
                        format_bytes(a.bytes),
                        a.window_minutes,
                        a.network.map(|n| format!(" on {n}")).unwrap_or_default()
                    ),
                    _ => {}
                }
            },
            Response::AlertConfig { rules, quiet_until } if !cli.json => {
                if let Some(t) = quiet_until {
                    println!("Quiet mode active until unix {t}");
                } else {
                    println!("Quiet mode: off");
                }
                println!("Alert rules:");
                for r in &rules {
                    println!(
                        "  {:>3}  {} MB in {} min",
                        r.id,
                        r.threshold_bytes / BYTES_PER_MB,
                        r.window_minutes
                    );
                }
            }
            Response::Usage(u) if !cli.json => println!(
                "{}  (down {}, up {}; days start at {:?} midnight)",
                format_bytes(u.bytes_in + u.bytes_out),
                format_bytes(u.bytes_in),
                format_bytes(u.bytes_out),
                u.day_boundary
            ),
            Response::Ok => println!("ok"),
            _ => {}
        }
        Ok(())
    }

    #[cfg(all(test, windows))]
    mod tests {
        use clap::Parser;

        use super::*;

        /// The impostor case: a pipe with the collector's name made by an ordinary
        /// process (here the test, not SYSTEM) is refused before anything is sent.
        #[tokio::test]
        async fn a_pipe_not_owned_by_the_system_is_refused() {
            let name = format!(r"\\.\pipe\datasabi-dsctl-test-{}", std::process::id());
            let _impostor = tokio::net::windows::named_pipe::ServerOptions::new()
                .create(&name)
                .unwrap();
            let cli = Cli::try_parse_from(["dsctl", "--socket", name.as_str(), "ping"]).unwrap();
            let err = open(&cli).err().expect("an impostor pipe must be refused");
            assert!(format!("{err:#}").contains("isn't owned by the system"));
        }
    }
}
