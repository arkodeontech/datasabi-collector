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
use datasabi_protocol::{Range, DEFAULT_SOCKET_PATH};

#[derive(Parser)]
#[command(name = "dsctl", version, about = "Query the DataSabi collector")]
struct Cli {
    #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
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

#[cfg(not(unix))]
mod imp {
    pub fn run(_cli: super::Cli) -> anyhow::Result<()> {
        anyhow::bail!("dsctl does not support this OS yet")
    }
}

#[cfg(unix)]
mod imp {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    use anyhow::{bail, Context, Result};
    use datasabi_protocol::{
        decode_line, encode_line, format_bytes, ClientMessage, Event, LiveSnapshot, Request,
        Response, ServerMessage, BYTES_PER_MB,
    };

    use super::{Cli, Cmd, NetMode};

    struct Client {
        reader: BufReader<UnixStream>,
        writer: UnixStream,
        next_id: u64,
    }

    impl Client {
        fn connect(cli: &Cli) -> Result<Self> {
            let s = UnixStream::connect(&cli.socket).with_context(|| {
                format!(
                    "cannot reach the collector at {} (is it running, and are you in the datasabi group?)",
                    cli.socket.display()
                )
            })?;
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
            Response::Ok => println!("ok"),
            _ => {}
        }
        Ok(())
    }
}
