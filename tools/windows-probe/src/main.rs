//! datasabi-probe: a test program for the DataSabi Windows plan.
//!
//! It counts how many bytes each process sends and receives, using the ETW provider
//! `Microsoft-Windows-Kernel-Network`, and compares the total with the network
//! adapters' own byte counters. Processes inside `svchost.exe` are labelled with the
//! services they host, to see whether Windows Update can be told apart from "System".
//!
//! Privacy: addresses are only looked at in memory, to skip loopback and local-network
//! traffic. Nothing about packet contents, addresses or websites is printed or saved.
//! The report holds process names, service names and byte counts only.

#[cfg(not(windows))]
fn main() {
    eprintln!("datasabi-probe only runs on Windows.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if let Err(e) = probe::run() {
        eprintln!();
        eprintln!("datasabi-probe stopped: {e:#}");
        eprintln!("Press Enter to close.");
        let _ = std::io::stdin().read_line(&mut String::new());
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod probe {
    use std::collections::HashMap;
    use std::io::Write;
    use std::net::IpAddr;
    use std::process::Command;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use anyhow::{bail, Context, Result};
    use ferrisetw::parser::Parser;
    use ferrisetw::provider::Provider;
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::{TraceTrait, UserTrace};
    use ferrisetw::EventRecord;

    /// Microsoft-Windows-Kernel-Network.
    const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
    /// KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6.
    const KEYWORDS: u64 = 0x10 | 0x20;
    const TRACE_NAME: &str = "DataSabiProbe";
    const DEFAULT_MINUTES: u64 = 60;
    const REPORT_EVERY: Duration = Duration::from_secs(60);
    const NAMES_EVERY: Duration = Duration::from_secs(10);

    #[derive(Default, Clone, Copy)]
    struct Bytes {
        rx: u64,
        tx: u64,
    }

    impl Bytes {
        fn add(&mut self, outgoing: bool, n: u64) {
            if outgoing {
                self.tx += n;
            } else {
                self.rx += n;
            }
        }
        fn total(&self) -> u64 {
            self.rx + self.tx
        }
        fn since(&self, start: &Bytes) -> Bytes {
            Bytes {
                rx: self.rx.saturating_sub(start.rx),
                tx: self.tx.saturating_sub(start.tx),
            }
        }
    }

    #[derive(Default)]
    struct Counters {
        per_pid: HashMap<u32, Bytes>,
        local: Bytes,
        events: u64,
        unparsed: u64,
        no_address: u64,
    }

    #[derive(Clone)]
    struct ProcInfo {
        image: String,
        services: String,
    }

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn run() -> Result<()> {
        let minutes = parse_minutes()?;
        println!("DataSabi Windows probe");
        println!("Counts data per app for {minutes} minutes, or until you press Enter.");
        println!("Nothing about websites, addresses or packet contents is saved.");
        println!();

        let (net_name, net_cost) = network_profile();
        println!("Network: {net_name} (Windows cost setting: {net_cost})");

        let adapters_start = adapter_totals().context("could not read adapter totals")?;
        let names: Arc<Mutex<HashMap<u32, ProcInfo>>> = Arc::new(Mutex::new(HashMap::new()));
        refresh_names(&names);

        let counters = Arc::new(Mutex::new(Counters::default()));
        let cb_counters = counters.clone();
        let provider = Provider::by_guid(KERNEL_NETWORK)
            .any(KEYWORDS)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                on_event(record, locator, &cb_counters);
            })
            .build();

        let trace = UserTrace::new()
            .named(String::from(TRACE_NAME))
            .enable(provider)
            .start_and_process()
            .map_err(|e| {
                anyhow::anyhow!(
                    "could not start the ETW trace ({e:?}). Run PowerShell as Administrator. \
                     If a previous run crashed, run `logman stop {TRACE_NAME} -ets` and try again."
                )
            })?;

        let started = Instant::now();
        let deadline = started + Duration::from_secs(minutes * 60);
        let (enter_tx, enter_rx) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _ = std::io::stdin().read_line(&mut String::new());
            let _ = enter_tx.send(());
        });

        println!("Running. Press Enter to stop early.");
        println!();
        let mut next_report = started + REPORT_EVERY;
        let mut next_names = started + NAMES_EVERY;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let wake = next_report.min(next_names).min(deadline);
            match enter_rx.recv_timeout(wake.saturating_duration_since(now)) {
                Ok(()) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(wake.saturating_duration_since(Instant::now()))
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let now = Instant::now();
            if now >= next_names {
                refresh_names(&names);
                next_names = now + NAMES_EVERY;
            }
            if now >= next_report {
                let adapters = adapter_totals().unwrap_or_default();
                print_progress(started, &counters, &names, &adapters_start, &adapters);
                next_report = now + REPORT_EVERY;
            }
        }

        refresh_names(&names);
        let adapters_end = adapter_totals().context("could not read adapter totals")?;
        let _ = trace.stop();
        let elapsed = started.elapsed();
        print_progress(started, &counters, &names, &adapters_start, &adapters_end);
        let path = write_report(
            elapsed,
            &net_cost,
            &counters,
            &names,
            &adapters_start,
            &adapters_end,
        )?;
        println!();
        println!("Report saved: {}", path.display());
        println!("Send it to Claude with the balance before and after, and a screenshot of");
        println!("Settings > Network & internet > Advanced network settings > Data usage.");
        println!("Press Enter to close.");
        let _ = std::io::stdin().read_line(&mut String::new());
        Ok(())
    }

    fn parse_minutes() -> Result<u64> {
        let mut args = std::env::args().skip(1);
        let mut minutes = DEFAULT_MINUTES;
        while let Some(a) = args.next() {
            match a.as_str() {
                "--minutes" => {
                    let v = args.next().context("--minutes needs a number")?;
                    minutes = v.parse().context("--minutes needs a whole number")?;
                    if minutes == 0 {
                        bail!("--minutes must be at least 1");
                    }
                }
                other => bail!("unknown option {other}. Usage: datasabi-probe [--minutes N]"),
            }
        }
        Ok(minutes)
    }

    fn on_event(record: &EventRecord, locator: &SchemaLocator, counters: &Mutex<Counters>) {
        // Send and receive events for TCP and UDP over IPv4 and IPv6.
        let outgoing = match record.event_id() {
            10 | 26 | 42 | 58 => true,
            11 | 27 | 43 | 59 => false,
            _ => return,
        };
        let Ok(schema) = locator.event_schema(record) else {
            lock(counters).unparsed += 1;
            return;
        };
        let parser = Parser::create(record, &schema);
        let pid: Result<u32, _> = parser.try_parse("PID");
        let size: Result<u32, _> = parser.try_parse("size");
        let (Ok(pid), Ok(size)) = (pid, size) else {
            lock(counters).unparsed += 1;
            return;
        };
        let daddr: Result<IpAddr, _> = parser.try_parse("daddr");
        let saddr: Result<IpAddr, _> = parser.try_parse("saddr");
        let mut c = lock(counters);
        c.events += 1;
        match (daddr, saddr) {
            (Ok(d), Ok(s)) if is_local(&d) && is_local(&s) => {
                c.local.add(outgoing, u64::from(size));
                return;
            }
            (Ok(_), Ok(_)) => {}
            _ => c.no_address += 1,
        }
        c.per_pid
            .entry(pid)
            .or_default()
            .add(outgoing, u64::from(size));
    }

    /// Loopback, private, link-local or unspecified: traffic that never uses the bundle
    /// when both ends are like this.
    fn is_local(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                let first = v6.segments()[0];
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (first & 0xfe00) == 0xfc00
                    || (first & 0xffc0) == 0xfe80
            }
        }
    }

    /// Runs a command and returns its output as text, or an empty string on failure.
    fn command_text(program: &str, args: &[&str]) -> String {
        Command::new(program)
            .args(args)
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
            .unwrap_or_default()
    }

    fn powershell(script: &str) -> String {
        command_text(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", script],
        )
    }

    /// The internet connection's profile name and Windows' cost setting for it.
    fn network_profile() -> (String, String) {
        let script = "$p=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile(); \
                      if ($p) { $c=$p.GetConnectionCost(); Write-Output \"$($p.ProfileName)|$($c.NetworkCostType)\" }";
        let out = powershell(script);
        let line = out.lines().next().unwrap_or("").trim();
        match line.split_once('|') {
            Some((name, cost)) => (name.to_string(), cost.to_string()),
            None => ("unknown".to_string(), "unknown".to_string()),
        }
    }

    /// Bytes received and sent per network adapter since it started.
    fn adapter_totals() -> Result<HashMap<String, Bytes>> {
        let out = powershell(
            "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Csv -NoTypeInformation",
        );
        let mut map = HashMap::new();
        for line in out.lines().skip(1) {
            let f = csv_fields(line);
            if f.len() < 3 {
                continue;
            }
            let (Ok(rx), Ok(tx)) = (f[1].parse::<u64>(), f[2].parse::<u64>()) else {
                continue;
            };
            map.insert(f[0].clone(), Bytes { rx, tx });
        }
        if map.is_empty() {
            bail!("Get-NetAdapterStatistics returned nothing");
        }
        Ok(map)
    }

    /// Process names and hosted services per PID, from `tasklist /svc`. Old entries are
    /// kept so that processes which have exited still have a name in the report.
    fn refresh_names(names: &Mutex<HashMap<u32, ProcInfo>>) {
        let out = command_text("tasklist", &["/svc", "/fo", "csv", "/nh"]);
        let mut map = lock(names);
        for line in out.lines() {
            let f = csv_fields(line);
            if f.len() < 3 {
                continue;
            }
            let Ok(pid) = f[1].parse::<u32>() else {
                continue;
            };
            let services = if f[2] == "N/A" {
                String::new()
            } else {
                f[2].clone()
            };
            map.insert(
                pid,
                ProcInfo {
                    image: f[0].clone(),
                    services,
                },
            );
        }
    }

    /// Splits one CSV line with double-quoted fields.
    fn csv_fields(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut cur = String::new();
        let mut quoted = false;
        let mut chars = line.trim_end_matches(['\r', '\n']).chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    cur.push('"');
                    chars.next();
                }
                '"' => quoted = !quoted,
                ',' if !quoted => fields.push(std::mem::take(&mut cur)),
                _ => cur.push(ch),
            }
        }
        fields.push(cur);
        fields
    }

    /// Groups byte counts by process name, with svchost labelled by its services.
    fn grouped(
        counters: &Mutex<Counters>,
        names: &Mutex<HashMap<u32, ProcInfo>>,
    ) -> Vec<(String, String, Bytes)> {
        let per_pid: Vec<(u32, Bytes)> = lock(counters)
            .per_pid
            .iter()
            .map(|(p, b)| (*p, *b))
            .collect();
        let names = lock(names);
        let mut groups: HashMap<(String, String), Bytes> = HashMap::new();
        for (pid, b) in per_pid {
            let (image, services) = match names.get(&pid) {
                Some(info) => (info.image.clone(), info.services.clone()),
                None => (format!("unknown (pid {pid})"), String::new()),
            };
            let entry = groups.entry((image, services)).or_default();
            entry.rx += b.rx;
            entry.tx += b.tx;
        }
        let mut rows: Vec<(String, String, Bytes)> =
            groups.into_iter().map(|((i, s), b)| (i, s, b)).collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.2.total()));
        rows
    }

    fn sum_adapters(start: &HashMap<String, Bytes>, now: &HashMap<String, Bytes>) -> Bytes {
        let mut total = Bytes::default();
        for (name, b) in now {
            if let Some(s) = start.get(name) {
                let d = b.since(s);
                total.rx += d.rx;
                total.tx += d.tx;
            }
        }
        total
    }

    fn mb(n: u64) -> f64 {
        n as f64 / (1024.0 * 1024.0)
    }

    fn coverage(apps: u64, adapters: u64) -> f64 {
        if adapters == 0 {
            0.0
        } else {
            apps as f64 * 100.0 / adapters as f64
        }
    }

    fn print_progress(
        started: Instant,
        counters: &Mutex<Counters>,
        names: &Mutex<HashMap<u32, ProcInfo>>,
        adapters_start: &HashMap<String, Bytes>,
        adapters_now: &HashMap<String, Bytes>,
    ) {
        let rows = grouped(counters, names);
        let apps: u64 = rows.iter().map(|r| r.2.total()).sum();
        let adapters = sum_adapters(adapters_start, adapters_now).total();
        println!(
            "[{} min] apps {:.1} MB | adapters {:.1} MB | apps / adapters {:.1}%",
            started.elapsed().as_secs() / 60,
            mb(apps),
            mb(adapters),
            coverage(apps, adapters)
        );
        for (image, services, b) in rows.iter().take(8) {
            let label = if services.is_empty() {
                image.clone()
            } else {
                format!("{image} [{services}]")
            };
            println!("    {:>9.1} MB  {label}", mb(b.total()));
        }
        println!();
    }

    fn write_report(
        elapsed: Duration,
        net_cost: &str,
        counters: &Mutex<Counters>,
        names: &Mutex<HashMap<u32, ProcInfo>>,
        adapters_start: &HashMap<String, Bytes>,
        adapters_end: &HashMap<String, Bytes>,
    ) -> Result<std::path::PathBuf> {
        let rows = grouped(counters, names);
        let apps = rows.iter().fold(Bytes::default(), |mut acc, r| {
            acc.rx += r.2.rx;
            acc.tx += r.2.tx;
            acc
        });
        let adapters = sum_adapters(adapters_start, adapters_end);
        let (local, events, unparsed, no_address) = {
            let c = lock(counters);
            (c.local, c.events, c.unparsed, c.no_address)
        };

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join(format!("datasabi-probe-{stamp}.csv"));
        let mut f = std::fs::File::create(&path)
            .with_context(|| format!("could not create {}", path.display()))?;

        let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let mut out = String::new();
        out.push_str("section,name,services,bytes_received,bytes_sent,bytes_total\n");
        out.push_str(&format!(
            "summary,minutes,,,,{:.1}\n",
            elapsed.as_secs_f64() / 60.0
        ));
        out.push_str(&format!(
            "summary,windows_cost_setting,{},,,\n",
            q(net_cost)
        ));
        out.push_str(&format!(
            "summary,apps_internet,,{},{},{}\n",
            apps.rx,
            apps.tx,
            apps.total()
        ));
        out.push_str(&format!(
            "summary,adapters,,{},{},{}\n",
            adapters.rx,
            adapters.tx,
            adapters.total()
        ));
        out.push_str(&format!(
            "summary,apps_percent_of_adapters,,,,{:.2}\n",
            coverage(apps.total(), adapters.total())
        ));
        out.push_str(&format!(
            "summary,local_network_skipped,,{},{},{}\n",
            local.rx,
            local.tx,
            local.total()
        ));
        out.push_str(&format!("summary,events,,,,{events}\n"));
        out.push_str(&format!("summary,events_not_parsed,,,,{unparsed}\n"));
        out.push_str(&format!("summary,events_without_address,,,,{no_address}\n"));
        let mut adapter_names: Vec<&String> = adapters_end.keys().collect();
        adapter_names.sort();
        for name in adapter_names {
            if let (Some(s), Some(e)) = (adapters_start.get(name), adapters_end.get(name)) {
                let d = e.since(s);
                out.push_str(&format!(
                    "adapter,{},,{},{},{}\n",
                    q(name),
                    d.rx,
                    d.tx,
                    d.total()
                ));
            }
        }
        for (image, services, b) in &rows {
            out.push_str(&format!(
                "app,{},{},{},{},{}\n",
                q(image),
                q(services),
                b.rx,
                b.tx,
                b.total()
            ));
        }
        f.write_all(out.as_bytes())
            .with_context(|| format!("could not write {}", path.display()))?;
        Ok(path)
    }
}
