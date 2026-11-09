//! datasabi-probe: a test program for the DataSabi Windows plan.
//!
//! It counts how many bytes each process sends and receives, using the ETW provider
//! `Microsoft-Windows-Kernel-Network`, and compares the total with the byte and packet
//! counters of the network adapter that carries the internet connection. Processes
//! inside `svchost.exe` are labelled with the services they host, to see whether
//! Windows Update can be told apart from "System".
//!
//! Privacy: addresses are only looked at in memory, to skip loopback and local-network
//! traffic. Nothing about packet contents, addresses, websites or the network's name is
//! printed or saved. The report holds process names, service names, adapter names and
//! counts only.

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

/// Small helpers with no Windows dependency, so they can be unit-tested.
#[cfg_attr(not(windows), allow(dead_code))]
mod parse {
    use std::collections::{BTreeMap, HashMap};
    use std::net::IpAddr;

    /// Loopback, private, link-local or unspecified: traffic that never uses the bundle
    /// when both ends are like this.
    pub fn is_local(ip: &IpAddr) -> bool {
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

    /// Splits one CSV line with double-quoted fields.
    pub fn csv_fields(line: &str) -> Vec<String> {
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

    /// Rows of `name,bytes_rx,bytes_tx,unicast_rx,other_rx,unicast_tx,other_tx` CSV
    /// (header first), as (name, [six counts]). Rows with too few fields are skipped and
    /// counts that do not parse are read as 0.
    pub fn adapter_rows(csv: &str) -> Vec<(String, [u64; 6])> {
        csv.lines()
            .skip(1)
            .filter_map(|line| {
                let f = csv_fields(line);
                if f.len() < 7 || f[0].is_empty() {
                    return None;
                }
                let mut n = [0u64; 6];
                for (slot, v) in n.iter_mut().zip(&f[1..7]) {
                    *slot = v.trim().parse().unwrap_or(0);
                }
                Some((f[0].clone(), n))
            })
            .collect()
    }

    /// Which adapter to compare the apps with, and how to label it in the report.
    /// `wanted` is the adapter Windows says carries the internet connection; `found` is
    /// every adapter name in the first counter reading. Returns `None` when the totals
    /// must fall back to all adapters added together.
    pub fn choose_adapter(wanted: Option<&str>, found: &[&str]) -> (Option<String>, String) {
        match wanted {
            Some(name) if found.contains(&name) => (Some(name.to_string()), name.to_string()),
            Some(name) => (None, format!("{name} (not found, all adapters used)")),
            None => (None, "unknown (all adapters used)".to_string()),
        }
    }

    /// How much an adapter's counters grew between two readings. If any counter went
    /// down, the adapter started counting again from zero (for example after the
    /// connection dropped and came back), so the growth is the new reading itself, and
    /// the flag is true. Traffic between the last reading and the restart is not seen.
    pub fn growth<const N: usize>(last: [u64; N], now: [u64; N]) -> ([u64; N], bool) {
        if now.iter().zip(&last).any(|(n, l)| n < l) {
            (now, true)
        } else {
            (std::array::from_fn(|i| now[i] - last[i]), false)
        }
    }

    /// Lines of `logman query <name> -ets` that report lost events or buffers, as
    /// (label, value) pairs, for example ("Events Lost", "0").
    pub fn lost_lines(logman_output: &str) -> Vec<(String, String)> {
        logman_output
            .lines()
            .filter_map(|line| {
                let (label, value) = line.split_once(':')?;
                let label = label.trim();
                if label.to_ascii_lowercase().contains("lost") {
                    Some((label.to_string(), value.trim().to_string()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Bytes or packets, received and sent.
    #[derive(Default, Clone, Copy)]
    pub struct Bytes {
        pub rx: u64,
        pub tx: u64,
    }

    impl Bytes {
        pub fn add(&mut self, outgoing: bool, n: u64) {
            if outgoing {
                self.tx += n;
            } else {
                self.rx += n;
            }
        }
        pub fn total(&self) -> u64 {
            self.rx + self.tx
        }
        pub fn plus(&self, other: &Bytes) -> Bytes {
            Bytes {
                rx: self.rx + other.rx,
                tx: self.tx + other.tx,
            }
        }
    }

    /// One adapter's counters: bytes and packets (whole packets, headers included).
    #[derive(Default, Clone, Copy)]
    pub struct Adapter {
        pub bytes: Bytes,
        pub packets: Bytes,
    }

    impl Adapter {
        pub fn counts(&self) -> [u64; 4] {
            [
                self.bytes.rx,
                self.bytes.tx,
                self.packets.rx,
                self.packets.tx,
            ]
        }
        pub fn from_counts(c: [u64; 4]) -> Adapter {
            Adapter {
                bytes: Bytes { rx: c[0], tx: c[1] },
                packets: Bytes { rx: c[2], tx: c[3] },
            }
        }
        pub fn plus(&self, other: &Adapter) -> Adapter {
            Adapter {
                bytes: self.bytes.plus(&other.bytes),
                packets: self.packets.plus(&other.packets),
            }
        }
    }

    /// Every adapter's growth since the start, added up one reading at a time. A phone
    /// hotspot or Wi-Fi that drops and comes back can restart the adapter's counters at
    /// zero; comparing only the first and last readings then gives nothing (seen in the
    /// 9 Nov 2026 hotspot run). Reading often keeps the part lost at each restart small.
    /// Every raw reading is kept for the report, so odd counters can be looked at later.
    #[derive(Default)]
    pub struct AdapterTally {
        /// Each adapter's last non-zero reading, with its milliseconds since the start. An
        /// adapter's first non-zero reading is its starting point: nothing before it is
        /// counted.
        last: HashMap<String, (u64, Adapter)>,
        grown: BTreeMap<String, Adapter>,
        /// Each adapter's fastest growth between two readings, in bytes per second. A
        /// MiFi or hotspot can't move hundreds of MB a second, so a figure like that
        /// means a bad reading (for example a brief low reading, then the old total).
        fastest: BTreeMap<String, u64>,
        pub restarts: u64,
        /// (milliseconds since the start, adapter, raw counters), in reading order.
        pub readings: Vec<(u64, String, Adapter)>,
    }

    impl AdapterTally {
        pub fn new(start: &HashMap<String, Adapter>) -> AdapterTally {
            let mut tally = AdapterTally::default();
            tally.update(0, start.clone());
            tally
        }

        /// Adds a new reading and returns the adapters whose counters restarted. An
        /// adapter missing from a reading keeps its last value. A reading of all zeros is
        /// skipped: an adapter can show it briefly while reconnecting, and taking it as a
        /// restart would add everything counted since the PC started when the old total
        /// comes back. A real restart still shows at the next non-zero reading, which is
        /// lower than the last one.
        pub fn update(&mut self, ms: u64, now: HashMap<String, Adapter>) -> Vec<String> {
            let mut restarted = Vec::new();
            for (name, reading) in now.into_iter().collect::<BTreeMap<_, _>>() {
                self.readings.push((ms, name.clone(), reading));
                let total = self.grown.entry(name.clone()).or_default();
                if reading.counts() == [0; 4] {
                    continue;
                }
                if let Some((last_ms, last)) = self.last.get(&name) {
                    let (grew, restart) = growth(last.counts(), reading.counts());
                    if restart {
                        self.restarts += 1;
                        restarted.push(name.clone());
                    }
                    let grew = Adapter::from_counts(grew);
                    let gap_ms = ms.saturating_sub(*last_ms).max(1);
                    let rate = grew.bytes.total().saturating_mul(1000) / gap_ms;
                    let fastest = self.fastest.entry(name.clone()).or_default();
                    *fastest = (*fastest).max(rate);
                    *total = total.plus(&grew);
                }
                self.last.insert(name, (ms, reading));
            }
            restarted
        }

        /// The growth of every adapter, sorted by name.
        pub fn sorted(&self) -> Vec<(String, Adapter)> {
            self.grown.iter().map(|(n, a)| (n.clone(), *a)).collect()
        }

        /// The fastest growth in bytes per second of `adapter` (0 if it has no figure
        /// yet), or of any adapter when no adapter is named, as with the totals.
        pub fn fastest(&self, adapter: Option<&str>) -> u64 {
            match adapter {
                Some(name) => self.fastest.get(name).copied().unwrap_or(0),
                None => self.fastest.values().copied().max().unwrap_or(0),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn local_addresses() {
            for local in ["127.0.0.1", "192.168.8.1", "10.0.0.5", "169.254.1.1", "::1"] {
                assert!(is_local(&local.parse().unwrap()), "{local}");
            }
            for local in ["fe80::1", "fd00::1"] {
                assert!(is_local(&local.parse().unwrap()), "{local}");
            }
            for public in ["8.8.8.8", "102.89.0.1", "2001:4860:4860::8888"] {
                assert!(!is_local(&public.parse().unwrap()), "{public}");
            }
        }

        #[test]
        fn csv_quoted_fields() {
            assert_eq!(
                csv_fields("\"svchost.exe\",\"1234\",\"wuauserv,BITS\"\r"),
                vec!["svchost.exe", "1234", "wuauserv,BITS"]
            );
            assert_eq!(csv_fields("\"a \"\"b\"\"\",1,"), vec!["a \"b\"", "1", ""]);
        }

        #[test]
        fn adapter_csv_rows() {
            let out = "\"Name\",\"Rx\",\"Tx\",\"RxU\",\"RxN\",\"TxU\",\"TxN\"\r\n\
                       \"Wi-Fi\",\"3356367038\",\"120\",\"10\",\"2\",\"8\",\"1\"\r\n\
                       \"Ethernet\",\"0\",\"0\",\"0\",\"\",\"0\",\"0\"\r\n\
                       \"short\",\"1\"\r\n";
            assert_eq!(
                adapter_rows(out),
                vec![
                    ("Wi-Fi".to_string(), [3356367038, 120, 10, 2, 8, 1]),
                    ("Ethernet".to_string(), [0; 6]),
                ]
            );
        }

        #[test]
        fn adapter_choice() {
            let found = ["Ethernet", "Wi-Fi"];
            assert_eq!(
                choose_adapter(Some("Wi-Fi"), &found),
                (Some("Wi-Fi".to_string()), "Wi-Fi".to_string())
            );
            assert_eq!(
                choose_adapter(Some("Wi-Fi"), &["Ethernet"]),
                (None, "Wi-Fi (not found, all adapters used)".to_string())
            );
            assert_eq!(
                choose_adapter(None, &found),
                (None, "unknown (all adapters used)".to_string())
            );
        }

        #[test]
        fn adapter_growth() {
            assert_eq!(growth([100, 10], [150, 12]), ([50, 2], false));
            assert_eq!(growth([100, 10], [100, 10]), ([0, 0], false));
            // The received counter went down: the adapter started again from zero, so
            // every counter is taken whole, even one that is now above its last value.
            assert_eq!(growth([100, 10], [40, 25]), ([40, 25], true));
        }

        fn reading(rows: &[(&str, [u64; 4])]) -> HashMap<String, Adapter> {
            rows.iter()
                .map(|(name, c)| (name.to_string(), Adapter::from_counts(*c)))
                .collect()
        }

        fn grown(tally: &AdapterTally) -> Vec<(String, [u64; 4])> {
            tally
                .sorted()
                .into_iter()
                .map(|(name, a)| (name, a.counts()))
                .collect()
        }

        #[test]
        fn tally_restart() {
            let mut t = AdapterTally::new(&reading(&[("Wi-Fi", [100, 10, 5, 1])]));
            assert!(t
                .update(15_000, reading(&[("Wi-Fi", [150, 12, 6, 2])]))
                .is_empty());
            // The counters started again from zero and have counted [40, 3, 2, 1] since.
            assert_eq!(
                t.update(30_000, reading(&[("Wi-Fi", [40, 3, 2, 1])])),
                vec!["Wi-Fi".to_string()]
            );
            t.update(45_000, reading(&[("Wi-Fi", [60, 4, 3, 1])]));
            assert_eq!(grown(&t), vec![("Wi-Fi".to_string(), [110, 6, 4, 2])]);
            assert_eq!(t.restarts, 1);
            assert_eq!(t.readings.len(), 4);
            // Fastest step: 50 + 2 bytes in 15 s is 3.47 B/s, rounded down to 3.
            assert_eq!(t.fastest(Some("Wi-Fi")), 3);
            // A named adapter with no figure gives 0, not another adapter's figure.
            assert_eq!(t.fastest(Some("Ethernet")), 0);
            assert_eq!(t.fastest(None), 3);
        }

        #[test]
        fn tally_low_glitch_shows_as_fastest_step() {
            // A brief low reading that isn't all zeros, then the old total: counted as a
            // restart plus a huge step. The fastest-step figure makes it stand out.
            let mut t = AdapterTally::new(&reading(&[("Wi-Fi", [5_000_000_000, 0, 0, 0])]));
            t.update(15_000, reading(&[("Wi-Fi", [70, 0, 0, 0])]));
            t.update(30_000, reading(&[("Wi-Fi", [5_000_000_100, 0, 0, 0])]));
            assert_eq!(t.restarts, 1);
            assert!(t.fastest(None) > 300_000_000);
        }

        #[test]
        fn tally_missing_adapter() {
            let mut t = AdapterTally::new(&reading(&[
                ("Ethernet", [500, 50, 5, 5]),
                ("Wi-Fi", [100; 4]),
            ]));
            t.update(15_000, reading(&[("Wi-Fi", [110; 4])]));
            t.update(
                30_000,
                reading(&[("Ethernet", [520, 51, 6, 5]), ("Wi-Fi", [120; 4])]),
            );
            assert_eq!(
                grown(&t),
                vec![
                    ("Ethernet".to_string(), [20, 1, 1, 0]),
                    ("Wi-Fi".to_string(), [20; 4]),
                ]
            );
            assert_eq!(t.restarts, 0);
        }

        #[test]
        fn tally_all_zero_reading() {
            // All zeros for a moment, then the old total plus 100: only 100 is growth.
            let mut t = AdapterTally::new(&reading(&[("Wi-Fi", [5_000_000_000, 9, 9, 9])]));
            assert!(t.update(15_000, reading(&[("Wi-Fi", [0; 4])])).is_empty());
            assert!(t
                .update(30_000, reading(&[("Wi-Fi", [5_000_000_100, 9, 9, 9])]))
                .is_empty());
            assert_eq!(grown(&t), vec![("Wi-Fi".to_string(), [100, 0, 0, 0])]);
            // All zeros, then a real restart: caught at the next non-zero reading.
            t.update(45_000, reading(&[("Wi-Fi", [0; 4])]));
            assert_eq!(
                t.update(60_000, reading(&[("Wi-Fi", [70, 1, 1, 1])])),
                vec!["Wi-Fi".to_string()]
            );
            assert_eq!(grown(&t), vec![("Wi-Fi".to_string(), [170, 1, 1, 1])]);
        }

        #[test]
        fn tally_first_non_zero_reading_is_the_start() {
            // All zeros at the start (or an adapter seen for the first time): the first
            // non-zero reading is the starting point, so its total isn't counted.
            let mut t = AdapterTally::new(&reading(&[("Wi-Fi", [0; 4])]));
            t.update(
                15_000,
                reading(&[("Wi-Fi", [9_000, 9, 9, 9]), ("VPN", [300, 3, 3, 3])]),
            );
            t.update(
                30_000,
                reading(&[("Wi-Fi", [9_050, 9, 9, 9]), ("VPN", [310, 3, 3, 3])]),
            );
            assert_eq!(
                grown(&t),
                vec![
                    ("VPN".to_string(), [10, 0, 0, 0]),
                    ("Wi-Fi".to_string(), [50, 0, 0, 0]),
                ]
            );
        }

        #[test]
        fn logman_lost_lines() {
            let out = "Name:                 DataSabiProbe\r\nEvents Lost:          3\r\nBuffers Written:      10\r\n";
            assert_eq!(
                lost_lines(out),
                vec![("Events Lost".to_string(), "3".to_string())]
            );
        }
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

    use crate::parse::{
        adapter_rows, choose_adapter, csv_fields, is_local, lost_lines, Adapter, AdapterTally,
        Bytes,
    };

    /// Microsoft-Windows-Kernel-Network.
    const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
    /// KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6.
    const KEYWORDS: u64 = 0x10 | 0x20;
    const TRACE_NAME: &str = "DataSabiProbe";
    const DEFAULT_MINUTES: u64 = 60;
    const REPORT_EVERY: Duration = Duration::from_secs(60);
    const NAMES_EVERY: Duration = Duration::from_secs(10);
    const ADAPTERS_EVERY: Duration = Duration::from_secs(15);

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
        println!(
            "Nothing about websites, addresses, packet contents or the network's name is saved."
        );
        println!();

        let (net_cost, wanted_adapter) = network_profile();
        println!("Windows cost setting for this network: {net_cost}");

        let adapters_start = adapter_totals().context("could not read adapter totals")?;
        let mut found: Vec<&str> = adapters_start.keys().map(String::as_str).collect();
        found.sort_unstable();
        let (internet_adapter, adapter_label) = choose_adapter(wanted_adapter.as_deref(), &found);
        match (&wanted_adapter, &internet_adapter) {
            (Some(name), Some(_)) => println!("Adapter carrying the internet connection: {name}"),
            (Some(name), None) => {
                println!();
                println!(
                    "WARNING: Windows says \"{name}\" carries the internet connection, but it has"
                );
                println!("no counters. Adapters found: {}.", found.join(", "));
                println!(
                    "The adapter total will be all adapters added together, which can be wrong."
                );
                println!("Tell whoever asked you to run this test before you go on.");
                println!();
            }
            (None, _) => {
                println!();
                println!("WARNING: could not tell which adapter carries the internet connection.");
                println!("Adapters found: {}.", found.join(", "));
                println!("The adapter total will be all adapters added together.");
                println!();
            }
        }
        let names: Arc<Mutex<HashMap<u32, ProcInfo>>> = Arc::new(Mutex::new(HashMap::new()));
        refresh_names(&names);

        // A session left behind by a crashed run would stop this one from starting.
        let _ = command_text("logman", &["stop", TRACE_NAME, "-ets"]);

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
                     If it still fails, run `logman stop {TRACE_NAME} -ets` and try again."
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
        let mut tally = AdapterTally::new(&adapters_start);
        let mut adapter_error: Option<String> = None;
        let mut next_report = started + REPORT_EVERY;
        let mut next_names = started + NAMES_EVERY;
        let mut next_adapters = started + ADAPTERS_EVERY;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let wake = next_report.min(next_names).min(next_adapters).min(deadline);
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
            // Read the adapters on their own timer and before every report, so a report
            // shows the totals as they are now.
            if now >= next_adapters || now >= next_report {
                match adapter_totals() {
                    Ok(adapters) => {
                        let restarted =
                            tally.update(started.elapsed().as_millis() as u64, adapters);
                        if !restarted.is_empty() {
                            println!(
                                "[{} min] adapter counters started again from zero: {}. The \
                                 connection probably dropped and came back; counting goes on.",
                                started.elapsed().as_secs() / 60,
                                restarted.join(", ")
                            );
                            println!();
                        }
                    }
                    Err(e) => adapter_error = Some(format!("{e:#}")),
                }
                next_adapters = now + ADAPTERS_EVERY;
            }
            if now >= next_report {
                if let Some(e) = adapter_error.take() {
                    println!(
                        "[{} min] could not read the adapter totals at least once this minute: {e}",
                        started.elapsed().as_secs() / 60
                    );
                }
                print_progress(
                    started,
                    &counters,
                    &names,
                    internet_adapter.as_deref(),
                    &tally,
                );
                next_report = now + REPORT_EVERY;
            }
        }

        refresh_names(&names);
        // A failed last reading keeps the totals from the reading before it, rather than
        // losing the whole run's report.
        match adapter_totals() {
            Ok(adapters) => {
                tally.update(started.elapsed().as_millis() as u64, adapters);
            }
            Err(e) => println!(
                "Could not read the adapter totals at the end ({e:#}); the last reading is used."
            ),
        }
        // Read the session's lost-event counters while it is still running.
        let lost = lost_lines(&command_text("logman", &["query", TRACE_NAME, "-ets"]));
        let handled = trace.events_handled();
        let _ = trace.stop();
        let elapsed = started.elapsed();
        print_progress(
            started,
            &counters,
            &names,
            internet_adapter.as_deref(),
            &tally,
        );
        if lost.is_empty() {
            println!("Lost events: unknown (logman gave no figure)");
        }
        for (label, value) in &lost {
            println!("{label}: {value}");
        }
        let path = write_report(&Report {
            elapsed,
            net_cost: &net_cost,
            internet_adapter: internet_adapter.as_deref(),
            adapter_label: &adapter_label,
            counters: &counters,
            names: &names,
            adapters: &tally,
            handled,
            lost: &lost,
        })?;
        println!();
        println!("Report saved: {}", path.display());
        println!("Send the report to whoever asked you to run this test, with your data balance");
        println!("before and after, and a screenshot of Settings > Network & internet >");
        println!("Advanced network settings > Data usage.");
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

    /// Windows' cost setting for the internet connection, and the name of the adapter
    /// that carries it. The network's own name (the Wi-Fi name) is not read.
    fn network_profile() -> (String, Option<String>) {
        let script = "$p=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile(); \
                      $cost = if ($p) { $p.GetConnectionCost().NetworkCostType } else { 'unknown' }; \
                      $alias = (Get-NetConnectionProfile | Where-Object { $_.IPv4Connectivity -eq 'Internet' -or $_.IPv6Connectivity -eq 'Internet' } | Select-Object -First 1).InterfaceAlias; \
                      Write-Output \"$cost|$alias\"";
        let out = powershell(script);
        let line = out.lines().next().unwrap_or("").trim();
        match line.split_once('|') {
            Some((cost, alias)) => {
                let alias = alias.trim();
                let cost = if cost.is_empty() { "unknown" } else { cost };
                (
                    cost.to_string(),
                    (!alias.is_empty()).then(|| alias.to_string()),
                )
            }
            None => ("unknown".to_string(), None),
        }
    }

    /// Bytes and packets received and sent per network adapter since it started.
    /// Read through .NET (`GetIfEntry2` underneath), because `Get-NetAdapterStatistics`
    /// leaves out some Wi-Fi adapters: on the first trial machine it listed only an
    /// unplugged Ethernet port.
    fn adapter_totals() -> Result<HashMap<String, Adapter>> {
        let out = powershell(
            "[System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | \
             Where-Object { $_.NetworkInterfaceType -ne 'Loopback' } | \
             ForEach-Object { $s = $_.GetIPStatistics(); [pscustomobject]@{ \
             Name = $_.Name; Rx = $s.BytesReceived; Tx = $s.BytesSent; \
             RxU = $s.UnicastPacketsReceived; RxN = $s.NonUnicastPacketsReceived; \
             TxU = $s.UnicastPacketsSent; TxN = $s.NonUnicastPacketsSent } } | \
             ConvertTo-Csv -NoTypeInformation",
        );
        let map: HashMap<String, Adapter> = adapter_rows(&out)
            .into_iter()
            .map(|(name, n)| {
                (
                    name,
                    Adapter {
                        bytes: Bytes { rx: n[0], tx: n[1] },
                        packets: Bytes {
                            rx: n[2] + n[3],
                            tx: n[4] + n[5],
                        },
                    },
                )
            })
            .collect();
        if map.is_empty() {
            bail!("no network adapters found");
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
            *entry = entry.plus(&b);
        }
        let mut rows: Vec<(String, String, Bytes)> =
            groups.into_iter().map(|((i, s), b)| (i, s, b)).collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.2.total()));
        rows
    }

    /// The internet adapter's change if known, otherwise all adapters added together.
    fn baseline(deltas: &[(String, Adapter)], internet_adapter: Option<&str>) -> Adapter {
        if let Some(name) = internet_adapter {
            if let Some((_, a)) = deltas.iter().find(|(n, _)| n == name) {
                return *a;
            }
        }
        deltas
            .iter()
            .fold(Adapter::default(), |acc, (_, a)| acc.plus(a))
    }

    fn mb(n: u64) -> f64 {
        n as f64 / (1024.0 * 1024.0)
    }

    fn percent(part: u64, whole: u64) -> f64 {
        if whole == 0 {
            0.0
        } else {
            part as f64 * 100.0 / whole as f64
        }
    }

    fn print_progress(
        started: Instant,
        counters: &Mutex<Counters>,
        names: &Mutex<HashMap<u32, ProcInfo>>,
        internet_adapter: Option<&str>,
        tally: &AdapterTally,
    ) {
        let rows = grouped(counters, names);
        let apps: u64 = rows.iter().map(|r| r.2.total()).sum();
        let deltas = tally.sorted();
        let adapter = baseline(&deltas, internet_adapter).bytes.total();
        println!(
            "[{} min] apps {:.1} MB | adapter {:.1} MB | apps / adapter {:.1}%",
            started.elapsed().as_secs() / 60,
            mb(apps),
            mb(adapter),
            percent(apps, adapter)
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

    struct Report<'a> {
        elapsed: Duration,
        net_cost: &'a str,
        internet_adapter: Option<&'a str>,
        adapter_label: &'a str,
        counters: &'a Mutex<Counters>,
        names: &'a Mutex<HashMap<u32, ProcInfo>>,
        adapters: &'a AdapterTally,
        handled: usize,
        lost: &'a [(String, String)],
    }

    fn write_report(r: &Report) -> Result<std::path::PathBuf> {
        let rows = grouped(r.counters, r.names);
        let apps = rows
            .iter()
            .fold(Bytes::default(), |acc, row| acc.plus(&row.2));
        let deltas = r.adapters.sorted();
        let base = baseline(&deltas, r.internet_adapter);
        let all = baseline(&deltas, None);
        let (local, events, unparsed, no_address) = {
            let c = lock(r.counters);
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
        let row =
            |section: &str, name: &str, services: &str, b: Option<&Bytes>, p: Option<&Bytes>| {
                let (brx, btx, btot) = b
                    .map_or((String::new(), String::new(), String::new()), |b| {
                        (b.rx.to_string(), b.tx.to_string(), b.total().to_string())
                    });
                let (prx, ptx) = p.map_or((String::new(), String::new()), |p| {
                    (p.rx.to_string(), p.tx.to_string())
                });
                format!(
                    "{section},{},{},{brx},{btx},{btot},{prx},{ptx}\n",
                    q(name),
                    q(services)
                )
            };
        let value = |name: &str, v: String| format!("summary,{},,,,{v},,\n", q(name));

        let mut out = String::from(
            "section,name,services,bytes_received,bytes_sent,bytes_total,packets_received,packets_sent\n",
        );
        out.push_str(&value(
            "minutes",
            format!("{:.1}", r.elapsed.as_secs_f64() / 60.0),
        ));
        out.push_str(&value("windows_cost_setting", r.net_cost.to_string()));
        out.push_str(&value("internet_adapter", r.adapter_label.to_string()));
        out.push_str(&row("summary", "apps_internet", "", Some(&apps), None));
        out.push_str(&row(
            "summary",
            "internet_adapter_totals",
            "",
            Some(&base.bytes),
            Some(&base.packets),
        ));
        out.push_str(&value(
            "apps_percent_of_internet_adapter",
            format!("{:.2}", percent(apps.total(), base.bytes.total())),
        ));
        out.push_str(&row(
            "summary",
            "all_adapters_totals",
            "",
            Some(&all.bytes),
            Some(&all.packets),
        ));
        out.push_str(&value(
            "adapter_counter_restarts",
            r.adapters.restarts.to_string(),
        ));
        out.push_str(&value(
            "internet_adapter_fastest_bytes_per_second",
            r.adapters.fastest(r.internet_adapter).to_string(),
        ));
        out.push_str(&row(
            "summary",
            "local_network_skipped",
            "",
            Some(&local),
            None,
        ));
        out.push_str(&value("events_counted", events.to_string()));
        out.push_str(&value("events_handled_by_etw", r.handled.to_string()));
        out.push_str(&value("events_not_parsed", unparsed.to_string()));
        out.push_str(&value("events_without_address", no_address.to_string()));
        if r.lost.is_empty() {
            out.push_str(&value("etw_lost", "unknown".to_string()));
        }
        for (label, v) in r.lost {
            out.push_str(&value(&format!("etw: {label}"), v.clone()));
        }
        for (name, a) in &deltas {
            out.push_str(&row("adapter", name, "", Some(&a.bytes), Some(&a.packets)));
        }
        for (image, services, b) in &rows {
            out.push_str(&row("app", image, services, Some(b), None));
        }
        // Raw counter readings; here the services column holds the milliseconds since the
        // start.
        for (secs, name, a) in &r.adapters.readings {
            out.push_str(&row(
                "reading",
                name,
                &secs.to_string(),
                Some(&a.bytes),
                Some(&a.packets),
            ));
        }
        f.write_all(out.as_bytes())
            .with_context(|| format!("could not write {}", path.display()))?;
        Ok(path)
    }
}
