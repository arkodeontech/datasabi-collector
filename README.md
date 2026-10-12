# DataSabi Collector

The open-source background service behind [DataSabi](https://arkodeon.com): it measures how much internet data each app on your computer uses, keeps that history **on your computer only**, and raises an alert when an app eats a lot of data on a metered connection (MiFi, phone hotspot, USB modem).

The DataSabi desktop app talks to this service over a local socket. The collector is open source so anyone can check that it reads packet headers only, never content, and never sends anything over the internet.

| | |
|---|---|
| Platforms | Linux (now), Windows (planned, using ETW) |
| License | Apache-2.0 |
| Language | Rust |

## What it does

1. **Captures packet headers** (first 128 bytes) on every physical interface with libpcap, picking up new interfaces as they appear (Wi-Fi, USB tethering, `usb0`, `enx…`).
2. **Matches each packet to a process** through `/proc/net/{tcp,udp}{,6}` (address tuple to socket inode) and `/proc/<pid>/fd` (inode to pid).
3. **Names the app**: Flatpak ID, Snap name, AppImage path, script for interpreters, otherwise the executable. Friendly names come from `.desktop` files ("Google Chrome", not `/opt/google/chrome/chrome`), with a built-in table for system updaters such as apt, snapd and PackageKit.
4. **Counts internet traffic only.** Traffic to LAN, private, loopback, link-local and multicast addresses is ignored because it does not use your data plan.
5. **Stores per-minute totals** per app and network in SQLite (`/var/lib/datasabi/usage.db`).
6. **Alerts** on networks treated as metered when an app uses **50 MB in 15 minutes** or **150 MB in 60 minutes**, then stays quiet about that app for an hour.

### Metered networks

The collector asks NetworkManager whether a connection is metered.

> **Unknown counts as metered.** Most MiFi routers don't tell the computer they are metered, and those are exactly the connections DataSabi is for. So a network NetworkManager reports as "unknown" gets alerts until you mark it unlimited, from the app or with `dsctl set-network <id> unlimited`. This is a deliberate change from PRD v0.3, which only alerted on networks detected as metered.

Without NetworkManager, every network is "unknown" and therefore treated as metered.

## Install (Linux)

From a release package:

```sh
sudo apt install ./datasabi-collector_0.1.0-1_amd64.deb      # Debian, Ubuntu, Mint, Pop!_OS
sudo dnf install ./datasabi-collector-0.1.0-1.x86_64.rpm      # Fedora, RHEL family
```

The package:

- creates a `datasabi` system user and group;
- installs `/usr/lib/datasabi/datasabi-collector` and `dsctl`;
- enables the `datasabi-collector` systemd service;
- adds the user who ran the install (via `sudo` or `pkexec`) to the `datasabi` group.

> **Log out and back in once after installing.** Group membership only takes effect in a new session. Until then, the app and `dsctl` can't reach the socket.

To add another user later: `sudo usermod -aG datasabi <username>`.

### Command line

```sh
dsctl ping                       # is the service running?
dsctl summary today              # data per app (also: week, month)
dsctl live                       # current download/upload rates
dsctl watch                      # live rates and alerts as they happen
dsctl networks                   # known networks and how they are treated
dsctl set-network 3 unlimited    # metered | unlimited | auto
```

Add `--json` for raw protocol output.

## Security model

The service runs as the unprivileged `datasabi` user. systemd gives it only:

| Capability | Why |
|---|---|
| `CAP_NET_RAW`, `CAP_NET_ADMIN` | packet capture with libpcap |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | read `/proc/<pid>/fd`, `exe`, `cgroup` and `environ` (`APPIMAGE` only) of other users' processes to find which app owns a socket |

The unit also turns on systemd sandboxing: `ProtectSystem=strict`, `ProtectHome=read-only` (needed to read `~/.local/share/applications`), `NoNewPrivileges` and restricted address families.

Its socket is `/run/datasabi/collector.sock`, mode `0660`, group `datasabi`. Only members of that group can read usage data.

Privacy:

- Payloads are never read; the snap length is 128 bytes, just enough for IP and port headers.
- No hostnames, URLs or remote addresses are stored, only byte counts per app, network and minute.
- No telemetry and no network calls.

## Known limitations (v0.1)

- **VPNs:** tunnel interfaces (`tun*`, `wg*`, `tailscale*`) are skipped to avoid double counting. VPN traffic shows up under the VPN client instead of the real app.
- **Containers and VMs:** traffic from Docker, Podman or VM bridges is counted on the physical interface, usually as "Unknown / system", because those processes live in other network namespaces.
- **DNS:** with systemd-resolved, apps' lookups are counted under "DNS lookups (systemd-resolved)". The amounts are tiny.
- **Very short connections** that open and close in under ~100 ms may land in "Unknown / system".
- **Hotspot sharing:** traffic this computer forwards for other devices is not counted.

## Build from source

```sh
sudo apt install libpcap-dev        # Fedora: sudo dnf install libpcap-devel
cargo build --release
cargo test
```

Run it by hand for development (the socket is world-accessible without `--socket-group`):

```sh
sudo ./target/release/datasabi-collector --db /tmp/ds.db --socket /tmp/ds.sock
./target/release/dsctl --socket /tmp/ds.sock watch
```

Packages:

```sh
cargo install cargo-deb cargo-generate-rpm
cargo build --release
cargo deb -p datasabi-collector --no-build
cargo generate-rpm -p crates/collector
```

## Repository layout

```
crates/protocol    datasabi-protocol: IPC message types (NDJSON), shared with the app
crates/collector   the service (datasabi-collector) and the CLI (dsctl)
  src/linux/       pcap capture, /proc socket mapping, app naming, NetworkManager
packaging/linux    systemd unit and deb/rpm maintainer scripts
packaging/windows  WiX fragment for the future Windows service
```

## Protocol

Newline-delimited JSON over the socket. Each request carries an `id`, and the matching response echoes it:

```json
→ {"id":1,"request":{"type":"get_summary","range":"today"}}
← {"kind":"response","id":1,"body":{"type":"summary","range":"today","since_unix":1791763200,"total_in":54859365,"total_out":87040,"apps":[…]}}
→ {"id":2,"request":{"type":"subscribe"}}
← {"kind":"event","body":{"type":"alert_fired","app_id":4,"app_name":"Curl","bytes":54859365,"window_minutes":15,"network":"MTN MiFi","at_unix":1791817757}}
```

See [`crates/protocol/src/lib.rs`](crates/protocol/src/lib.rs) for every message.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 Arkodeon Technologies Ltd.

## Contributing

After cloning, activate the git hooks (pre-commit checks `cargo fmt` + `cargo clippy`; commit-msg enforces [Conventional Commits](https://www.conventionalcommits.org)):

```sh
git config core.hooksPath .githooks
```

CI requires: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`. Install `libpcap-dev` before building on Ubuntu/Debian.
