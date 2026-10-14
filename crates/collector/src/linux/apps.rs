//! Turns a pid into an app identity (stable key) and a friendly name.
//!
//! Key priority: Flatpak app ID, Snap name, AppImage path, interpreter + script,
//! executable path. Names come from .desktop files, then a small built-in table
//! for system services, then a tidied-up executable name.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInfo {
    pub key: String,
    pub name: String,
    pub exe: Option<String>,
}

impl AppInfo {
    pub fn unknown() -> Self {
        Self {
            key: "unknown".into(),
            name: "Unknown / system".into(),
            exe: None,
        }
    }
}

/// Where the identity came from, before naming.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Identity {
    Flatpak(String),
    Snap(String),
    AppImage(String),
    Script { interpreter: String, script: String },
    Exe(String),
}

const DESKTOP_DIRS: &[&str] = &[
    "/usr/share/applications",
    "/usr/local/share/applications",
    "/var/lib/flatpak/exports/share/applications",
    "/var/lib/snapd/desktop/applications",
];

const BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/sbin",
    "/snap/bin",
    "/usr/libexec",
    "/usr/lib",
];

const INTERPRETERS: &[&str] = &[
    "python", "node", "java", "perl", "ruby", "bash", "sh", "dotnet",
];

/// System services that commonly use data in the background.
const BUILTIN_NAMES: &[(&str, &str)] = &[
    ("systemd-resolved", "DNS lookups (systemd-resolved)"),
    ("snapd", "Snap updates (snapd)"),
    ("packagekitd", "System updates (PackageKit)"),
    ("http", "System updates (apt)"),
    ("https", "System updates (apt)"),
    ("apt", "System updates (apt)"),
    ("apt-get", "System updates (apt)"),
    ("unattended-upgrade", "System updates (apt)"),
    ("dnf", "System updates (dnf)"),
    ("dnf5", "System updates (dnf)"),
    ("fwupd", "Firmware updates (fwupd)"),
    ("flatpak", "Flatpak updates"),
    ("flatpak-system-helper", "Flatpak updates"),
    ("NetworkManager", "NetworkManager"),
    ("chronyd", "Time sync (chrony)"),
    ("systemd-timesyncd", "Time sync"),
    ("avahi-daemon", "Local network discovery (Avahi)"),
    ("cupsd", "Printing (CUPS)"),
    ("tracker-miner-fs-3", "File indexing (Tracker)"),
    ("evolution-source-registry", "Online accounts (Evolution)"),
    ("goa-daemon", "Online accounts (GNOME)"),
    ("dropbox", "Dropbox"),
    ("chrome", "Google Chrome"),
    ("msedge", "Microsoft Edge"),
    ("qemu-system-x86_64", "Android Emulator (QEMU)"),
    ("qemu-system-aarch64", "Android Emulator (QEMU)"),
    ("qemu-system-i386", "QEMU VM"),
    ("qemu-system-arm", "QEMU VM"),
    ("claude", "Claude Code"),
    ("claude.exe", "Claude Code"),
    ("code", "Visual Studio Code"),
    ("node", "Node.js"),
];

#[derive(Debug, Default)]
struct DesktopIndex {
    by_id: HashMap<String, String>,
    by_exe: HashMap<String, String>,
    by_base: HashMap<String, String>,
    by_dir: HashMap<String, String>,
}

impl DesktopIndex {
    fn build() -> Self {
        let mut files: Vec<(String, String)> = Vec::new();
        let mut dirs: Vec<PathBuf> = DESKTOP_DIRS.iter().map(PathBuf::from).collect();
        if let Ok(homes) = fs::read_dir("/home") {
            for h in homes.flatten() {
                dirs.push(h.path().join(".local/share/applications"));
                dirs.push(
                    h.path()
                        .join(".local/share/flatpak/exports/share/applications"),
                );
            }
        }
        for dir in dirs {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let path = e.path();
                if path.extension().and_then(|x| x.to_str()) != Some("desktop") {
                    continue;
                }
                if let Ok(text) = fs::read_to_string(&path) {
                    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                    files.push((stem.to_string(), text));
                }
            }
        }
        Self::from_files(files.iter().map(|(s, t)| (s.as_str(), t.as_str())))
    }

    /// Main entries are indexed before hidden/handler entries. Every map uses
    /// first-wins inserts, so e.g. code.desktop ("Visual Studio Code") beats
    /// code-url-handler.desktop no matter which file the directory listing returns first.
    fn from_files<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut idx = DesktopIndex::default();
        let (main, secondary): (Vec<_>, Vec<_>) = files
            .into_iter()
            .filter_map(|(stem, text)| parse_desktop(text).map(|e| (stem, e)))
            .partition(|(stem, e)| !is_secondary(stem, e));
        for (stem, entry) in main {
            idx.insert(stem, entry);
        }
        for (stem, mut entry) in secondary {
            entry.name = strip_handler_suffix(&entry.name);
            idx.insert(stem, entry);
        }
        idx
    }

    fn insert(&mut self, file_stem: &str, entry: DesktopEntry) {
        let name = entry.name;
        // Flatpak exports are named <app-id>.desktop; snap ones <snap>_<app>.desktop.
        self.by_id
            .entry(file_stem.to_string())
            .or_insert_with(|| name.clone());
        if let Some((snap, _)) = file_stem.split_once('_') {
            self.by_id
                .entry(format!("snap:{snap}"))
                .or_insert_with(|| name.clone());
        }
        if let Some(fp) = entry.flatpak_id {
            self.by_id.entry(fp).or_insert_with(|| name.clone());
        }
        if let Some(prog) = entry.program.filter(|p| !is_interpreter(p)) {
            let resolved = resolve_program(&prog);
            if let Some(path) = &resolved {
                let p = path.to_string_lossy().to_string();
                self.by_exe.entry(p.clone()).or_insert_with(|| name.clone());
                if let Some(dir) = path.parent().and_then(|d| d.to_str()) {
                    if !BIN_DIRS.contains(&dir) {
                        self.by_dir
                            .entry(dir.to_string())
                            .or_insert_with(|| name.clone());
                    }
                }
            }
            if let Some(base) = Path::new(&prog).file_name().and_then(|b| b.to_str()) {
                self.by_base
                    .entry(base.to_string())
                    .or_insert_with(|| name.clone());
            }
            if let Some(base) = resolved
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|b| b.to_str())
            {
                self.by_base
                    .entry(base.to_string())
                    .or_insert_with(|| name.clone());
            }
        }
        if let Some(wm) = entry.wm_class {
            self.by_base.entry(wm.to_lowercase()).or_insert(name);
        }
    }

    fn name_for_exe(&self, exe: &str) -> Option<&String> {
        let path = Path::new(exe);
        let base = path.file_name().and_then(|b| b.to_str()).unwrap_or("");
        self.by_exe
            .get(exe)
            .or_else(|| self.by_base.get(base))
            .or_else(|| self.by_base.get(&base.to_lowercase()))
            .or_else(|| {
                path.parent()
                    .and_then(|d| d.to_str())
                    .and_then(|d| self.by_dir.get(d))
            })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DesktopEntry {
    name: String,
    program: Option<String>,
    flatpak_id: Option<String>,
    wm_class: Option<String>,
    no_display: bool,
    hidden: bool,
}

/// Hidden launchers and URL/MIME handlers name the same program as the main
/// entry, but with a worse name ("Visual Studio Code - URL Handler").
fn is_secondary(file_stem: &str, entry: &DesktopEntry) -> bool {
    entry.no_display
        || entry.hidden
        || file_stem.ends_with("-handler")
        || entry.name.to_lowercase().contains("url handler")
}

/// "Visual Studio Code - URL Handler" -> "Visual Studio Code",
/// "Claude Code URL Handler" -> "Claude Code".
fn strip_handler_suffix(name: &str) -> String {
    const SUFFIX: &str = "url handler";
    let trimmed = name.trim_end();
    let cut = trimmed.len().saturating_sub(SUFFIX.len());
    if trimmed.is_char_boundary(cut) && trimmed[cut..].eq_ignore_ascii_case(SUFFIX) {
        let base = trimmed[..cut].trim_end().trim_end_matches('-').trim_end();
        if !base.is_empty() {
            return base.to_string();
        }
    }
    trimmed.to_string()
}

fn parse_desktop(text: &str) -> Option<DesktopEntry> {
    let mut in_main = false;
    let (mut name, mut exec, mut wm, mut fp) = (None, None, None, None);
    let (mut no_display, mut hidden) = (false, false);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_main = line == "[Desktop Entry]";
            continue;
        }
        if !in_main {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "Name" => name = Some(v.trim().to_string()),
                "Exec" => exec = Some(v.trim().to_string()),
                "StartupWMClass" => wm = Some(v.trim().to_string()),
                "X-Flatpak" => fp = Some(v.trim().to_string()),
                "NoDisplay" => no_display = v.trim().eq_ignore_ascii_case("true"),
                "Hidden" => hidden = v.trim().eq_ignore_ascii_case("true"),
                _ => {}
            }
        }
    }
    let name = name?;
    let program = exec.as_deref().and_then(exec_program);
    Some(DesktopEntry {
        name,
        program,
        flatpak_id: fp,
        wm_class: wm,
        no_display,
        hidden,
    })
}

/// First real program in an Exec= line, skipping `env` and VAR=value prefixes.
fn exec_program(exec: &str) -> Option<String> {
    let mut parts = exec.split_whitespace().map(|p| p.trim_matches('"'));
    loop {
        let p = parts.next()?;
        if p == "env" || (p.contains('=') && !p.starts_with('/')) || p.starts_with('-') {
            continue;
        }
        return Some(p.to_string());
    }
}

fn resolve_program(prog: &str) -> Option<PathBuf> {
    let candidate = if prog.starts_with('/') {
        PathBuf::from(prog)
    } else {
        [
            "/usr/bin",
            "/usr/local/bin",
            "/bin",
            "/snap/bin",
            "/usr/games",
        ]
        .iter()
        .map(|d| Path::new(d).join(prog))
        .find(|p| p.exists())?
    };
    fs::canonicalize(&candidate).ok().or(Some(candidate))
}

/// Flatpak ID or Snap name from /proc/<pid>/cgroup.
fn identity_from_cgroup(cgroup: &str) -> Option<Identity> {
    for seg in cgroup
        .lines()
        .flat_map(|l| l.rsplit(':').next().unwrap_or("").split('/'))
    {
        if let Some(rest) = seg.strip_prefix("app-flatpak-") {
            let rest = rest.strip_suffix(".scope").unwrap_or(rest);
            let id = rest.rsplit_once('-').map(|(id, _)| id).unwrap_or(rest);
            return Some(Identity::Flatpak(id.to_string()));
        }
        if let Some(rest) = seg.strip_prefix("snap.") {
            if let Some(name) = rest.split('.').next().filter(|n| !n.is_empty()) {
                return Some(Identity::Snap(name.to_string()));
            }
        }
    }
    None
}

fn appimage_from_environ(environ: &[u8]) -> Option<String> {
    environ
        .split(|b| *b == 0)
        .filter_map(|kv| std::str::from_utf8(kv).ok())
        .find_map(|kv| kv.strip_prefix("APPIMAGE="))
        .filter(|p| !p.is_empty())
        .map(str::to_string)
}

fn is_interpreter(path: &str) -> bool {
    let base = Path::new(path)
        .file_name()
        .and_then(|b| b.to_str())
        .unwrap_or("");
    // "python3.12" and "node18" count, "shotwell" does not.
    INTERPRETERS.iter().any(|i| {
        base.strip_prefix(i)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    })
}

/// Special names for JVM processes identified by their command line.
fn java_cmdline_name(cmdline: &[u8]) -> Option<&'static str> {
    let text = std::str::from_utf8(cmdline)
        .unwrap_or("")
        .replace('\0', " ");
    if text.contains("GradleDaemon")
        || text.contains("gradle-launcher")
        || text.contains("GradleWorkerMain")
    {
        return Some("Gradle (Android builds)");
    }
    None
}

fn interpreter_script(exe: &str, cmdline: &[u8]) -> Option<String> {
    if !is_interpreter(exe) {
        return None;
    }
    let script = cmdline
        .split(|b| *b == 0)
        .skip(1)
        .filter_map(|a| std::str::from_utf8(a).ok())
        .find(|a| !a.is_empty() && !a.starts_with('-'))?;
    // Reject inline expressions (node -e "code" / python -c "code"); only accept file paths.
    if script.contains('/')
        || script.ends_with(".js")
        || script.ends_with(".py")
        || script.ends_with(".sh")
        || script.ends_with(".rb")
        || script.ends_with(".ts")
    {
        Some(script.to_string())
    } else {
        None
    }
}

/// "gnome-software" -> "Gnome software", "/x/MyTool.AppImage" -> "MyTool".
pub fn pretty_name(path_or_name: &str) -> String {
    let base = Path::new(path_or_name)
        .file_name()
        .and_then(|b| b.to_str())
        .unwrap_or(path_or_name);
    let base = base
        .strip_suffix(".AppImage")
        .or_else(|| base.strip_suffix(".appimage"))
        .or_else(|| base.strip_suffix(".py"))
        .or_else(|| base.strip_suffix(".js"))
        .unwrap_or(base);
    let spaced: String = base
        .chars()
        .map(|c| if c == '-' || c == '_' { ' ' } else { c })
        .collect();
    let mut chars = spaced.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => "Unknown".into(),
    }
}

pub struct AppResolver {
    index: DesktopIndex,
    built_at: Instant,
    cache: HashMap<u32, AppInfo>,
}

impl Default for AppResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl AppResolver {
    pub fn new() -> Self {
        Self {
            index: DesktopIndex::build(),
            built_at: Instant::now(),
            cache: HashMap::new(),
        }
    }

    /// Forget pids that exited (pid numbers get reused).
    pub fn retain_pids(&mut self, alive: &std::collections::HashSet<u32>) {
        self.cache.retain(|pid, _| alive.contains(pid));
    }

    pub fn resolve(&mut self, pid: u32) -> AppInfo {
        if let Some(info) = self.cache.get(&pid) {
            return info.clone();
        }
        let info = self.resolve_uncached(pid);
        self.cache.insert(pid, info.clone());
        info
    }

    fn resolve_uncached(&mut self, pid: u32) -> AppInfo {
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let exe = fs::read_link(proc.join("exe")).ok().map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        });
        let identity = fs::read_to_string(proc.join("cgroup"))
            .ok()
            .and_then(|c| identity_from_cgroup(&c))
            .or_else(|| {
                fs::read(proc.join("environ"))
                    .ok()
                    .and_then(|e| appimage_from_environ(&e))
                    .map(Identity::AppImage)
            })
            .or_else(|| {
                let exe = exe.as_ref()?;
                let cmdline = fs::read(proc.join("cmdline")).ok()?;
                interpreter_script(exe, &cmdline).map(|script| Identity::Script {
                    interpreter: exe.clone(),
                    script,
                })
            })
            .or_else(|| exe.clone().map(Identity::Exe));
        let Some(identity) = identity else {
            return AppInfo::unknown();
        };
        let mut info = self.name(&identity, exe.clone());

        // For JVM processes, try cmdline-based name lookup before falling back.
        if info.name.is_empty() {
            if let Some(ref exe_path) = exe {
                if is_interpreter(exe_path) {
                    if let Ok(cmdline) = fs::read(proc.join("cmdline")) {
                        if let Some(n) = java_cmdline_name(&cmdline) {
                            info.name = n.to_string();
                        }
                    }
                }
            }
        }

        if info.name.is_empty() && self.built_at.elapsed() > Duration::from_secs(60) {
            // Maybe the app was just installed.
            self.index = DesktopIndex::build();
            self.built_at = Instant::now();
            info = self.name(&identity, exe);
        }
        if info.name.is_empty() {
            info.name = fallback_name(&identity);
        }
        info
    }

    /// Returns an empty name when nothing better than the fallback is known.
    fn name(&self, identity: &Identity, exe: Option<String>) -> AppInfo {
        let (key, name) = match identity {
            Identity::Flatpak(id) => (format!("flatpak:{id}"), self.index.by_id.get(id).cloned()),
            Identity::Snap(n) => (
                format!("snap:{n}"),
                self.index.by_id.get(&format!("snap:{n}")).cloned(),
            ),
            Identity::AppImage(p) => (format!("appimage:{p}"), None),
            Identity::Script {
                interpreter,
                script,
            } => (format!("{interpreter} {script}"), None),
            Identity::Exe(e) => {
                let base = Path::new(e)
                    .file_name()
                    .and_then(|b| b.to_str())
                    .unwrap_or("");
                let builtin = BUILTIN_NAMES
                    .iter()
                    .find(|(b, _)| *b == base)
                    .map(|(_, n)| n.to_string());
                let desktop = self.index.name_for_exe(e).cloned();
                (e.clone(), desktop.or(builtin))
            }
        };
        AppInfo {
            key,
            name: name.unwrap_or_default(),
            exe,
        }
    }
}

fn fallback_name(identity: &Identity) -> String {
    match identity {
        Identity::Flatpak(id) => id
            .rsplit('.')
            .next()
            .map(pretty_name)
            .unwrap_or_else(|| id.clone()),
        Identity::Snap(n) => pretty_name(n),
        Identity::AppImage(p) => pretty_name(p),
        Identity::Script { script, .. } => pretty_name(script),
        Identity::Exe(e) => pretty_name(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_flatpak_and_snap() {
        let fp = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-12345.scope\n";
        assert_eq!(
            identity_from_cgroup(fp),
            Some(Identity::Flatpak("org.mozilla.firefox".into()))
        );
        let snap = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.spotify.spotify-6b1c2d.scope\n";
        assert_eq!(
            identity_from_cgroup(snap),
            Some(Identity::Snap("spotify".into()))
        );
        let plain = "0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(identity_from_cgroup(plain), None);
    }

    #[test]
    fn desktop_parsing() {
        let text = "[Desktop Entry]\nName=Google Chrome\nName[fr]=Chrome\nExec=/usr/bin/google-chrome-stable %U\nStartupWMClass=Google-chrome\n\n[Desktop Action new-window]\nName=New Window\nExec=/usr/bin/google-chrome-stable --new-window\n";
        let e = parse_desktop(text).unwrap();
        assert_eq!(e.name, "Google Chrome");
        assert_eq!(e.program.as_deref(), Some("/usr/bin/google-chrome-stable"));
        assert_eq!(e.wm_class.as_deref(), Some("Google-chrome"));
        assert_eq!(
            exec_program("env BAMF_DESKTOP_FILE_HINT=/x.desktop /snap/bin/spotify %U").as_deref(),
            Some("/snap/bin/spotify")
        );
    }

    #[test]
    fn index_lookup_by_basename() {
        let idx = DesktopIndex::from_files([(
            "org.telegram.desktop",
            "[Desktop Entry]\nName=Telegram Desktop\nExec=telegram-desktop -- %u\n",
        )]);
        assert_eq!(
            idx.name_for_exe("/opt/telegram/telegram-desktop")
                .map(String::as_str),
            Some("Telegram Desktop")
        );
        assert_eq!(
            idx.by_id.get("org.telegram.desktop").map(String::as_str),
            Some("Telegram Desktop")
        );
    }

    const VSCODE: (&str, &str) = (
        "code",
        "[Desktop Entry]\nName=Visual Studio Code\nExec=/usr/share/code/code %F\n\n[Desktop Action new-empty-window]\nName=New Empty Window\nExec=/usr/share/code/code --new-window %F\n",
    );
    const VSCODE_HANDLER: (&str, &str) = (
        "code-url-handler",
        "[Desktop Entry]\nName=Visual Studio Code - URL Handler\nExec=/usr/share/code/code --open-url %U\nNoDisplay=true\n",
    );

    #[test]
    fn main_entry_beats_url_handler_in_either_order() {
        for files in [[VSCODE, VSCODE_HANDLER], [VSCODE_HANDLER, VSCODE]] {
            let idx = DesktopIndex::from_files(files);
            assert_eq!(
                idx.name_for_exe("/usr/share/code/code").map(String::as_str),
                Some("Visual Studio Code")
            );
        }
    }

    #[test]
    fn handler_only_app_gets_cleaned_name() {
        let idx = DesktopIndex::from_files([(
            "claude-code-url-handler",
            "[Desktop Entry]\nName=Claude Code URL Handler\nExec=\"/home/a/.nvm/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe\" --handle-uri %u\nNoDisplay=true\n",
        )]);
        assert_eq!(
            idx.name_for_exe(
                "/home/a/.nvm/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
            )
            .map(String::as_str),
            Some("Claude Code")
        );
    }

    #[test]
    fn handler_suffix_stripping() {
        assert_eq!(
            strip_handler_suffix("Visual Studio Code - URL Handler"),
            "Visual Studio Code"
        );
        assert_eq!(
            strip_handler_suffix("Claude Code URL Handler"),
            "Claude Code"
        );
        assert_eq!(strip_handler_suffix("Devin - Url Handler "), "Devin");
        assert_eq!(strip_handler_suffix("Firefox"), "Firefox");
        assert_eq!(strip_handler_suffix("URL Handler"), "URL Handler");
    }

    #[test]
    fn builtin_names_for_cli_tools() {
        let resolver = AppResolver {
            index: DesktopIndex::default(),
            built_at: Instant::now(),
            cache: HashMap::new(),
        };
        for (exe, want) in [
            ("/home/a/bin/claude.exe", "Claude Code"),
            ("/usr/local/bin/claude", "Claude Code"),
            ("/usr/share/code/code", "Visual Studio Code"),
            ("/usr/bin/node", "Node.js"),
        ] {
            let info = resolver.name(&Identity::Exe(exe.into()), Some(exe.into()));
            assert_eq!(info.name, want, "{exe}");
        }
    }

    #[test]
    fn environ_cmdline_and_names() {
        assert_eq!(
            appimage_from_environ(b"HOME=/home/a\0APPIMAGE=/home/a/Obsidian.AppImage\0"),
            Some("/home/a/Obsidian.AppImage".into())
        );
        assert_eq!(
            interpreter_script("/usr/bin/python3.12", b"python3\0-u\0/opt/bot/sync.py\0"),
            Some("/opt/bot/sync.py".into())
        );
        assert_eq!(interpreter_script("/usr/bin/firefox", b"firefox\0"), None);
        assert_eq!(pretty_name("/usr/bin/gnome-software"), "Gnome software");
        assert_eq!(pretty_name("/home/a/Obsidian.AppImage"), "Obsidian");
    }
}
