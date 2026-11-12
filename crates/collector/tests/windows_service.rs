//! The collector as a real Windows service: install, start, ping it over the named pipe,
//! uninstall. It changes the machine (a service, `%ProgramData%\DataSabi`), so it runs
//! only when asked, as administrator: `cargo test -- --ignored` (Windows CI does).
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use windows_service::service::ServiceAccess;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const COLLECTOR: &str = env!("CARGO_BIN_EXE_datasabi-collector");
const DSCTL: &str = env!("CARGO_BIN_EXE_dsctl");

fn run(program: &Path, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running {}: {e}", program.display()))
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Removes the service even when the test fails half-way.
struct Uninstall;

impl Drop for Uninstall {
    fn drop(&mut self) {
        let _ = run(Path::new(COLLECTOR), &["uninstall"]);
    }
}

/// The command line Windows has registered for the service.
fn registered_command_line() -> String {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .expect("opening the Service Control Manager");
    let service = manager
        .open_service("DataSabiCollector", ServiceAccess::QUERY_CONFIG)
        .expect("opening the service");
    let config = service.query_config().expect("reading its configuration");
    config.executable_path.to_string_lossy().into_owned()
}

#[test]
#[ignore = "installs a Windows service; run as administrator"]
fn the_installed_service_answers_over_the_pipe() {
    // A copy in a folder with a space, like Program Files, so the quoting is tested.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("service test");
    std::fs::create_dir_all(&dir).expect("making the test folder");
    let program = dir.join("datasabi-collector.exe");
    std::fs::copy(COLLECTOR, &program).expect("copying the collector");

    // Outside Program Files, install refuses without --dev.
    let refused = run(&program, &["install"]);
    assert!(
        !refused.status.success(),
        "install accepted a user-writable folder"
    );
    assert!(
        stderr(&refused).contains("refusing"),
        "{}",
        stderr(&refused)
    );

    let installed = run(&program, &["install", "--dev"]);
    let _cleanup = Uninstall;
    assert!(
        installed.status.success(),
        "install failed: {}",
        stderr(&installed)
    );

    // Quoted, or Windows could run `C:\…\service.exe` for `C:\…\service test\…`.
    let command_line = registered_command_line();
    assert!(
        command_line.starts_with('"') && command_line.contains("service test"),
        "registered unquoted: {command_line}"
    );
    assert!(command_line.ends_with(" service"), "{command_line}");

    // `dsctl ping` also checks the pipe belongs to SYSTEM, so this proves the service
    // (not this test) serves it. Up to 20 s for the ETW session and the pipe to start.
    let mut last = None;
    for _ in 0..40 {
        let ping = run(Path::new(DSCTL), &["ping"]);
        if ping.status.success() {
            last = None;
            break;
        }
        last = Some(stderr(&ping));
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(last.is_none(), "the service never answered: {last:?}");

    let removed = run(Path::new(COLLECTOR), &["uninstall"]);
    assert!(
        removed.status.success(),
        "uninstall failed: {}",
        stderr(&removed)
    );
    let query = run(Path::new("sc.exe"), &["query", "DataSabiCollector"]);
    assert!(!query.status.success(), "the service is still registered");
}
