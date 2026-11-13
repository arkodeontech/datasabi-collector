//! The collector as a real Windows service: install, start, ping it over the named pipe,
//! uninstall. It changes the machine (a service, `%ProgramData%\DataSabi`), so it runs
//! only when asked, as administrator: `cargo test -- --ignored` (Windows CI does).
#![cfg(windows)]

use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows_service::service::ServiceAccess;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

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

/// Undoes the test even when it fails half-way: removes the service, then puts back
/// the data folder this PC had before (so running the test on a real PC can't hide
/// its usage history).
struct Cleanup {
    /// Where the PC's own `DataSabi` folder was moved for the test, if it had one.
    restore: Option<PathBuf>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = run(Path::new(COLLECTOR), &["uninstall"]);
        if let Some(kept) = &self.restore {
            let data = program_data().join("DataSabi");
            // The test's own folder (or junction: removed as a link, never followed).
            if std::fs::symlink_metadata(&data).is_ok() {
                let removed = if is_link(&data) {
                    std::fs::remove_dir(&data)
                } else {
                    std::fs::remove_dir_all(&data)
                };
                if let Err(e) = removed {
                    eprintln!("couldn't remove the test's {}: {e}", data.display());
                    eprintln!("this PC's own data folder is kept at {}", kept.display());
                    return;
                }
            }
            if let Err(e) = std::fs::rename(kept, &data) {
                eprintln!("couldn't put back {}: {e}", kept.display());
            }
        }
    }
}

fn program_data() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramData").expect("%ProgramData% is set"))
}

/// A junction or symlink (not followed).
fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .unwrap_or(false)
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

    // A trap laid before install: `%ProgramData%\DataSabi` as a junction to another
    // folder. The service must move it aside, not write through it.
    let data = program_data().join("DataSabi");
    let mut cleanup = Cleanup { restore: None };
    if std::fs::symlink_metadata(&data).is_ok() {
        // This PC's own folder: out of the way for the test, put back by `cleanup`.
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let keep = data.with_file_name(format!("DataSabi.before-test-{unix}"));
        std::fs::rename(&data, &keep).expect("moving the existing data folder aside");
        cleanup.restore = Some(keep);
    }
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("junction-target");
    let _ = std::fs::remove_dir_all(&target);
    std::fs::create_dir_all(&target).expect("making the junction's target");
    let junction = run(
        Path::new("cmd.exe"),
        &[
            "/C",
            "mklink",
            "/J",
            data.to_str().unwrap(),
            target.to_str().unwrap(),
        ],
    );
    assert!(
        junction.status.success(),
        "mklink failed: {}",
        stderr(&junction)
    );
    assert!(is_link(&data));

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

    // The junction was moved aside; the service wrote into a fresh, real folder and
    // nothing through the junction.
    assert!(
        !is_link(&data) && data.is_dir(),
        "the junction is still in place"
    );
    assert!(
        data.join("usage.db").exists(),
        "no database in the fresh folder"
    );
    assert!(
        data.join("logs").join("collector.log").exists(),
        "no log in the fresh folder"
    );
    let written: Vec<_> = std::fs::read_dir(&target).unwrap().collect();
    assert!(
        written.is_empty(),
        "written through the junction: {written:?}"
    );
    let aside: Vec<PathBuf> = std::fs::read_dir(program_data())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("DataSabi.untrusted-")
        })
        .collect();
    assert!(
        aside.iter().any(|p| is_link(p)),
        "the junction wasn't moved aside: {aside:?}"
    );
    for link in aside.iter().filter(|p| is_link(p)) {
        let _ = std::fs::remove_dir(link); // the junction only, not its target
    }

    let removed = run(Path::new(COLLECTOR), &["uninstall"]);
    assert!(
        removed.status.success(),
        "uninstall failed: {}",
        stderr(&removed)
    );
    let query = run(Path::new("sc.exe"), &["query", "DataSabiCollector"]);
    assert!(!query.status.success(), "the service is still registered");
}
