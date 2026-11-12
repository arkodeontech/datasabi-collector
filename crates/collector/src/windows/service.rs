//! The collector as a Windows service, under the Service Control Manager
//! (`windows-service`, Mullvad's): `datasabi-collector install` registers it (start with
//! Windows, restart on failure) and starts it; `uninstall` stops and removes it; the
//! SCM runs it as `datasabi-collector service`. It runs as LocalSystem: the per-app
//! network events need administrator rights (least privilege is checked in D3).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};

use crate::config::{data_dir, Config};
use crate::ipc::pipe::SecurityDescriptor;
use crate::rolling::RollingFile;
use crate::winrules::{is_inside, plain_drive_path};

/// The service's name in the Service Control Manager.
pub const SERVICE_NAME: &str = "DataSabiCollector";
const DISPLAY_NAME: &str = "DataSabi service";
const DESCRIPTION: &str = "Measures how much internet data each app uses, for the DataSabi \
                           app. Nothing is sent over the internet.";
/// The data folder (`%ProgramData%\DataSabi`: the usage history and the logs): SYSTEM
/// and Administrators only, inherited by everything inside (`OICI`), nothing inherited
/// from above (`P`).
const DATA_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
const LOG_KEEP: usize = 3;
/// How long Windows is told to wait while the service stops (ETW session, last flush).
const STOP_WAIT: Duration = Duration::from_secs(20);

/// The Windows-only commands, if the arguments are one: `service` (from the SCM),
/// `install [--dev]`, `uninstall`. Anything else runs the collector in this window.
pub fn from_command_line() -> Option<Result<()>> {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["service"] => Some(
            service_dispatcher::start(SERVICE_NAME, ffi_service_main).context(
                "`service` is for the Service Control Manager; use `install`, or run the \
                 collector without arguments",
            ),
        ),
        ["install"] => Some(install(false)),
        ["install", "--dev"] => Some(install(true)),
        ["uninstall"] => Some(uninstall()),
        _ => None,
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("{e:#}");
    }
}

fn status(
    state: ServiceState,
    accept: ServiceControlAccept,
    exit: ServiceExitCode,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: exit,
        checkpoint: 0,
        wait_hint: if state == ServiceState::StopPending {
            STOP_WAIT
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

fn run_service() -> Result<()> {
    // Stop or shutdown: report "stopping" and let the collector wind down (the ETW
    // session stopped, the engine's last counts flushed) before reporting "stopped".
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let mut stop_tx = Some(stop_tx);
    let handle_cell: Arc<OnceLock<ServiceStatusHandle>> = Arc::default();
    let cell = handle_cell.clone();
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(h) = cell.get() {
                let _ = h.set_service_status(status(
                    ServiceState::StopPending,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::NO_ERROR,
                ));
            }
            if let Some(tx) = stop_tx.take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .context("registering with the Service Control Manager")?;
    let _ = handle_cell.set(handle);

    let result = serve(handle, stop_rx);
    if let Err(e) = &result {
        tracing::error!("stopping after an error: {e:#}");
    }
    // Always tell Windows it stopped; a non-zero exit code makes it apply the recovery
    // actions (restart).
    let exit = match result {
        Ok(()) => ServiceExitCode::NO_ERROR,
        Err(_) => ServiceExitCode::ServiceSpecific(1),
    };
    handle
        .set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit,
        ))
        .context("reporting the service stopped")?;
    Ok(())
}

fn serve(handle: ServiceStatusHandle, stop_rx: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
    prepare_data_dir()?;
    init_file_logging()?;
    handle
        .set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::NO_ERROR,
        ))
        .context("reporting the service running")?;
    // As installed: no options, so the defaults (the pipe, the database in the data folder).
    let cfg = Config::parse_from(["datasabi-collector"]);
    crate::serve_windows(cfg, async {
        let _ = stop_rx.await;
    })
}

/// Logs to `%ProgramData%\DataSabi\logs\collector.log`, rolled over at 5 MB, 3 kept.
fn init_file_logging() -> Result<()> {
    let file = RollingFile::open(
        &data_dir().join("logs").join("collector.log"),
        LOG_MAX_BYTES,
        LOG_KEEP,
    )
    .context("opening the log file")?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_ansi(false)
        .with_writer(Mutex::new(file))
        .init();
    Ok(())
}

/// Creates the data folder and gives it its access list ([`DATA_SDDL`]), also on an
/// existing folder (the collector may have been run by hand before).
fn prepare_data_dir() -> Result<()> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    set_dacl(&dir, DATA_SDDL)
}

fn set_dacl(path: &Path, sddl: &str) -> Result<()> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is a valid descriptor; `dacl` points into it and is used while it lives.
    let ok =
        unsafe { GetSecurityDescriptorDacl(sd.as_ptr(), &mut present, &mut dacl, &mut defaulted) };
    if ok == 0 || present == 0 {
        bail!("the access list for {} has no DACL", path.display());
    }
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated; `dacl` is valid while `sd` lives (to the end).
    let err = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if err != ERROR_SUCCESS {
        bail!(
            "setting the access list on {} failed (Windows error {err})",
            path.display()
        );
    }
    Ok(())
}

/// The program the service will run: this one, by its real path (links resolved), and
/// only from inside Program Files. The service runs as LocalSystem, so whoever can
/// replace its file controls the PC; only administrators can change Program Files.
/// `dev` (tests, CI) allows any folder, with a warning.
fn service_program(dev: bool) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("finding this program's path")?;
    let exe =
        std::fs::canonicalize(&exe).with_context(|| format!("resolving {}", exe.display()))?;
    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    let program_files = std::fs::canonicalize(&program_files)
        .with_context(|| format!("resolving {}", program_files.display()))?;
    if !is_inside(&exe, &program_files) {
        if !dev {
            bail!(
                "refusing to install the service from {}: it must be inside {} (only \
                 administrators can change files there)",
                exe.display(),
                program_files.display()
            );
        }
        eprintln!(
            "Warning (--dev): the service will run {} with full control of this PC; \
             anyone who can change that file can take over the PC. For testing only.",
            exe.display()
        );
    }
    plain_drive_path(&exe).with_context(|| format!("{} isn't on a local drive", exe.display()))
}

/// Registers the service (start with Windows; restart on failure: after 5 s, 30 s and
/// 60 s, the count reset after a day), prepares the data folder and starts it. Run
/// again, it updates the registration (for example after the program moved).
fn install(dev: bool) -> Result<()> {
    let executable_path = service_program(dev)?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening the Service Control Manager (run as administrator)")?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        // windows-service quotes it when it has a space (Program Files): see the test.
        executable_path,
        launch_arguments: vec!["service".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(existing) => {
            existing
                .change_config(&info)
                .context("updating the service")?;
            existing
        }
        Err(_) => manager
            .create_service(&info, access)
            .context("creating the service")?,
    };
    service
        .set_description(DESCRIPTION)
        .context("describing the service")?;
    let restart = |secs| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(secs),
    };
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(5), restart(30), restart(60)]),
        })
        .context("setting the restart-on-failure actions")?;
    // Also when it stops with an error code, not only when it crashes.
    service
        .set_failure_actions_on_non_crash_failures(true)
        .context("setting restart on error exits")?;
    prepare_data_dir()?;
    let state = service
        .query_status()
        .context("querying the service")?
        .current_state;
    if state == ServiceState::Stopped {
        service.start::<&str>(&[]).context("starting the service")?;
    }
    println!("The DataSabi service is installed and running.");
    Ok(())
}

/// Stops and removes the service. The usage history in the data folder is kept.
fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the Service Control Manager (run as administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("the DataSabi service isn't installed")?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop().context("stopping the service")?;
        let deadline = Instant::now() + STOP_WAIT + Duration::from_secs(10);
        while service.query_status()?.current_state != ServiceState::Stopped {
            if Instant::now() > deadline {
                bail!("the service didn't stop in time");
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    service.delete().context("removing the service")?;
    println!("The DataSabi service is removed. Your usage history is kept.");
    Ok(())
}
