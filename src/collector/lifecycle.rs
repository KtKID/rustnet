//! Short-lived CLI control plus the sole long-lived collector process.

use super::{config, session};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Local};
use clap::{Arg, Command};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_POLL: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub(crate) struct Paths {
    pub config_file: PathBuf,
    pub data: PathBuf,
    pub runtime: PathBuf,
    pub config: config::CollectorConfig,
}
impl Paths {
    pub fn load(path: &Path) -> Result<Self> {
        let config_file = path.canonicalize().context("collector config path")?;
        let config = config::load(&config_file)?;
        let base = config_file.parent().context("config parent")?;
        let mut runtime = base.join(&config.runtime_directory);
        let anchor = sidecar(&config_file, "runtime.json");
        match fs::read(&anchor) {
            Ok(bytes) => {
                let recorded: Value =
                    serde_json::from_slice(&bytes).context("runtime anchor JSON")?;
                let previous = PathBuf::from(
                    recorded["runtime_directory"]
                        .as_str()
                        .context("runtime anchor directory")?,
                );
                match fs::read(previous.join("collector.json")) {
                    Ok(bytes) => {
                        let value: Value = serde_json::from_slice(&bytes)
                            .context("previous runtime status JSON")?;
                        ensure!(
                            value["config_file"].as_str() == config_file.to_str(),
                            "runtime anchor config mismatch"
                        );
                        if owned(&value) {
                            runtime = previous;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            data: base.join(&config.data_directory),
            runtime,
            config_file,
            config,
        })
    }
    pub fn status_file(&self) -> PathBuf {
        self.runtime.join("collector.json")
    }
    pub fn empty_status(&self) -> Value {
        json!({"schema_version":1,"state":"stopped","pid":null,"process_start_id":null,"executable":null,"run_id":null,"started_at":null,"updated_at":session::now(),"session_directory":null,"config_file":self.config_file,"config":self.config,"listener_scans":0,"error":null})
    }
}

fn sidecar(config_file: &Path, suffix: &str) -> PathBuf {
    let mut name = config_file.as_os_str().to_os_string();
    name.push(format!(".{suffix}"));
    PathBuf::from(name)
}

pub fn main() -> Result<()> {
    let matches = Command::new("x-net-collector")
        .arg(
            Arg::new("action")
                .value_parser([
                    "start",
                    "stop",
                    "status",
                    "run",
                    "daemon",
                    "validate",
                    "capture-helper",
                ])
                .required(true),
        )
        .arg(
            Arg::new("config")
                .long("config")
                .required(true)
                .value_name("YAML"),
        )
        .get_matches();
    let path = Path::new(matches.get_one::<String>("config").unwrap());
    let action = matches.get_one::<String>("action").unwrap().as_str();
    if action == "capture-helper" {
        return rustnet_capture::delegated::helper(serde_json::from_slice(&fs::read(path)?)?);
    }
    if matches!(action, "start" | "run" | "daemon") {
        ensure!(
            unsafe { libc::geteuid() } != 0,
            "请用普通用户启动；系统授权仅用于打开抓包设备"
        );
    }
    let paths = match Paths::load(path) {
        Ok(paths) => paths,
        Err(error) => {
            let directory = service_log_directory(path);
            let _ = private_directory(&directory);
            session::diagnostic(
                &directory,
                "collector-control",
                "configuration_failed",
                &format!("{error:#}"),
                "error",
            );
            return Err(error);
        }
    };
    let result = match action {
        "validate" => {
            println!("{}", serde_json::to_string(&paths.config)?);
            Ok(())
        }
        "status" => {
            println!("{}", status(&paths)?);
            Ok(())
        }
        "stop" => control_stop(&paths),
        "start" => control_start(&paths),
        "daemon" => daemon(&paths),
        "run" => run(&paths),
        _ => unreachable!(),
    };
    if let Err(error) = &result {
        let directory = service_log_directory(&paths.config_file);
        let _ = private_directory(&directory);
        session::diagnostic(
            &directory,
            "collector-control",
            action,
            &format!("{error:#}"),
            "error",
        );
        eprintln!("{} {action}: {error:#}", session::now());
    }
    result
}

fn service_log_directory(config: &Path) -> PathBuf {
    log_directory(config, std::env::var_os("X_OS_COLLECTOR_LOG_DIR"))
}

fn log_directory(config: &Path, override_path: Option<std::ffi::OsString>) -> PathBuf {
    override_path
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| config.parent().unwrap_or(Path::new(".")).join("logs"))
}

fn private_directory(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(
            fs::symlink_metadata(path)?.is_dir(),
            "directory must be a real directory: {}",
            path.display()
        );
    } else {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        if unsafe { libc::geteuid() } == 0
            && let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID"))
        {
            let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
            ensure!(
                unsafe { libc::chown(c.as_ptr(), uid.parse()?, gid.parse()?) } == 0,
                "directory ownership: {}",
                io::Error::last_os_error()
            );
        }
    }
    Ok(())
}
fn lock(path: &Path, nonblocking: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    session::invoking_owner(&file)?;
    // SAFETY: flock operates on a live owned descriptor and named lock flags.
    ensure!(
        unsafe {
            libc::flock(
                file.as_raw_fd(),
                libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 },
            )
        } == 0,
        "采集操作正在执行：{}",
        io::Error::last_os_error()
    );
    Ok(file)
}

#[cfg(target_os = "macos")]
pub(super) fn process_identity(pid: u32) -> Option<(u64, String)> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: PROC_PIDTBSDINFO fills exactly proc_bsdinfo in an aligned buffer.
    let size = unsafe {
        libc::proc_pidinfo(
            pid.try_into().ok()?,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            std::mem::size_of::<libc::proc_bsdinfo>() as i32,
        )
    };
    if size != std::mem::size_of::<libc::proc_bsdinfo>() as i32 {
        return None;
    }
    // SAFETY: the complete struct was returned by libproc.
    let info = unsafe { info.assume_init() };
    if info.pbi_status == libc::SZOMB {
        return None;
    }
    let mut path = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the output buffer has its advertised byte size.
    let length = unsafe {
        libc::proc_pidpath(
            pid.try_into().ok()?,
            path.as_mut_ptr().cast(),
            path.len() as u32,
        )
    };
    if length <= 0 {
        return None;
    }
    let end = path.iter().position(|b| *b == 0).unwrap_or(length as usize);
    Some((
        info.pbi_start_tvsec
            .checked_mul(1000)?
            .checked_add(info.pbi_start_tvusec / 1000)?,
        String::from_utf8_lossy(&path[..end]).to_string(),
    ))
}
#[cfg(not(target_os = "macos"))]
pub(super) fn process_identity(_pid: u32) -> Option<(u64, String)> {
    None
}

fn owned(value: &Value) -> bool {
    let Some(pid) = value["pid"].as_u64().and_then(|n| u32::try_from(n).ok()) else {
        return false;
    };
    process_identity(pid).is_some_and(|(birth, path)| {
        value["process_start_id"].as_u64() == Some(birth)
            && value["executable"].as_str() == Some(path.as_str())
            && std::env::current_exe()
                .ok()
                .and_then(|p| p.canonicalize().ok())
                .is_some_and(|p| p == Path::new(&path))
    })
}
pub(super) fn status(paths: &Paths) -> Result<Value> {
    let mut value = match fs::read(paths.status_file()) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes).context("collector status JSON")?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(paths.empty_status()),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        value["schema_version"] == 1 && value["config_file"].as_str() == paths.config_file.to_str(),
        "collector status identity/config mismatch"
    );
    if !owned(&value) {
        let age = value["started_at"]
            .as_str()
            .and_then(|time| DateTime::parse_from_rfc3339(time).ok())
            .map(|time| Local::now().signed_duration_since(time).num_milliseconds());
        let privileged_start=value["state"]=="starting" && age.is_some_and(|age|age>=0 && age<START_TIMEOUT.as_millis() as i64)
            && value["pid"].as_i64().is_some_and(|pid| unsafe{libc::kill(pid as i32,0)}==0 || io::Error::last_os_error().raw_os_error()==Some(libc::EPERM));
        if !privileged_start {
            if matches!(
                value["state"].as_str(),
                Some("running" | "starting" | "stopping")
            ) {
                value["state"] = json!("failed");
                value["error"] = json!("采集进程已退出");
            }
            value["pid"] = Value::Null;
        }
    } else if value["state"] == "running" {
        let timestamp = DateTime::parse_from_rfc3339(
            value["updated_at"].as_str().context("status timestamp")?,
        )?;
        let elapsed = Local::now()
            .signed_duration_since(timestamp)
            .num_milliseconds();
        let limit = paths
            .config
            .sampling
            .status_interval_ms
            .saturating_mul(5)
            .max(paths.config.sampling.socket_interval_ms.saturating_mul(3));
        if elapsed > limit as i64 {
            value["state"] = json!("failed");
            value["error"] = json!("采集状态更新超时");
        }
    }
    Ok(value)
}

fn control_start(paths: &Paths) -> Result<()> {
    private_directory(&paths.runtime)?;
    let _lock = lock(&sidecar(&paths.config_file, "control.lock"), true)?;
    let current = status(paths)?;
    if owned(&current) {
        println!("{current}");
        return Ok(());
    }
    let exe = std::env::current_exe()?.canonicalize()?;
    fs::remove_file(paths.status_file()).or_else(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(e)
        }
    })?;
    let output = std::process::Command::new(&exe)
        .arg("daemon")
        .arg("--config")
        .arg(&paths.config_file)
        .output()?;
    ensure!(
        output.status.success(),
        "采集启动失败：{}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        let current = status(paths)?;
        if current["state"] == "running" {
            println!("{current}");
            return Ok(());
        }
        if current["state"] == "failed" {
            bail!("{}", current["error"]);
        }
        if current["state"] == "stopped" && current["run_id"].is_string() {
            println!("{current}");
            return Ok(());
        }
        std::thread::sleep(CONTROL_POLL);
    }
    let _ = stop_owned(paths);
    bail!(
        "采集启动等待超时，详见 {}",
        paths.runtime.join("collector.log").display()
    )
}
fn control_stop(paths: &Paths) -> Result<()> {
    private_directory(&paths.runtime)?;
    let _lock = lock(&sidecar(&paths.config_file, "control.lock"), true)?;
    stop_owned(paths)?;
    println!("{}", status(paths)?);
    Ok(())
}
fn stop_owned(paths: &Paths) -> Result<()> {
    let value = status(paths)?;
    if !owned(&value) {
        return Ok(());
    }
    let pid = value["pid"].as_u64().unwrap() as i32;
    // SAFETY: PID and birth identity were checked against this executable.
    ensure!(
        unsafe { libc::kill(pid, libc::SIGTERM) } == 0,
        "停止采集失败：{}",
        io::Error::last_os_error()
    );
    let deadline = Instant::now()
        + STOP_TIMEOUT
        + Duration::from_millis(paths.config.storage.flush_timeout_ms);
    while Instant::now() < deadline {
        if !owned(&value) {
            return Ok(());
        }
        std::thread::sleep(CONTROL_POLL);
    }
    if owned(&value) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let mut failed = value;
    failed["state"] = json!("failed");
    failed["updated_at"] = json!(session::now());
    failed["error"] = json!("采集关闭超时，已强制终止");
    session::atomic_json(&paths.status_file(), &failed)?;
    bail!("采集关闭超时，已强制终止")
}

fn daemon(paths: &Paths) -> Result<()> {
    // Fork is restricted to this startup entry, before logging or any workers.
    let pid = unsafe { libc::fork() };
    ensure!(pid >= 0, "fork failed");
    if pid > 0 {
        return Ok(());
    }
    if unsafe { libc::setsid() } < 0 {
        unsafe { libc::_exit(1) };
    }
    let output = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(paths.runtime.join("collector.log"))?;
    session::invoking_owner(&output)?;
    let input = File::open("/dev/null")?;
    unsafe {
        libc::dup2(input.as_raw_fd(), 0);
        libc::dup2(output.as_raw_fd(), 1);
        libc::dup2(output.as_raw_fd(), 2);
    }
    let code = match run(paths) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{} {error:#}", session::now());
            1
        }
    };
    unsafe { libc::_exit(code) }
}

fn run(paths: &Paths) -> Result<()> {
    private_directory(&paths.runtime)?;
    private_directory(&paths.data)?;
    let _lock = lock(&sidecar(&paths.config_file, "instance.lock"), true)?;
    session::atomic_json(
        &sidecar(&paths.config_file, "runtime.json"),
        &json!({"runtime_directory":paths.runtime}),
    )?;
    let id = uuid::Uuid::new_v4().to_string();
    let suffix = if paths.config.mode == config::Mode::Full {
        "sockets"
    } else {
        "traffic"
    };
    let directory = paths.data.join(format!(
        "{}-{}-{suffix}",
        Local::now().format("%Y%m%d-%H%M%S"),
        &id[..8]
    ));
    let session = Arc::new(Mutex::new(session::Session::create(
        directory.clone(),
        paths.config.clone(),
        id.clone(),
    )?));
    // The files belong to the invoking ordinary user after privileged capture setup.
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    if let (Some(uid), Some(gid)) = (uid, gid) {
        for path in [&directory, &directory.join("manifest.json")] {
            let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
            ensure!(
                unsafe { libc::chown(c.as_ptr(), uid, gid) } == 0,
                "session ownership: {}",
                io::Error::last_os_error()
            );
        }
    }
    let identity = process_identity(std::process::id()).context("collector process identity")?;
    let mut initial = paths.empty_status();
    initial["state"] = json!("starting");
    initial["pid"] = json!(std::process::id());
    initial["process_start_id"] = json!(identity.0);
    initial["executable"] = json!(identity.1);
    initial["run_id"] = json!(id);
    initial["started_at"] = json!(session.lock().unwrap().started_at);
    initial["session_directory"] = json!(directory);
    session::atomic_json(&paths.status_file(), &initial)?;
    crate::bootstrap::install_signal_handlers()?;
    let result =
        super::delegation::prepare(paths.config.capture.interface.clone()).and_then(|()| {
            crate::bootstrap::run_collector(Arc::clone(&session), paths.clone(), initial.clone())
        });
    let error = result.as_ref().err().map(|e| format!("{e:#}"));
    let finished = session
        .lock()
        .map_err(|_| anyhow::anyhow!("session poisoned"))?
        .finish(error.as_deref());
    let failure = error.or_else(|| finished.as_ref().err().map(|e| format!("{e:#}")));
    initial["state"] = json!(if failure.is_some() {
        "failed"
    } else {
        "stopped"
    });
    initial["error"] = json!(failure);
    initial["updated_at"] = json!(session::now());
    initial["listener_scans"] = json!(session.lock().unwrap().listener_scans);
    session::atomic_json(&paths.status_file(), &initial)?;
    result.and(finished)
}

pub(crate) fn initialize_logger(
    directory: &Path,
    failed: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    struct Logger {
        directory: PathBuf,
        lock: Mutex<()>,
        failed: Arc<std::sync::atomic::AtomicBool>,
    }
    impl log::Log for Logger {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.level() <= log::Level::Warn
        }
        fn log(&self, record: &log::Record<'_>) {
            if !self.enabled(record.metadata()) {
                return;
            }
            let message = record.args().to_string();
            eprintln!("{} {} {}", session::now(), record.level(), message);
            if let Ok(_guard) = self.lock.lock() {
                if !session::diagnostic(
                    &self.directory,
                    record.target(),
                    "native_diagnostic",
                    &message,
                    if record.level() == log::Level::Error {
                        "error"
                    } else {
                        "warning"
                    },
                ) {
                    self.failed
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
                let result = (|| -> io::Result<()> {
                    let mut f = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(self.directory.join("diagnostics.log"))?;
                    session::invoking_owner(&f).map_err(|e| io::Error::other(e.to_string()))?;
                    use std::io::Write;
                    writeln!(f, "{} {} {}", session::now(), record.level(), message)?;
                    f.sync_all()
                })();
                if let Err(e) = result {
                    self.failed
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("diagnostic log failed: {e}");
                }
            }
        }
        fn flush(&self) {}
    }
    log::set_boxed_logger(Box::new(Logger {
        directory: directory.to_path_buf(),
        lock: Mutex::new(()),
        failed,
    }))
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    log::set_max_level(log::LevelFilter::Warn);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_diagnostics_keep_the_existing_directory_override() {
        let config = Path::new("/project/collector.yaml");
        assert_eq!(log_directory(config, None), Path::new("/project/logs"));
        assert_eq!(
            log_directory(config, Some("/isolated/diagnostics".into())),
            Path::new("/isolated/diagnostics")
        );
        assert_eq!(
            log_directory(config, Some("".into())),
            Path::new("/project/logs")
        );
    }

    #[test]
    fn changing_runtime_configuration_keeps_control_of_the_live_instance() {
        let root = std::env::temp_dir().join(format!("collector-runtime-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let config = root.join("collector.yaml");
        let text = include_str!("../../../collector.yaml");
        fs::write(&config, text).unwrap();
        let paths = Paths::load(&config).unwrap();
        private_directory(&paths.runtime).unwrap();
        let mut value = paths.empty_status();
        let (birth, exe) = process_identity(std::process::id()).unwrap();
        value["state"] = json!("running");
        value["pid"] = json!(std::process::id());
        value["process_start_id"] = json!(birth);
        value["executable"] = json!(exe);
        session::atomic_json(&paths.status_file(), &value).unwrap();
        // The controller's per-config location survives a runtime-directory edit.
        let mut anchor = config.as_os_str().to_os_string();
        anchor.push(".runtime.json");
        session::atomic_json(
            Path::new(&anchor),
            &json!({"runtime_directory":paths.runtime}),
        )
        .unwrap();
        fs::write(&config, text.replace(".build/service", ".build/moved")).unwrap();
        let changed = Paths::load(&config).unwrap();
        assert_eq!(changed.runtime, paths.runtime);
        assert_eq!(status(&changed).unwrap()["pid"], std::process::id());
        let held = lock(&sidecar(&paths.config_file, "instance.lock"), true).unwrap();
        assert!(lock(&sidecar(&changed.config_file, "instance.lock"), true).is_err());
        drop(held);
        value["state"] = json!("stopped");
        value["pid"] = Value::Null;
        session::atomic_json(&paths.status_file(), &value).unwrap();
        assert_eq!(
            Paths::load(&config).unwrap().runtime,
            paths.config_file.parent().unwrap().join(".build/moved")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn status_requires_matching_birth_and_a_fresh_heartbeat() {
        let root = std::env::temp_dir().join(format!("collector-status-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let config = root.join("collector.yaml");
        fs::write(&config, include_str!("../../../collector.yaml")).unwrap();
        let paths = Paths::load(&config).unwrap();
        private_directory(&paths.runtime).unwrap();
        assert_eq!(status(&paths).unwrap()["state"], "stopped");
        let mut value = paths.empty_status();
        let (birth, exe) = process_identity(std::process::id()).unwrap();
        value["state"] = json!("running");
        value["pid"] = json!(std::process::id());
        value["process_start_id"] = json!(birth);
        value["executable"] = json!(exe);
        session::atomic_json(&paths.status_file(), &value).unwrap();
        assert_eq!(status(&paths).unwrap()["state"], "running");
        value["updated_at"] = json!("2020-01-01T00:00:00.000+08:00");
        session::atomic_json(&paths.status_file(), &value).unwrap();
        let stale = status(&paths).unwrap();
        assert_eq!(stale["state"], "failed");
        assert!(stale["pid"].is_number());
        value["updated_at"] = json!(session::now());
        value["process_start_id"] = json!(birth + 1);
        session::atomic_json(&paths.status_file(), &value).unwrap();
        let reused = status(&paths).unwrap();
        assert_eq!(reused["state"], "failed");
        assert_eq!(reused["pid"], Value::Null);
        stop_owned(&paths).unwrap();
        assert!(process_identity(std::process::id()).is_some());
        fs::remove_dir_all(root).unwrap();
    }
}
