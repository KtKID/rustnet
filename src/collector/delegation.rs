//! Acquire capture privilege once while retaining the ordinary process's file access.

use anyhow::{Context, Result, bail, ensure};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn prepare(interface: Option<String>) -> Result<()> {
    let directory =
        Path::new("/private/tmp").join(format!("collector-capture-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<()> {
        let executable = directory.join("x-net-collector");
        fs::copy(std::env::current_exe()?, &executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
        let socket = directory.join("capture.sock");
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let nonce = uuid::Uuid::new_v4().to_string();
        let request = rustnet_capture::delegated::Request {
            socket_path: socket.to_string_lossy().into_owned(),
            nonce: nonce.clone(),
            interface,
            uid: unsafe { libc::geteuid() },
        };
        let path = directory.join("request.json");
        fs::write(&path, serde_json::to_vec(&request)?)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let quote = |s: &Path| format!("'{}'", s.to_string_lossy().replace('\'', "'\\''"));
        let command = format!(
            "{} capture-helper --config {}",
            quote(&executable),
            quote(&path)
        );
        let script = format!(
            "do shell script {} with administrator privileges with prompt {}",
            serde_json::to_string(&command)?,
            serde_json::to_string(
                "x-net-collector 需要授权打开抓包设备；采集文件由当前用户保存。"
            )?
        );
        let mut child = Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let received = (|| -> Result<()> {
            loop {
                if crate::bootstrap::SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
                    bail!("capture authorization cancelled");
                }
                match listener.accept() {
                    Ok((stream, _)) => return rustnet_capture::delegated::receive(stream, &nonce),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
                if child.try_wait()?.is_some() {
                    bail!("capture authorization helper exited before handoff");
                }
                ensure!(Instant::now() < deadline, "capture authorization timed out");
                std::thread::sleep(Duration::from_millis(50));
            }
        })();
        if received.is_err() {
            let _ = child.kill();
        }
        let output = child.wait_with_output()?;
        received.with_context(|| {
            format!(
                "系统授权/抓包初始化：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
        })?;
        ensure!(
            output.status.success(),
            "capture helper exit: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    })();
    if let Err(error) = fs::remove_dir_all(&directory) {
        eprintln!("capture handoff cleanup failed: {error}");
    }
    result
}
