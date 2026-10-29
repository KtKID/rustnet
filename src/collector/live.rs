//! Private local request/response transport. Live facts remain in App memory.
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::app::LiveSources;
use anyhow::{Context, Result, ensure};

const IO_TIMEOUT: Duration = Duration::from_millis(300);
const ACCEPT_POLL: Duration = Duration::from_millis(20);
const MAX_REPLY_BYTES: usize = 2 * 1024 * 1024;

pub(crate) struct LiveServer {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
    path: PathBuf,
}
impl LiveServer {
    pub(crate) fn start(sources: LiveSources, path: PathBuf, run_id: String) -> Result<Self> {
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            ensure!(
                metadata.file_type().is_socket(),
                "live endpoint path is occupied"
            );
            fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path).context("live memory endpoint")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let requested = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("collector_live".into())
            .spawn(move || {
                while !requested.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            // macOS inherits O_NONBLOCK on accepted sockets. Switch
                            // the client to bounded blocking I/O so large views can
                            // wait for the reader instead of truncating on EAGAIN.
                            stream.set_nonblocking(false)?;
                            stream.set_read_timeout(Some(IO_TIMEOUT))?;
                            stream.set_write_timeout(Some(IO_TIMEOUT))?;
                            let mut command = [0; 4];
                            if stream.read_exact(&mut command).is_err() || &command != b"GET\n" {
                                continue;
                            }
                            let result = (|| -> Result<()> {
                                let mut body = serde_json::to_vec(&sources.snapshot(&run_id)?)?;
                                ensure!(
                                    body.len() < MAX_REPLY_BYTES,
                                    "live view exceeds reply limit"
                                );
                                body.push(b'\n');
                                stream.write_all(&body)?;
                                Ok(())
                            })();
                            if let Err(error) = result {
                                log::warn!("Live view request failed: {error:#}");
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(ACCEPT_POLL)
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok(())
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
            path,
        })
    }
    pub(crate) fn finish(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        let result = self
            .worker
            .take()
            .context("live worker")?
            .join()
            .map_err(|_| anyhow::anyhow!("live worker panicked"))?;
        fs::remove_file(&self.path).or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        })?;
        result
    }
}
impl Drop for LiveServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    #[test]
    fn live_socket_serves_memory_and_cleans_up_with_a_stalled_client() {
        let directory =
            std::path::Path::new("/private/tmp").join(format!("live-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("live.sock");
        let app = crate::app::App::new(crate::app::Config {
            resolve_dns: false,
            ..Default::default()
        })
        .unwrap();
        let mut history = crate::network::types::TrafficHistory::new(120);
        for _ in 0..120 {
            history.add_sample(
                Some((100000, 200000)),
                Default::default(),
                10,
                0,
                Some(20.0),
            );
        }
        app.set_traffic_history_for_test(history);
        let server = LiveServer::start(
            app.live_sources(),
            path.clone(),
            uuid::Uuid::new_v4().to_string(),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"GET\n").unwrap();
        thread::sleep(Duration::from_millis(100));
        let mut body = String::new();
        client.read_to_string(&mut body).unwrap();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["pid"], std::process::id());
        assert_eq!(value["history"].as_array().unwrap().len(), 120);
        assert!(body.len() > 16384);
        let _stalled = UnixStream::connect(&path).unwrap();
        let started = std::time::Instant::now();
        server.finish().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!path.exists());
        fs::remove_dir(directory).unwrap();
    }
}
