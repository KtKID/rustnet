//! Listener and status work uses the App's shared in-process socket scan.

use super::{Paths, Session, listeners::Tracker, session};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) struct Auxiliary {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}
impl Auxiliary {
    pub fn start(
        app: &crate::app::App,
        session: Arc<Mutex<Session>>,
        paths: Paths,
        mut status: Value,
        shutdown: &'static AtomicBool,
    ) -> Result<Self> {
        let snapshots = app.shared_socket_snapshot();
        let stop = Arc::new(AtomicBool::new(false));
        let request = Arc::clone(&stop);
        let cadence = paths.config.sampling.clone();
        let uid = unsafe { libc::geteuid() };
        let worker = thread::Builder::new()
            .name("collector_status_listeners".into())
            .spawn(move || -> Result<()> {
                let run_id = session.lock().unwrap().run_id.clone();
                let mut tracker = Tracker::new(run_id, uid);
                let mut next_listener = Instant::now();
                let mut next_status = Instant::now();
                let mut last_observation = None;
                let mut ready = false;
                let mut issue: Option<String> = None;
                let listener_interval = Duration::from_millis(cadence.listener_interval_ms);
                let status_interval = Duration::from_millis(cadence.status_interval_ms);
                let result = (|| -> Result<()> {
                    while !request.load(Ordering::Relaxed) {
                        let now = Instant::now();
                        if now >= next_listener && !shutdown.load(Ordering::Relaxed) {
                            let snapshot = snapshots
                                .read()
                                .map_err(|_| anyhow::anyhow!("socket inventory lock poisoned"))?
                                .clone();
                            if snapshot.collected_at.is_some() {
                                let fresh = snapshot.collected_at.is_some_and(|time| {
                                    time.elapsed().is_ok_and(|age| {
                                        age <= Duration::from_millis(
                                            cadence.socket_interval_ms.saturating_mul(3),
                                        )
                                    })
                                });
                                if !snapshot.complete || !fresh {
                                    issue = Some("Socket扫描失败或清单已过期，保留监听基线".into());
                                    ensure!(
                                        session::diagnostic(
                                            &session.lock().unwrap().directory,
                                            "listeners",
                                            "scan_failed",
                                            issue.as_deref().unwrap(),
                                            "warning",
                                        ),
                                        "listener diagnostic could not be saved"
                                    );
                                } else if snapshot.collected_at != last_observation {
                                    let timestamp = session::now();
                                    let events =
                                        tracker.update(&snapshot.sockets, &timestamp, true)?;
                                    for event in events {
                                        session::append(
                                            &paths.data.join("listener-events.jsonl"),
                                            &event,
                                        )?;
                                    }
                                    session.lock().unwrap().listener_scans += 1;
                                    last_observation = snapshot.collected_at;
                                    ready = true;
                                    issue = None;
                                }
                            }
                            next_listener = now + listener_interval;
                        }
                        if now >= next_status {
                            status["state"] = json!(if shutdown.load(Ordering::Relaxed) {
                                "stopping"
                            } else if issue.is_some() {
                                "failed"
                            } else if ready {
                                "running"
                            } else {
                                "starting"
                            });
                            status["error"] = json!(issue);
                            status["updated_at"] = json!(session::now());
                            status["listener_scans"] =
                                json!(session.lock().unwrap().listener_scans);
                            session::atomic_json(&paths.status_file(), &status)?;
                            next_status = now + status_interval;
                        }
                        thread::sleep(
                            next_listener
                                .min(next_status)
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_millis(50)),
                        );
                    }
                    Ok(())
                })();
                if let Err(error) = &result {
                    session::diagnostic(
                        &session.lock().unwrap().directory,
                        "collector",
                        "auxiliary_failed",
                        &format!("{error:#}"),
                        "error",
                    );
                    shutdown.store(true, Ordering::Relaxed);
                }
                result
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
    pub fn finish(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.worker
            .take()
            .context("auxiliary worker")?
            .join()
            .map_err(|_| anyhow::anyhow!("collector auxiliary worker panicked"))?
    }
}
impl Drop for Auxiliary {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    #[test]
    fn a_valid_initial_inventory_is_ready_with_a_long_socket_interval() {
        let root = std::env::temp_dir().join(format!("collector-ready-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let config = root.join("collector.yaml");
        std::fs::write(
            &config,
            include_str!("../../../collector.yaml")
                .replace("socket_interval_ms: 1000", "socket_interval_ms: 10000"),
        )
        .unwrap();
        let paths = Paths::load(&config).unwrap();
        std::fs::create_dir_all(&paths.data).unwrap();
        std::fs::create_dir_all(&paths.runtime).unwrap();
        let session = Arc::new(Mutex::new(
            Session::create(
                paths.data.join("session"),
                paths.config.clone(),
                uuid::Uuid::new_v4().to_string(),
            )
            .unwrap(),
        ));
        let app = crate::app::App::new(crate::app::Config {
            resolve_dns: false,
            ..crate::app::Config::default()
        })
        .unwrap();
        {
            let snapshots = app.shared_socket_snapshot();
            let mut snapshot = snapshots.write().unwrap();
            snapshot.complete = true;
            snapshot.collected_at = Some(SystemTime::now());
        }
        // Auxiliary starts after App's initial inventory has already completed.
        thread::sleep(Duration::from_millis(1));
        static STOP: AtomicBool = AtomicBool::new(false);
        let worker =
            Auxiliary::start(&app, session, paths.clone(), paths.empty_status(), &STOP).unwrap();
        let deadline = Instant::now() + Duration::from_millis(300);
        let mut ready = false;
        while Instant::now() < deadline {
            if let Ok(bytes) = std::fs::read(paths.status_file()) {
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                if value["state"] == "running" {
                    ready = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        worker.finish().unwrap();
        std::fs::remove_dir_all(root).unwrap();
        assert!(ready, "a valid initial inventory must establish readiness");
    }
}
