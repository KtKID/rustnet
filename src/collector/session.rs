//! A single owner for collector files; shared only across in-process workers.

use super::codec::Encoder;
use super::config::{CollectorConfig, Mode};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Local, SecondsFormat};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const CHECKPOINT_FRAMES: u64 = 60;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
pub fn now() -> String {
    Local::now().to_rfc3339_opts(SecondsFormat::Millis, false)
}
pub fn invoking_owner(file: &File) -> Result<()> {
    if unsafe { libc::geteuid() } == 0
        && let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID"))
    {
        let uid = uid.parse::<u32>()?;
        let gid = gid.parse::<u32>()?;
        ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
            "output ownership: {}",
            io::Error::last_os_error()
        );
    }
    Ok(())
}
pub fn append(path: &Path, value: &Value) -> Result<usize> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= MAX_LINE_BYTES, "record exceeds 8 MiB");
    append_bytes(path, &bytes)
}
fn append_bytes(path: &Path, bytes: &[u8]) -> Result<usize> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    invoking_owner(&file)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(bytes.len())
}
pub fn atomic_json(path: &Path, value: &Value) -> Result<()> {
    let temporary = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        invoking_owner(&file)?;
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(path.parent().context("metadata parent")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
pub fn diagnostic(
    directory: &Path,
    component: &str,
    event: &str,
    message: &str,
    severity: &str,
) -> bool {
    let value = json!({"schema_version":1,"type":"diagnostic","timestamp":now(),"severity":severity,"component":component,"event":event,"message":message});
    if let Err(error) = append(&directory.join("errors.jsonl"), &value) {
        eprintln!(
            "{} diagnostic_write_failed: {error:#}; original={value}",
            now()
        );
        return false;
    }
    true
}

pub struct Session {
    pub directory: PathBuf,
    pub config: CollectorConfig,
    pub run_id: String,
    pub started_at: String,
    pub listener_scans: u64,
    pub diagnostics_failed: Arc<AtomicBool>,
    capture_started_at: Option<String>,
    manifest: Value,
    encoder: Encoder,
    records: u64,
    bytes: u64,
    peak_bytes: u64,
    source_bytes: u64,
    source_hash: Sha256,
    stored_hash: Sha256,
    checkpoints: u64,
    first: Option<String>,
    last: Option<Value>,
    identities: HashSet<String>,
    pub terminal: bool,
    last_generation: Option<u64>,
}

impl Session {
    pub fn create(directory: PathBuf, config: CollectorConfig, run_id: String) -> Result<Self> {
        fs::create_dir(&directory)
            .with_context(|| format!("create session {}", directory.display()))?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let started_at = now();
        let mut manifest = json!({"completed":false,"collection_mode":if config.mode == Mode::Anomalies {"process-traffic"} else {"full"},
            "source_commit":env!("RUSTNET_COLLECTOR_SOURCE"),"collector_version":env!("CARGO_PKG_VERSION"),
            "binary_sha256":hex(&Sha256::digest(fs::read(std::env::current_exe()?)?)),
            "collector_process_name":"x-net-collector","started_at":started_at,"run_id":run_id,
            "duration_seconds":config.duration_seconds,"refresh_interval_ms":config.sampling.snapshot_interval_ms,
            "config":config,"snapshot_compaction":config.mode == Mode::Full,"raw_snapshot_file_written":false,
            "show_localhost":config.capture.show_localhost,"show_ptr_lookups":config.capture.show_ptr_lookups,"socket_inventory_exported":true});
        if config.mode == Mode::Full {
            manifest.as_object_mut().unwrap().remove("collection_mode");
            manifest["snapshot_storage_format"] = json!("rustnet-delta-v1");
        }
        atomic_json(&directory.join("manifest.json"), &manifest)?;
        Ok(Self {
            directory,
            config,
            run_id,
            started_at,
            listener_scans: 0,
            diagnostics_failed: Arc::new(AtomicBool::new(false)),
            capture_started_at: None,
            manifest,
            encoder: Encoder::new(CHECKPOINT_FRAMES),
            records: 0,
            bytes: 0,
            peak_bytes: 0,
            source_bytes: 0,
            source_hash: Sha256::new(),
            stored_hash: Sha256::new(),
            checkpoints: 0,
            first: None,
            last: None,
            identities: HashSet::new(),
            terminal: false,
            last_generation: None,
        })
    }

    pub fn start_sampling(&mut self) -> Result<()> {
        let time = now();
        self.capture_started_at = Some(time.clone());
        self.manifest["capture_started_at"] = json!(time);
        atomic_json(&self.directory.join("manifest.json"), &self.manifest)
    }

    pub fn record(&mut self, value: Value, source: &[u8]) -> Result<()> {
        ensure!(!self.terminal, "record after terminal summary");
        if self.config.mode == Mode::Anomalies {
            if let Some(events) = value.as_array() {
                ensure!(!events.is_empty(), "empty anomaly batch");
                let generation = events[0]["generation"]
                    .as_u64()
                    .context("event generation")?;
                ensure!(
                    self.last_generation
                        .is_none_or(|previous| generation > previous),
                    "event generations must increase"
                );
                let mut identities = HashSet::new();
                let mut detail_bytes = Vec::new();
                let mut peak_bytes = Vec::new();
                for event in events {
                    ensure!(
                        event["generation"] == generation
                            && identities.insert(
                                json!([event["process"]["pid"], event["process"]["uid"]])
                                    .to_string()
                            ),
                        "mixed or duplicated anomaly batch"
                    );
                    ensure!(
                        event["upload_threshold_bytes_per_second"].as_f64()
                            == Some(self.config.thresholds.upload_mb_s * 1_000_000.0)
                            && event["download_threshold_bytes_per_second"].as_f64()
                                == Some(self.config.thresholds.download_mb_s * 1_000_000.0),
                        "event/config threshold mismatch"
                    );
                    serde_json::to_writer(&mut detail_bytes, event)?;
                    detail_bytes.push(b'\n');
                    serde_json::to_writer(&mut peak_bytes, &peak(event)?)?;
                    peak_bytes.push(b'\n');
                }
                self.bytes +=
                    append_bytes(&self.directory.join("process-traffic.jsonl"), &detail_bytes)?
                        as u64;
                self.peak_bytes +=
                    append_bytes(&self.directory.join("traffic-peaks.jsonl"), &peak_bytes)? as u64;
                self.records += events.len() as u64;
                self.last_generation = Some(generation);
                for event in events {
                    if event["process"]["name"].is_null()
                        && event["process"]["executable"].is_null()
                    {
                        ensure!(
                            diagnostic(
                                &self.directory,
                                "collector",
                                "process_identity_unavailable",
                                "峰值进程只有PID，程序名称与路径暂不可用",
                                "warning"
                            ),
                            "identity diagnostic could not be saved"
                        );
                    }
                }
            } else {
                ensure!(
                    value["type"] == "process_traffic_summary"
                        && value["anomaly_records"].as_u64() == Some(self.records),
                    "terminal count mismatch"
                );
                let mut summary = value;
                summary["upload_mb_s"] = json!(self.config.thresholds.upload_mb_s);
                summary["download_mb_s"] = json!(self.config.thresholds.download_mb_s);
                summary["jsonl_bytes"] = json!(self.bytes);
                summary["anomaly_file_created"] = json!(self.records > 0);
                summary["peak_log_bytes"] = json!(self.peak_bytes);
                summary["peak_log_file_created"] = json!(self.records > 0);
                summary["total_jsonl_bytes"] = json!(self.bytes + self.peak_bytes);
                for field in [
                    "unattributed_connections",
                    "missing_upload_rates",
                    "missing_download_rates",
                    "counter_resets",
                ] {
                    if summary[field].as_u64().is_some_and(|count| count > 0) {
                        ensure!(
                            diagnostic(
                                &self.directory,
                                "collector",
                                field,
                                &format!("{field}={}", summary[field]),
                                "warning",
                            ),
                            "coverage diagnostic could not be saved"
                        );
                    }
                }
                atomic_json(&self.directory.join("summary.json"), &summary)?;
                self.last = Some(summary);
                self.terminal = true;
            }
        } else {
            let frame = self.encoder.encode(&value)?;
            let mut stored = serde_json::to_vec(&frame)?;
            stored.push(b'\n');
            self.bytes += append(&self.directory.join("snapshots.jsonl"), &frame)? as u64;
            self.source_bytes += source.len() as u64;
            self.source_hash.update(source);
            self.stored_hash.update(&stored);
            self.checkpoints += u64::from(frame["kind"] == "checkpoint");
            self.records += 1;
            self.first
                .get_or_insert_with(|| value["timestamp"].as_str().unwrap_or("").to_string());
            if let Some(connections) = value["connections"].as_array() {
                for c in connections {
                    self.identities.insert(c["id"].to_string());
                }
            }
            self.terminal = matches!(
                value["runtime"]["status"].as_str(),
                Some("stopped" | "stopped_with_errors" | "stopping")
            );
            self.last = Some(value);
        }
        Ok(())
    }

    pub fn finish(&mut self, error: Option<&str>) -> Result<()> {
        let result = self.finish_inner(error);
        if let Err(failure) = &result {
            self.manifest["completed"] = json!(false);
            self.manifest["error"] = json!(format!("{failure:#}"));
            diagnostic(
                &self.directory,
                "collector",
                "finalization_failed",
                &format!("{failure:#}"),
                "error",
            );
            if let Err(record) = atomic_json(&self.directory.join("manifest.json"), &self.manifest)
            {
                eprintln!("manifest finalization failed: {record:#}; primary={failure:#}");
            }
        }
        result
    }

    fn finish_inner(&mut self, error: Option<&str>) -> Result<()> {
        let error = error
            .map(str::to_string)
            .or_else(|| {
                self.diagnostics_failed
                    .load(Ordering::Relaxed)
                    .then(|| "诊断日志保存失败".to_string())
            })
            .or_else(|| (!self.terminal).then(|| "采集缺少最终摘要".into()));
        if self.config.mode == Mode::Full && self.records > 0 {
            let last = self.last.as_ref().context("last full snapshot")?;
            let connections_path = self.directory.join("connections.jsonl");
            let events =
                fs::read_to_string(&connections_path).context("read final connection events")?;
            let event_bytes = events.len() as u64;
            let event_records = events.lines().filter(|l| !l.trim().is_empty()).count();
            let diagnostic_bytes = fs::metadata(self.directory.join("diagnostics.log"))
                .map(|s| s.len())
                .unwrap_or(0);
            let sockets = last["socket_inventory"]["sockets"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let actual_seconds = DateTime::parse_from_rfc3339(&now())?
                .signed_duration_since(DateTime::parse_from_rfc3339(
                    self.capture_started_at.as_ref().unwrap_or(&self.started_at),
                )?)
                .num_milliseconds()
                .max(1) as f64
                / 1000.0;
            let total = self.bytes + event_bytes;
            let source = self.source_bytes + event_bytes;
            let summary = json!({"snapshot_storage_format":"rustnet-delta-v1","snapshot_records":self.records,"event_records":event_records,
                "unique_connections":self.identities.len(),"socket_count_latest":sockets.len(),
                "tcp_listen_latest":sockets.iter().filter(|s| s["protocol"] == "TCP" && s["state"] == "LISTEN").count(),
                "udp_bound_latest":sockets.iter().filter(|s| s["protocol"] == "UDP" && s["state"] == "BOUND").count(),
                "first_timestamp":self.first,"last_timestamp":last["timestamp"],"snapshot_interval_ms":self.config.sampling.snapshot_interval_ms,
                "configured_duration_seconds":self.config.duration_seconds.unwrap_or(actual_seconds.ceil() as u64),
                "runtime":last["runtime"],"stats":last["stats"],"sandbox":last["sandbox"],"checkpoint_records":self.checkpoints,
                "patch_records":self.records-self.checkpoints,"checkpoint_interval_frames":CHECKPOINT_FRAMES,
                "source_snapshot_bytes":self.source_bytes,"source_snapshot_sha256":hex(&self.source_hash.clone().finalize()),
                "stored_snapshot_sha256":hex(&self.stored_hash.clone().finalize()),"source_jsonl_bytes":source,"jsonl_bytes":total,
                "jsonl_bytes_saved":source as i64-total as i64,"reduction_percent":if source>0 {(1.0-total as f64/source as f64)*100.0} else {0.0},
                "jsonl_bytes_per_second":total as f64/actual_seconds,"files":{"snapshots.jsonl":self.bytes,"connections.jsonl":event_bytes,"diagnostics.log":diagnostic_bytes}});
            atomic_json(&self.directory.join("summary.json"), &summary)?;
        }
        self.manifest["completed"] = json!(error.is_none());
        self.manifest["capture_exit_code"] = json!(if error.is_none() { 0 } else { 1 });
        self.manifest["collector_exit_code"] = self.manifest["capture_exit_code"].clone();
        self.manifest["ended_at"] = json!(now());
        if let Some(message) = &error {
            self.manifest["error"] = json!(message);
            diagnostic(
                &self.directory,
                "collector",
                "collection_failed",
                message,
                "error",
            );
        }
        atomic_json(&self.directory.join("manifest.json"), &self.manifest)?;
        if let Some(message) = error {
            anyhow::bail!(message);
        }
        Ok(())
    }
}

fn peak(event: &Value) -> Result<Value> {
    let process = &event["process"];
    let parent = process["lineage"]["ancestors"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["pid"] == process["ppid"]));
    let timestamp =
        DateTime::parse_from_rfc3339(event["timestamp"].as_str().context("event timestamp")?)?
            .with_timezone(&Local)
            .to_rfc3339_opts(SecondsFormat::Millis, false);
    Ok(
        json!({"schema_version":1,"type":"traffic_peak","timestamp":timestamp,"source_generation":event["generation"],"source_file":"process-traffic.jsonl",
        "pid":process["pid"],"program_name":process["name"],"executable":process["executable"],"uid":process["uid"],
        "parent_process":if process["ppid"].is_null() {Value::Null} else {json!({"pid":process["ppid"],"program_name":parent.map(|p| &p["name"]),"executable":parent.map(|p| &p["executable"])})},
        "upload_bytes_per_second":event["upload_bytes_per_second"],"download_bytes_per_second":event["download_bytes_per_second"],
        "upload_threshold_bytes_per_second":event["upload_threshold_bytes_per_second"],"download_threshold_bytes_per_second":event["download_threshold_bytes_per_second"],
        "upload_exceeded":event["upload_exceeded"],"download_exceeded":event["download_exceeded"],"sampling_mode":event["sampling_mode"],"sample_interval_ms":event["sample_interval_ms"]}),
    )
}

pub struct SessionWriter {
    session: Arc<Mutex<Session>>,
    pending: Vec<u8>,
}
impl SessionWriter {
    pub fn new(session: Arc<Mutex<Session>>) -> Self {
        Self {
            session,
            pending: Vec::new(),
        }
    }
}
impl Write for SessionWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<_> = self.pending.drain(..=end).collect();
            let result = serde_json::from_slice(&line)
                .map_err(anyhow::Error::from)
                .and_then(|value| {
                    self.session
                        .lock()
                        .map_err(|_| anyhow::anyhow!("session lock poisoned"))?
                        .record(value, &line)
                });
            result.map_err(|e| io::Error::other(format!("{e:#}")))?;
        }
        if self.pending.len() > MAX_LINE_BYTES {
            return Err(io::Error::other("incomplete record exceeds 8 MiB"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prepare() -> Session {
        let root = std::env::temp_dir().join(format!("collector-storage-{}", uuid::Uuid::new_v4()));
        let config = super::super::config::parse(include_str!("../../../collector.yaml")).unwrap();
        Session::create(root, config, uuid::Uuid::new_v4().to_string()).unwrap()
    }
    fn terminal(records: u64) -> Value {
        let snapshot: Value =
            serde_json::from_str(include_str!("../../../web/tests/fixtures/snapshot.json"))
                .unwrap();
        let mut runtime = snapshot["runtime"].clone();
        runtime["status"] = json!("stopped");
        runtime["termination_reason"] = json!("shutdown_requested");
        runtime["shutdown"] = json!({"joined_workers":1,"panicked_workers":0,"timed_out_workers":0,"output_errors":0});
        json!({"schema_version":1,"type":"process_traffic_summary","checks":3,"anomaly_records":records,
            "unattributed_connections":0,"missing_upload_rates":0,"missing_download_rates":0,"runtime":runtime,"stats":snapshot["stats"]})
    }
    #[test]
    fn normal_sampling_creates_only_metadata_and_final_summary() {
        let mut session = prepare();
        let end = terminal(0);
        session
            .record(end.clone(), &serde_json::to_vec(&end).unwrap())
            .unwrap();
        session.finish(None).unwrap();
        assert!(!session.directory.join("process-traffic.jsonl").exists());
        assert!(!session.directory.join("traffic-peaks.jsonl").exists());
        let manifest: Value =
            serde_json::from_slice(&fs::read(session.directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["completed"], true);
        fs::remove_dir_all(session.directory).unwrap();
    }
    #[test]
    fn threshold_events_write_linked_detail_and_peak_records() {
        let mut session = prepare();
        let event: Value = serde_json::from_str(include_str!(
            "../../../web/tests/fixtures/process-traffic.json"
        ))
        .unwrap();
        let batch = json!([event]);
        session
            .record(batch.clone(), &serde_json::to_vec(&batch).unwrap())
            .unwrap();
        let end = terminal(1);
        session
            .record(end.clone(), &serde_json::to_vec(&end).unwrap())
            .unwrap();
        session.finish(None).unwrap();
        let peak: Value = serde_json::from_str(
            fs::read_to_string(session.directory.join("traffic-peaks.jsonl"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(peak["source_generation"], 1);
        assert_eq!(peak["pid"], 42);
        assert_eq!(peak["upload_bytes_per_second"], 6000000);
        assert_eq!(peak["parent_process"]["pid"], 1);
        assert_eq!(peak["parent_process"]["program_name"], Value::Null);
        assert!(peak["timestamp"].as_str().unwrap().contains(".000"));
        fs::remove_dir_all(session.directory).unwrap();
    }
    #[test]
    fn writing_failure_is_visible_and_cannot_complete_the_session() {
        use std::os::unix::fs::symlink;
        let mut session = prepare();
        symlink("/dev/null", session.directory.join("process-traffic.jsonl")).unwrap();
        let event: Value = serde_json::from_str(include_str!(
            "../../../web/tests/fixtures/process-traffic.json"
        ))
        .unwrap();
        let batch = json!([event]);
        assert!(
            session
                .record(batch.clone(), &serde_json::to_vec(&batch).unwrap())
                .is_err()
        );
        assert!(session.finish(Some("controlled output failure")).is_err());
        let manifest: Value =
            serde_json::from_slice(&fs::read(session.directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["completed"], false);
        assert!(session.directory.join("errors.jsonl").exists());
        fs::remove_dir_all(session.directory).unwrap();
    }

    #[test]
    fn warning_failure_preserves_peak_facts_and_fails_the_run() {
        use std::os::unix::fs::symlink;
        let mut session = prepare();
        symlink("/dev/null", session.directory.join("errors.jsonl")).unwrap();
        let mut event: Value = serde_json::from_str(include_str!(
            "../../../web/tests/fixtures/process-traffic.json"
        ))
        .unwrap();
        event["process"]["name"] = Value::Null;
        event["process"]["executable"] = Value::Null;
        let batch = json!([event]);
        assert!(
            session
                .record(batch.clone(), &serde_json::to_vec(&batch).unwrap())
                .is_err()
        );
        assert!(session.directory.join("process-traffic.jsonl").exists());
        assert!(session.directory.join("traffic-peaks.jsonl").exists());
        assert!(
            session
                .finish(Some("controlled diagnostic failure"))
                .is_err()
        );
        fs::remove_dir_all(session.directory).unwrap();
    }
}
