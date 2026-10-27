//! Per-process threshold checks before full snapshot projection/serialization.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Instant, SystemTime};

use anyhow::{Result, ensure};
use serde::Serialize;

use super::output::AsyncOutput;
use super::schema::{
    ConnectionSnapshot, ProcessSnapshot, RuntimePhase, RuntimeSnapshot, StatsSnapshot, timestamp,
};
use super::{
    HeadlessOptions, MAX_STOP_POLL_INTERVAL, SCHEMA_VERSION, TerminationReason, exit_reason,
    fail_if_runtime_unhealthy, runtime_failure, shutdown_failure, sleep_duration,
};
use crate::app::{App, StopReport};
use crate::network::types::Connection;

#[cfg(test)]
mod adaptive_probe;
#[cfg(test)]
mod benchmark;
mod cadence;
mod interval;
pub use cadence::TrafficCadence;
use cadence::{CadenceTracker, SamplingMode};
use interval::IntervalSampler;

#[derive(Debug, Clone, Copy)]
pub struct TrafficThresholds {
    pub upload: f64,
    pub download: f64,
}

#[derive(Default)]
struct Coverage {
    unattributed_connections: u64,
    missing_upload_rates: u64,
    missing_download_rates: u64,
}

#[derive(Default)]
struct ProcessRates<'a> {
    upload: f64,
    download: f64,
    missing_upload_rates: u64,
    missing_download_rates: u64,
    connections: Vec<&'a Connection>,
}

#[derive(Serialize)]
struct TrafficEvent {
    schema_version: u8,
    #[serde(rename = "type")]
    record_type: &'static str,
    timestamp: String,
    generation: u64,
    process: Option<ProcessSnapshot>,
    upload_bytes_per_second: f64,
    download_bytes_per_second: f64,
    upload_threshold_bytes_per_second: f64,
    download_threshold_bytes_per_second: f64,
    upload_exceeded: bool,
    download_exceeded: bool,
    missing_upload_rates: u64,
    missing_download_rates: u64,
    connections: Vec<ConnectionSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sample_interval_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_basis: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampling_mode: Option<SamplingMode>,
}

#[derive(Serialize)]
struct TrafficSummary {
    schema_version: u8,
    #[serde(rename = "type")]
    record_type: &'static str,
    checks: u64,
    anomaly_records: u64,
    unattributed_connections: u64,
    missing_upload_rates: u64,
    missing_download_rates: u64,
    traffic_interval_ms: u64,
    traffic_alert_interval_ms: u64,
    traffic_alert_cooldown_ms: u64,
    normal_checks: u64,
    alert_checks: u64,
    alert_activations: u64,
    alert_recoveries: u64,
    final_traffic_mode: SamplingMode,
    counter_resets: u64,
    traffic_check_total_ns: u64,
    traffic_check_max_ns: u64,
    runtime: RuntimeSnapshot,
    stats: StatsSnapshot,
}

#[derive(Serialize)]
#[serde(untagged)]
enum TrafficOutput {
    Events(Vec<TrafficEvent>),
    Summary(Box<TrafficSummary>),
}

fn usable_rate(value: f64) -> Option<f64> {
    (value.is_finite() && value >= 0.0).then_some(value)
}

fn project_events(
    connections: &[Connection],
    generation: u64,
    limits: TrafficThresholds,
    coverage: &mut Coverage,
    sample_interval_ms: Option<f64>,
) -> Vec<TrafficEvent> {
    let mut processes: BTreeMap<(u32, Option<u32>), ProcessRates<'_>> = BTreeMap::new();
    for connection in connections
        .iter()
        .filter(|connection| sample_interval_ms.is_some() || !connection.is_historic)
    {
        let Some(pid) = connection.pid else {
            coverage.unattributed_connections += 1;
            continue;
        };
        let rates = processes.entry((pid, connection.process_uid)).or_default();
        rates.connections.push(connection);
        if let Some(value) = usable_rate(connection.current_outgoing_rate_bps) {
            rates.upload += value;
        } else {
            rates.missing_upload_rates += 1;
            coverage.missing_upload_rates += 1;
        }
        if let Some(value) = usable_rate(connection.current_incoming_rate_bps) {
            rates.download += value;
        } else {
            rates.missing_download_rates += 1;
            coverage.missing_download_rates += 1;
        }
    }
    let mut events = Vec::new();
    for rates in processes.into_values() {
        if rates.upload <= limits.upload && rates.download <= limits.download {
            continue;
        }
        let Some(first) = rates.connections.first() else {
            continue;
        };
        // Projection happens only after a process crosses its own threshold.
        let process = ConnectionSnapshot::from_connection(first).process;
        let connections = rates
            .connections
            .iter()
            .map(|connection| {
                let mut connection = (*connection).clone();
                connection.current_outgoing_rate_bps =
                    usable_rate(connection.current_outgoing_rate_bps).unwrap_or(f64::NAN);
                connection.current_incoming_rate_bps =
                    usable_rate(connection.current_incoming_rate_bps).unwrap_or(f64::NAN);
                ConnectionSnapshot::from_connection(&connection)
            })
            .collect();
        events.push(TrafficEvent {
            schema_version: SCHEMA_VERSION,
            record_type: "process_traffic",
            timestamp: timestamp(SystemTime::now()),
            generation,
            process,
            upload_bytes_per_second: rates.upload,
            download_bytes_per_second: rates.download,
            upload_threshold_bytes_per_second: limits.upload,
            download_threshold_bytes_per_second: limits.download,
            upload_exceeded: rates.upload > limits.upload,
            download_exceeded: rates.download > limits.download,
            missing_upload_rates: rates.missing_upload_rates,
            missing_download_rates: rates.missing_download_rates,
            connections,
            sample_interval_ms,
            rate_basis: sample_interval_ms.map(|_| "interval_bytes"),
            sampling_mode: None,
        });
    }
    events
}

pub fn run_process_traffic<W: Write + Send + 'static>(
    app: &mut App,
    writer: W,
    options: &HeadlessOptions,
    limits: TrafficThresholds,
    cadence: TrafficCadence,
    shutdown_requested: &AtomicBool,
) -> Result<StopReport> {
    ensure!(
        usable_rate(limits.upload).is_some() && usable_rate(limits.download).is_some(),
        "invalid process traffic thresholds"
    );
    let mut output =
        match AsyncOutput::spawn_with_capacity(writer, app.event_output_queue_capacity()) {
            Ok(output) => output,
            Err(error) => {
                let _ = app.stop();
                return Err(error.into());
            }
        };
    let started = Instant::now();
    let poll = MAX_STOP_POLL_INTERVAL;
    let mut schedule = CadenceTracker::new(cadence);
    let mut sampler = IntervalSampler::default();
    let mut next_check = started;
    let mut checks = 0;
    let mut anomalies = 0;
    let mut coverage = Coverage::default();
    let mut resets = 0;
    let mut check_total = 0;
    let mut check_max = 0;
    let monitor = (|| -> Result<_> {
        loop {
            fail_if_runtime_unhealthy(app).map_err(|failure| failure.error)?;
            if let Some(exit) = output.poll()? {
                return Ok(exit);
            }
            let now = Instant::now();
            if now >= next_check {
                let sampling_mode = schedule.mode();
                let interval_before = schedule.interval();
                let work_started = Instant::now();
                let sample = sampler.sample(app, now, limits);
                coverage.unattributed_connections += sample.unattributed_connections;
                resets += sample.counter_resets;
                let mut events = project_events(
                    &sample.connections,
                    checks,
                    limits,
                    &mut coverage,
                    sample.elapsed_ms,
                );
                for event in &mut events {
                    event.sampling_mode = Some(sampling_mode);
                }
                schedule.observe(now, !events.is_empty());
                let elapsed_ns = work_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                check_total += elapsed_ns;
                check_max = check_max.max(elapsed_ns);
                checks += 1;
                let next_interval = schedule.interval();
                if interval_before != next_interval {
                    next_check = now + next_interval;
                } else {
                    next_check += next_interval;
                }
                if next_check <= now {
                    next_check = now + next_interval;
                }
                if !events.is_empty() {
                    let admitted = events.len() as u64;
                    output.offer_event(TrafficOutput::Events(events))?;
                    anomalies += admitted;
                }
            }
            if let Some(exit) = exit_reason(options.duration, shutdown_requested, started) {
                return Ok(exit);
            }
            thread::sleep(
                sleep_duration(options.duration, started, poll)
                    .min(next_check.saturating_duration_since(Instant::now())),
            );
        }
    })();
    let report = app.stop();
    let failure = runtime_failure(app).or_else(|| shutdown_failure(report));
    let failed = monitor.is_err() || failure.is_some();
    let reason = if let Some(failure) = &failure {
        Some(failure.kind.termination_reason())
    } else if let Ok(exit) = monitor.as_ref() {
        Some(TerminationReason::from_exit(*exit))
    } else {
        Some(TerminationReason::OutputFailed)
    };
    let summary = TrafficOutput::Summary(Box::new(TrafficSummary {
        schema_version: SCHEMA_VERSION,
        record_type: "process_traffic_summary",
        checks,
        anomaly_records: anomalies,
        unattributed_connections: coverage.unattributed_connections,
        missing_upload_rates: coverage.missing_upload_rates,
        missing_download_rates: coverage.missing_download_rates,
        traffic_interval_ms: cadence.normal.as_millis().min(u128::from(u64::MAX)) as u64,
        traffic_alert_interval_ms: cadence.alert.as_millis().min(u128::from(u64::MAX)) as u64,
        traffic_alert_cooldown_ms: cadence.cooldown.as_millis().min(u128::from(u64::MAX)) as u64,
        normal_checks: schedule.normal_checks,
        alert_checks: schedule.alert_checks,
        alert_activations: schedule.activations,
        alert_recoveries: schedule.recoveries,
        final_traffic_mode: schedule.mode(),
        counter_resets: resets,
        traffic_check_total_ns: check_total,
        traffic_check_max_ns: check_max,
        runtime: RuntimeSnapshot::new(
            app,
            app.snapshot_generation(),
            RuntimePhase::after_stop(report, failed),
            reason,
            Some(report),
        ),
        stats: StatsSnapshot::from_stats(&app.get_stats()),
    }));
    let flushed = output.finish_events(summary, app.output_shutdown_deadline());
    if let Err(error) = monitor {
        return match flushed {
            Ok(()) => Err(error),
            Err(flush) => Err(anyhow::anyhow!("{error:#}; output completion: {flush:#}")),
        };
    }
    flushed?;
    if let Some(failure) = failure {
        return Err(failure.error);
    }
    Ok(report)
}

#[cfg(test)]
fn detect(
    connections: &[Connection],
    generation: u64,
    limits: TrafficThresholds,
    coverage: &mut Coverage,
) -> Vec<TrafficEvent> {
    project_events(connections, generation, limits, coverage, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headless::OUTPUT_SHUTDOWN_DEADLINE;
    use crate::network::types::{Protocol, ProtocolState};

    fn fixed_cadence(ms: u64) -> TrafficCadence {
        TrafficCadence::new(
            std::time::Duration::from_millis(ms),
            std::time::Duration::from_millis(ms),
            std::time::Duration::from_secs(10),
        )
        .unwrap()
    }

    fn connection(pid: Option<u32>, upload: f64, download: f64) -> Connection {
        let mut value = Connection::new(
            Protocol::Udp,
            "127.0.0.1:50000".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
            ProtocolState::Udp,
        );
        value.pid = pid;
        value.process_uid = Some(501);
        value.process_name = Some("synthetic".into());
        value.current_outgoing_rate_bps = upload;
        value.current_incoming_rate_bps = download;
        value
    }

    #[test]
    fn processes_are_independent_and_directions_use_their_own_limits() {
        let limits = TrafficThresholds {
            upload: 5.0,
            download: 10.0,
        };
        let mut coverage = Coverage::default();
        assert!(
            detect(
                &[connection(Some(1), 4.0, 9.0), connection(Some(2), 4.0, 9.0)],
                1,
                limits,
                &mut coverage
            )
            .is_empty()
        );
        let events = detect(
            &[
                connection(Some(1), 4.0, 1.0),
                connection(Some(1), 2.0, 1.0),
                connection(Some(2), 1.0, 11.0),
            ],
            2,
            limits,
            &mut coverage,
        );
        assert_eq!(events.len(), 2);
        assert!(events[0].upload_exceeded && !events[0].download_exceeded);
        assert_eq!(events[0].upload_bytes_per_second, 6.0);
        assert!(!events[1].upload_exceeded && events[1].download_exceeded);
        assert_eq!(events[0].connections.len(), 2);
    }

    #[test]
    fn equal_threshold_archived_and_missing_facts_preserve_boundaries() {
        let limits = TrafficThresholds {
            upload: 5.0,
            download: 5.0,
        };
        let mut coverage = Coverage::default();
        let mut archived = connection(Some(1), 100.0, 100.0);
        archived.is_historic = true;
        assert!(
            detect(
                &[
                    archived,
                    connection(Some(1), 5.0, 5.0),
                    connection(None, 100.0, 100.0),
                    connection(Some(2), f64::NAN, -1.0)
                ],
                1,
                limits,
                &mut coverage
            )
            .is_empty()
        );
        assert_eq!(coverage.unattributed_connections, 1);
        assert_eq!(coverage.missing_upload_rates, 1);
        assert_eq!(coverage.missing_download_rates, 1);
        let events = detect(
            &[
                connection(Some(1), 5.001, 5.001),
                connection(Some(1), -1.0, f64::INFINITY),
            ],
            2,
            limits,
            &mut coverage,
        );
        assert_eq!(events.len(), 1);
        assert!(events[0].upload_exceeded && events[0].download_exceeded);
        let json = serde_json::to_value(&events).unwrap();
        assert!(json[0]["connections"][1]["traffic"]["outgoing_bytes_per_second"].is_null());
    }

    #[test]
    fn normal_run_only_emits_summary_and_checks_run_without_ui_publication() {
        use super::super::tests::{SharedWriter, app_with_connections};
        let mut app = app_with_connections();
        let writer = SharedWriter::default();
        let output = writer.clone();
        let shutdown = AtomicBool::new(true);
        let report = run_process_traffic(
            &mut app,
            writer,
            &HeadlessOptions::default(),
            TrafficThresholds {
                upload: 5.0,
                download: 5.0,
            },
            fixed_cadence(500),
            &shutdown,
        )
        .unwrap();
        assert_eq!(report.timed_out_workers, 0);
        assert_eq!(report.panicked_workers, 0);
        let rows: Vec<serde_json::Value> = String::from_utf8(output.bytes())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["type"], "process_traffic_summary");
        assert_eq!(rows[0]["anomaly_records"], 0);

        let mut app = app_with_connections();
        let writer = SharedWriter::default();
        let output = writer.clone();
        let report = run_process_traffic(
            &mut app,
            writer,
            &HeadlessOptions {
                duration: Some(std::time::Duration::from_millis(80)),
                ..HeadlessOptions::default()
            },
            TrafficThresholds {
                upload: 5.0,
                download: 5.0,
            },
            fixed_cadence(10),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.timed_out_workers, 0);
        let rows: Vec<serde_json::Value> = String::from_utf8(output.bytes())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 1);
        assert!(rows[0]["checks"].as_u64().unwrap() > 1);
        assert_eq!(rows[0]["traffic_interval_ms"], 10);
    }

    #[test]
    fn process_traffic_propagates_output_failures() {
        struct FailedWriter;
        impl Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("controlled output failure"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut app = super::super::tests::app_with_connections();
        app.set_connections_snapshot_for_test(vec![connection(Some(42), 6.0, 7.0)]);
        let result = run_process_traffic(
            &mut app,
            FailedWriter,
            &HeadlessOptions::default(),
            TrafficThresholds {
                upload: 5.0,
                download: 5.0,
            },
            fixed_cadence(500),
            &AtomicBool::new(true),
        );
        assert!(result.is_err());
    }

    #[test]
    fn event_backpressure_preserves_queued_records_and_fails_visibly() {
        use std::sync::mpsc;
        struct PausedWriter {
            entered: Option<mpsc::SyncSender<()>>,
            release: mpsc::Receiver<()>,
            output: super::super::tests::SharedWriter,
        }
        impl Write for PausedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if let Some(entered) = self.entered.take() {
                    entered.send(()).unwrap();
                    self.release.recv().unwrap();
                }
                self.output.write(bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (entered, seen) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::channel();
        let output = super::super::tests::SharedWriter::default();
        let mut writer = AsyncOutput::spawn(PausedWriter {
            entered: Some(entered),
            release: wait,
            output: output.clone(),
        })
        .unwrap();
        writer.offer_event(1).unwrap();
        seen.recv_timeout(OUTPUT_SHUTDOWN_DEADLINE).unwrap();
        writer.offer_event(2).unwrap();
        assert!(writer.offer_event(9).is_err());
        release.send(()).unwrap();
        writer.finish_events(3, OUTPUT_SHUTDOWN_DEADLINE).unwrap();
        assert_eq!(String::from_utf8(output.bytes()).unwrap(), "1\n2\n3\n");
    }
}
