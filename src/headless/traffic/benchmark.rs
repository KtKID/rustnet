//! Explicit, unprivileged benchmark of the production detector and output path.
//! Run through tests/benchmark_traffic_interval.py; ordinary tests skip this load.

use super::*;
use crate::app::Config;
use crate::network::types::{ConnectionKey, Protocol, ProtocolState};
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;

#[test]
#[ignore = "explicit timed benchmark with controlled counters and a real FIFO consumer"]
fn controlled_pipeline() {
    let interval: u64 = std::env::var("TRAFFIC_BENCH_INTERVAL_MS")
        .unwrap()
        .parse()
        .unwrap();
    let seconds: u64 = std::env::var("TRAFFIC_BENCH_SECONDS")
        .unwrap()
        .parse()
        .unwrap();
    let count: usize = std::env::var("TRAFFIC_BENCH_FLOWS")
        .unwrap()
        .parse()
        .unwrap();
    let process_count: usize = std::env::var("TRAFFIC_BENCH_PROCESSES")
        .unwrap()
        .parse()
        .unwrap();
    let scenario = std::env::var("TRAFFIC_BENCH_SCENARIO").unwrap();
    assert!(matches!(
        scenario.as_str(),
        "normal" | "upload" | "download" | "both"
    ));
    assert!(count > 0 && count <= 50_000 && process_count > 0 && count % process_count == 0);
    let mut app = App::new(Config {
        resolve_dns: false,
        refresh_interval: 1000,
        ..Config::default()
    })
    .unwrap();
    let tracker = app.traffic_tracker_for_test();
    let per_process = count / process_count;
    let mut inputs = Vec::new();
    for index in 0..count {
        let process_index = index % process_count;
        let mut connection = Connection::new(
            Protocol::Udp,
            format!("127.0.0.1:{}", 10_000 + index).parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            ProtocolState::Udp,
        );
        connection.pid = Some(10_000 + process_index as u32);
        connection.process_uid = Some(501);
        connection.process_name = Some(format!("bench-process-{process_index}"));
        connection.bytes_sent = 1_000_000;
        connection.bytes_received = 2_000_000;
        let key = ConnectionKey::from_connection(&connection);
        tracker.connections().insert(key, connection);
        let upload = if process_index == 0 && matches!(scenario.as_str(), "upload" | "both") {
            6_000_000
        } else {
            100_000
        };
        let download = if process_index == 0 && matches!(scenario.as_str(), "download" | "both") {
            6_000_000
        } else {
            100_000
        };
        inputs.push((
            key,
            upload / per_process as u64,
            download / per_process as u64,
        ));
    }
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(std::env::var("TRAFFIC_BENCH_FIFO").unwrap())
        .unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let producer_running = Arc::clone(&running);
    let producer = thread::spawn(move || {
        let started = Instant::now();
        while producer_running.load(Ordering::Relaxed) {
            let elapsed = started.elapsed().as_secs_f64();
            for (key, upload, download) in &inputs {
                let mut connection = tracker.connections().get_mut(key).unwrap();
                connection.bytes_sent = 1_000_000 + (elapsed * *upload as f64) as u64;
                connection.bytes_received = 2_000_000 + (elapsed * *download as f64) as u64;
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
    let started = Instant::now();
    let result = run_process_traffic(
        &mut app,
        writer,
        &HeadlessOptions {
            duration: Some(Duration::from_secs(seconds)),
            ..HeadlessOptions::default()
        },
        TrafficThresholds {
            upload: 5_000_000.0,
            download: 5_000_000.0,
        },
        TrafficCadence::new(
            Duration::from_millis(interval),
            Duration::from_millis(interval),
            Duration::from_secs(10),
        )
        .unwrap(),
        &AtomicBool::new(false),
    );
    let elapsed = started.elapsed().as_secs_f64();
    running.store(false, Ordering::Relaxed);
    producer.join().unwrap();
    let report = result.unwrap();
    assert_eq!(report.timed_out_workers, 0);
    assert_eq!(report.panicked_workers, 0);
    assert_eq!(app.snapshot_refresh_interval(), Duration::from_millis(1000));
    // stop() publishes one final snapshot, with the periodic UI worker absent.
    assert_eq!(app.snapshot_generation(), 1);
    std::fs::write(
        std::env::var("TRAFFIC_BENCH_RECEIPT").unwrap(),
        serde_json::to_vec_pretty(&serde_json::json!({
            "elapsed_seconds": elapsed, "connections": count, "processes": process_count,
        "producer_interval_ms": 10, "snapshot_interval_ms": 1000, "snapshot_generation_after_stop": app.snapshot_generation(),
            "scenario": scenario, "traffic_interval_ms": interval,
        }))
        .unwrap(),
    )
    .unwrap();
}
