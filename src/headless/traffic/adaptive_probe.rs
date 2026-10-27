//! Ordinary-user controlled input, with the real detector and FIFO writer.
use super::*;
use crate::app::Config;
use crate::network::types::{ConnectionKey, Protocol, ProtocolState};
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;

#[test]
#[ignore = "explicit adaptive traffic pipeline verification"]
fn controlled_adaptive_pipeline() {
    let number = |name: &str| std::env::var(name).unwrap().parse::<u64>().unwrap();
    let normal = number("ALERT_PROBE_NORMAL_MS");
    let alert = number("ALERT_PROBE_ALERT_MS");
    let cooldown = number("ALERT_PROBE_COOLDOWN_MS");
    let duration = number("ALERT_PROBE_DURATION_MS");
    let scenario = std::env::var("ALERT_PROBE_SCENARIO").unwrap();
    let windows: Vec<(f64, f64)> = match scenario.as_str() {
        "normal" => vec![],
        "default-upload" | "stop-alert" => vec![(0.6, 1.8)],
        "download-reentry" | "both-reentry" | "equal" => vec![(0.2, 0.6), (1.2, 1.6)],
        _ => panic!("unknown controlled scenario"),
    };
    let upload = matches!(
        scenario.as_str(),
        "default-upload" | "stop-alert" | "both-reentry" | "equal"
    );
    let download = matches!(scenario.as_str(), "download-reentry" | "both-reentry");
    let mut app = App::new(Config {
        resolve_dns: false,
        refresh_interval: 1000,
        ..Config::default()
    })
    .unwrap();
    let tracker = app.traffic_tracker_for_test();
    let mut inputs = Vec::new();
    for index in 0..4 {
        let mut flow = Connection::new(
            Protocol::Udp,
            format!("127.0.0.1:{}", 20_000 + index).parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            ProtocolState::Udp,
        );
        flow.pid = Some(10_000 + index % 2);
        flow.process_uid = Some(501);
        flow.process_name = Some(format!("controlled-process-{}", index % 2));
        flow.bytes_sent = 1_000_000_000;
        flow.bytes_received = 2_000_000_000;
        let key = ConnectionKey::from_connection(&flow);
        tracker.connections().insert(key, flow);
        inputs.push((key, index % 2 == 0));
    }
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(std::env::var("ALERT_PROBE_FIFO").unwrap())
        .unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let producer_running = Arc::clone(&running);
    let producer = thread::spawn(move || {
        let started = Instant::now();
        while producer_running.load(Ordering::Relaxed) {
            let elapsed = started.elapsed().as_secs_f64();
            let hot_seconds: f64 = windows
                .iter()
                .map(|(start, end)| (elapsed - start).clamp(0.0, end - start))
                .sum();
            for (key, target) in &inputs {
                let ordinary = (elapsed * 2_000_000.0) as u64;
                let extra = if *target {
                    (hot_seconds * 5_000_000.0) as u64
                } else {
                    0
                };
                let mut flow = tracker.connections().get_mut(key).unwrap();
                flow.bytes_sent = 1_000_000_000 + ordinary + if upload { extra } else { 0 };
                flow.bytes_received = 2_000_000_000 + ordinary + if download { extra } else { 0 };
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    let started = Instant::now();
    let result = run_process_traffic(
        &mut app,
        writer,
        &HeadlessOptions {
            duration: Some(Duration::from_millis(duration)),
            ..HeadlessOptions::default()
        },
        TrafficThresholds {
            upload: 5_000_000.0,
            download: 5_000_000.0,
        },
        TrafficCadence::new(
            Duration::from_millis(normal),
            Duration::from_millis(alert),
            Duration::from_millis(cooldown),
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
    assert_eq!(app.snapshot_generation(), 1);
    std::fs::write(
        std::env::var("ALERT_PROBE_RECEIPT").unwrap(),
        serde_json::to_vec_pretty(
            &serde_json::json!({ "scenario": scenario, "elapsed_seconds": elapsed,
            "snapshot_refresh_interval_ms": 1000, "final_snapshot_generation": 1,
            "producer_interval_ms": 5, "connections": 4, "processes": 2 }),
        )
        .unwrap(),
    )
    .unwrap();
}
