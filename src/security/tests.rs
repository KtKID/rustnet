use super::{ingress::IngressTracker, journal::Journal, protocol::*};
use std::path::PathBuf;

fn config() -> IngressConfig {
    IngressConfig {
        attempt_result_wait_ms: 10000,
        attempt_idle_ms: 120000,
        scan_window_ms: 10000,
        scan_distinct_ports: 3,
        repeat_window_ms: 10000,
        repeat_attempts: 4,
        echo_window_ms: 10000,
        echo_requests: 4,
        access_aggregate_ms: 60000,
        correlation_window_ms: 300000,
        udp_reply_window_ms: 30000,
        focus_services: FocusServices {
            mode: "explicit".into(),
            endpoints: vec!["127.0.0.1:49161".parse().unwrap()],
        },
    }
}
fn tracker() -> IngressTracker {
    IngressTracker::new(
        config(),
        uuid::Uuid::new_v4().to_string(),
        "test-interface".into(),
        100,
    )
}
fn packet(port: u16, seq: u32) -> PacketFact {
    PacketFact {
        source: "192.0.2.2:42000".parse().unwrap(),
        target: format!("127.0.0.1:{port}").parse().unwrap(),
        source_local: false,
        target_local: true,
        protocol: "TCP".into(),
        interface: Some("test0".into()),
        seq,
        ack: 0,
        syn: true,
        ack_flag: false,
        rst: false,
        fin: false,
        payload_len: 0,
        bytes: 60,
        icmp_type: None,
        icmp_code: None,
        echo_id: None,
        echo_seq: None,
        quoted: None,
        pid: None,
        process_name: None,
    }
}
fn time(ms: u64) -> String {
    (chrono::DateTime::parse_from_rfc3339("2026-10-30T00:00:00.000+08:00").unwrap()
        + chrono::Duration::milliseconds(ms as i64))
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, false)
}
fn feed(t: &mut IngressTracker, p: PacketFact, ms: u64) -> Vec<Item> {
    t.observe(p, ms, time(ms))
}
fn evidence(items: &[Item]) -> Vec<&Evidence> {
    items
        .iter()
        .filter_map(|i| {
            if let Item::Observation(e) = i {
                Some(e.as_ref())
            } else {
                None
            }
        })
        .collect()
}
fn incidents(items: &[Item]) -> Vec<&Incident> {
    items
        .iter()
        .filter_map(|i| {
            if let Item::IncidentRevision(e) = i {
                Some(e.as_ref())
            } else {
                None
            }
        })
        .collect()
}
fn handshake(t: &mut IngressTracker, port: u16, x: u32, ms: u64) -> Vec<Item> {
    let p = packet(port, x);
    let mut out = feed(t, p.clone(), ms);
    let mut reply = p.clone();
    reply.source = p.target;
    reply.target = p.source;
    reply.source_local = true;
    reply.target_local = false;
    reply.ack_flag = true;
    reply.seq = 300;
    reply.ack = x.wrapping_add(1);
    out.extend(feed(t, reply, ms + 1));
    let mut ack = p;
    ack.syn = false;
    ack.ack_flag = true;
    ack.seq = x.wrapping_add(1);
    ack.ack = 301;
    out.extend(feed(t, ack, ms + 2));
    out
}
fn root() -> PathBuf {
    let p = std::env::temp_dir().join(format!("security-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&p).unwrap();
    p
}
fn storage() -> StorageConfig {
    StorageConfig {
        segment_bytes: 33554432,
        max_record_bytes: 8388608,
    }
}
#[test]
fn ing_t01_tiny_closed_port_and_unknown_owner_are_preserved() {
    let out = feed(&mut tracker(), packet(49162, 100), 0);
    let e = evidence(&out);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].source.ip().to_string(), "192.0.2.2");
    assert_eq!(e[0].target.port(), 49162);
    assert_eq!(e[0].pid, None);
    assert_eq!(e[0].result, "attempt_observed");
    assert_eq!(e[0].interface.as_deref(), Some("test0"));
}

#[test]
fn ing_busy_input_still_expires_attempt_result_window() {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    let root = root();
    let mut config = security_config();
    config.ingress.attempt_result_wait_ms = 10;
    config.runtime.tick_ms = 20;
    let runtime = super::SecurityRuntime::start(
        &root,
        config,
        uuid::Uuid::new_v4().to_string(),
        "busy-input".into(),
        Arc::new(|message| panic!("unexpected failure {message}")),
    )
    .unwrap();
    runtime.sink.observe(packet(49162, 99));
    let mut noise = packet(443, 1);
    noise.protocol = "UDP".into();
    std::mem::swap(&mut noise.source, &mut noise.target);
    noise.source_local = true;
    noise.target_local = false;
    noise.syn = false;
    let until = Instant::now() + Duration::from_millis(100);
    while Instant::now() < until {
        runtime.sink.observe(noise.clone());
    }
    runtime.finish().unwrap();
    let expired = Journal::replay(&root).unwrap().into_iter().any(|batch| {
        batch.items.into_iter().any(|item| {
            matches!(item, Item::Observation(e) if e.result == "establishment_unobserved_in_window")
        })
    });
    assert!(
        expired,
        "a busy input queue must still advance result windows"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn ing_delayed_processing_keeps_the_original_capture_window() {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    let root = root();
    let mut config = security_config();
    config.ingress.scan_window_ms = 10;
    config.runtime.tick_ms = 1000;
    let runtime = super::SecurityRuntime::start(
        &root,
        config,
        uuid::Uuid::new_v4().to_string(),
        "delayed-input".into(),
        Arc::new(|message| panic!("unexpected failure {message}")),
    )
    .unwrap();
    let captured = SystemTime::now();
    for (index, port) in [49161, 49162, 49163].into_iter().enumerate() {
        runtime.sink.observe_captured(
            packet(port, index as u32),
            captured + Duration::from_millis(index as u64),
        );
        std::thread::sleep(Duration::from_millis(30));
    }
    runtime.finish().unwrap();
    let probe = Journal::replay(&root).unwrap().into_iter().any(|batch| {
        batch.items.into_iter().any(|item| {
            matches!(item, Item::IncidentRevision(e) if e.kind == "port_probe_suspected" && e.target_ports.len() == 3)
        })
    });
    assert!(
        probe,
        "processing delay must preserve the captured scan interval"
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn ing_t02_only_full_matching_handshake_establishes_access() {
    let mut t = tracker();
    let out = handshake(&mut t, 49161, 100, 0);
    assert!(
        evidence(&out)
            .iter()
            .any(|e| e.result == "established" && e.result_evidence_ids.len() == 3)
    );
    assert!(
        incidents(&out)
            .iter()
            .any(|e| e.kind == "external_access_review")
    );
}
#[test]
fn ing_t02_partial_and_wrong_ack_do_not_establish() {
    let mut t = tracker();
    let mut p = packet(49161, 101);
    p.syn = false;
    p.ack_flag = true;
    p.ack = 301;
    let out = feed(&mut t, p, 0);
    assert_eq!(evidence(&out)[0].initiator, "unknown");
    assert!(incidents(&out).is_empty());
}
#[test]
fn ing_t02_outbound_return_and_forwarded_packets_are_not_inbound() {
    let mut t = tracker();
    let mut p = packet(49161, 100);
    p.source_local = true;
    p.target_local = false;
    let mut out = feed(&mut t, p.clone(), 0);
    std::mem::swap(&mut p.source, &mut p.target);
    p.source_local = false;
    p.target_local = true;
    p.ack_flag = true;
    p.ack = 101;
    p.seq = 300;
    out.extend(feed(&mut t, p, 1));
    assert!(incidents(&out).is_empty());
    assert_eq!(evidence(&out)[0].initiator, "outbound");
    let mut p = packet(55, 1);
    p.target_local = false;
    assert_eq!(evidence(&feed(&mut t, p, 2))[0].initiator, "forwarded");
}
#[test]
fn ing_t03_refusal_timeout_and_late_evidence_keep_history() {
    let mut t = tracker();
    feed(&mut t, packet(49162, 100), 0);
    let mut r = packet(49162, 0);
    std::mem::swap(&mut r.source, &mut r.target);
    r.source_local = true;
    r.target_local = false;
    r.syn = false;
    r.rst = true;
    r.ack_flag = true;
    r.ack = 101;
    assert_eq!(
        evidence(&feed(&mut t, r, 1))[0].result,
        "local_rejection_observed"
    );
    feed(&mut t, packet(49161, 500), 20);
    let out = t.advance(10021, time(10021));
    assert!(
        evidence(&out)
            .iter()
            .any(|e| e.result == "establishment_unobserved_in_window")
    );
    let out = handshake(&mut t, 49161, 500, 10030);
    assert!(evidence(&out).iter().any(|e| e.result == "established"));
}
#[test]
fn ing_t03_reset_after_establishment_is_termination() {
    let mut t = tracker();
    handshake(&mut t, 49161, 100, 0);
    let mut r = packet(49161, 101);
    r.syn = false;
    r.rst = true;
    let out = feed(&mut t, r, 10);
    assert_eq!(evidence(&out)[0].result, "reset_after_established");
}
#[test]
fn ing_t04_distinct_ports_and_retransmissions() {
    let mut t = tracker();
    let a = feed(&mut t, packet(49161, 100), 0);
    let id = evidence(&a)[0].attempt_id.clone();
    let b = feed(&mut t, packet(49161, 100), 1);
    assert_eq!(evidence(&b)[0].attempt_id, id);
    assert_eq!(evidence(&b)[0].retransmit_count, 1);
    assert!(incidents(&b).is_empty());
    feed(&mut t, packet(49162, 200), 2);
    let c = feed(&mut t, packet(49163, 300), 3);
    let events = incidents(&c);
    let scan = events
        .iter()
        .find(|i| i.kind == "port_probe_suspected")
        .unwrap();
    assert_eq!(scan.target_ports, vec![49161, 49162, 49163]);
    assert_eq!(scan.count, 3);
    let later = feed(&mut t, packet(49164, 400), 10001);
    let later_events = incidents(&later);
    let later_scan = later_events
        .iter()
        .find(|i| i.kind == "port_probe_suspected")
        .unwrap();
    assert_eq!(later_scan.count, later_scan.target_ports.len());
}
#[test]
fn ing_t05_independent_same_tuple_attempts_and_normal_control() {
    let mut t = tracker();
    let mut ids = Vec::new();
    let mut out = Vec::new();
    for n in 0..4 {
        let x = feed(&mut t, packet(49161, 100 + n), u64::from(n));
        ids.push(evidence(&x)[0].connection_id.clone());
        out.extend(x);
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 4);
    let es = incidents(&out);
    assert_eq!(
        es.iter()
            .find(|i| i.kind == "repeated_access_review")
            .unwrap()
            .count,
        4
    );
}
#[test]
fn ing_t06_access_aggregates_and_window_creates_new_incident() {
    let mut t = tracker();
    let a = handshake(&mut t, 49161, 100, 0);
    let id = incidents(&a)[0].incident_id.clone();
    let b = handshake(&mut t, 49161, 200, 20);
    let es = incidents(&b);
    let b = es
        .iter()
        .find(|i| i.kind == "external_access_review")
        .unwrap();
    assert_eq!(b.incident_id, id);
    assert_eq!(b.count, 2);
    let c = handshake(&mut t, 49161, 300, 60010);
    assert_ne!(
        incidents(&c)
            .iter()
            .find(|i| i.kind == "external_access_review")
            .unwrap()
            .incident_id,
        id
    );
}
#[test]
fn ing_t07_probe_then_connected_has_both_evidence_sides() {
    let mut t = tracker();
    feed(&mut t, packet(49161, 100), 0);
    feed(&mut t, packet(49162, 200), 1);
    feed(&mut t, packet(49163, 300), 2);
    let out = handshake(&mut t, 49161, 400, 10);
    let es = incidents(&out);
    let related = es
        .iter()
        .find(|i| i.kind == "probe_then_connected")
        .unwrap();
    assert!(!related.related_incident_ids.is_empty());
    assert!(related.evidence_ids.len() >= 4);
}
#[test]
fn ing_t09_udp_echo_and_normal_outbound_reply() {
    let mut t = tracker();
    for port in 1..=3 {
        let mut p = packet(port, 0);
        p.protocol = "UDP".into();
        p.syn = false;
        let out = feed(&mut t, p, u64::from(port));
        if port == 3 {
            assert!(
                incidents(&out)
                    .iter()
                    .any(|i| i.kind == "datagram_probe_review")
            );
        }
    }
    let mut all = Vec::new();
    for n in 0..4 {
        let mut p = packet(0, 0);
        p.protocol = "ICMP".into();
        p.syn = false;
        p.icmp_type = Some(8);
        p.echo_id = Some(5);
        p.echo_seq = Some(n);
        all.extend(feed(&mut t, p, 20 + u64::from(n)));
    }
    assert!(
        incidents(&all)
            .iter()
            .any(|i| i.kind == "echo_probe_review")
    );
}
#[test]
fn ing_t10_journal_reloads_committed_facts_and_rotates() {
    let root = root();
    let mut j = Journal::open(
        &root,
        "run-a".into(),
        StorageConfig {
            segment_bytes: 900,
            max_record_bytes: 8388608,
        },
    )
    .unwrap();
    let input = feed(&mut tracker(), packet(49162, 100), 0);
    assert_eq!(j.commit(input.clone()).unwrap().committed_seq, "1");
    j.commit(input).unwrap();
    drop(j);
    let before = Journal::replay(&root).unwrap();
    assert_eq!(before.len(), 2);
    let mut j = Journal::open(&root, "run-b".into(), storage()).unwrap();
    let w = j
        .commit(vec![Item::RunLifecycle(Lifecycle {
            run_id: "run-b".into(),
            observed_at: time(20),
            reason: "test".into(),
        })])
        .unwrap();
    assert_eq!(w.committed_seq, "3");
    assert_eq!(Journal::replay(&root).unwrap().len(), 3);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn ing_t10_occupied_and_corrupt_storage_fail_visibly() {
    let root = root();
    std::fs::write(root.join("journal"), b"occupied").unwrap();
    assert!(Journal::open(&root, "run".into(), storage()).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

fn security_config() -> SecurityConfig {
    SecurityConfig {
        enabled: true,
        ingress: config(),
        runtime: RuntimeConfig {
            queue_capacity: 4096,
            active_attempt_limit: 50000,
            tick_ms: 10,
            commit_interval_ms: 20,
        },
        storage: storage(),
    }
}
fn tcp_bytes(
    source: [u8; 4],
    target: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let mut b = vec![0u8; 54];
    b[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    b[14] = 0x45;
    b[16..18].copy_from_slice(&40u16.to_be_bytes());
    b[22] = 64;
    b[23] = 6;
    b[26..30].copy_from_slice(&source);
    b[30..34].copy_from_slice(&target);
    b[34..36].copy_from_slice(&sport.to_be_bytes());
    b[36..38].copy_from_slice(&dport.to_be_bytes());
    b[38..42].copy_from_slice(&seq.to_be_bytes());
    b[42..46].copy_from_slice(&ack.to_be_bytes());
    b[46] = 0x50;
    b[47] = flags;
    b
}
#[test]
fn ing_component_smoke_real_parser_rules_journal_and_restart() {
    use super::SecurityRuntime;
    use crate::network::parser::PacketParser;
    use std::sync::Arc;
    let root = root();
    let run = uuid::Uuid::new_v4().to_string();
    let runtime = SecurityRuntime::start(
        &root,
        security_config(),
        run,
        "test0".into(),
        Arc::new(|m| panic!("unexpected diagnostic {m}")),
    )
    .unwrap();
    let parser = PacketParser::new().with_linktype(1);
    for (index, port) in [49161, 49162, 49163].iter().enumerate() {
        let raw = tcp_bytes(
            [192, 0, 2, 2],
            [127, 0, 0, 1],
            42000,
            *port,
            100 + index as u32,
            0,
            2,
        );
        let parsed = parser.parse_packet(&raw).unwrap();
        runtime.sink.observe(
            PacketFact::from_parsed(&parsed, Some("fixture-interface".into()))
                .expect("parser security metadata"),
        );
    }
    runtime.finish().unwrap();
    let batches = Journal::replay(&root).unwrap();
    let mut observations = 0;
    let mut probes = 0;
    for batch in &batches {
        for item in &batch.items {
            match item {
                Item::Observation(_) => observations += 1,
                Item::IncidentRevision(e) if e.kind == "port_probe_suspected" => probes += 1,
                _ => {}
            }
        }
    }
    assert!(observations >= 3);
    assert_eq!(probes, 1);
    let prior = batches.len();
    let runtime = SecurityRuntime::start(
        &root,
        security_config(),
        uuid::Uuid::new_v4().to_string(),
        "test0".into(),
        Arc::new(|m| panic!("{m}")),
    )
    .unwrap();
    runtime.finish().unwrap();
    assert!(Journal::replay(&root).unwrap().len() > prior);
    if let Ok(path) = std::env::var("X_SECURITY_FIXTURE") {
        std::fs::write(
            path,
            serde_json::to_string(&Journal::replay(&root).unwrap()).unwrap(),
        )
        .unwrap();
    }
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn ing_t11_queue_loss_is_visible_and_storage_error_propagates() {
    use super::SecurityRuntime;
    use std::sync::Arc;
    let root = root();
    let mut cfg = security_config();
    cfg.runtime.queue_capacity = 1;
    let runtime = SecurityRuntime::start(
        &root,
        cfg,
        uuid::Uuid::new_v4().to_string(),
        "test0".into(),
        Arc::new(|_| {}),
    )
    .unwrap();
    for x in 0..10000 {
        runtime.sink.observe(packet(49161, x));
    }
    runtime.finish().unwrap();
    let batches = Journal::replay(&root).unwrap();
    assert!(
        batches
            .iter()
            .flat_map(|b| &b.items)
            .any(|i| matches!(i,Item::HealthObservation(h) if h.lost_records!="0"))
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn ing_t10_corrupt_tail_is_preserved_and_rejected() {
    let root = root();
    std::fs::create_dir(root.join("journal")).unwrap();
    let path = root.join("journal/segment-000001.jsonl");
    std::fs::write(&path, b"{broken").unwrap();
    assert!(Journal::replay(&root).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"{broken");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn ing_t04_probe_first_time_and_threshold_boundary_are_exact() {
    let mut t = tracker();
    feed(&mut t, packet(49161, 1), 0);
    assert!(incidents(&feed(&mut t, packet(49162, 2), 1)).is_empty());
    let out = feed(&mut t, packet(49163, 3), 2);
    let es = incidents(&out);
    let i = es
        .iter()
        .find(|i| i.kind == "port_probe_suspected")
        .unwrap();
    assert_eq!(i.first_observed_at, time(0));
    assert_eq!(i.last_observed_at, time(2));
}
#[test]
fn ing_t09_echo_reply_is_linked_to_request() {
    let mut t = tracker();
    let mut p = packet(0, 0);
    p.syn = false;
    p.protocol = "ICMP".into();
    p.echo_id = Some(8);
    p.echo_seq = Some(2);
    p.icmp_type = Some(8);
    let a = feed(&mut t, p.clone(), 0);
    let eid = evidence(&a)[0].evidence_id.clone();
    let cid = evidence(&a)[0].connection_id.clone();
    std::mem::swap(&mut p.source, &mut p.target);
    p.source_local = true;
    p.target_local = false;
    p.icmp_type = Some(0);
    let b = feed(&mut t, p, 1);
    assert_eq!(evidence(&b)[0].connection_id, cid);
    assert!(evidence(&b)[0].result_evidence_ids.contains(&eid));
}
#[test]
fn ing_t02_wrong_final_ack_and_sequence_wrap() {
    let mut t = tracker();
    let p = packet(49161, 100);
    feed(&mut t, p.clone(), 0);
    let mut q = p.clone();
    std::mem::swap(&mut q.source, &mut q.target);
    q.source_local = true;
    q.target_local = false;
    q.seq = 300;
    q.ack = 101;
    q.ack_flag = true;
    feed(&mut t, q, 1);
    let mut ack = p;
    ack.syn = false;
    ack.ack_flag = true;
    ack.seq = 101;
    ack.ack = 999;
    assert!(incidents(&feed(&mut t, ack, 2)).is_empty());
    let out = handshake(&mut t, 49161, u32::MAX, 10);
    assert!(evidence(&out).iter().any(|e| e.result == "established"));
}
#[test]
fn ing_t09_normal_udp_outbound_reply_keeps_outbound_role() {
    let mut t = tracker();
    let mut p = packet(53, 0);
    p.protocol = "UDP".into();
    p.syn = false;
    p.source_local = true;
    p.target_local = false;
    let first = feed(&mut t, p.clone(), 0);
    let cid = evidence(&first)[0].connection_id.clone();
    std::mem::swap(&mut p.source, &mut p.target);
    p.source_local = false;
    p.target_local = true;
    let out = feed(&mut t, p, 1);
    assert!(incidents(&out).is_empty());
    assert_eq!(evidence(&out)[0].initiator, "outbound");
    assert_eq!(evidence(&out)[0].result, "reply_observed");
    assert_eq!(evidence(&out)[0].connection_id, cid);
}
#[test]
fn ing_t10_symlink_and_oversize_output_fail_without_overwrite() {
    use std::os::unix::fs::symlink;
    let root = root();
    let other = root.join("outside");
    std::fs::write(&other, b"preserve").unwrap();
    std::fs::create_dir(root.join("journal")).unwrap();
    symlink(&other, root.join("journal/segment-000001.jsonl")).unwrap();
    assert!(Journal::open(&root, "run".into(), storage()).is_err());
    assert_eq!(std::fs::read(other).unwrap(), b"preserve");
    std::fs::remove_dir_all(&root).unwrap();
    let root = std::env::temp_dir().join(format!("security-size-{}", uuid::Uuid::new_v4()));
    let mut j = Journal::open(
        &root,
        "run".into(),
        StorageConfig {
            segment_bytes: 33554432,
            max_record_bytes: 10,
        },
    )
    .unwrap();
    assert!(
        j.commit(feed(&mut tracker(), packet(49162, 100), 0))
            .is_err()
    );
    let w: Watermark =
        serde_json::from_slice(&std::fs::read(root.join("committed.json")).unwrap()).unwrap();
    assert_eq!(w.committed_seq, "0");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn ing_t01_visible_source_categories_and_ipv6_are_preserved() {
    let mut t = tracker();
    let mut p = packet(49161, 1);
    p.source = "10.2.3.4:40000".parse().unwrap();
    let out = feed(&mut t, p, 0);
    assert_eq!(evidence(&out)[0].source_category, "private");
    let mut p = packet(49162, 2);
    p.source = "[2001:db8::2]:40000".parse().unwrap();
    p.target = "[::1]:49162".parse().unwrap();
    let out = feed(&mut t, p, 1);
    assert_eq!(evidence(&out)[0].source_category, "unknown");
    assert!(evidence(&out)[0].source.is_ipv6());
}
#[test]
fn ing_t11_window_capacity_keeps_gap_evidence() {
    let mut t = IngressTracker::new(config(), uuid::Uuid::new_v4().to_string(), "test".into(), 2);
    for n in 0..2 {
        let mut p = packet(n + 1, 0);
        p.protocol = "UDP".into();
        feed(&mut t, p, u64::from(n));
    }
    let mut p = packet(3, 0);
    p.protocol = "UDP".into();
    let out = feed(&mut t, p, 3);
    assert!(out.iter().any(|x| matches!(x, Item::HealthObservation(_))));
}

#[test]
fn ing_t10_journal_excludes_a_second_writer() {
    let root = root();
    let a = Journal::open(&root, "run-a".into(), storage()).unwrap();
    assert!(Journal::open(&root, "run-b".into(), storage()).is_err());
    drop(a);
    assert!(Journal::open(&root, "run-c".into(), storage()).is_ok());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn ing_t09_time_exceeded_is_distinct_from_destination_unreachable() {
    let mut t = tracker();
    let mut p = packet(0, 0);
    p.protocol = "ICMP".into();
    p.syn = false;
    p.icmp_type = Some(11);
    p.quoted = Some((
        "127.0.0.1:53".parse().unwrap(),
        "192.0.2.2:2000".parse().unwrap(),
    ));
    let out = feed(&mut t, p, 0);
    assert_eq!(evidence(&out)[0].result, "icmp_error_observed");
}

#[test]
fn ing_t09_local_udp_response_keeps_inbound_connection_identity() {
    let mut t = tracker();
    let mut p = packet(49161, 0);
    p.protocol = "UDP".into();
    p.syn = false;
    let a = feed(&mut t, p.clone(), 0);
    let cid = evidence(&a)[0].connection_id.clone();
    std::mem::swap(&mut p.source, &mut p.target);
    p.source_local = true;
    p.target_local = false;
    let out = feed(&mut t, p, 1);
    assert_eq!(evidence(&out)[0].result, "reply_observed");
    assert_eq!(evidence(&out)[0].initiator, "inbound");
    assert_eq!(evidence(&out)[0].connection_id, cid);
}

#[test]
fn ing_t08_both_storage_modes_keep_low_traffic_collector_evidence() {
    use super::SecurityRuntime;
    use std::sync::Arc;
    let text = include_str!("../../../collector.yaml");
    let mut results = Vec::new();
    for mode in ["anomalies", "full"] {
        let text = text.replace("mode: anomalies", &format!("mode: {mode}"));
        let cfg = crate::collector::config::parse(&text).unwrap();
        let mut security = cfg.security.unwrap();
        security.ingress.focus_services = config().focus_services;
        let root = root();
        let runtime = SecurityRuntime::start(
            &root,
            security,
            uuid::Uuid::new_v4().to_string(),
            "test".into(),
            Arc::new(|m| panic!("{m}")),
        )
        .unwrap();
        for port in 49161..=49163 {
            runtime.sink.observe(packet(port, u32::from(port)));
        }
        runtime.finish().unwrap();
        let batches = Journal::replay(&root).unwrap();
        let kinds: Vec<_> = batches
            .iter()
            .flat_map(|b| &b.items)
            .filter_map(|i| {
                if let Item::IncidentRevision(e) = i {
                    Some(e.kind.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(kinds, vec!["port_probe_suspected"]);
        results.push(kinds);
        std::fs::remove_dir_all(root).unwrap();
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn ing_t10_runtime_reports_persistence_failure_and_keeps_watermark() {
    use super::SecurityRuntime;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let root = root();
    let mut cfg = security_config();
    cfg.storage.max_record_bytes = 1024;
    let errors = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&errors);
    let runtime = SecurityRuntime::start(
        &root,
        cfg,
        uuid::Uuid::new_v4().to_string(),
        "test".into(),
        Arc::new(move |_| {
            seen.fetch_add(1, Ordering::Relaxed);
        }),
    )
    .unwrap();
    for port in 49161..=49163 {
        runtime.sink.observe(packet(port, u32::from(port)));
    }
    assert!(runtime.finish().is_err());
    assert_eq!(errors.load(Ordering::Relaxed), 1);
    let value: Watermark =
        serde_json::from_slice(&std::fs::read(root.join("committed.json")).unwrap()).unwrap();
    assert_eq!(value.committed_seq, "1");
    std::fs::remove_dir_all(root).unwrap();
}
