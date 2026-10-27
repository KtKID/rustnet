use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Instant, SystemTime};

use crate::app::App;
use crate::network::types::{Connection, ConnectionKey};

use super::TrafficThresholds;

type FlowId = (ConnectionKey, SystemTime);
type ProcessId = (u32, Option<u32>);

#[derive(Clone, Copy)]
struct Counters {
    sent: u64,
    received: u64,
    pid: Option<u32>,
    uid: Option<u32>,
}

#[derive(Default)]
pub(super) struct IntervalSampler {
    previous: HashMap<FlowId, Counters>,
    sampled_at: Option<Instant>,
}

#[derive(Default)]
pub(super) struct IntervalSample {
    pub connections: Vec<Connection>,
    pub elapsed_ms: Option<f64>,
    pub unattributed_connections: u64,
    pub counter_resets: u64,
}

fn identity(connection: &Connection) -> FlowId {
    (
        ConnectionKey::from_connection(connection),
        connection.created_at,
    )
}

impl IntervalSampler {
    pub(super) fn sample(
        &mut self,
        app: &App,
        now: Instant,
        limits: TrafficThresholds,
    ) -> IntervalSample {
        if self.sampled_at.is_some_and(|previous| now <= previous) {
            return IntervalSample::default();
        }
        let mut current: HashMap<FlowId, Counters> = HashMap::with_capacity(self.previous.len());
        app.visit_traffic_connections(|connection| {
            let entry = current.entry(identity(connection)).or_insert(Counters {
                sent: connection.bytes_sent,
                received: connection.bytes_received,
                pid: connection.pid,
                uid: connection.process_uid,
            });
            // A flow can move between the active and historic tables during a
            // visit. Keep its final counters exactly once.
            entry.sent = entry.sent.max(connection.bytes_sent);
            entry.received = entry.received.max(connection.bytes_received);
            if connection.pid.is_some() {
                entry.pid = connection.pid;
                entry.uid = connection.process_uid;
            }
        });
        let Some(previous_time) = self.sampled_at.replace(now) else {
            self.previous = current;
            return IntervalSample::default();
        };
        let elapsed = now.duration_since(previous_time).as_secs_f64();
        let mut sample = IntervalSample {
            elapsed_ms: Some(elapsed * 1000.0),
            ..IntervalSample::default()
        };
        let mut rates: HashMap<FlowId, (f64, f64)> = HashMap::with_capacity(current.len());
        let mut processes: BTreeMap<ProcessId, (f64, f64)> = BTreeMap::new();
        for (flow, counters) in &current {
            let previous = self.previous.get(flow);
            let sent = previous.map_or(counters.sent, |old| {
                if counters.sent < old.sent {
                    sample.counter_resets += 1;
                }
                counters.sent.saturating_sub(old.sent)
            });
            let received = previous.map_or(counters.received, |old| {
                if counters.received < old.received {
                    sample.counter_resets += 1;
                }
                counters.received.saturating_sub(old.received)
            });
            let Some(pid) = counters.pid else {
                sample.unattributed_connections += 1;
                continue;
            };
            let rate = (sent as f64 / elapsed, received as f64 / elapsed);
            rates.insert(*flow, rate);
            let process = processes.entry((pid, counters.uid)).or_default();
            process.0 += rate.0;
            process.1 += rate.1;
        }
        self.previous = current;
        let hot: HashSet<_> = processes
            .into_iter()
            .filter_map(|(pid, (upload, download))| {
                (upload > limits.upload || download > limits.download).then_some(pid)
            })
            .collect();
        if hot.is_empty() {
            return sample;
        }
        let mut observed = HashSet::new();
        app.visit_traffic_connections(|connection| {
            let Some(pid) = connection.pid else { return };
            let flow = identity(connection);
            if !hot.contains(&(pid, connection.process_uid)) {
                return;
            }
            let Some(&(upload, download)) = rates.get(&flow) else {
                return;
            };
            if connection.is_historic && upload == 0.0 && download == 0.0 {
                return;
            }
            if !observed.insert(flow) {
                return;
            }
            let mut snapshot = connection.snapshot_clone();
            if let Some(counters) = self.previous.get(&flow) {
                snapshot.bytes_sent = counters.sent;
                snapshot.bytes_received = counters.received;
            }
            snapshot.current_outgoing_rate_bps = upload;
            snapshot.current_incoming_rate_bps = download;
            sample.connections.push(snapshot);
        });
        sample
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Config;
    use crate::network::tracker::HistoricKey;
    use crate::network::types::{Protocol, ProtocolState};
    use std::time::Duration;

    fn app() -> App {
        App::new(Config {
            resolve_dns: false,
            refresh_interval: 1000,
            ..Config::default()
        })
        .unwrap()
    }
    fn flow(pid: Option<u32>, sent: u64, received: u64) -> Connection {
        let mut value = Connection::new(
            Protocol::Udp,
            "127.0.0.1:40000".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
            ProtocolState::Udp,
        );
        value.pid = pid;
        value.process_uid = Some(501);
        value.bytes_sent = sent;
        value.bytes_received = received;
        value.current_outgoing_rate_bps = f64::INFINITY;
        value
    }
    fn put(app: &App, connection: Connection) {
        let tracker = app.traffic_tracker_for_test();
        let key = ConnectionKey::from_connection(&connection);
        if connection.is_historic {
            tracker
                .historic()
                .insert(HistoricKey::for_connection(key, &connection), connection);
        } else {
            tracker.connections().insert(key, connection);
        }
    }
    fn limits() -> TrafficThresholds {
        TrafficThresholds {
            upload: 5_000_000.0,
            download: 5_000_000.0,
        }
    }

    #[test]
    fn interval_rates_use_raw_deltas_and_preserve_other_sampling_periods() {
        let app = app();
        let mut connection = flow(Some(42), 1_000_000_000, 2_000_000_000);
        put(&app, connection.clone());
        let mut sampler = IntervalSampler::default();
        let now = Instant::now();
        assert!(sampler.sample(&app, now, limits()).connections.is_empty());
        connection.bytes_sent += 3_000_000;
        connection.bytes_received += 1_000_000;
        put(&app, connection);
        let sample = sampler.sample(&app, now + Duration::from_millis(500), limits());
        assert_eq!(sample.elapsed_ms, Some(500.0));
        assert_eq!(sample.connections.len(), 1);
        assert_eq!(sample.connections[0].current_outgoing_rate_bps, 6_000_000.0);
        assert_eq!(sample.connections[0].current_incoming_rate_bps, 2_000_000.0);
        assert_eq!(app.snapshot_refresh_interval(), Duration::from_millis(1000));
        assert_eq!(app.snapshot_generation(), 0);
    }

    #[test]
    fn a_short_burst_has_the_expected_100ms_and_500ms_window_rates() {
        let app = app();
        let mut connection = flow(Some(42), 0, 0);
        put(&app, connection.clone());
        let now = Instant::now();
        let mut fast = IntervalSampler::default();
        let mut slow = IntervalSampler::default();
        fast.sample(&app, now, limits());
        slow.sample(&app, now, limits());
        connection.bytes_sent = 600_000;
        put(&app, connection);
        let sample = fast.sample(&app, now + Duration::from_millis(100), limits());
        assert_eq!(sample.connections[0].current_outgoing_rate_bps, 6_000_000.0);
        assert!(
            slow.sample(&app, now + Duration::from_millis(500), limits())
                .connections
                .is_empty()
        );
    }

    #[test]
    fn counter_resets_repeated_time_and_retired_state_remain_safe() {
        let app = app();
        let mut connection = flow(Some(42), 1000, 1000);
        put(&app, connection.clone());
        let now = Instant::now();
        let mut sampler = IntervalSampler::default();
        sampler.sample(&app, now, limits());
        connection.bytes_sent = 100;
        connection.bytes_received = 150;
        put(&app, connection.clone());
        assert!(sampler.sample(&app, now, limits()).elapsed_ms.is_none());
        let reset = sampler.sample(&app, now + Duration::from_millis(100), limits());
        assert_eq!(reset.counter_resets, 2);
        assert!(reset.connections.is_empty());
        connection.bytes_sent += 600_000;
        put(&app, connection);
        assert_eq!(
            sampler
                .sample(&app, now + Duration::from_millis(200), limits())
                .connections
                .len(),
            1
        );
        app.traffic_tracker_for_test().connections().clear();
        sampler.sample(&app, now + Duration::from_millis(300), limits());
        assert!(sampler.previous.is_empty());
    }

    #[test]
    fn newly_closed_connections_keep_final_bytes_and_duplicate_visits_count_once() {
        let app = app();
        let now = Instant::now();
        let mut sampler = IntervalSampler::default();
        sampler.sample(&app, now, limits());
        let mut connection = flow(Some(42), 1_000_000, 0);
        connection.is_historic = true;
        put(&app, connection.clone());
        let closed = sampler.sample(&app, now + Duration::from_millis(100), limits());
        assert_eq!(closed.connections.len(), 1);
        assert!(closed.connections[0].is_historic);
        assert_eq!(
            closed.connections[0].current_outgoing_rate_bps,
            10_000_000.0
        );
        assert!(
            sampler
                .sample(&app, now + Duration::from_millis(200), limits())
                .connections
                .is_empty()
        );
        connection.is_historic = false;
        connection.bytes_sent += 1_000_000;
        put(&app, connection.clone());
        connection.is_historic = true;
        connection.bytes_sent += 1_000_000;
        put(&app, connection);
        let duplicate = sampler.sample(&app, now + Duration::from_millis(300), limits());
        assert_eq!(duplicate.connections.len(), 1);
        assert_eq!(
            duplicate.connections[0].current_outgoing_rate_bps,
            20_000_000.0
        );
    }

    #[test]
    fn reused_endpoints_have_distinct_counter_baselines_and_unknown_owners_are_counted() {
        let app = app();
        let now = Instant::now();
        let mut connection = flow(Some(42), 10_000_000, 0);
        put(&app, connection.clone());
        let mut sampler = IntervalSampler::default();
        sampler.sample(&app, now, limits());
        connection.created_at += Duration::from_secs(1);
        connection.bytes_sent = 600_000;
        put(&app, connection.clone());
        assert_eq!(
            sampler
                .sample(&app, now + Duration::from_millis(100), limits())
                .connections
                .len(),
            1
        );
        connection.pid = None;
        put(&app, connection);
        assert_eq!(
            sampler
                .sample(&app, now + Duration::from_millis(200), limits())
                .unattributed_connections,
            1
        );
    }
}
