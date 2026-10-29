//! Bounded read-only projection of existing App memory. No capture or disk I/O.
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Local, SecondsFormat};
use dashmap::DashMap;
use rustnet_host::{HostSocketState, HostTcpState, SocketSnapshot};
use serde_json::{Value, json};

use super::capture::CaptureStatus;
use super::{App, AppStats};
use crate::network::{
    interface_stats::{InterfaceRates, InterfaceStats},
    process_activity::ProcessActivityTracker,
    tracker::ConnectionTracker,
    types::{Connection, TrafficHistory},
};

const PROCESS_LIMIT: usize = 20;
const CONNECTION_LIMIT: usize = 12;
const INTERFACE_LIMIT: usize = 64;
const DNS_QUESTION_LIMIT: usize = 8;

fn time(value: SystemTime) -> String {
    DateTime::<Local>::from(value).to_rfc3339_opts(SecondsFormat::Millis, false)
}
fn rate(value: f64) -> Option<f64> {
    (value.is_finite() && value >= 0.0).then_some(value)
}

pub(crate) struct LiveSources {
    history: Arc<RwLock<TrafficHistory>>,
    connections: Arc<RwLock<Vec<Connection>>>,
    generation: Arc<AtomicU64>,
    activity: Arc<RwLock<ProcessActivityTracker>>,
    interfaces: Arc<DashMap<String, InterfaceStats>>,
    interface_rates: Arc<RwLock<HashMap<String, InterfaceRates>>>,
    sockets: Arc<RwLock<SocketSnapshot>>,
    stats: Arc<AppStats>,
    tracker: Arc<ConnectionTracker>,
    interface: Arc<RwLock<Option<String>>>,
    capture: Arc<RwLock<CaptureStatus>>,
    hide_ptr: bool,
}

impl App {
    pub(crate) fn live_sources(&self) -> LiveSources {
        LiveSources {
            history: Arc::clone(&self.traffic_history),
            connections: Arc::clone(&self.connections_snapshot),
            generation: Arc::clone(&self.snapshot_generation),
            activity: Arc::clone(&self.process_activity),
            interfaces: Arc::clone(&self.interface_stats),
            interface_rates: Arc::clone(&self.interface_rates),
            sockets: Arc::clone(&self.socket_snapshot),
            stats: Arc::clone(&self.stats),
            tracker: Arc::clone(&self.tracker),
            interface: Arc::clone(&self.current_interface),
            capture: Arc::clone(&self.capture_status),
            hide_ptr: self.hide_ptr_lookups(),
        }
    }
}

impl LiveSources {
    pub(crate) fn snapshot(&self, run_id: &str) -> Result<Value> {
        let history = self
            .history
            .read()
            .map_err(|_| anyhow!("live history lock"))?
            .live_samples()
            .map(|point| {
                let rates = point.live_rates();
                let (opened, closed) = point.lifecycle_rates();
                json!({"timestamp":time(point.observed_at),
                    "upload":rates.map(|(_, tx)|tx),"download":rates.map(|(rx, _)|rx),
                    "active_connections":point.connection_count,"opened_per_second":opened,
                    "closed_per_second":closed,"packets_per_second":point.packets_per_sec,
                    "retransmission_percent":rate(f64::from(point.packet_loss_pct)),
                    "rtt_ms":point.avg_rtt_ms.and_then(rate)})
            })
            .collect::<Vec<_>>();
        let connections = self
            .connections
            .read()
            .map_err(|_| anyhow!("live connections lock"))?;
        let generation = self.generation.load(Ordering::Acquire);
        let mut active = connections
            .iter()
            .filter(|connection| {
                !connection.is_historic
                    && !(self.hide_ptr && super::state::is_ptr_lookup(connection))
            })
            .collect::<Vec<_>>();
        let active_count = active.len();
        let mut protocols = BTreeMap::<String, usize>::new();
        for connection in &active {
            let name = connection
                .dpi_info
                .as_ref()
                .map(|dpi| dpi.application.sort_key().to_string())
                .unwrap_or_else(|| connection.protocol.to_string());
            *protocols.entry(name).or_default() += 1;
        }
        active.sort_by(|a, b| {
            (b.current_incoming_rate_bps + b.current_outgoing_rate_bps)
                .total_cmp(&(a.current_incoming_rate_bps + a.current_outgoing_rate_bps))
        });
        let top = active
            .into_iter()
            .take(CONNECTION_LIMIT)
            .map(|c| c.snapshot_clone())
            .collect::<Vec<_>>();
        drop(connections);
        let connections = crate::headless::live_connections(&top)?;
        let activity = self
            .activity
            .read()
            .map_err(|_| anyhow!("live processes lock"))?
            .snapshot();
        let mut processes = activity.processes;
        processes.retain(|p| p.active_connections > 0);
        let process_count = processes.len();
        processes.sort_by(|a, b| {
            (b.current_tx_bps + b.current_rx_bps).total_cmp(&(a.current_tx_bps + a.current_rx_bps))
        });
        let processes = processes
            .into_iter()
            .take(PROCESS_LIMIT)
            .map(|p| {
                json!({
                    "pid":p.identity.pid,"name":p.identity.name,"attributed":p.identity.attributed,
                    "upload":rate(p.current_tx_bps),"download":rate(p.current_rx_bps),
                    "peak_upload":rate(p.peak_tx_bps),"peak_download":rate(p.peak_rx_bps),
                    "sent":p.retained_tx_bytes,"received":p.retained_rx_bytes,
                    "active_connections":p.active_connections,"destinations":p.unique_destinations,
                })
            })
            .collect::<Vec<_>>();
        let rates = self
            .interface_rates
            .read()
            .map_err(|_| anyhow!("live interface rates lock"))?;
        let mut interfaces = self
            .interfaces
            .iter()
            .map(|row| row.value().clone())
            .collect::<Vec<_>>();
        interfaces.sort_by(|a, b| a.interface_name.cmp(&b.interface_name));
        let interfaces = interfaces.into_iter().take(INTERFACE_LIMIT).map(|i| {
            let r = rates.get(&i.interface_name);
            json!({"name":i.interface_name,"upload":r.map(|v|v.tx_bytes_per_sec),
                "download":r.map(|v|v.rx_bytes_per_sec),"sent":i.tx_bytes,"received":i.rx_bytes,
                "packets_sent":i.tx_packets,"packets_received":i.rx_packets,
                "errors":i.rx_errors.saturating_add(i.tx_errors),"dropped":i.rx_dropped.saturating_add(i.tx_dropped)})
        }).collect::<Vec<_>>();
        drop(rates);
        let sockets = self
            .sockets
            .read()
            .map_err(|_| anyhow!("live sockets lock"))?;
        let totals = json!({"active_connections":active_count,"processes":process_count,
            "sockets":sockets.sockets.len(),"tcp_listen":sockets.sockets.iter().filter(|s|s.state==HostSocketState::Tcp(HostTcpState::Listen)).count(),
            "udp_bound":sockets.sockets.iter().filter(|s|s.state==HostSocketState::UdpBound).count(),
            "socket_observed_at":sockets.collected_at.map(time),"socket_complete":sockets.complete});
        drop(sockets);
        let dns = self.tracker.dns_analytics_snapshot();
        let dns_window = dns.window_label().to_string();
        let mut questions = dns.questions;
        questions.sort_by_key(|q| std::cmp::Reverse(q.lookups));
        let capture_error = match &*self
            .capture
            .read()
            .map_err(|_| anyhow!("live capture lock"))?
        {
            CaptureStatus::Healthy => None,
            CaptureStatus::Failed(message) => Some(message.clone()),
        };
        Ok(
            json!({"schema_version":1,"run_id":run_id,"pid":std::process::id(),
            "published_at":time(SystemTime::now()),"sample_interval_ms":500,"history_window_seconds":60,
            "interface":self.interface.read().map_err(|_| anyhow!("live interface lock"))?.clone(),
            "capture_error":capture_error,"generation":generation,"history":history,
            "interfaces":interfaces,"totals":totals,"processes":processes,"connections":connections,
            "protocols":protocols.into_iter().take(16).map(|(name,connections)|json!({"name":name,"connections":connections})).collect::<Vec<_>>(),
            "dns":{"window":dns_window,"lookups":dns.lookups,"answered":dns.answered,"pending":dns.pending,
                "timeouts":dns.timeouts,"failures":dns.failures,
                "p50_ms":dns.latency_p50.map(|v|v.as_secs_f64()*1000.0),
                "p95_ms":dns.latency_p95.map(|v|v.as_secs_f64()*1000.0),"truncated":dns.truncated,
                "questions":questions.into_iter().take(DNS_QUESTION_LIMIT).map(|q|json!({"name":q.name,"lookups":q.lookups})).collect::<Vec<_>>()},
            "stats":crate::headless::live_stats(&self.stats)?}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Config;
    use crate::network::types::{ConnectionLifecycleSample, Protocol, ProtocolState};
    use std::time::Duration;

    #[test]
    fn live_projection_preserves_gaps_timestamps_and_bounds_and_exports_contract() {
        let app = App::new(Config {
            resolve_dns: false,
            ..Config::default()
        })
        .unwrap();
        let mut connections = Vec::new();
        for port in 40000..40030 {
            let mut connection = Connection::new(
                Protocol::Udp,
                format!("127.0.0.1:{port}").parse().unwrap(),
                "192.0.2.1:53".parse().unwrap(),
                ProtocolState::Udp,
            );
            connection.pid = Some(42);
            connection.current_outgoing_rate_bps = f64::NAN;
            connections.push(connection);
        }
        app.set_connections_snapshot_for_test(connections);
        app.traffic_history.write().unwrap().add_sample(
            None,
            ConnectionLifecycleSample::default(),
            0,
            0,
            None,
        );
        std::thread::sleep(Duration::from_millis(500));
        app.traffic_history.write().unwrap().add_sample(
            Some((125000, 250000)),
            ConnectionLifecycleSample {
                active: 30,
                opened_per_sec_tenths: 15,
                closed_per_sec_tenths: 5,
                ..Default::default()
            },
            200,
            2,
            Some(12.5),
        );
        let source = app.live_sources();
        let value = source
            .snapshot("6feb7de2-2a2a-4af5-8267-2166c8de23ff")
            .unwrap();
        assert_eq!(value["history"][0]["upload"], Value::Null);
        assert_eq!(value["history"][1]["upload"], 250000);
        assert_eq!(value["history"][1]["opened_per_second"], 1.5);
        assert_eq!(value["totals"]["active_connections"], 30);
        assert_eq!(value["connections"].as_array().unwrap().len(), 12);
        assert_eq!(
            value["connections"][0]["traffic"]["outgoing_bytes_per_second"],
            Value::Null
        );
        let next = source
            .snapshot("6feb7de2-2a2a-4af5-8267-2166c8de23ff")
            .unwrap();
        assert_eq!(value["history"], next["history"]);
        if let Ok(path) = std::env::var("COLLECTOR_LIVE_FIXTURE") {
            std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        }
    }
}
