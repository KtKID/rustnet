//! Controlled Rust representation of web/src/shared/security*.schema.ts.
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IngressConfig {
    pub attempt_result_wait_ms: u64,
    pub attempt_idle_ms: u64,
    pub scan_window_ms: u64,
    pub scan_distinct_ports: usize,
    pub repeat_window_ms: u64,
    pub repeat_attempts: usize,
    pub echo_window_ms: u64,
    pub echo_requests: usize,
    pub access_aggregate_ms: u64,
    pub correlation_window_ms: u64,
    pub udp_reply_window_ms: u64,
    pub focus_services: FocusServices,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FocusServices {
    pub mode: String,
    pub endpoints: Vec<SocketAddr>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub ingress: IngressConfig,
    pub runtime: RuntimeConfig,
    pub storage: StorageConfig,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub queue_capacity: usize,
    pub active_attempt_limit: usize,
    pub tick_ms: u64,
    pub commit_interval_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub segment_bytes: u64,
    pub max_record_bytes: usize,
}
#[derive(Debug, Clone)]
pub struct PacketFact {
    pub source: SocketAddr,
    pub target: SocketAddr,
    pub source_local: bool,
    pub target_local: bool,
    pub protocol: String,
    pub interface: Option<String>,
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub rst: bool,
    pub fin: bool,
    pub payload_len: u32,
    pub bytes: u64,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub echo_id: Option<u16>,
    pub echo_seq: Option<u16>,
    pub quoted: Option<(SocketAddr, SocketAddr)>,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source_category: String,
    pub evidence_id: String,
    pub attempt_id: String,
    pub connection_id: String,
    pub run_id: String,
    pub capture_scope_id: String,
    pub observed_at: String,
    pub source: SocketAddr,
    pub target: SocketAddr,
    pub protocol: String,
    pub interface: Option<String>,
    pub initiator: String,
    pub result: String,
    pub first_observed_at: String,
    pub window_end_at: Option<String>,
    pub result_evidence_ids: Vec<String>,
    pub packet: PacketSummary,
    pub bytes_observed: String,
    pub retransmit_count: u64,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketSummary {
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub rst: bool,
    pub fin: bool,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub echo_id: Option<u16>,
    pub echo_seq: Option<u16>,
    pub quoted_source: Option<SocketAddr>,
    pub quoted_target: Option<SocketAddr>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub incident_id: String,
    pub revision: u64,
    pub run_id: String,
    pub capture_scope_id: String,
    pub kind: String,
    pub attention: String,
    pub source_address: IpAddr,
    pub target_address: IpAddr,
    pub target_ports: Vec<u16>,
    pub first_observed_at: String,
    pub last_observed_at: String,
    pub count: usize,
    pub window_count: usize,
    pub evidence_ids: Vec<String>,
    pub related_incident_ids: Vec<String>,
    pub rule_window_ms: u64,
    pub rule_threshold: usize,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Item {
    Observation(Box<Evidence>),
    IncidentRevision(Box<Incident>),
    HealthObservation(Health),
    RunLifecycle(Lifecycle),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub source_id: String,
    pub state: String,
    pub observed_at: String,
    pub lost_records: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    pub run_id: String,
    pub observed_at: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub schema_version: u8,
    pub seq: String,
    pub committed_at: String,
    pub run_id: String,
    pub items: Vec<Item>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watermark {
    pub schema_version: u8,
    pub committed_seq: String,
    pub segment: u64,
    pub offset: u64,
}
pub fn now() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false)
}
impl SecurityConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::ensure;
        let c = &self.ingress;
        for value in [
            c.attempt_result_wait_ms,
            c.attempt_idle_ms,
            c.scan_window_ms,
            c.repeat_window_ms,
            c.echo_window_ms,
            c.access_aggregate_ms,
            c.correlation_window_ms,
            c.udp_reply_window_ms,
            self.runtime.tick_ms,
            self.runtime.commit_interval_ms,
        ] {
            ensure!(
                value > 0 && value <= 9_007_199_254_740_991,
                "security interval must be a positive safe integer"
            );
        }
        ensure!(
            c.attempt_idle_ms >= c.attempt_result_wait_ms,
            "attempt idle must cover result wait"
        );
        ensure!(
            c.correlation_window_ms >= c.scan_window_ms,
            "correlation window must cover scan window"
        );
        for count in [c.scan_distinct_ports, c.repeat_attempts, c.echo_requests] {
            ensure!(
                (2..=1000).contains(&count),
                "security count must be 2..1000"
            );
        }
        ensure!(
            (1..=65536).contains(&self.runtime.queue_capacity),
            "invalid security queue capacity"
        );
        ensure!(
            (1..=50000).contains(&self.runtime.active_attempt_limit),
            "invalid active attempt limit"
        );
        ensure!(
            matches!(
                c.focus_services.mode.as_str(),
                "current_user_listeners" | "explicit"
            ),
            "unknown focus service mode"
        );
        ensure!(
            c.focus_services.endpoints.len() <= 1000
                && c.focus_services.endpoints.iter().all(|a| a.port() > 0),
            "invalid focus endpoints"
        );
        ensure!(
            self.storage.segment_bytes > 0
                && self.storage.segment_bytes <= 1024 * 1024 * 1024
                && self.storage.max_record_bytes > 0
                && self.storage.max_record_bytes <= 8 * 1024 * 1024,
            "invalid security storage limits"
        );
        Ok(())
    }
}
