//! YAML runtime values. Business defaults live in the checked-in YAML only.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<crate::security::protocol::SecurityConfig>,
    pub schema_version: u8,
    pub mode: Mode,
    #[serde(deserialize_with = "required_option")]
    pub duration_seconds: Option<u64>,
    pub data_directory: String,
    pub runtime_directory: String,
    pub capture: Capture,
    pub sampling: Sampling,
    pub thresholds: Thresholds,
    pub storage: Storage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Anomalies,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    #[serde(deserialize_with = "required_option")]
    pub interface: Option<String>,
    pub show_localhost: bool,
    pub show_ptr_lookups: bool,
}

fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Sampling {
    pub traffic_interval_ms: u64,
    pub traffic_alert_interval_ms: u64,
    pub traffic_alert_cooldown_ms: u64,
    pub listener_interval_ms: u64,
    pub socket_interval_ms: u64,
    pub snapshot_interval_ms: u64,
    pub enrichment_interval_ms: u64,
    pub enrichment_full_interval_ms: u64,
    pub status_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub upload_mb_s: f64,
    pub download_mb_s: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub event_queue_capacity: usize,
    pub flush_timeout_ms: u64,
}

pub fn load(path: &Path) -> Result<CollectorConfig> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read YAML {}", path.display()))?;
    parse(&text)
}

pub fn parse(text: &str) -> Result<CollectorConfig> {
    let value: CollectorConfig = serde_yaml_ng::from_str(text).context("collector YAML")?;
    ensure!(
        matches!(value.schema_version, 1 | 2),
        "schema_version must be 1 or 2"
    );
    ensure!(
        (value.schema_version == 2) == value.security.is_some(),
        "v2 requires security; v1 keeps its original fields"
    );
    if let Some(security) = &value.security {
        security.validate()?;
    }
    ensure!(
        !value.data_directory.trim().is_empty() && !value.runtime_directory.trim().is_empty(),
        "data/runtime directories must be nonempty"
    );
    ensure!(
        value
            .duration_seconds
            .is_none_or(|v| v > 0 && v <= 9_007_199_254_740_991),
        "duration_seconds must be a positive safe integer or null"
    );
    ensure!(
        value
            .capture
            .interface
            .as_ref()
            .is_none_or(|name| !name.trim().is_empty()),
        "capture.interface must be nonempty or null"
    );
    let s = &value.sampling;
    ensure!(
        value.storage.event_queue_capacity > 0 && value.storage.event_queue_capacity <= 4096,
        "storage.event_queue_capacity must be 1..4096"
    );
    ensure!(
        value.storage.flush_timeout_ms > 0
            && value.storage.flush_timeout_ms <= 9_007_199_254_740_991,
        "storage.flush_timeout_ms must be a positive safe integer"
    );
    for (name, number) in [
        ("traffic_interval_ms", s.traffic_interval_ms),
        ("traffic_alert_interval_ms", s.traffic_alert_interval_ms),
        ("traffic_alert_cooldown_ms", s.traffic_alert_cooldown_ms),
        ("listener_interval_ms", s.listener_interval_ms),
        ("socket_interval_ms", s.socket_interval_ms),
        ("snapshot_interval_ms", s.snapshot_interval_ms),
        ("enrichment_interval_ms", s.enrichment_interval_ms),
        ("enrichment_full_interval_ms", s.enrichment_full_interval_ms),
        ("status_interval_ms", s.status_interval_ms),
    ] {
        ensure!(
            number > 0 && number <= 9_007_199_254_740_991,
            "{name} must be a positive safe integer"
        );
    }
    ensure!(
        s.traffic_alert_interval_ms <= s.traffic_interval_ms,
        "alert interval must be <= normal interval"
    );
    ensure!(
        s.enrichment_interval_ms <= s.socket_interval_ms,
        "enrichment interval must be <= socket interval"
    );
    for (name, rate) in [
        ("upload_mb_s", value.thresholds.upload_mb_s),
        ("download_mb_s", value.thresholds.download_mb_s),
    ] {
        ensure!(
            rate.is_finite() && (0.0..=9_007_199_254_740_991.0 / 1_000_000.0).contains(&rate),
            "{name} must be finite, nonnegative MB/s"
        );
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn security_v2_is_explicit_and_v1_stays_compatible() {
        let original = include_str!("../../../collector.yaml");
        let old = original
            .split("security:\n")
            .next()
            .unwrap()
            .replace("schema_version: 2", "schema_version: 1");
        assert!(parse(&old).is_ok());
        let block = include_str!("../security/test-security-config.yaml");
        let new = old.replace("schema_version: 1", "schema_version: 2") + block;
        assert!(parse(&new).is_ok(), "v2 security config must be accepted");
        for bad in [
            new.replace("scan_distinct_ports: 3", "scan_distinct_ports: 0"),
            new.replace("tick_ms: 100", "tick_ms: 0"),
            new.replace("mode: current_user_listeners", "mode: unknown"),
            old.replace("schema_version: 1", "schema_version: 2"),
        ] {
            assert!(parse(&bad).is_err());
        }
    }

    #[test]
    fn yaml_is_the_source_of_all_business_values() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../collector.yaml");
        let config = load(&path).expect("valid checked-in YAML");
        assert_eq!(config.thresholds.upload_mb_s, 5.0);
        assert_eq!(config.thresholds.download_mb_s, 5.0);
        assert_eq!(config.sampling.traffic_interval_ms, 500);
        assert_eq!(config.sampling.listener_interval_ms, 1000);
        assert_eq!(config.duration_seconds, None);
    }

    #[test]
    fn custom_values_are_preserved_and_invalid_yaml_is_rejected() {
        let text = include_str!("../../../collector.yaml");
        let custom = text
            .replace("upload_mb_s: 5", "upload_mb_s: 2.5")
            .replace("download_mb_s: 5", "download_mb_s: 9")
            .replace("listener_interval_ms: 1000", "listener_interval_ms: 1234");
        let value = parse(&custom).unwrap();
        assert_eq!(value.thresholds.upload_mb_s, 2.5);
        assert_eq!(value.thresholds.download_mb_s, 9.0);
        assert_eq!(value.sampling.listener_interval_ms, 1234);
        for bad in [
            text.replace("upload_mb_s: 5", "upload_mb_s: -1"),
            text.replace("traffic_interval_ms: 500", "traffic_interval_ms: 0"),
            text.replace(
                "traffic_alert_interval_ms: 100",
                "traffic_alert_interval_ms: 501",
            ),
            text.replace("mode: anomalies", "mode: other"),
            text.replace("schema_version: 2", "schema_version: 2\nunknown: true"),
        ] {
            assert!(parse(&bad).is_err(), "accepted {bad}");
        }
    }
}
