use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use serde::Serialize;

/// Explicitly validated durations; defaults are owned by the TS configuration.
#[derive(Debug, Clone, Copy)]
pub struct TrafficCadence {
    pub(super) normal: Duration,
    pub(super) alert: Duration,
    pub(super) cooldown: Duration,
}

impl TrafficCadence {
    pub fn new(normal: Duration, alert: Duration, cooldown: Duration) -> Result<Self> {
        ensure!(
            !normal.is_zero() && !alert.is_zero() && !cooldown.is_zero(),
            "traffic cadence durations must be positive"
        );
        ensure!(
            alert <= normal,
            "alert interval must not exceed normal interval"
        );
        Ok(Self {
            normal,
            alert,
            cooldown,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SamplingMode {
    Normal,
    Alert,
}

pub(super) struct CadenceTracker {
    config: TrafficCadence,
    last_hit: Option<Instant>,
    pub normal_checks: u64,
    pub alert_checks: u64,
    pub activations: u64,
    pub recoveries: u64,
}

impl CadenceTracker {
    pub fn new(config: TrafficCadence) -> Self {
        Self {
            config,
            last_hit: None,
            normal_checks: 0,
            alert_checks: 0,
            activations: 0,
            recoveries: 0,
        }
    }
    pub fn mode(&self) -> SamplingMode {
        if self.last_hit.is_some() {
            SamplingMode::Alert
        } else {
            SamplingMode::Normal
        }
    }
    pub fn interval(&self) -> Duration {
        match self.mode() {
            SamplingMode::Normal => self.config.normal,
            SamplingMode::Alert => self.config.alert,
        }
    }
    pub fn observe(&mut self, now: Instant, exceeded: bool) {
        match self.mode() {
            SamplingMode::Normal => self.normal_checks += 1,
            SamplingMode::Alert => self.alert_checks += 1,
        }
        if exceeded {
            if self.last_hit.is_none() {
                self.activations += 1;
            }
            self.last_hit = Some(now);
        } else if self
            .last_hit
            .is_some_and(|last| now.saturating_duration_since(last) >= self.config.cooldown)
        {
            self.last_hit = None;
            self.recoveries += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> TrafficCadence {
        TrafficCadence::new(
            Duration::from_millis(500),
            Duration::from_millis(100),
            Duration::from_secs(10),
        )
        .unwrap()
    }

    #[test]
    fn switches_after_hit_and_recovers_at_ten_quiet_seconds() {
        let mut state = CadenceTracker::new(config());
        let now = Instant::now();
        state.observe(now, false);
        assert_eq!(state.interval(), Duration::from_millis(500));
        state.observe(now + Duration::from_millis(500), true);
        assert_eq!(state.interval(), Duration::from_millis(100));
        state.observe(now + Duration::from_millis(10_499), false);
        assert_eq!(state.mode(), SamplingMode::Alert);
        state.observe(now + Duration::from_millis(10_500), false);
        assert_eq!(state.interval(), Duration::from_millis(500));
        assert_eq!(
            (
                state.normal_checks,
                state.alert_checks,
                state.activations,
                state.recoveries
            ),
            (2, 2, 1, 1)
        );
        state.observe(now + Duration::from_secs(11), true);
        assert_eq!(
            (state.activations, state.recoveries, state.mode()),
            (2, 1, SamplingMode::Alert)
        );
    }

    #[test]
    fn each_hit_extends_the_deadline_and_wins_at_its_boundary() {
        let mut state = CadenceTracker::new(config());
        let now = Instant::now();
        state.observe(now, true);
        state.observe(now + Duration::from_secs(10), true);
        state.observe(now + Duration::from_millis(19_999), false);
        assert_eq!(state.mode(), SamplingMode::Alert);
        state.observe(now + Duration::from_secs(20), false);
        assert_eq!((state.activations, state.recoveries), (1, 1));
        assert_eq!(state.mode(), SamplingMode::Normal);
    }

    #[test]
    fn custom_and_equal_cadences_validate_and_normal_stays_idle() {
        assert!(
            TrafficCadence::new(
                Duration::ZERO,
                Duration::from_millis(1),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            TrafficCadence::new(
                Duration::from_millis(10),
                Duration::from_millis(11),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            TrafficCadence::new(
                Duration::from_millis(10),
                Duration::from_millis(1),
                Duration::ZERO
            )
            .is_err()
        );
        let equal = TrafficCadence::new(
            Duration::from_millis(40),
            Duration::from_millis(40),
            Duration::from_millis(200),
        )
        .unwrap();
        let mut state = CadenceTracker::new(equal);
        let now = Instant::now();
        state.observe(now, false);
        state.observe(now + Duration::from_secs(12), false);
        assert_eq!(
            (state.activations, state.alert_checks, state.mode()),
            (0, 0, SamplingMode::Normal)
        );
        state.observe(now + Duration::from_secs(13), true);
        assert_eq!(state.interval(), Duration::from_millis(40));
        state.observe(now + Duration::from_millis(13_200), false);
        assert_eq!(state.mode(), SamplingMode::Normal);
    }
}
