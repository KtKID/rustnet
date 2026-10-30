//! Bounded packet-level process evidence for shared sockets.

use std::time::{Duration, SystemTime};

pub const PROCESS_OBSERVATION_LIMIT: usize = 8;
const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct ObservedProcess {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub observations: u64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessObservations {
    pub processes: Vec<ObservedProcess>,
    pub overflow_observations: u64,
    pub alternate_observations: u64,
    pub first_alternate_seen: Option<SystemTime>,
    pub last_alternate_seen: Option<SystemTime>,
    reported_observations: u64,
    last_reported_at: Option<SystemTime>,
}

#[derive(Debug)]
pub struct ProcessObservationSummary {
    pub additional: u64,
    pub total: u64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
}

impl ProcessObservations {
    pub fn observe(
        &mut self,
        primary_pid: Option<u32>,
        pid: Option<u32>,
        name: Option<&str>,
        now: SystemTime,
    ) {
        if pid.is_none() && name.is_none() {
            return;
        }
        if let Some(known) = self
            .processes
            .iter_mut()
            .find(|known| known.pid == pid && (pid.is_some() || known.name.as_deref() == name))
        {
            known.observations = known.observations.saturating_add(1);
            known.first_seen = known.first_seen.min(now);
            known.last_seen = known.last_seen.max(now);
            if known.name.is_none() {
                known.name = name.map(str::to_owned);
            }
        } else if self.processes.len() < PROCESS_OBSERVATION_LIMIT {
            self.processes.push(ObservedProcess {
                pid,
                name: name.map(str::to_owned),
                observations: 1,
                first_seen: now,
                last_seen: now,
            });
        } else {
            self.overflow_observations = self.overflow_observations.saturating_add(1);
        }
        // A name-only observation cannot establish a second process identity.
        // Names from different system APIs may also have different truncation.
        if pid.is_some() && primary_pid.is_some() && pid != primary_pid {
            self.alternate_observations = self.alternate_observations.saturating_add(1);
            self.first_alternate_seen = Some(self.first_alternate_seen.map_or(now, |t| t.min(now)));
            self.last_alternate_seen = Some(self.last_alternate_seen.map_or(now, |t| t.max(now)));
        }
    }

    /// First alternate identity is visible immediately; subsequent observations
    /// are summarized at most once per minute, with a final pending tail on close.
    pub fn take_summary(
        &mut self,
        now: SystemTime,
        force: bool,
    ) -> Option<ProcessObservationSummary> {
        let additional = self
            .alternate_observations
            .saturating_sub(self.reported_observations);
        if additional == 0 {
            return None;
        }
        if !force
            && self
                .last_reported_at
                .is_some_and(|last| now.duration_since(last).unwrap_or_default() < SUMMARY_INTERVAL)
        {
            return None;
        }
        let summary = ProcessObservationSummary {
            additional,
            total: self.alternate_observations,
            first_seen: self.first_alternate_seen?,
            last_seen: self.last_alternate_seen?,
        };
        self.reported_observations = self.alternate_observations;
        self.last_reported_at = Some(now);
        Some(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_observations_are_counted_once_per_packet_and_summarized_by_time() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut state = ProcessObservations::default();
        state.observe(Some(1), Some(1), Some("wine"), start);
        assert!(state.take_summary(start, false).is_none());
        state.observe(Some(1), Some(2), Some("steam"), start);
        assert_eq!(state.take_summary(start, false).unwrap().additional, 1);
        for _ in 0..10_000 {
            state.observe(
                Some(1),
                Some(2),
                Some("steam"),
                start + Duration::from_secs(1),
            );
            assert!(
                state
                    .take_summary(start + Duration::from_secs(1), false)
                    .is_none()
            );
        }
        let summary = state
            .take_summary(start + Duration::from_secs(60), false)
            .unwrap();
        assert_eq!((summary.additional, summary.total), (10_000, 10_001));
        assert_eq!(summary.first_seen, start);
        assert_eq!(summary.last_seen, start + Duration::from_secs(1));
        assert!(
            state
                .take_summary(start + Duration::from_secs(61), true)
                .is_none()
        );
        state.observe(Some(1), Some(2), None, start + Duration::from_secs(61));
        assert_eq!(
            state
                .take_summary(start + Duration::from_secs(61), true)
                .unwrap()
                .additional,
            1
        );
        assert!(
            state
                .take_summary(start + Duration::from_secs(61), true)
                .is_none()
        );
        assert_eq!(state.processes.len(), 2);
    }

    #[test]
    fn same_pid_name_aliases_and_missing_pid_preserve_evidence_without_shared_warning() {
        let now = SystemTime::UNIX_EPOCH;
        let mut state = ProcessObservations::default();
        state.observe(Some(1), Some(1), Some("steamwebhelper"), now);
        state.observe(Some(1), Some(1), Some("steamwebhelper.exe"), now);
        state.observe(Some(1), None, Some("steamwebhelper.exe"), now);
        assert_eq!(state.processes[0].observations, 2);
        assert_eq!(state.processes.len(), 2);
        assert!(state.take_summary(now, true).is_none());
    }

    #[test]
    fn observer_memory_is_bounded_and_overflow_remains_counted() {
        let mut state = ProcessObservations::default();
        for pid in 1..=100 {
            state.observe(Some(1), Some(pid), Some("process"), SystemTime::UNIX_EPOCH);
        }
        assert_eq!(state.processes.len(), PROCESS_OBSERVATION_LIMIT);
        assert_eq!(state.overflow_observations, 92);
        assert_eq!(
            state
                .take_summary(SystemTime::UNIX_EPOCH, true)
                .unwrap()
                .total,
            99
        );
    }

    #[test]
    fn out_of_order_times_preserve_bounds_and_do_not_trigger_extra_summaries() {
        let mut state = ProcessObservations::default();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        state.observe(Some(1), Some(2), None, start);
        state.take_summary(start, false).unwrap();
        state.observe(Some(1), Some(2), None, start - Duration::from_secs(10));
        assert!(
            state
                .take_summary(start - Duration::from_secs(10), false)
                .is_none()
        );
        let summary = state.take_summary(start, true).unwrap();
        assert_eq!(summary.first_seen, start - Duration::from_secs(10));
        assert_eq!(summary.last_seen, start);
    }
}
