//! Evidence-based attempts and bounded-window rules, independent of traffic thresholds.
use super::protocol::*;
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
};
fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
#[derive(Clone)]
struct Attempt {
    evidence: Evidence,
    x: u32,
    y: Option<u32>,
    last_ms: u64,
    started_ms: u64,
    established: bool,
    rejected: bool,
    timed_out: bool,
}
#[derive(Clone)]
struct Hit {
    timestamp: String,
    at: u64,
    port: u16,
    evidence: String,
}
struct Episode {
    incident: Incident,
    start: u64,
    last: u64,
}
struct RuleSpec {
    kind: &'static str,
    window: u64,
    threshold: usize,
    fixed: bool,
    related: Vec<String>,
}
pub struct IngressTracker {
    config: IngressConfig,
    run_id: String,
    scope: String,
    limit: usize,
    attempts: HashMap<(SocketAddr, SocketAddr, u32), Attempt>,
    latest: HashMap<(SocketAddr, SocketAddr), (SocketAddr, SocketAddr, u32)>,
    windows: HashMap<String, VecDeque<Hit>>,
    episodes: HashMap<String, Episode>,
    probes: HashMap<(IpAddr, IpAddr), Episode>,
    udp_out: HashMap<(SocketAddr, SocketAddr), (u64, Evidence)>,
    echo_seen: HashMap<(SocketAddr, SocketAddr, u16, u16), (u64, Evidence)>,
    listeners: Vec<SocketAddr>,
}
impl IngressTracker {
    pub fn new(config: IngressConfig, run_id: String, scope: String, limit: usize) -> Self {
        Self {
            config,
            run_id,
            scope,
            limit,
            attempts: HashMap::new(),
            latest: HashMap::new(),
            windows: HashMap::new(),
            episodes: HashMap::new(),
            probes: HashMap::new(),
            udp_out: HashMap::new(),
            echo_seen: HashMap::new(),
            listeners: Vec::new(),
        }
    }
    pub fn set_listeners(&mut self, endpoints: Vec<SocketAddr>) {
        self.listeners = endpoints;
    }
    fn base(&self, p: &PacketFact, timestamp: String, initiator: &str, result: &str) -> Evidence {
        let aid = id();
        Evidence {
            source_category: source_category(p.source.ip()).into(),
            evidence_id: id(),
            attempt_id: aid.clone(),
            connection_id: aid,
            run_id: self.run_id.clone(),
            capture_scope_id: self.scope.clone(),
            observed_at: timestamp.clone(),
            source: p.source,
            target: p.target,
            protocol: p.protocol.clone(),
            interface: p.interface.clone(),
            initiator: initiator.into(),
            result: result.into(),
            first_observed_at: timestamp,
            window_end_at: None,
            result_evidence_ids: vec![],
            packet: PacketSummary {
                seq: p.seq,
                ack: p.ack,
                syn: p.syn,
                ack_flag: p.ack_flag,
                rst: p.rst,
                fin: p.fin,
                icmp_type: p.icmp_type,
                icmp_code: p.icmp_code,
                echo_id: p.echo_id,
                echo_seq: p.echo_seq,
                quoted_source: p.quoted.map(|q| q.0),
                quoted_target: p.quoted.map(|q| q.1),
            },
            bytes_observed: p.bytes.to_string(),
            retransmit_count: 0,
            pid: p.pid,
            process_name: p.process_name.clone(),
            limitations: vec![
                "visible_source_address_only".into(),
                "network_facts_application_authentication_unknown".into(),
            ],
        }
    }
    fn inbound(p: &PacketFact) -> bool {
        p.target_local
            && !p.source_local
            && !p.target.ip().is_multicast()
            && !p.target.ip().is_unspecified()
    }
    fn emit_update(a: &mut Attempt, p: &PacketFact, result: &str, timestamp: String) -> Evidence {
        let mut e = a.evidence.clone();
        e.evidence_id = id();
        e.observed_at = timestamp;
        e.result = result.into();
        e.packet = PacketSummary {
            seq: p.seq,
            ack: p.ack,
            syn: p.syn,
            ack_flag: p.ack_flag,
            rst: p.rst,
            fin: p.fin,
            icmp_type: p.icmp_type,
            icmp_code: p.icmp_code,
            echo_id: p.echo_id,
            echo_seq: p.echo_seq,
            quoted_source: p.quoted.map(|q| q.0),
            quoted_target: p.quoted.map(|q| q.1),
        };
        e.bytes_observed =
            (a.evidence.bytes_observed.parse::<u64>().unwrap_or(0) + p.bytes).to_string();
        e.result_evidence_ids.push(e.evidence_id.clone());
        a.evidence = e.clone();
        e
    }
    pub fn observe(&mut self, p: PacketFact, ms: u64, timestamp: String) -> Vec<Item> {
        let mut out = Vec::new();
        let direction = if p.source_local && p.target_local {
            "local"
        } else if p.source_local {
            "outbound"
        } else if p.target_local {
            "inbound"
        } else {
            "forwarded"
        };
        if direction == "local" || direction == "forwarded" {
            out.push(Item::Observation(Box::new(self.base(
                &p,
                timestamp,
                direction,
                "activity_observed",
            ))));
            return out;
        }
        if p.protocol != "TCP" {
            out.extend(self.datagram(p, ms, timestamp, direction));
            return out;
        }
        if p.syn && !p.ack_flag {
            let key = (p.source, p.target, p.seq);
            if let Some(a) = self.attempts.get_mut(&key) {
                a.last_ms = ms;
                a.evidence.retransmit_count += 1;
                let e = Self::emit_update(a, &p, "attempt_retransmitted", timestamp);
                out.push(Item::Observation(Box::new(e)));
                return out;
            }
            if self.attempts.len() >= self.limit {
                out.push(Item::HealthObservation(Health {
                    source_id: "security_pipeline".into(),
                    state: "degraded".into(),
                    observed_at: timestamp,
                    lost_records: "1".into(),
                    reason: "active_attempt_limit".into(),
                }));
                return out;
            }
            let mut e = self.base(&p, timestamp, direction, "attempt_observed");
            e.result_evidence_ids.push(e.evidence_id.clone());
            let a = Attempt {
                evidence: e.clone(),
                x: p.seq,
                y: None,
                last_ms: ms,
                started_ms: ms,
                established: false,
                rejected: false,
                timed_out: false,
            };
            self.attempts.insert(key, a);
            self.latest.insert((p.source, p.target), key);
            out.push(Item::Observation(Box::new(e.clone())));
            if Self::inbound(&p) {
                out.extend(self.hit(&e, ms, "TCP", false));
            }
            return out;
        }
        let forward = self.latest.get(&(p.source, p.target)).copied();
        let reverse = self.latest.get(&(p.target, p.source)).copied();
        let key = forward.or(reverse);
        let Some(key) = key else {
            out.push(Item::Observation(Box::new(self.base(
                &p,
                timestamp,
                "unknown",
                "midstream_observed",
            ))));
            return out;
        };
        let a = self.attempts.get_mut(&key).expect("registered attempt");
        a.last_ms = ms;
        let from_initiator = forward.is_some();
        let result = if p.rst {
            if a.established {
                Some("reset_after_established")
            } else if !from_initiator
                && p.source_local
                && p.ack_flag
                && p.ack == a.x.wrapping_add(1)
            {
                a.rejected = true;
                Some("local_rejection_observed")
            } else {
                Some("reset_observed")
            }
        } else if !a.rejected
            && !a.established
            && p.syn
            && p.ack_flag
            && !from_initiator
            && p.ack == a.x.wrapping_add(1)
            && p.payload_len == 0
        {
            a.y = Some(p.seq);
            Some("syn_ack_observed")
        } else if !a.rejected
            && !a.established
            && !p.syn
            && p.ack_flag
            && from_initiator
            && p.seq == a.x.wrapping_add(1)
            && a.y.is_some_and(|y| p.ack == y.wrapping_add(1))
        {
            a.established = true;
            Some("established")
        } else if p.fin {
            Some("close_observed")
        } else {
            None
        };
        if let Some(result) = result {
            let e = Self::emit_update(a, &p, result, timestamp);
            let inbound = a.evidence.initiator == "inbound";
            out.push(Item::Observation(Box::new(e.clone())));
            if result == "established" && inbound {
                out.extend(self.access(&e, ms));
            }
        }
        out
    }
    fn focused(&self, e: &Evidence) -> bool {
        let endpoints = if self.config.focus_services.mode == "current_user_listeners" {
            &self.listeners
        } else {
            &self.config.focus_services.endpoints
        };
        endpoints.iter().any(|a| {
            a.port() == e.target.port()
                && (a.ip() == e.target.ip() || a.ip().is_unspecified())
                && a.is_ipv4() == e.target.is_ipv4()
        })
    }
    fn event(
        &mut self,
        key: String,
        e: &Evidence,
        hits: Vec<Hit>,
        ms: u64,
        rule: RuleSpec,
    ) -> Incident {
        let RuleSpec {
            kind,
            window,
            threshold,
            fixed,
            related,
        } = rule;
        let old = self.episodes.get(&key).filter(|x| {
            if fixed {
                ms.saturating_sub(x.start) < window
            } else {
                ms.saturating_sub(x.last) <= window
            }
        });
        let mut i = if let Some(x) = old {
            x.incident.clone()
        } else {
            Incident {
                incident_id: id(),
                revision: 0,
                run_id: self.run_id.clone(),
                capture_scope_id: self.scope.clone(),
                kind: kind.into(),
                attention: if kind == "port_probe_suspected" || kind == "probe_then_connected" {
                    "elevated"
                } else {
                    "review"
                }
                .into(),
                source_address: e.source.ip(),
                target_address: e.target.ip(),
                target_ports: vec![],
                first_observed_at: hits
                    .first()
                    .map(|h| h.timestamp.clone())
                    .unwrap_or_else(|| e.first_observed_at.clone()),
                last_observed_at: e.observed_at.clone(),
                count: 0,
                window_count: 0,
                evidence_ids: vec![],
                related_incident_ids: vec![],
                rule_window_ms: window,
                rule_threshold: threshold,
                limitations: e.limitations.clone(),
            }
        };
        let start = old.map(|x| x.start).unwrap_or(ms);
        i.revision += 1;
        i.last_observed_at = e.observed_at.clone();
        let window_count = if kind == "port_probe_suspected" || kind == "datagram_probe_review" {
            hits.iter().map(|h| h.port).collect::<BTreeSet<_>>().len()
        } else {
            hits.len()
        };
        for h in hits {
            if !i.evidence_ids.contains(&h.evidence) {
                i.evidence_ids.push(h.evidence);
                i.count += 1;
            }
            if !i.target_ports.contains(&h.port) {
                i.target_ports.push(h.port);
            }
        }
        for x in related {
            if !i.related_incident_ids.contains(&x) {
                i.related_incident_ids.push(x);
            }
        }
        i.count = if kind == "port_probe_suspected" || kind == "datagram_probe_review" {
            i.target_ports.len()
        } else {
            i.evidence_ids.len()
        };
        i.window_count = if fixed { i.count } else { window_count };
        i.target_ports.sort();
        self.episodes.insert(
            key,
            Episode {
                incident: i.clone(),
                start,
                last: ms,
            },
        );
        i
    }
    fn hit(&mut self, e: &Evidence, ms: u64, protocol: &str, echo: bool) -> Vec<Item> {
        let (window, threshold, kind) = if echo {
            (
                self.config.echo_window_ms,
                self.config.echo_requests,
                "echo_probe_review",
            )
        } else {
            (
                self.config.scan_window_ms,
                self.config.scan_distinct_ports,
                if protocol == "TCP" {
                    "port_probe_suspected"
                } else {
                    "datagram_probe_review"
                },
            )
        };
        let key = format!("{kind}:{}:{}:{protocol}", e.source.ip(), e.target.ip());
        if !self.windows.contains_key(&key) && self.windows.len() >= self.limit {
            return vec![self.capacity(&e.observed_at)];
        }
        let q = self.windows.entry(key.clone()).or_default();
        q.retain(|h| ms.saturating_sub(h.at) <= window);
        if q.len() >= self.limit {
            return vec![self.capacity(&e.observed_at)];
        }
        q.push_back(Hit {
            timestamp: e.observed_at.clone(),
            at: ms,
            port: e.target.port(),
            evidence: e.evidence_id.clone(),
        });
        let hits: Vec<_> = q.iter().cloned().collect();
        let count = if echo {
            hits.len()
        } else {
            hits.iter().map(|h| h.port).collect::<BTreeSet<_>>().len()
        };
        let mut out = Vec::new();
        if count >= threshold {
            let mut i = self.event(
                key.clone(),
                e,
                hits,
                ms,
                RuleSpec {
                    kind,
                    window,
                    threshold,
                    fixed: false,
                    related: vec![],
                },
            );
            i.window_count = count;
            self.episodes.get_mut(&key).unwrap().incident = i.clone();
            if protocol == "TCP" {
                self.probes.insert(
                    (e.source.ip(), e.target.ip()),
                    Episode {
                        incident: i.clone(),
                        start: ms,
                        last: ms,
                    },
                );
            }
            out.push(Item::IncidentRevision(Box::new(i)));
        } else {
            self.episodes.remove(&key);
        }
        if protocol == "TCP" {
            let key = format!("repeat:{}:{}", e.source.ip(), e.target);
            let q = self.windows.entry(key.clone()).or_default();
            q.retain(|h| ms.saturating_sub(h.at) <= self.config.repeat_window_ms);
            q.push_back(Hit {
                timestamp: e.observed_at.clone(),
                at: ms,
                port: e.target.port(),
                evidence: e.evidence_id.clone(),
            });
            let hits: Vec<_> = q.iter().cloned().collect();
            if hits.len() >= self.config.repeat_attempts {
                let i = self.event(
                    key,
                    e,
                    hits,
                    ms,
                    RuleSpec {
                        kind: "repeated_access_review",
                        window: self.config.repeat_window_ms,
                        threshold: self.config.repeat_attempts,
                        fixed: false,
                        related: vec![],
                    },
                );
                out.push(Item::IncidentRevision(Box::new(i)));
            } else {
                self.episodes.remove(&key);
            }
        }
        out
    }
    fn access(&mut self, e: &Evidence, ms: u64) -> Vec<Item> {
        let mut out = Vec::new();
        if self.focused(e) {
            let key = format!("access:{}:{}", e.source.ip(), e.target);
            let i = self.event(
                key,
                e,
                vec![Hit {
                    timestamp: e.observed_at.clone(),
                    at: ms,
                    port: e.target.port(),
                    evidence: e.evidence_id.clone(),
                }],
                ms,
                RuleSpec {
                    kind: "external_access_review",
                    window: self.config.access_aggregate_ms,
                    threshold: 1,
                    fixed: true,
                    related: vec![],
                },
            );
            out.push(Item::IncidentRevision(Box::new(i)));
        }
        if let Some(probe) = self
            .probes
            .get(&(e.source.ip(), e.target.ip()))
            .filter(|p| {
                ms > p.last
                    && ms.saturating_sub(p.last) <= self.config.correlation_window_ms
                    && p.incident.target_ports.contains(&e.target.port())
            })
        {
            let relation = probe.incident.incident_id.clone();
            let mut hits: Vec<_> = probe
                .incident
                .evidence_ids
                .iter()
                .map(|x| Hit {
                    timestamp: e.observed_at.clone(),
                    at: ms,
                    port: e.target.port(),
                    evidence: x.clone(),
                })
                .collect();
            hits.push(Hit {
                timestamp: e.observed_at.clone(),
                at: ms,
                port: e.target.port(),
                evidence: e.evidence_id.clone(),
            });
            let i = self.event(
                format!("correlate:{relation}:{}", e.target),
                e,
                hits,
                ms,
                RuleSpec {
                    kind: "probe_then_connected",
                    window: self.config.correlation_window_ms,
                    threshold: 1,
                    fixed: true,
                    related: vec![relation],
                },
            );
            out.push(Item::IncidentRevision(Box::new(i)));
        }
        out
    }
    fn datagram(
        &mut self,
        p: PacketFact,
        ms: u64,
        timestamp: String,
        direction: &str,
    ) -> Vec<Item> {
        let mut out = Vec::new();
        let mut e = self.base(&p, timestamp, direction, "datagram_observed");
        if p.protocol == "UDP" {
            if let Some((_, request)) = self
                .udp_out
                .get(&(p.target, p.source))
                .filter(|(at, _)| ms.saturating_sub(*at) <= self.config.udp_reply_window_ms)
            {
                e.result = "reply_observed".into();
                Self::link_reply(&mut e, request);
            } else if p.source_local {
                e.result = "outbound_datagram_observed".into();
                if self.udp_out.len() < self.limit
                    || self.udp_out.contains_key(&(p.source, p.target))
                {
                    self.udp_out.insert((p.source, p.target), (ms, e.clone()));
                } else {
                    out.push(self.capacity(&e.observed_at));
                }
            } else if Self::inbound(&p) {
                e.result = "inbound_datagram_observed".into();
                e.limitations
                    .push("udp_initiator_based_on_observed_context".into());
                out.extend(self.hit(&e, ms, "UDP", false));
                if self.udp_out.len() < self.limit
                    || self.udp_out.contains_key(&(p.source, p.target))
                {
                    self.udp_out.insert((p.source, p.target), (ms, e.clone()));
                } else {
                    out.push(self.capacity(&e.observed_at));
                }
            }
        } else if p.protocol == "ICMP" || p.protocol == "ICMPv6" {
            if matches!(p.icmp_type, Some(8 | 128)) {
                e.result = "echo_request_observed".into();
                if let (Some(a), Some(b)) = (p.echo_id, p.echo_seq) {
                    let key = (p.source, p.target, a, b);
                    if let Some((_, request)) = self.echo_seen.get(&key) {
                        Self::link_reply(&mut e, request);
                    } else if self.echo_seen.len() < self.limit {
                        self.echo_seen.insert(key, (ms, e.clone()));
                        if Self::inbound(&p) {
                            out.extend(self.hit(&e, ms, &p.protocol, true));
                        }
                    } else {
                        out.push(self.capacity(&e.observed_at));
                    }
                }
            } else if matches!(p.icmp_type, Some(0 | 129)) {
                e.result = "echo_reply_observed".into();
                e.initiator = "unknown".into();
                if let (Some(a), Some(b)) = (p.echo_id, p.echo_seq)
                    && let Some((_, request)) = self.echo_seen.get(&(p.target, p.source, a, b))
                {
                    Self::link_reply(&mut e, request);
                }
            } else if let Some((a, b)) = p.quoted {
                e.result = if (p.protocol == "ICMP" && p.icmp_type == Some(3))
                    || (p.protocol == "ICMPv6" && p.icmp_type == Some(1))
                {
                    "unreachable_report_observed"
                } else {
                    "icmp_error_observed"
                }
                .into();
                e.limitations
                    .push("error_reporter_and_quoted_endpoints_preserved".into());
                let original = self
                    .udp_out
                    .get(&(a, b))
                    .or_else(|| self.udp_out.get(&(b, a)));
                if let Some((_, request)) = original {
                    Self::link_reply(&mut e, request);
                }
            }
        }
        out.insert(0, Item::Observation(Box::new(e)));
        out
    }
    fn link_reply(reply: &mut Evidence, request: &Evidence) {
        reply.initiator = request.initiator.clone();
        reply.attempt_id = request.attempt_id.clone();
        reply.connection_id = request.connection_id.clone();
        reply.first_observed_at = request.first_observed_at.clone();
        reply.result_evidence_ids = vec![request.evidence_id.clone(), reply.evidence_id.clone()];
    }
    fn capacity(&self, timestamp: &str) -> Item {
        Item::HealthObservation(Health {
            source_id: "security_pipeline".into(),
            state: "degraded".into(),
            observed_at: timestamp.into(),
            lost_records: "1".into(),
            reason: "security_state_limit".into(),
        })
    }
    pub fn advance(&mut self, ms: u64, timestamp: String) -> Vec<Item> {
        let mut out = Vec::new();
        for a in self.attempts.values_mut() {
            if !a.established
                && !a.rejected
                && !a.timed_out
                && ms.saturating_sub(a.started_ms) >= self.config.attempt_result_wait_ms
            {
                a.timed_out = true;
                let mut e = a.evidence.clone();
                e.evidence_id = id();
                e.observed_at = timestamp.clone();
                e.window_end_at = Some(timestamp.clone());
                e.result = "establishment_unobserved_in_window".into();
                a.evidence = e.clone();
                out.push(Item::Observation(Box::new(e)));
            }
        }
        self.attempts
            .retain(|_, a| ms.saturating_sub(a.last_ms) <= self.config.attempt_idle_ms);
        self.latest.retain(|_, k| self.attempts.contains_key(k));
        self.udp_out
            .retain(|_, (at, _)| ms.saturating_sub(*at) <= self.config.udp_reply_window_ms);
        self.echo_seen
            .retain(|_, (at, _)| ms.saturating_sub(*at) <= self.config.echo_window_ms);
        let max = self
            .config
            .correlation_window_ms
            .max(self.config.access_aggregate_ms)
            .max(self.config.attempt_idle_ms);
        let episodes = &mut self.episodes;
        let config = &self.config;
        self.windows.retain(|key, q| {
            let (window, threshold, distinct) = if key.starts_with("repeat:") {
                (config.repeat_window_ms, config.repeat_attempts, false)
            } else if key.starts_with("echo_probe_review:") {
                (config.echo_window_ms, config.echo_requests, false)
            } else {
                (config.scan_window_ms, config.scan_distinct_ports, true)
            };
            q.retain(|h| ms.saturating_sub(h.at) <= window);
            let count = if distinct {
                q.iter().map(|h| h.port).collect::<BTreeSet<_>>().len()
            } else {
                q.len()
            };
            if count < threshold {
                episodes.remove(key);
            }
            !q.is_empty()
        });
        self.episodes
            .retain(|_, e| ms.saturating_sub(e.last) <= max);
        self.probes
            .retain(|_, e| ms.saturating_sub(e.last) <= self.config.correlation_window_ms);
        out
    }
}

fn source_category(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(a) if a.is_loopback() => "loopback",
        IpAddr::V4(a) if a.is_private() => "private",
        IpAddr::V4(a) if a.is_link_local() => "link_local",
        IpAddr::V4(a) if a.is_multicast() => "multicast",
        IpAddr::V4(a) if a.is_unspecified() => "unspecified",
        IpAddr::V4(a)
            if a.is_documentation()
                || a.is_broadcast()
                || a.octets()[0] == 0
                || a.octets()[0] >= 240
                || (a.octets()[0] == 198 && (a.octets()[1] == 18 || a.octets()[1] == 19)) =>
        {
            "unknown"
        }
        IpAddr::V4(_) => "global_address",
        IpAddr::V6(a) if a.to_ipv4_mapped().is_some() => a
            .to_ipv4_mapped()
            .map(|v| source_category(IpAddr::V4(v)))
            .unwrap_or("unknown"),
        IpAddr::V6(a) if a.is_loopback() => "loopback",
        IpAddr::V6(a) if a.is_unique_local() => "private",
        IpAddr::V6(a) if a.is_unicast_link_local() => "link_local",
        IpAddr::V6(a) if a.is_multicast() => "multicast",
        IpAddr::V6(a) if a.is_unspecified() => "unspecified",
        IpAddr::V6(a) if a.segments()[0] == 0x2001 && a.segments()[1] == 0xdb8 => "unknown",
        IpAddr::V6(a) if (a.segments()[0] & 0xe000) == 0x2000 => "global_address",
        IpAddr::V6(_) => "unknown",
    }
}
