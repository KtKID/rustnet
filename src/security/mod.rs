//! Passive inbound observation and evidence storage inside the existing collector.
pub mod ingress;
pub mod journal;
pub mod protocol;
#[cfg(test)]
mod tests;
use anyhow::{Context, Result};
use crossbeam::channel::{RecvTimeoutError, Sender, bounded};
use protocol::*;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};
enum Message {
    Packet(Box<PacketFact>, SystemTime),
    Listeners(Vec<std::net::SocketAddr>),
    Finish,
}
#[derive(Clone, Debug)]
pub struct SecuritySink {
    tx: Sender<Message>,
    dropped: Arc<AtomicU64>,
}
impl SecuritySink {
    pub fn observe(&self, p: PacketFact) {
        self.observe_captured(p, SystemTime::now());
    }
    pub fn observe_captured(&self, p: PacketFact, at: SystemTime) {
        if self.tx.try_send(Message::Packet(Box::new(p), at)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn listeners(&self, values: Vec<std::net::SocketAddr>) {
        if self.tx.try_send(Message::Listeners(values)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}
pub struct SecurityRuntime {
    pub sink: SecuritySink,
    worker: Option<JoinHandle<Result<()>>>,
}
impl SecurityRuntime {
    pub fn start(
        root: &Path,
        config: SecurityConfig,
        run: String,
        scope: String,
        diagnostic: Arc<dyn Fn(String) + Send + Sync>,
    ) -> Result<Self> {
        config.validate()?;
        let mut journal = journal::Journal::open(root, run.clone(), config.storage.clone())?;
        journal.commit(vec![Item::RunLifecycle(Lifecycle {
            run_id: run.clone(),
            observed_at: now(),
            reason: "observation_started".into(),
        })])?;
        let (tx, rx) = bounded(config.runtime.queue_capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let loss = Arc::clone(&dropped);
        let start = SystemTime::now();
        let worker = thread::Builder::new()
            .name("collector_security".into())
            .spawn(move || {
                let result = (|| -> Result<()> {
                    let mut tracker = ingress::IngressTracker::new(
                        config.ingress,
                        run.clone(),
                        scope,
                        config.runtime.active_attempt_limit,
                    );
                    let mut pending = Vec::new();
                    let mut flushed = Instant::now();
                    let mut advanced_ms = 0u64;
                    let tick = Duration::from_millis(config.runtime.tick_ms);
                    let elapsed_ms = |at: SystemTime| {
                        at.duration_since(start).unwrap_or_default().as_millis() as u64
                    };
                    loop {
                        let (finish, clock) = match rx.recv_timeout(tick) {
                            Ok(Message::Packet(p, at)) => {
                                let timestamp: chrono::DateTime<chrono::Local> = at.into();
                                pending.extend(tracker.observe(
                                    *p,
                                    elapsed_ms(at),
                                    timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, false),
                                ));
                                (false, Some(at))
                            }
                            Ok(Message::Listeners(endpoints)) => {
                                tracker.set_listeners(endpoints);
                                (false, None)
                            }
                            Ok(Message::Finish) | Err(RecvTimeoutError::Disconnected) => {
                                (true, Some(SystemTime::now()))
                            }
                            Err(RecvTimeoutError::Timeout) => (false, Some(SystemTime::now())),
                        };
                        // A busy queue advances with packet capture time, so
                        // processing delay cannot expire earlier queued hits.
                        // An idle queue and normal shutdown advance with now.
                        if let Some(at) = clock {
                            let ms = elapsed_ms(at);
                            if finish || ms.saturating_sub(advanced_ms) >= config.runtime.tick_ms {
                                let timestamp: chrono::DateTime<chrono::Local> = at.into();
                                pending.extend(tracker.advance(
                                    ms,
                                    timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, false),
                                ));
                                advanced_ms = advanced_ms.max(ms);
                            }
                        }
                        let losses = loss.swap(0, Ordering::Relaxed);
                        if losses > 0 {
                            pending.push(Item::HealthObservation(Health {
                                source_id: "security_pipeline".into(),
                                state: "degraded".into(),
                                observed_at: now(),
                                lost_records: losses.to_string(),
                                reason: "queue_capacity_exceeded".into(),
                            }));
                        }
                        if finish {
                            pending.push(Item::RunLifecycle(Lifecycle {
                                run_id: run.clone(),
                                observed_at: now(),
                                reason: "observation_stopped".into(),
                            }));
                        }
                        if !pending.is_empty()
                            && (finish
                                || pending.len() >= 32
                                || flushed.elapsed()
                                    >= Duration::from_millis(config.runtime.commit_interval_ms))
                        {
                            // Each producer group remains together; small bounded batches avoid huge records.
                            journal.commit(std::mem::take(&mut pending))?;
                            flushed = Instant::now();
                        }
                        if finish {
                            break;
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = &result {
                    diagnostic(format!("security_pipeline_failed: {error:#}"));
                }
                result
            })?;
        Ok(Self {
            sink: SecuritySink { tx, dropped },
            worker: Some(worker),
        })
    }
    pub fn finish(mut self) -> Result<()> {
        let _ = self.sink.tx.send(Message::Finish);
        self.worker
            .take()
            .context("security worker")?
            .join()
            .map_err(|_| anyhow::anyhow!("security worker panicked"))?
    }
}
impl Drop for SecurityRuntime {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = self.sink.tx.send(Message::Finish);
            let _ = worker.join();
        }
    }
}
impl PacketFact {
    pub fn from_parsed(
        p: &crate::network::parser::ParsedPacket,
        interface: Option<String>,
    ) -> Option<Self> {
        use crate::network::types::{Protocol, ProtocolState};
        let protocol = match p.protocol {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => {
                if p.local_addr.is_ipv6() {
                    "ICMPv6"
                } else {
                    "ICMP"
                }
            }
            _ => return None,
        };
        let (source, target, source_local, target_local) = if p.is_outgoing {
            (
                p.local_addr,
                p.remote_addr,
                p.local_is_local,
                p.remote_is_local,
            )
        } else {
            (
                p.remote_addr,
                p.local_addr,
                p.remote_is_local,
                p.local_is_local,
            )
        };
        let (icmp_type, echo_id, echo_seq) = match p.protocol_state {
            ProtocolState::Icmp {
                icmp_type,
                icmp_id,
                icmp_sequence,
                ..
            } => (Some(icmp_type), icmp_id, icmp_sequence),
            _ => (None, None, None),
        };
        let quoted = p
            .icmp_error
            .as_ref()
            .and_then(|e| e.quoted_connection)
            .map(|q| (q.local_addr, q.remote_addr));
        let tcp = p.tcp_header;
        Some(Self {
            source,
            target,
            source_local,
            target_local,
            protocol: protocol.into(),
            interface: p.observed_interface.clone().or(interface),
            seq: tcp.map(|t| t.seq).unwrap_or(0),
            ack: tcp.map(|t| t.ack).unwrap_or(0),
            syn: tcp.is_some_and(|t| t.flags.syn),
            ack_flag: tcp.is_some_and(|t| t.flags.ack),
            rst: tcp.is_some_and(|t| t.flags.rst),
            fin: tcp.is_some_and(|t| t.flags.fin),
            payload_len: tcp.map(|t| t.payload_len).unwrap_or(0),
            bytes: p.packet_len as u64,
            icmp_type,
            icmp_code: p.icmp_error.as_ref().map(|e| e.error.code),
            echo_id,
            echo_seq,
            quoted,
            pid: p.process_id,
            process_name: p.process_name.clone(),
        })
    }
}
