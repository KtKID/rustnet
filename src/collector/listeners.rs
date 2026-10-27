//! Listener changes over successful in-process socket inventories.

use anyhow::Result;
use rustnet_host::{HostSocket, HostSocketState, HostTcpState};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct Tracker {
    previous: BTreeMap<String, (Value, String)>,
    initialized: bool,
    run_id: String,
    uid: u32,
    scan_id: u64,
}
impl Tracker {
    pub fn new(run_id: String, uid: u32) -> Self {
        Self {
            previous: BTreeMap::new(),
            initialized: false,
            run_id,
            uid,
            scan_id: 0,
        }
    }
    pub fn update(
        &mut self,
        sockets: &[HostSocket],
        timestamp: &str,
        complete: bool,
    ) -> Result<Vec<Value>> {
        self.scan_id += 1;
        if !complete {
            return Ok(Vec::new());
        }
        let mut current = BTreeMap::new();
        for socket in sockets {
            if socket.state != HostSocketState::Tcp(HostTcpState::Listen) {
                continue;
            }
            let Some(owner) = &socket.owner else {
                continue;
            };
            if owner.uid != Some(self.uid) {
                continue;
            }
            let family = if socket.local_addr.is_ipv4() {
                "IPv4"
            } else {
                "IPv6"
            };
            let record = json!({"protocol":"TCP","address_family":family,"local_address":socket.local_addr.ip().to_string(),
                "port":socket.local_addr.port(),"pid":owner.pid,"process_name":owner.name,"uid":self.uid});
            let identity = json!([
                owner.pid,
                self.uid,
                "TCP",
                family,
                socket.local_addr.ip().to_string(),
                socket.local_addr.port()
            ])
            .to_string();
            current.insert(identity, (record, timestamp.to_string()));
        }
        let common = |record: &Value, status: &str, initial: bool, last: Option<&str>| {
            let mut event = record.clone();
            let map = event.as_object_mut().unwrap();
            map.insert("schema_version".into(), json!(1));
            map.insert("timestamp".into(), json!(timestamp));
            map.insert("run_id".into(), json!(self.run_id));
            map.insert("scan_id".into(), json!(self.scan_id));
            map.insert("scope".into(), json!("current_user"));
            map.insert("status".into(), json!(status));
            map.insert("initial".into(), json!(initial));
            if let Some(last) = last {
                map.insert("last_seen_at".into(), json!(last));
            }
            event
        };
        let mut events = Vec::new();
        for (key, (record, seen)) in &self.previous {
            if !current.contains_key(key) {
                events.push(common(record, "removed", false, Some(seen)));
            }
        }
        for (key, (record, _)) in &current {
            if !self.previous.contains_key(key) {
                events.push(common(record, "added", !self.initialized, None));
            }
        }
        self.previous = current;
        self.initialized = true;
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::Protocol;
    use rustnet_host::SocketOwner;
    #[test]
    fn failed_scans_preserve_baseline_and_empty_success_removes() {
        let listener = HostSocket {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1:5678".parse().unwrap(),
            remote_addr: None,
            state: HostSocketState::Tcp(HostTcpState::Listen),
            owner: Some(SocketOwner::new(42, "app", Some(501))),
            native_id: Some(1),
        };
        let mut tracker = Tracker::new(uuid::Uuid::new_v4().to_string(), 501);
        let first = tracker
            .update(
                std::slice::from_ref(&listener),
                "2026-10-27T12:00:00.000+08:00",
                true,
            )
            .unwrap();
        assert_eq!(first[0]["initial"], true);
        assert!(
            tracker
                .update(&[], "2026-10-27T12:00:01.000+08:00", false)
                .unwrap()
                .is_empty()
        );
        assert!(
            tracker
                .update(&[listener], "2026-10-27T12:00:02.000+08:00", true)
                .unwrap()
                .is_empty()
        );
        let removed = tracker
            .update(&[], "2026-10-27T12:00:03.000+08:00", true)
            .unwrap();
        assert_eq!(removed[0]["status"], "removed");
        assert_eq!(removed[0]["last_seen_at"], "2026-10-27T12:00:02.000+08:00");
        assert_eq!(removed[0]["scan_id"], 4);
    }
}
