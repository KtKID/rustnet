//! rustnet-delta-v1, interoperable with the existing TypeScript decoder.

use anyhow::{Result, ensure};
use serde_json::{Value, json};

pub struct Encoder {
    previous: Option<Value>,
    index: u64,
    interval: u64,
}
impl Encoder {
    pub fn new(interval: u64) -> Self {
        Self {
            previous: None,
            index: 0,
            interval,
        }
    }
    pub fn encode(&mut self, snapshot: &Value) -> Result<Value> {
        let connections = snapshot["connections"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("snapshot connections must be an array"))?;
        let mut table = serde_json::Map::new();
        let mut order = Vec::new();
        let mut duplicate = false;
        for connection in connections {
            let id = connection["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("connection ID must be a string"))?;
            duplicate |= table.insert(id.to_string(), connection.clone()).is_some();
            order.push(id.to_string());
        }
        let state = if duplicate {
            json!({"mode":"raw", "value":snapshot})
        } else {
            let mut envelope = snapshot
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("snapshot must be an object"))?
                .clone();
            envelope.remove("connections");
            json!({"mode":"keyed", "envelope":envelope, "order":order, "connections":table})
        };
        let checkpoint = json!({"storage_format":"rustnet-delta-v1", "index":self.index, "kind":"checkpoint", "value":state});
        let mut frame = checkpoint.clone();
        if !self.index.is_multiple_of(self.interval)
            && let Some(previous) = &self.previous
        {
            let mut operations = Vec::new();
            difference(previous, &state, &[], &mut operations);
            let patch = json!({"storage_format":"rustnet-delta-v1", "index":self.index, "kind":"patch", "ops":operations});
            if serde_json::to_vec(&patch)?.len() < serde_json::to_vec(&checkpoint)?.len() {
                frame = patch;
            }
        }
        let mut restored = self.previous.clone().unwrap_or(Value::Null);
        if frame["kind"] == "checkpoint" {
            restored = frame["value"].clone();
        } else {
            for operation in frame["ops"].as_array().unwrap() {
                apply(&mut restored, operation)?;
            }
        }
        ensure!(
            restored == state && restore(&restored)? == *snapshot,
            "snapshot round-trip mismatch"
        );
        self.previous = Some(restored);
        self.index += 1;
        Ok(frame)
    }
}

fn difference(before: &Value, after: &Value, path: &[String], output: &mut Vec<Value>) {
    if let (Some(old), Some(new)) = (before.as_object(), after.as_object()) {
        for key in old.keys().filter(|key| !new.contains_key(*key)) {
            let mut nested = path.to_vec();
            nested.push(key.clone());
            output.push(json!(["delete", nested]));
        }
        for (key, value) in new {
            let mut nested = path.to_vec();
            nested.push(key.clone());
            if let Some(previous) = old.get(key) {
                difference(previous, value, &nested, output);
            } else {
                output.push(json!(["set", nested, value]));
            }
        }
    } else if before != after {
        output.push(json!(["set", path, after]));
    }
}

fn apply(target: &mut Value, operation: &Value) -> Result<()> {
    let path = operation[1]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid patch path"))?;
    if path.is_empty() {
        ensure!(operation[0] == "set", "invalid root deletion");
        *target = operation[2].clone();
        return Ok(());
    }
    let mut current = target;
    for item in &path[..path.len() - 1] {
        current = current
            .get_mut(
                item.as_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid patch key"))?,
            )
            .ok_or_else(|| anyhow::anyhow!("missing patch parent"))?;
    }
    let map = current
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("patch parent is not an object"))?;
    let key = path
        .last()
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("invalid patch leaf"))?;
    if operation[0] == "set" {
        map.insert(key.to_string(), operation[2].clone());
    } else {
        ensure!(map.remove(key).is_some(), "missing patch deletion");
    }
    Ok(())
}

fn restore(state: &Value) -> Result<Value> {
    if state["mode"] == "raw" {
        return Ok(state["value"].clone());
    }
    let mut result = state["envelope"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid envelope"))?
        .clone();
    let connections = state["order"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid order"))?
        .iter()
        .map(|id| state["connections"][id.as_str().unwrap()].clone())
        .collect();
    result.insert("connections".into(), Value::Array(connections));
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_frames_match_the_shared_interop_fixture() {
        let template: Value =
            serde_json::from_str(include_str!("../../../web/tests/fixtures/snapshot.json"))
                .unwrap();
        let traffic: Value = serde_json::from_str(include_str!(
            "../../../web/tests/fixtures/process-traffic.json"
        ))
        .unwrap();
        let mut a = traffic["connections"][0].clone();
        a["id"] = json!("a");
        a["test_padding"] = json!("x".repeat(512));
        let mut b = a.clone();
        b["id"] = json!("b");
        let mut encoder = Encoder::new(3);
        let mut cases = Vec::new();
        for index in 0..8 {
            let mut source = template.clone();
            source["runtime"]["snapshot_generation"] = json!(index);
            source["connections"] = match index {
                2 => json!([b.clone(), a.clone()]),
                3 | 7 => json!([a.clone()]),
                4 => json!([a.clone(), a.clone()]),
                _ => json!([a.clone(), b.clone()]),
            };
            source["connection_count"] = json!(source["connections"].as_array().unwrap().len());
            if index < 7 {
                source["test_optional"] = json!({"value":index,"nullable":null});
            }
            cases.push(json!({"source":source,"frame":encoder.encode(&source).unwrap()}));
        }
        assert_eq!(cases[7]["frame"]["kind"], "patch");
        assert!(
            cases[7]["frame"]["ops"]
                .as_array()
                .unwrap()
                .iter()
                .any(|op| op[0] == "delete")
        );
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../web/tests/fixtures/native-codec.json");
        if std::env::var_os("X_COLLECTOR_WRITE_CODEC_FIXTURE").is_some() {
            std::fs::write(&path, serde_json::to_vec_pretty(&cases).unwrap()).unwrap();
        }
        let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(fixture, json!(cases));
    }

    #[test]
    fn roundtrips_changes_deletion_order_duplicates_and_checkpoints() {
        let mut encoder = Encoder::new(3);
        let first = json!({"connections":[{"id":"a", "payload":"x".repeat(1000)}, {"id":"b"}], "version":1});
        assert_eq!(encoder.encode(&first).unwrap()["kind"], "checkpoint");
        let mut next = first.clone();
        next["version"] = json!(2);
        assert_eq!(encoder.encode(&next).unwrap()["kind"], "patch");
        next["connections"] = json!([{"id":"b"}]);
        encoder.encode(&next).unwrap();
        assert_eq!(encoder.encode(&next).unwrap()["kind"], "checkpoint");
        next["connections"] = json!([{"id":"a"}, {"id":"a"}]);
        encoder.encode(&next).unwrap();
    }
}
