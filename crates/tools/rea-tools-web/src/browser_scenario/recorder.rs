//! Arrival-ordered scenario event capture with current-step attribution.
//!
//! Compatibility owner: `src/browser/PlaywrightScenarioEvents.ts` (event
//! admission, allocation accounting, omissions and limitations). Events are
//! fed by the CDP dispatcher in receipt order; each retained event is
//! projected in its schema's key order.
use super::input::Limits;
use super::secrets::Secrets;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// `MAX_LISTENER_OWNERS`.
pub(crate) const MAX_LISTENER_OWNERS: usize = 2048;

/// `allocationCost`: UTF-16 storage and worst-case JSON escaping.
pub(crate) fn allocation_cost(value: &Value, remaining: i64) -> i64 {
    match value {
        Value::String(text) => text.encode_utf16().count() as i64 * 8 + 2,
        Value::Object(map) => {
            let mut cost: i64 = 2;
            for (key, item) in map {
                cost += key.encode_utf16().count() as i64 * 8
                    + 4
                    + allocation_cost(item, remaining - cost);
                if cost > remaining {
                    break;
                }
            }
            cost
        }
        Value::Array(items) => {
            let mut cost: i64 = 2;
            for (index, item) in items.iter().enumerate() {
                cost += index.to_string().len() as i64 * 8
                    + 4
                    + allocation_cost(item, remaining - cost);
                if cost > remaining {
                    break;
                }
            }
            cost
        }
        _ => 32,
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Admission {
    Retained(u64),
    Omitted { reason: &'static str },
}

impl Admission {
    pub(crate) fn retained(&self) -> bool {
        matches!(self, Self::Retained(_))
    }
}

/// Selected event families (`capture.events`, widened by network content).
#[derive(Clone, Debug, Default)]
pub(crate) struct Families {
    pub enabled: BTreeSet<String>,
}

impl Families {
    pub(crate) fn has(&self, family: &str) -> bool {
        self.enabled.contains(family)
    }
}

pub(crate) struct Recorder {
    pub limits: Limits,
    pub families: Families,
    pub owns_context: bool,
    items: Vec<Value>,
    retained_cost: i64,
    dropped: u64,
    omitted_kinds: BTreeMap<String, (u64, BTreeSet<&'static str>)>,
    omitted_network: BTreeMap<String, (BTreeSet<String>, BTreeSet<&'static str>)>,
    step_index: u64,
    sequence: u64,
    pub incomplete_families: BTreeSet<String>,
    pub listener_owners: usize,
    pub sealed: bool,
    /// Scenario listeners exist (`new PlaywrightScenarioEvents`); producer
    /// activity before that, such as console replay on attach, is unobserved.
    pub listening: bool,
}

impl Recorder {
    pub(crate) fn new(limits: Limits, families: Families, owns_context: bool) -> Self {
        Self {
            limits,
            families,
            owns_context,
            items: Vec::new(),
            retained_cost: 0,
            dropped: 0,
            omitted_kinds: BTreeMap::new(),
            omitted_network: BTreeMap::new(),
            step_index: 0,
            sequence: 0,
            incomplete_families: BTreeSet::new(),
            listener_owners: 0,
            sealed: false,
            listening: false,
        }
    }

    pub(crate) fn set_step(&mut self, index: u64) {
        self.step_index = index;
    }

    pub(crate) fn next_sequence(&self) -> u64 {
        self.sequence + 1
    }

    pub(crate) fn last_sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn items(&self) -> &[Value] {
        &self.items
    }

    fn admission_reason(&self, cost: i64) -> Option<&'static str> {
        if self.sealed || self.items.len() as u64 >= self.limits.max_events {
            return Some("max-events");
        }
        if cost > self.limits.max_event_allocation_bytes as i64 {
            return Some("max-event-allocation-bytes");
        }
        if cost > self.limits.max_total_event_allocation_bytes as i64 - self.retained_cost {
            return Some("max-total-event-allocation-bytes");
        }
        None
    }

    /// `push`: `fields` are the event's schema fields after `sequence` and
    /// `step_index`, in schema order.
    pub(crate) fn push(&mut self, kind: &str, fields: Vec<(&str, Value)>) -> Admission {
        self.sequence += 1;
        let mut unindexed = Map::new();
        for (key, value) in &fields {
            unindexed.insert((*key).to_owned(), value.clone());
        }
        unindexed.insert("kind".into(), Value::String(kind.to_owned()));
        let cost = allocation_cost(
            &Value::Object(unindexed),
            self.limits.max_event_allocation_bytes as i64,
        ) + 128;
        let reason = self.admission_reason(cost);
        if self.sealed || reason.is_some() {
            let reason = reason.unwrap_or("max-events");
            self.omit_event(kind, reason);
            return Admission::Omitted { reason };
        }
        self.retained_cost += cost;
        let mut event = Map::new();
        event.insert("sequence".into(), json!(self.sequence));
        event.insert("step_index".into(), json!(self.step_index));
        for (key, value) in fields {
            event.insert(key.to_owned(), value);
        }
        if !event.contains_key("kind") {
            event.insert("kind".into(), Value::String(kind.to_owned()));
        }
        self.items.push(Value::Object(event));
        Admission::Retained(self.sequence)
    }

    /// `admitText` / `admitProducerText`.
    pub(crate) fn admit_text(
        &mut self,
        secrets: &Secrets,
        kind: &str,
        values: &[&str],
        network_metadata: bool,
    ) -> Admission {
        let mut cost: i64 = 4096;
        for value in values {
            cost += secrets.redaction_cost_of(value) as i64;
        }
        let reason = if network_metadata
            && cost > self.limits.max_network_metadata_allocation_bytes as i64
        {
            Some("max-network-metadata-allocation-bytes")
        } else {
            self.admission_reason(cost)
        };
        if let Some(reason) = reason {
            self.sequence += 1;
            self.omit_event(kind, reason);
            return Admission::Omitted { reason };
        }
        Admission::Retained(self.sequence + 1)
    }

    /// `admitContentBody`.
    pub(crate) fn admit_content_body(
        &mut self,
        secrets: &Secrets,
        transaction_id: &str,
        source_sequence: u64,
        phase: &str,
        headers: &Value,
        observed_bytes: u64,
        allocation_bytes: i64,
        media_type: Option<&str>,
    ) -> Admission {
        let probe = json!({
            "kind": "network-content",
            "sequence": self.sequence + 1,
            "step_index": self.step_index,
            "transaction_id": transaction_id,
            "source_event_sequence": source_sequence,
            "phase": phase,
            "headers": headers,
            "body": {
                "state": "captured",
                "representation": if phase == "request" { "browser-exposed-request-bytes" } else { "playwright-response-body-bytes" },
                "encoding": "base64",
                "content": null,
                "bytes": observed_bytes,
                "sha256": "0".repeat(64),
                "media_type": null,
                "redacted": false,
            },
        });
        let media = media_type
            .map(|media| {
                let length = media.encode_utf16().count();
                ((length * 8 + 2) as i64).max(secrets.redaction_allocation_cost(length) as i64)
            })
            .unwrap_or(0);
        let cost = allocation_cost(&probe, self.limits.max_event_allocation_bytes as i64) - 64
            + allocation_bytes
            + media
            + 128;
        if let Some(reason) = self.admission_reason(cost) {
            self.sequence += 1;
            self.omit_event("network-content", reason);
            return Admission::Omitted { reason };
        }
        Admission::Retained(self.sequence + 1)
    }

    pub(crate) fn omit_event(&mut self, kind: &str, reason: &'static str) {
        self.dropped += 1;
        let entry = self.omitted_kinds.entry(kind.to_owned()).or_default();
        entry.0 += 1;
        entry.1.insert(reason);
    }

    pub(crate) fn omit_network(&mut self, transaction_id: &str, kind: &str, reason: &'static str) {
        let entry = self
            .omitted_network
            .entry(transaction_id.to_owned())
            .or_default();
        entry.0.insert(kind.to_owned());
        entry.1.insert(reason);
    }

    /// `admitOwner`.
    pub(crate) fn admit_owner(&mut self, kind: &str) -> bool {
        if self.listener_owners < MAX_LISTENER_OWNERS {
            self.listener_owners += 1;
            return true;
        }
        self.sequence += 1;
        self.omit_event(kind, "max-listener-owners");
        false
    }

    /// `limitations()` excluding network collector gaps, which the caller adds.
    pub(crate) fn limitations(&self, network_gaps: Vec<String>) -> Vec<String> {
        let mut gaps: Vec<String> = self
            .incomplete_families
            .iter()
            .map(|family| format!("Popup {family} events before Page discovery are unavailable; later events are retained."))
            .collect();
        gaps.extend(network_gaps);
        if self.dropped > 0 {
            gaps.push("Browser event collection reached a selected resource budget; per-kind omissions and affected network transaction IDs are listed in events.omissions, and event coverage is incomplete.".to_owned());
        }
        if self.families.has("network") && !self.owns_context {
            let mut shared = vec!["Shared-context network capture excludes requests without a known root or descendant Page frame.".to_owned()];
            shared.extend(gaps);
            return shared;
        }
        gaps
    }

    /// `result()`.
    pub(crate) fn result(&self, transaction_range: Value) -> Value {
        let by_kind: Vec<Value> = self
            .omitted_kinds
            .iter()
            .map(|(kind, (count, reasons))| json!({ "kind": kind, "count": count, "reasons": reasons.iter().collect::<Vec<_>>() }))
            .collect();
        let network: Vec<Value> = self
            .omitted_network
            .iter()
            .map(|(id, (kinds, reasons))| {
                json!({ "transaction_id": id, "omitted_kinds": kinds.iter().collect::<Vec<_>>(), "reasons": reasons.iter().collect::<Vec<_>>() })
            })
            .collect();
        json!({
            "retained": self.items.len(),
            "dropped": self.dropped,
            "items": self.items,
            "omissions": {
                "by_kind": by_kind,
                "network_transactions": network,
                "network_transaction_range": transaction_range,
            },
        })
    }
}
