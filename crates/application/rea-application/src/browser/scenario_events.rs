//! Bounded event retention for browser scenario captures.
//!
//! Sequence numbers advance for omitted events as well as retained events.
//! This preserves arrival identity while the omission ledger makes resource
//! limits and incomplete coverage explicit to callers.

use rea_core::failure::{Detail, Failure};
use rea_host::cdp_transport::CdpEventBatch;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "capture_browser_scenario_events";

#[derive(Debug, Clone, Copy)]
pub struct EventLimits {
    pub max_events: usize,
    pub max_event_bytes: usize,
    pub max_total_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventAdmission {
    pub status: &'static str,
    pub sequence: u64,
    pub reason: Option<&'static str>,
}

#[derive(Debug)]
pub struct EventLedger {
    limits: EventLimits,
    items: Vec<Value>,
    omitted: BTreeMap<String, Omission>,
    omitted_network: BTreeMap<String, NetworkOmission>,
    retained_bytes: usize,
    sequence: u64,
    sealed: bool,
}

#[derive(Debug)]
struct Omission {
    count: u64,
    reasons: BTreeSet<String>,
}

#[derive(Debug)]
struct NetworkOmission {
    kinds: BTreeSet<String>,
    reasons: BTreeSet<String>,
}

impl EventLedger {
    pub fn new(limits: EventLimits) -> Self {
        Self {
            limits,
            items: Vec::new(),
            omitted: BTreeMap::new(),
            omitted_network: BTreeMap::new(),
            retained_bytes: 0,
            sequence: 0,
            sealed: false,
        }
    }

    pub fn admit(
        &mut self,
        kind: &str,
        step_index: u64,
        payload: Value,
    ) -> Result<EventAdmission, Failure> {
        let sequence = self.sequence.saturating_add(1);
        self.admit_at_sequence(kind, step_index, payload, sequence)
    }

    fn admit_at_sequence(
        &mut self,
        kind: &str,
        step_index: u64,
        payload: Value,
        sequence: u64,
    ) -> Result<EventAdmission, Failure> {
        if kind.is_empty() {
            return Err(invalid("event kind must be a non-empty string"));
        }
        let payload = payload
            .as_object()
            .ok_or_else(|| invalid("event payload must be an object"))?;

        let sequence = sequence.max(self.sequence.saturating_add(1));
        self.sequence = sequence;
        let estimated_bytes = serde_json::to_vec(&payload)
            .map(|bytes| bytes.len().saturating_add(128))
            .unwrap_or(usize::MAX);
        let reason = if self.sealed {
            Some("sealed")
        } else if self.items.len() >= self.limits.max_events {
            Some("max-events")
        } else if estimated_bytes > self.limits.max_event_bytes {
            Some("max-event-allocation-bytes")
        } else if estimated_bytes
            > self
                .limits
                .max_total_bytes
                .saturating_sub(self.retained_bytes)
        {
            Some("max-total-event-allocation-bytes")
        } else {
            None
        };

        if let Some(reason) = reason {
            self.record_omission(kind, reason);
            return Ok(EventAdmission {
                status: "omitted",
                sequence,
                reason: Some(reason),
            });
        }

        let mut event = Map::new();
        event.extend(payload.clone());
        event.insert("kind".into(), Value::String(kind.into()));
        event.insert("sequence".into(), json!(sequence));
        event.insert("step_index".into(), json!(step_index));
        self.retained_bytes = self.retained_bytes.saturating_add(estimated_bytes);
        self.items.push(Value::Object(event));

        Ok(EventAdmission {
            status: "retained",
            sequence,
            reason: None,
        })
    }

    /// Admit events from the host CDP transport while preserving its sequence.
    pub fn admit_cdp_batch(
        &mut self,
        step_index: u64,
        batch: CdpEventBatch,
    ) -> Result<(), Failure> {
        for event in batch.items {
            let kind = event
                .value
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("cdp")
                .to_owned();
            self.admit_at_sequence(&kind, step_index, event.value, event.sequence)?;
        }
        if batch.dropped > 0 {
            self.record_transport_omissions(step_index, batch.dropped);
        }
        Ok(())
    }

    fn record_transport_omissions(&mut self, _step_index: u64, count: u64) {
        for _ in 0..count {
            self.sequence = self.sequence.saturating_add(1);
            self.record_omission("cdp", "transport-overflow");
        }
    }

    pub fn seal(&mut self) {
        self.sealed = true;
    }

    /// Admit a network event while retaining transaction identity when the
    /// event is omitted by a bound. This keeps incomplete transaction
    /// coverage distinguishable from an absent transaction.
    pub fn admit_network(
        &mut self,
        transaction_id: &str,
        kind: &str,
        step_index: u64,
        payload: Value,
    ) -> Result<EventAdmission, Failure> {
        if transaction_id.is_empty() {
            return Err(invalid("network transaction ID must be non-empty"));
        }
        let admission = self.admit(kind, step_index, payload)?;
        if let Some(reason) = admission.reason {
            let omission = self
                .omitted_network
                .entry(transaction_id.into())
                .or_insert_with(|| NetworkOmission {
                    kinds: BTreeSet::new(),
                    reasons: BTreeSet::new(),
                });
            omission.kinds.insert(kind.into());
            omission.reasons.insert(reason.into());
        }
        Ok(admission)
    }

    pub fn result(&self, cancelled: bool) -> Value {
        let dropped = self
            .omitted
            .values()
            .map(|omission| omission.count)
            .sum::<u64>();
        let by_kind = self
            .omitted
            .iter()
            .map(|(kind, omission)| {
                json!({
                    "kind": kind,
                    "count": omission.count,
                    "reasons": omission.reasons.iter().collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        let network_transactions = self
            .omitted_network
            .iter()
            .map(|(transaction_id, omission)| {
                json!({
                    "transaction_id": transaction_id,
                    "omitted_kinds": omission.kinds.iter().collect::<Vec<_>>(),
                    "reasons": omission.reasons.iter().collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        let mut missing_sections = Vec::new();
        let mut truncated_sections = Vec::new();
        if cancelled {
            missing_sections.push("events");
        }
        if dropped > 0 {
            truncated_sections.push("events");
        }

        json!({
            "retained": self.items.len(),
            "dropped": dropped,
            "items": self.items,
            "omissions": {
                "by_kind": by_kind,
                "network_transactions": network_transactions,
                "network_transaction_range": null,
            },
            "limitations": if dropped > 0 {
                vec!["Browser event collection reached a selected resource budget; event coverage is incomplete."]
            } else {
                Vec::<&str>::new()
            },
            "completeness": {
                "missing_sections": missing_sections,
                "truncated_sections": truncated_sections,
            },
        })
    }

    fn record_omission(&mut self, kind: &str, reason: &str) {
        let omission = self.omitted.entry(kind.into()).or_insert_with(|| Omission {
            count: 0,
            reasons: BTreeSet::new(),
        });
        omission.count = omission.count.saturating_add(1);
        omission.reasons.insert(reason.into());
    }
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a named event kind and an object payload.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_host::cdp_transport::{CdpEvent, CdpEventBatch};

    #[test]
    fn omitted_events_keep_sequence_and_kind_reason_provenance() {
        let mut ledger = EventLedger::new(EventLimits {
            max_events: 1,
            max_event_bytes: 4096,
            max_total_bytes: 4096,
        });
        let first = ledger
            .admit("console", 1, json!({"text": "ready"}))
            .unwrap();
        let second = ledger
            .admit("network", 1, json!({"url": "https://example.test/"}))
            .unwrap();

        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        assert_eq!(second.status, "omitted");
        assert_eq!(second.reason, Some("max-events"));

        let result = ledger.result(false);
        assert_eq!(result["retained"], 1);
        assert_eq!(result["dropped"], 1);
        assert_eq!(result["omissions"]["by_kind"][0]["kind"], "network");
        assert_eq!(
            result["completeness"]["truncated_sections"],
            json!(["events"])
        );
    }

    #[test]
    fn sealed_ledger_omits_late_events_without_losing_identity() {
        let mut ledger = EventLedger::new(EventLimits {
            max_events: 4,
            max_event_bytes: 4096,
            max_total_bytes: 4096,
        });
        ledger.seal();
        let admission = ledger.admit("console", 2, json!({"text": "late"})).unwrap();

        assert_eq!(admission.sequence, 1);
        assert_eq!(admission.reason, Some("sealed"));
        assert_eq!(ledger.result(false)["dropped"], 1);
    }

    #[test]
    fn cancellation_marks_event_coverage_missing_separately_from_budget_truncation() {
        let ledger = EventLedger::new(EventLimits {
            max_events: 4,
            max_event_bytes: 4096,
            max_total_bytes: 4096,
        });
        let result = ledger.result(true);

        assert_eq!(
            result["completeness"]["missing_sections"],
            json!(["events"])
        );
        assert_eq!(result["completeness"]["truncated_sections"], json!([]));
        assert_eq!(result["omissions"]["network_transactions"], json!([]));
        assert_eq!(
            result["omissions"]["network_transaction_range"],
            json!(null)
        );
    }

    #[test]
    fn oversized_event_has_single_allocation_omission_reason() {
        let mut ledger = EventLedger::new(EventLimits {
            max_events: 4,
            max_event_bytes: 128,
            max_total_bytes: 4096,
        });
        let admission = ledger
            .admit(
                "console",
                1,
                json!({"text": "event larger than its individual budget"}),
            )
            .expect("event admission");

        assert_eq!(admission.status, "omitted");
        assert_eq!(admission.reason, Some("max-event-allocation-bytes"));
        assert_eq!(ledger.result(false)["dropped"], 1);
    }

    #[test]
    fn omitted_network_event_retains_transaction_identity_and_limitation() {
        let mut ledger = EventLedger::new(EventLimits {
            max_events: 0,
            max_event_bytes: 4096,
            max_total_bytes: 4096,
        });
        let admission = ledger
            .admit_network("txn-7", "response", 3, json!({"status": 503}))
            .expect("network event admission");
        let result = ledger.result(false);

        assert_eq!(admission.reason, Some("max-events"));
        assert_eq!(
            result["omissions"]["network_transactions"][0]["transaction_id"],
            "txn-7"
        );
        assert_eq!(
            result["omissions"]["network_transactions"][0]["omitted_kinds"],
            json!(["response"])
        );
        assert_eq!(
            result["omissions"]["network_transaction_range"],
            json!(null)
        );
        assert_eq!(
            result["limitations"][0],
            "Browser event collection reached a selected resource budget; event coverage is incomplete."
        );
    }

    #[test]
    fn cdp_batch_preserves_transport_order_and_overflow_reason() {
        let mut ledger = EventLedger::new(EventLimits {
            max_events: 4,
            max_event_bytes: 4096,
            max_total_bytes: 4096,
        });
        ledger
            .admit_cdp_batch(
                2,
                CdpEventBatch {
                    items: vec![
                        CdpEvent {
                            sequence: 4,
                            value: json!({"method": "Page.loadEventFired", "params": {}}),
                        },
                        CdpEvent {
                            sequence: 5,
                            value: json!({"method": "Runtime.consoleAPICalled", "params": {}}),
                        },
                    ],
                    dropped: 2,
                    overflowed: true,
                },
            )
            .expect("CDP event batch");

        let result = ledger.result(false);
        assert_eq!(result["items"][0]["sequence"], 4);
        assert_eq!(result["items"][1]["sequence"], 5);
        assert_eq!(result["dropped"], 2);
        assert_eq!(result["omissions"]["by_kind"][0]["kind"], "cdp");
        assert_eq!(
            result["omissions"]["by_kind"][0]["reasons"],
            json!(["transport-overflow"])
        );
    }
}
