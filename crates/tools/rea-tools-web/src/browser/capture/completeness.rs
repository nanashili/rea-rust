//! `src/browser/CdpCaptureCompleteness.ts` and `classifyBrowserCompleteness`
//! (`src/domain/browserCompleteness.ts`): the mutable adapter ledger
//! projected into canonical completeness v2.
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

const POLICY_REASONS: [&str; 5] = [
    "disallowed_origin",
    "unsupported_url",
    "unattributed_origin",
    "not_approved",
    "out_of_target_scope",
];

/// Dropped-event kinds in schema order. The tools bound here never drop
/// events, so every count stays zero.
const DROPPED_KINDS: [&str; 7] = [
    "scripts",
    "network_requests",
    "console_events",
    "websocket_connections",
    "websocket_frames",
    "webmcp_tools",
    "timeline_events",
];

#[derive(Default)]
pub(crate) struct Completeness {
    policy_filtered: BTreeSet<&'static str>,
    attach_limited: BTreeSet<&'static str>,
    truncated: BTreeSet<&'static str>,
    unavailable: BTreeSet<&'static str>,
    /// `(section, reason)` → combined count (`None` is unknown).
    excluded: BTreeMap<(&'static str, &'static str), Option<u64>>,
    dropped: BTreeMap<&'static str, u64>,
}

impl Completeness {
    pub(crate) fn new(initial_attach_limited: &[&'static str]) -> Self {
        let mut completeness = Self::default();
        completeness
            .attach_limited
            .extend(initial_attach_limited.iter().copied());
        completeness
    }

    /// `exclude(section, reason, count)`; `count == None` is unknown.
    pub(crate) fn exclude_count(
        &mut self,
        section: &'static str,
        reason: &'static str,
        count: Option<u64>,
    ) {
        if POLICY_REASONS.contains(&reason) {
            self.policy_filtered.insert(section);
        }
        if reason == "provider_unavailable" || reason == "invalid_protocol_value" {
            self.unavailable.insert(section);
        }
        if reason == "resource_budget_exhausted" {
            self.truncated.insert(section);
        }
        let entry = self.excluded.entry((section, reason));
        match entry {
            std::collections::btree_map::Entry::Vacant(vacant) => {
                vacant.insert(count);
            }
            std::collections::btree_map::Entry::Occupied(mut occupied) => {
                let combined = match (*occupied.get(), count) {
                    (Some(existing), Some(added)) => Some(existing + added),
                    _ => None,
                };
                occupied.insert(combined);
            }
        }
    }

    pub(crate) fn exclude(&mut self, section: &'static str, reason: &'static str) {
        self.exclude_count(section, reason, Some(1));
    }

    pub(crate) fn attach_limited(&mut self, section: &'static str) {
        self.attach_limited.insert(section);
    }

    pub(crate) fn unavailable(&mut self, section: &'static str) {
        self.unavailable.insert(section);
        self.exclude_count(section, "provider_unavailable", None);
    }

    pub(crate) fn truncate(&mut self, section: &'static str) {
        self.truncated.insert(section);
    }
    pub(crate) fn dropped_total(&self) -> u64 {
        self.dropped.values().sum()
    }

    pub(crate) fn snapshot(&self) -> Value {
        let dropped_any = self.dropped.values().any(|count| *count > 0);
        let policy_filtered = !self.policy_filtered.is_empty();
        let truncated = !self.truncated.is_empty() || dropped_any;
        let attach_limited = !self.attach_limited.is_empty() || !self.unavailable.is_empty();
        let status = if truncated {
            "truncated"
        } else if policy_filtered {
            "policy_filtered"
        } else if attach_limited {
            "attach_limited"
        } else {
            "complete_within_window"
        };
        let mut conditions = Vec::new();
        if attach_limited {
            conditions.push("attach_limited");
        }
        if policy_filtered {
            conditions.push("policy_filtered");
        }
        if truncated {
            conditions.push("truncated");
        }
        if conditions.is_empty() {
            conditions.push("complete_within_window");
        }
        let excluded: Vec<Value> = self
            .excluded
            .iter()
            .map(|((section, reason), count)| json!({ "section": section, "reason": reason, "count": count }))
            .collect();
        let mut dropped = Map::new();
        for kind in DROPPED_KINDS {
            dropped.insert(
                kind.into(),
                json!(self.dropped.get(kind).copied().unwrap_or(0)),
            );
        }
        dropped.insert("total".into(), json!(self.dropped_total()));
        json!({
            "status": status,
            "conditions": conditions,
            "policy_filtered_sections": self.policy_filtered,
            "attach_limited_sections": self.attach_limited,
            "truncated_sections": self.truncated,
            "unavailable_sections": self.unavailable,
            "excluded": excluded,
            "dropped_events": dropped,
        })
    }
}
