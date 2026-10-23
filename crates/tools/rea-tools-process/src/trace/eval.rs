//! Trace evaluation and comparison.
//!
//! Compatibility owners: `evaluateProcessTraceSide`
//! (`processTraceEvaluation.ts`), `compareProcessTraces` and
//! `processTraceOutcomesDiffer` (`processTraceComparison.ts`) and
//! `projectProcessObservation` (`processObservation.ts`).
use super::spec::{Language, Specification, Token, canonical_trace, comparable_payload};
use crate::capture::validation::source_truncated;
use crate::json::{array, field, safe_integer, text};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

/// A journal location in the result schema's key order.
#[derive(Clone, Debug, PartialEq)]
pub struct Location {
    pub collection: String,
    pub index: Value,
    pub capture_order: Value,
}

impl Location {
    fn from_entry(entry: &Value) -> Self {
        Self {
            collection: text(entry, "collection").unwrap_or_default().to_owned(),
            index: field(entry, "index").cloned().unwrap_or(Value::Null),
            capture_order: field(entry, "capture_order")
                .cloned()
                .unwrap_or(Value::Null),
        }
    }

    pub fn to_value(&self) -> Value {
        json!({
            "collection": self.collection,
            "index": self.index,
            "capture_order": self.capture_order,
        })
    }

    fn order(&self) -> f64 {
        self.capture_order.as_f64().unwrap_or(f64::NAN)
    }

    fn key(&self) -> String {
        format!("{}:{}", self.collection, self.index)
    }
}

#[derive(Clone, Debug)]
struct Matched {
    event_id: String,
    location: Location,
}

/// One side's result.
#[derive(Clone, Debug)]
pub struct SideResult {
    pub status: &'static str,
    pub matched_variant: Option<String>,
    pub satisfied_constraints: Vec<String>,
    raw_trace: Vec<Matched>,
}

impl SideResult {
    fn unknown(raw_trace: Vec<Matched>) -> Self {
        Self {
            status: "unknown",
            matched_variant: None,
            satisfied_constraints: Vec::new(),
            raw_trace,
        }
    }

    fn raw_ids(&self) -> Vec<&str> {
        self.raw_trace
            .iter()
            .map(|matched| matched.event_id.as_str())
            .collect()
    }

    fn to_value(&self) -> Value {
        json!({
            "satisfied_constraints": self.satisfied_constraints,
            "raw_trace": self
                .raw_trace
                .iter()
                .map(|matched| json!({
                    "event_id": matched.event_id,
                    "location": matched.location.to_value(),
                }))
                .collect::<Vec<_>>(),
            "status": self.status,
            "matched_variant": self.matched_variant,
        })
    }
}

/// One side's diagnostic.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub kind: &'static str,
    pub message: String,
    pub event_ids: Vec<String>,
    pub locations: Vec<Location>,
}

struct Evaluated {
    result: SideResult,
    diagnostic: Option<Diagnostic>,
}

fn failure(
    kind: &'static str,
    message: String,
    event_ids: Vec<String>,
    locations: Vec<Location>,
    raw_trace: Vec<Matched>,
) -> Evaluated {
    Evaluated {
        result: SideResult {
            status: "fail",
            matched_variant: None,
            satisfied_constraints: Vec::new(),
            raw_trace,
        },
        diagnostic: Some(Diagnostic {
            kind,
            message,
            event_ids,
            locations,
        }),
    }
}

/// The comparison of both sides.
pub struct TraceComparison {
    pub verdict: &'static str,
    pub left: SideResult,
    pub right: SideResult,
    pub diagnostic: Option<(&'static str, Diagnostic)>,
}

impl TraceComparison {
    /// `processTraceOutcomesDiffer`.
    pub fn outcomes_differ(&self) -> bool {
        self.left.status != self.right.status || self.left.raw_ids() != self.right.raw_ids()
    }

    pub fn to_value(&self) -> Value {
        json!({
            "verdict": self.verdict,
            "left": self.left.to_value(),
            "right": self.right.to_value(),
            "diagnostic": self.diagnostic.as_ref().map(|(side, diagnostic)| json!({
                "kind": diagnostic.kind,
                "side": side,
                "message": diagnostic.message,
                "event_ids": diagnostic.event_ids,
                "locations": diagnostic.locations.iter().map(Location::to_value).collect::<Vec<_>>(),
            })),
        })
    }
}

/// `comparableTerminalFrame`.
pub fn comparable_terminal_frame(frame: &Value) -> Value {
    json!({
        "sequence": field(frame, "sequence").cloned().unwrap_or(Value::Null),
        "at_ms": field(frame, "at_ms").cloned().unwrap_or(Value::Null),
        "data": field(frame, "data").cloned().unwrap_or(Value::Null),
    })
}

fn with_event(event: &str, value: &Value) -> Value {
    let mut object = Map::new();
    object.insert("event".into(), json!(event));
    if let Some(fields) = value.as_object() {
        for (key, value) in fields {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

/// `projectedRecord`: source and payload for one journal reference.
fn project(capture: &Value, entry: &Value) -> Option<(&'static str, Value)> {
    let index = field(entry, "index").and_then(safe_integer)?;
    let index = usize::try_from(index).ok()?;
    let at = |key: &str| array(capture, key).get(index);
    match text(entry, "collection")? {
        "frames" => at("frames").map(|frame| ("terminal_raw", comparable_terminal_frame(frame))),
        "rendered_frames" => {
            at("rendered_frames").map(|frame| ("terminal_rendered", frame.clone()))
        }
        "interaction_events" => {
            at("interaction_events").map(|event| ("interaction", event.clone()))
        }
        "lifecycle" => match index {
            0 => Some(("lifecycle", with_event("exit", &capture["exit"]))),
            1 => Some((
                "lifecycle",
                with_event("settlement", &capture["settlement"]),
            )),
            _ => None,
        },
        "process_samples" => at("process_samples").map(|sample| ("process", sample.clone())),
        "filesystem_checkpoints" => {
            at("filesystem_checkpoints").map(|checkpoint| ("filesystem", checkpoint.clone()))
        }
        _ => None,
    }
}

fn scope_for(source: &str) -> &'static str {
    if source.starts_with("terminal_") {
        "terminal"
    } else {
        match source {
            "lifecycle" => "exit",
            "filesystem" => "filesystem",
            "process" => "process",
            _ => "interaction",
        }
    }
}

struct MatchedTrace {
    raw_trace: Vec<Matched>,
    by_id: HashMap<String, Vec<Location>>,
}

fn match_records(
    records: &[(&'static str, Value, Location)],
    spec: &Specification,
) -> Result<MatchedTrace, Box<Evaluated>> {
    let mut ignored_by_source: HashMap<&str, &[String]> = HashMap::new();
    let mut events_by_key: HashMap<String, &str> = HashMap::new();
    for event in &spec.events {
        ignored_by_source.insert(event.source.as_str(), event.ignored());
        events_by_key.insert(
            format!(
                "{}\0{}",
                event.source,
                canonical_trace(&comparable_payload(&event.exact, event.ignored()))
            ),
            event.id.as_str(),
        );
    }
    let mut trace = MatchedTrace {
        raw_trace: Vec::new(),
        by_id: HashMap::new(),
    };
    for (source, payload, location) in records {
        let ignored = ignored_by_source.get(source).copied().unwrap_or_default();
        let key = format!(
            "{source}\0{}",
            canonical_trace(&comparable_payload(payload, ignored))
        );
        let Some(id) = events_by_key.get(&key) else {
            return Err(Box::new(failure(
                "predicate",
                "Observed event does not match any declared exact predicate.".into(),
                Vec::new(),
                vec![location.clone()],
                trace.raw_trace,
            )));
        };
        trace.raw_trace.push(Matched {
            event_id: (*id).to_owned(),
            location: location.clone(),
        });
        trace
            .by_id
            .entry((*id).to_owned())
            .or_default()
            .push(location.clone());
    }
    Ok(trace)
}

fn cardinality_failure(trace: &MatchedTrace, spec: &Specification) -> Option<Evaluated> {
    for event in &spec.events {
        let (minimum, maximum) = event.cardinality.bounds();
        let locations = trace.by_id.get(&event.id).cloned().unwrap_or_default();
        let count = locations.len() as u64;
        if count < minimum || count > maximum {
            return Some(failure(
                "cardinality",
                format!(
                    "{} observed {count} times; expected {minimum}..{maximum}.",
                    event.id
                ),
                vec![event.id.clone()],
                locations,
                trace.raw_trace.clone(),
            ));
        }
    }
    None
}

fn unique_by<T: Clone>(values: Vec<T>, key: impl Fn(&T) -> String) -> Vec<T> {
    // `new Map(values.map(...)).values()`: first position, last value.
    let mut order: Vec<String> = Vec::new();
    let mut latest: HashMap<String, T> = HashMap::new();
    for value in values {
        let key = key(&value);
        if !latest.contains_key(&key) {
            order.push(key.clone());
        }
        latest.insert(key, value);
    }
    order
        .into_iter()
        .filter_map(|key| latest.remove(&key))
        .collect()
}

fn evaluate_partial_order(
    trace: &MatchedTrace,
    happens_before: &[(String, String)],
    not_before: &[(String, String)],
    unordered_groups: &[Vec<String>],
    prefix: &[String],
    suffix: &[String],
) -> Evaluated {
    let empty = Vec::new();
    let locations = |id: &str| trace.by_id.get(id).unwrap_or(&empty);
    let mut satisfied = Vec::new();
    let mut failures: Vec<(String, Vec<String>, Vec<Location>)> = Vec::new();
    for (before, after) in happens_before {
        let last_before = locations(before).last();
        let first_after = locations(after).first();
        match (last_before, first_after) {
            (None, Some(first_after)) => failures.push((
                format!("{before} is required when {after} occurs."),
                vec![before.clone(), after.clone()],
                vec![first_after.clone()],
            )),
            (Some(last_before), Some(first_after))
                if last_before.order() >= first_after.order() =>
            {
                failures.push((
                    format!("{before} must happen before {after}."),
                    vec![before.clone(), after.clone()],
                    vec![last_before.clone(), first_after.clone()],
                ));
            }
            _ => satisfied.push(format!("happens_before:{before}:{after}")),
        }
    }
    for (event, anchor) in not_before {
        let first_event = locations(event).first();
        let first_anchor = locations(anchor).first();
        match (first_event, first_anchor) {
            (Some(first_event), None) => failures.push((
                format!("{anchor} is required when {event} occurs."),
                vec![event.clone(), anchor.clone()],
                vec![first_event.clone()],
            )),
            (Some(first_event), Some(first_anchor))
                if first_event.order() < first_anchor.order() =>
            {
                failures.push((
                    format!("{event} must not occur before {anchor}."),
                    vec![event.clone(), anchor.clone()],
                    vec![first_event.clone(), first_anchor.clone()],
                ));
            }
            _ => satisfied.push(format!("not_before:{event}:{anchor}")),
        }
    }
    if !failures.is_empty() {
        let message = failures
            .iter()
            .map(|(message, _, _)| message.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let event_ids = unique_by(
            failures
                .iter()
                .flat_map(|(_, ids, _)| ids.clone())
                .collect(),
            Clone::clone,
        );
        let locations = unique_by(
            failures
                .iter()
                .flat_map(|(_, _, locations)| locations.clone())
                .collect(),
            Location::key,
        );
        return failure(
            "edge",
            message,
            event_ids,
            locations,
            trace.raw_trace.clone(),
        );
    }
    let ids = trace
        .raw_trace
        .iter()
        .map(|matched| matched.event_id.clone())
        .collect::<Vec<_>>();
    for (kind, expected) in [("prefix", prefix), ("suffix", suffix)] {
        let range = if kind == "prefix" {
            0..expected.len().min(ids.len())
        } else if expected.is_empty() {
            0..0
        } else {
            ids.len().saturating_sub(expected.len())..ids.len()
        };
        if ids[range.clone()] == *expected {
            continue;
        }
        // `slice(-0)` is the whole trace for an empty suffix, but an empty
        // expected suffix always matches before reaching this point.
        return failure(
            kind,
            format!("Observed trace does not satisfy the declared {kind}."),
            expected.to_vec(),
            trace.raw_trace[range]
                .iter()
                .map(|matched| matched.location.clone())
                .collect(),
            trace.raw_trace.clone(),
        );
    }
    satisfied.extend(
        unordered_groups
            .iter()
            .map(|events| format!("unordered:{}", events.join(":"))),
    );
    if !prefix.is_empty() {
        satisfied.push(format!("prefix:{}", prefix.join(":")));
    }
    if !suffix.is_empty() {
        satisfied.push(format!("suffix:{}", suffix.join(":")));
    }
    Evaluated {
        result: SideResult {
            status: "pass",
            matched_variant: None,
            satisfied_constraints: satisfied,
            raw_trace: trace.raw_trace.clone(),
        },
        diagnostic: None,
    }
}

enum Finite {
    Pass(String),
    Fail(Vec<String>, Vec<usize>),
}

/// Insertion-ordered set for the best-prefix attribution.
#[derive(Default)]
struct Ordered<T: PartialEq> {
    items: Vec<T>,
}

impl<T: PartialEq> Ordered<T> {
    fn add(&mut self, item: T) {
        if !self.items.contains(&item) {
            self.items.push(item);
        }
    }
    fn clear(&mut self) {
        self.items.clear();
    }
}

fn evaluate_finite(ids: &[String], variants: &[(String, Vec<Token>)]) -> Finite {
    let mut best_prefix: i64 = -1;
    let mut best_ids: Ordered<String> = Ordered::default();
    let mut best_locations: Ordered<usize> = Ordered::default();
    let mut record = |offset: usize, missing: &[String], unexpected: &[(String, usize)]| {
        let offset = offset as i64;
        if offset > best_prefix {
            best_prefix = offset;
            best_ids.clear();
            best_locations.clear();
        }
        if offset != best_prefix {
            return;
        }
        for id in missing {
            best_ids.add(id.clone());
        }
        for (id, index) in unexpected {
            best_ids.add(id.clone());
            best_locations.add(*index);
        }
    };
    for (variant_id, trace) in variants {
        let mut offset = 0usize;
        let mut mismatched = false;
        for token in trace {
            let expected = token.ids();
            let end = (offset + expected.len()).min(ids.len());
            let actual = &ids[offset.min(ids.len())..end];
            // Insertion-ordered remaining counts.
            let mut remaining: Vec<(String, usize)> = Vec::new();
            for id in expected {
                match remaining.iter_mut().find(|(name, _)| name == id) {
                    Some((_, count)) => *count += 1,
                    None => remaining.push((id.clone(), 1)),
                }
            }
            let mut unexpected = Vec::new();
            for (index, id) in actual.iter().enumerate() {
                match remaining.iter().position(|(name, _)| name == id) {
                    None => unexpected.push((id.clone(), offset + index)),
                    Some(position) => {
                        if remaining[position].1 == 1 {
                            remaining.remove(position);
                        } else {
                            remaining[position].1 -= 1;
                        }
                    }
                }
            }
            let missing = remaining
                .iter()
                .flat_map(|(id, count)| std::iter::repeat_n(id.clone(), *count))
                .collect::<Vec<_>>();
            if !missing.is_empty() || !unexpected.is_empty() || actual.len() < expected.len() {
                record(offset, &missing, &unexpected);
                mismatched = true;
                break;
            }
            offset += expected.len();
        }
        if mismatched {
            continue;
        }
        if offset == ids.len() {
            return Finite::Pass(variant_id.clone());
        }
        let unexpected = ids
            .get(offset)
            .map(|id| vec![(id.clone(), offset)])
            .unwrap_or_default();
        record(offset, &[], &unexpected);
    }
    Finite::Fail(best_ids.items, best_locations.items)
}

fn evaluate_matched(trace: MatchedTrace, spec: &Specification) -> Evaluated {
    if let Some(failure) = cardinality_failure(&trace, spec) {
        return failure;
    }
    match &spec.language {
        Language::PartialOrder {
            happens_before,
            not_before,
            unordered_groups,
            prefix,
            suffix,
        } => evaluate_partial_order(
            &trace,
            happens_before,
            not_before,
            unordered_groups,
            prefix,
            suffix,
        ),
        Language::FiniteTraces { variants } => {
            let ids = trace
                .raw_trace
                .iter()
                .map(|matched| matched.event_id.clone())
                .collect::<Vec<_>>();
            match evaluate_finite(&ids, variants) {
                Finite::Fail(event_ids, indexes) => failure(
                    "trace",
                    "Observed events do not match any finite trace variant.".into(),
                    event_ids,
                    indexes
                        .into_iter()
                        .filter_map(|index| {
                            trace
                                .raw_trace
                                .get(index)
                                .map(|matched| matched.location.clone())
                        })
                        .collect(),
                    trace.raw_trace,
                ),
                Finite::Pass(variant) => Evaluated {
                    result: SideResult {
                        status: "pass",
                        matched_variant: Some(variant.clone()),
                        satisfied_constraints: vec![format!("variant:{variant}")],
                        raw_trace: trace.raw_trace,
                    },
                    diagnostic: None,
                },
            }
        }
    }
}

/// The declared sources in first-declaration order.
pub fn sources(spec: &Specification) -> Vec<&str> {
    let mut seen = HashSet::new();
    spec.events
        .iter()
        .map(|event| event.source.as_str())
        .filter(|source| seen.insert(*source))
        .collect()
}

fn evaluate_side(capture: &Value, spec: &Specification) -> Evaluated {
    let sources = sources(spec);
    let scopes = sources
        .iter()
        .map(|source| scope_for(source))
        .collect::<HashSet<_>>();
    let incomplete = sources
        .iter()
        .any(|source| source_truncated(capture, source))
        || array(capture, "residual_unknowns")
            .iter()
            .any(|unknown| text(unknown, "scope").is_some_and(|scope| scopes.contains(scope)));
    let journal = array(capture, "event_journal");
    if journal.is_empty() {
        return Evaluated {
            result: SideResult::unknown(Vec::new()),
            diagnostic: Some(Diagnostic {
                kind: "journal",
                message: "Capture has no cross-source event journal.".into(),
                event_ids: Vec::new(),
                locations: Vec::new(),
            }),
        };
    }
    let records = journal
        .iter()
        .filter_map(|entry| {
            let (source, payload) = project(capture, entry)?;
            sources
                .contains(&source)
                .then(|| (source, payload, Location::from_entry(entry)))
        })
        .collect::<Vec<_>>();
    let matched = match_records(&records, spec);
    if incomplete {
        let raw = match matched {
            Ok(trace) => trace.raw_trace,
            Err(failure) => failure.result.raw_trace,
        };
        return Evaluated {
            result: SideResult::unknown(raw),
            diagnostic: None,
        };
    }
    match matched {
        Ok(trace) => evaluate_matched(trace, spec),
        Err(failure) => *failure,
    }
}

/// `compareProcessTraces`.
pub fn compare(left: &Value, right: &Value, spec: &Specification) -> TraceComparison {
    let left = evaluate_side(left, spec);
    let right = evaluate_side(right, spec);
    let diagnostic = match (left.diagnostic, right.diagnostic) {
        (Some(diagnostic), _) => Some(("left", diagnostic)),
        (None, Some(diagnostic)) => Some(("right", diagnostic)),
        (None, None) => None,
    };
    let mut comparison = TraceComparison {
        verdict: "unknown",
        left: left.result,
        right: right.result,
        diagnostic,
    };
    comparison.verdict =
        if comparison.left.status == "unknown" || comparison.right.status == "unknown" {
            "unknown"
        } else if comparison.left.status == "pass" && comparison.right.status == "pass" {
            "equivalent"
        } else if comparison.outcomes_differ() {
            "different"
        } else {
            "nonconforming"
        };
    comparison
}
