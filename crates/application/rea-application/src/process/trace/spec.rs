//! `processTraceSpecificationSchema` (`processTraceSpecification.ts`).
//!
//! The advertised JSON Schema already checked shape and defaults; this module
//! owns the typed specification and every refinement JSON Schema cannot
//! express, reported in the original Zod order.
use super::json::{canonical, field};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

/// `processTraceCardinalityBounds` input.
#[derive(Clone, Debug)]
pub enum Cardinality {
    Required,
    Optional,
    Exact(u64),
    Range(u64, u64),
}

impl Cardinality {
    pub fn bounds(&self) -> (u64, u64) {
        match self {
            Self::Required => (1, 1),
            Self::Optional => (0, 1),
            Self::Exact(count) => (*count, *count),
            Self::Range(min, max) => (*min, *max),
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Required => json!({ "kind": "required" }),
            Self::Optional => json!({ "kind": "optional" }),
            Self::Exact(count) => json!({ "kind": "exact", "count": count }),
            Self::Range(min, max) => json!({ "kind": "range", "min": min, "max": max }),
        }
    }
}

/// One declared exact event.
#[derive(Clone, Debug)]
pub struct Event {
    pub id: String,
    pub source: String,
    pub exact: Value,
    pub ignore_fields: Option<Vec<String>>,
    pub cardinality: Cardinality,
}

impl Event {
    pub fn ignored(&self) -> &[String] {
        self.ignore_fields.as_deref().unwrap_or_default()
    }
}

/// One finite-trace token.
#[derive(Clone, Debug)]
pub enum Token {
    Id(String),
    Unordered(Vec<String>),
}

impl Token {
    pub fn ids(&self) -> &[String] {
        match self {
            Self::Id(id) => std::slice::from_ref(id),
            Self::Unordered(ids) => ids,
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Id(id) => json!(id),
            Self::Unordered(ids) => json!({ "unordered": ids }),
        }
    }
}

/// The declared trace language.
#[derive(Clone, Debug)]
pub enum Language {
    PartialOrder {
        happens_before: Vec<(String, String)>,
        not_before: Vec<(String, String)>,
        unordered_groups: Vec<Vec<String>>,
        prefix: Vec<String>,
        suffix: Vec<String>,
    },
    FiniteTraces {
        variants: Vec<(String, Vec<Token>)>,
    },
}

/// A parsed trace specification.
#[derive(Clone, Debug)]
pub struct Specification {
    pub events: Vec<Event>,
    pub language: Language,
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn pairs(value: Option<&Value>, left: &str, right: &str) -> Vec<(String, String)> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    (
                        field(item, left)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        field(item, right)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn count(value: &Value, key: &str) -> u64 {
    field(value, key)
        .and_then(Value::as_u64)
        .unwrap_or_default()
}

impl Specification {
    /// Read a schema-validated specification, applying declared defaults.
    pub fn from_value(value: &Value) -> Self {
        let events = field(value, "events")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|event| {
                let cardinality = field(event, "cardinality");
                let cardinality = match cardinality
                    .and_then(|value| field(value, "kind"))
                    .and_then(Value::as_str)
                {
                    Some("optional") => Cardinality::Optional,
                    Some("exact") => {
                        Cardinality::Exact(count(cardinality.unwrap_or(&Value::Null), "count"))
                    }
                    Some("range") => {
                        let cardinality = cardinality.unwrap_or(&Value::Null);
                        Cardinality::Range(count(cardinality, "min"), count(cardinality, "max"))
                    }
                    _ => Cardinality::Required,
                };
                Event {
                    id: field(event, "id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    source: field(event, "source")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    exact: field(event, "exact").cloned().unwrap_or(Value::Null),
                    ignore_fields: field(event, "ignore_fields").map(|value| strings(Some(value))),
                    cardinality,
                }
            })
            .collect();
        let language = field(value, "language").cloned().unwrap_or(Value::Null);
        let language = if field(&language, "kind").and_then(Value::as_str) == Some("finite_traces")
        {
            Language::FiniteTraces {
                variants: field(&language, "variants")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .map(|variant| {
                        let trace = field(variant, "trace")
                            .and_then(Value::as_array)
                            .map(Vec::as_slice)
                            .unwrap_or_default()
                            .iter()
                            .map(|token| match token.as_str() {
                                Some(id) => Token::Id(id.to_owned()),
                                None => Token::Unordered(strings(field(token, "unordered"))),
                            })
                            .collect();
                        (
                            field(variant, "id")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                            trace,
                        )
                    })
                    .collect(),
            }
        } else {
            Language::PartialOrder {
                happens_before: pairs(field(&language, "happens_before"), "before", "after"),
                not_before: pairs(field(&language, "not_before"), "event", "anchor"),
                unordered_groups: field(&language, "unordered_groups")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .map(|group| strings(field(group, "events")))
                    .collect(),
                prefix: strings(field(&language, "prefix")),
                suffix: strings(field(&language, "suffix")),
            }
        };
        Self { events, language }
    }

    /// The Zod output: shape key order with every default applied.
    pub fn to_value(&self) -> Value {
        let events = self
            .events
            .iter()
            .map(|event| {
                let mut object = Map::new();
                object.insert("id".into(), json!(event.id));
                object.insert("source".into(), json!(event.source));
                object.insert("exact".into(), event.exact.clone());
                if let Some(fields) = &event.ignore_fields {
                    object.insert("ignore_fields".into(), json!(fields));
                }
                object.insert("cardinality".into(), event.cardinality.to_value());
                Value::Object(object)
            })
            .collect::<Vec<_>>();
        let language = match &self.language {
            Language::PartialOrder {
                happens_before,
                not_before,
                unordered_groups,
                prefix,
                suffix,
            } => json!({
                "kind": "partial_order",
                "happens_before": happens_before
                    .iter()
                    .map(|(before, after)| json!({ "before": before, "after": after }))
                    .collect::<Vec<_>>(),
                "not_before": not_before
                    .iter()
                    .map(|(event, anchor)| json!({ "event": event, "anchor": anchor }))
                    .collect::<Vec<_>>(),
                "unordered_groups": unordered_groups
                    .iter()
                    .map(|events| json!({ "events": events }))
                    .collect::<Vec<_>>(),
                "prefix": prefix,
                "suffix": suffix,
            }),
            Language::FiniteTraces { variants } => json!({
                "kind": "finite_traces",
                "variants": variants
                    .iter()
                    .map(|(id, trace)| json!({
                        "id": id,
                        "trace": trace.iter().map(Token::to_value).collect::<Vec<_>>(),
                    }))
                    .collect::<Vec<_>>(),
            }),
        };
        json!({ "events": events, "language": language })
    }
}

/// `comparableProcessObservationPayload`.
pub fn comparable_payload(value: &Value, ignored: &[String]) -> Value {
    match value {
        Value::Object(object) if !ignored.is_empty() => Value::Object(
            object
                .iter()
                .filter(|(name, _)| !ignored.iter().any(|field| field == *name))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        ),
        _ => value.clone(),
    }
}

/// `canonicalTraceJson` (input values are always JSON).
pub fn canonical_trace(value: &Value) -> String {
    canonical(value).unwrap_or_default()
}

/// One refinement issue: path segments below `trace_spec`, message.
pub type Refinement = (Vec<String>, String);

struct Issues(Vec<Refinement>);

impl Issues {
    fn add(&mut self, path: &[&dyn ToString], message: impl Into<String>) {
        self.0.push((
            path.iter().map(|segment| segment.to_string()).collect(),
            message.into(),
        ));
    }

    fn reference(&mut self, known: &HashSet<&str>, id: &str, path: &[&dyn ToString]) {
        if !known.contains(id) {
            self.add(path, format!("unknown event id: {id}"));
        }
    }
}

fn pair_key(left: &str, right: &str) -> String {
    if left <= right {
        format!("{left}\0{right}")
    } else {
        format!("{right}\0{left}")
    }
}

/// JavaScript `Map`/`Set` insertion-ordered set of strings.
#[derive(Default, Clone)]
struct OrderedSet {
    items: Vec<String>,
    index: HashSet<String>,
}

impl OrderedSet {
    fn insert(&mut self, item: &str) {
        if self.index.insert(item.to_owned()) {
            self.items.push(item.to_owned());
        }
    }
    fn contains(&self, item: &str) -> bool {
        self.index.contains(item)
    }
    fn iter(&self) -> impl Iterator<Item = &String> {
        self.items.iter()
    }
}

/// Insertion-ordered adjacency keyed by event id.
#[derive(Default)]
struct Adjacency {
    order: Vec<String>,
    edges: HashMap<String, OrderedSet>,
}

impl Adjacency {
    fn with_keys<'a>(keys: impl IntoIterator<Item = &'a str>) -> Self {
        let mut adjacency = Self::default();
        for key in keys {
            if !adjacency.edges.contains_key(key) {
                adjacency.order.push(key.to_owned());
                adjacency
                    .edges
                    .insert(key.to_owned(), OrderedSet::default());
            }
        }
        adjacency
    }
    fn get(&self, key: &str) -> Option<&OrderedSet> {
        self.edges.get(key)
    }
}

fn collect_reachable(origin: &str, adjacency: &Adjacency) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut pending = adjacency
        .get(origin)
        .map(|set| set.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    while let Some(current) = pending.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        if let Some(successors) = adjacency.get(&current) {
            pending.extend(successors.iter().cloned());
        }
    }
    seen
}

enum Graph {
    Cyclic,
    Total(HashMap<String, usize>),
    Partial(Adjacency),
}

fn classify_graph(ids: &[&str], adjacency: &Adjacency) -> Graph {
    let mut incoming_order = Vec::new();
    let mut incoming: HashMap<&str, i64> = HashMap::new();
    for id in ids {
        if !incoming.contains_key(id) {
            incoming_order.push(*id);
        }
        incoming.insert(id, 0);
    }
    let mut unknown_successor = false;
    for key in &adjacency.order {
        for successor in adjacency.edges[key].iter() {
            match incoming.get_mut(successor.as_str()) {
                Some(count) => *count += 1,
                None => unknown_successor = true,
            }
        }
    }
    let mut ready = incoming_order
        .iter()
        .filter(|id| incoming[**id] == 0)
        .map(|id| (*id).to_owned())
        .collect::<Vec<_>>();
    let mut order = Vec::new();
    let mut unique = true;
    while !ready.is_empty() {
        if ready.len() != 1 {
            unique = false;
        }
        let Some(current) = ready.pop() else { break };
        if let Some(successors) = adjacency.get(&current) {
            for successor in successors.iter() {
                if let Some(count) = incoming.get_mut(successor.as_str()) {
                    let previous = *count;
                    *count -= 1;
                    if previous == 1 {
                        ready.push(successor.clone());
                    }
                }
            }
        }
        order.push(current);
    }
    if order.len() != incoming.len() {
        return Graph::Cyclic;
    }
    if unique && order.len() == ids.len() && !unknown_successor {
        return Graph::Total(
            order
                .into_iter()
                .enumerate()
                .map(|(index, id)| (id, index))
                .collect(),
        );
    }
    let mut reverse = Adjacency::with_keys(incoming_order.iter().copied());
    for before in &adjacency.order {
        for after in adjacency.edges[before].iter() {
            if let Some(set) = reverse.edges.get_mut(after) {
                set.insert(before);
            }
        }
    }
    Graph::Partial(reverse)
}

struct UnorderedGroups {
    groups: Vec<OrderedSet>,
    memberships: HashMap<String, Vec<usize>>,
    repeated: HashMap<String, Vec<usize>>,
}

fn push_unique(list: &mut Vec<usize>, value: usize) {
    if !list.contains(&value) {
        list.push(value);
    }
}

impl UnorderedGroups {
    fn has_pair(&self, left: &str, right: &str) -> bool {
        if left == right {
            return self.memberships.contains_key(left);
        }
        let right_groups = self.memberships.get(right);
        self.memberships
            .get(left)
            .into_iter()
            .flatten()
            .any(|group| right_groups.is_some_and(|groups| groups.contains(group)))
    }

    fn mark_shared(&self, left: &str, right: &str, conflicts: &mut [bool]) {
        if left == right {
            for group in self.repeated.get(left).into_iter().flatten() {
                conflicts[*group] = true;
            }
            return;
        }
        let right_groups = self.memberships.get(right);
        for group in self.memberships.get(left).into_iter().flatten() {
            if right_groups.is_some_and(|groups| groups.contains(group)) {
                conflicts[*group] = true;
            }
        }
    }

    fn mark_declared(&self, pairs: &OrderedSet, conflicts: &mut [bool]) {
        for key in pairs.iter() {
            let (left, right) = key.split_once('\0').unwrap_or((key, ""));
            self.mark_shared(left, right, conflicts);
        }
    }
}

fn validate_unordered_groups(
    groups: &[Vec<String>],
    known: &HashSet<&str>,
    issues: &mut Issues,
) -> UnorderedGroups {
    let mut result = UnorderedGroups {
        groups: Vec::new(),
        memberships: HashMap::new(),
        repeated: HashMap::new(),
    };
    for (group_index, group) in groups.iter().enumerate() {
        let mut unique = OrderedSet::default();
        let mut repeated = OrderedSet::default();
        for id in group {
            if unique.contains(id) {
                repeated.insert(id);
            } else {
                unique.insert(id);
            }
        }
        for id in repeated.iter() {
            push_unique(result.repeated.entry(id.clone()).or_default(), group_index);
        }
        if unique.items.len() != group.len() {
            issues.add(
                &[&"language", &"unordered_groups", &group_index, &"events"],
                "unordered groups must not repeat event ids",
            );
        }
        for (event_index, id) in group.iter().enumerate() {
            issues.reference(
                known,
                id,
                &[
                    &"language",
                    &"unordered_groups",
                    &group_index,
                    &"events",
                    &event_index,
                ],
            );
        }
        let mut overlaps: BTreeMap<usize, usize> = BTreeMap::new();
        for id in unique.iter() {
            let prior = result.memberships.entry(id.clone()).or_default();
            for group in prior.iter() {
                *overlaps.entry(*group).or_default() += 1;
            }
            push_unique(prior, group_index);
        }
        if overlaps.values().any(|count| *count > 1) {
            issues.add(
                &[&"language", &"unordered_groups", &group_index],
                "unordered event pairs must be declared once",
            );
        }
        result.groups.push(unique);
    }
    result
}

fn conflict_issues(conflicts: &[bool], issues: &mut Issues) {
    for (index, conflict) in conflicts.iter().enumerate() {
        if *conflict {
            issues.add(
                &[&"language", &"unordered_groups", &index],
                "ordered events cannot also be declared unordered",
            );
        }
    }
}

fn validate_partial_order(spec: &Specification, issues: &mut Issues) {
    let Language::PartialOrder {
        happens_before,
        not_before,
        unordered_groups,
        prefix,
        suffix,
    } = &spec.language
    else {
        return;
    };
    let ids = spec
        .events
        .iter()
        .map(|event| event.id.as_str())
        .collect::<Vec<_>>();
    let known = ids.iter().copied().collect::<HashSet<_>>();
    // `new Map([...known])`: known in first-insertion order.
    let mut known_order = Vec::new();
    let mut seen = HashSet::new();
    for id in &ids {
        if seen.insert(*id) {
            known_order.push(*id);
        }
    }
    let mut adjacency = Adjacency::with_keys(known_order.iter().copied());
    for (index, (before, after)) in happens_before.iter().enumerate() {
        issues.reference(
            &known,
            before,
            &[&"language", &"happens_before", &index, &"before"],
        );
        issues.reference(
            &known,
            after,
            &[&"language", &"happens_before", &index, &"after"],
        );
        if before == after {
            issues.add(
                &[&"language", &"happens_before", &index],
                "happens-before edges must reference distinct events",
            );
        }
        if let Some(set) = adjacency.edges.get_mut(before) {
            set.insert(after);
        }
    }
    let graph = classify_graph(&ids, &adjacency);
    if matches!(graph, Graph::Cyclic) {
        issues.add(&[&"language"], "happens-before graph must be acyclic");
    }
    let mut not_before_pairs = OrderedSet::default();
    for (index, (event, anchor)) in not_before.iter().enumerate() {
        issues.reference(
            &known,
            event,
            &[&"language", &"not_before", &index, &"event"],
        );
        issues.reference(
            &known,
            anchor,
            &[&"language", &"not_before", &index, &"anchor"],
        );
        if event == anchor {
            issues.add(
                &[&"language", &"not_before", &index],
                "not-before constraints must reference distinct events",
            );
        }
        let key = pair_key(event, anchor);
        if not_before_pairs.contains(&key) {
            issues.add(
                &[&"language", &"not_before", &index],
                "not-before event pairs must be declared once",
            );
        }
        not_before_pairs.insert(&key);
    }
    let groups = validate_unordered_groups(unordered_groups, &known, issues);
    match &graph {
        Graph::Total(rank) => {
            for (index, (event, anchor)) in not_before.iter().enumerate() {
                if let (Some(before), Some(after)) = (rank.get(event), rank.get(anchor))
                    && before < after
                {
                    issues.add(
                        &[&"language", &"not_before", &index],
                        "not-before constraint conflicts with happens-before order",
                    );
                }
            }
            let mut conflicts = vec![false; unordered_groups.len()];
            for (group_index, group) in groups.groups.iter().enumerate() {
                if group
                    .iter()
                    .filter(|id| rank.contains_key(*id))
                    .take(2)
                    .count()
                    == 2
                {
                    conflicts[group_index] = true;
                }
            }
            groups.mark_declared(&not_before_pairs, &mut conflicts);
            conflict_issues(&conflicts, issues);
        }
        Graph::Partial(reverse) => {
            let mut missing = 0usize;
            let mut first_missing = String::new();
            let mut conflicts = vec![false; unordered_groups.len()];
            groups.mark_declared(&not_before_pairs, &mut conflicts);
            let mut not_before_conflicts = vec![false; not_before.len()];
            let mut by_source: HashMap<&str, Vec<usize>> = HashMap::new();
            for (index, (event, _)) in not_before.iter().enumerate() {
                by_source.entry(event.as_str()).or_default().push(index);
            }
            for (left_index, left) in ids.iter().enumerate() {
                let forward = collect_reachable(left, &adjacency);
                let backward = collect_reachable(left, reverse);
                for index in by_source.get(left).into_iter().flatten() {
                    if forward.contains(&not_before[*index].1) {
                        not_before_conflicts[*index] = true;
                    }
                }
                for right in &ids[left_index + 1..] {
                    let same_event = left == right;
                    let ordered =
                        !same_event && (forward.contains(*right) || backward.contains(*right));
                    let declared_not_before = not_before_pairs.contains(&pair_key(left, right));
                    let unordered = groups.has_pair(left, right);
                    if (ordered || declared_not_before) && !same_event {
                        groups.mark_shared(left, right, &mut conflicts);
                    }
                    if !ordered && !declared_not_before && !unordered {
                        if missing == 0 {
                            first_missing = format!("{left}/{right}");
                        }
                        missing += 1;
                    }
                }
            }
            for (index, conflict) in not_before_conflicts.iter().enumerate() {
                if *conflict {
                    issues.add(
                        &[&"language", &"not_before", &index],
                        "not-before constraint conflicts with happens-before order",
                    );
                }
            }
            conflict_issues(&conflicts, issues);
            if missing > 0 {
                issues.add(
                    &[&"language"],
                    if missing == 1 {
                        format!("event pair {first_missing} must be explicitly ordered or unordered")
                    } else {
                        format!(
                            "{missing} event pairs must be explicitly ordered or unordered; first undeclared pair: {first_missing}"
                        )
                    },
                );
            }
        }
        Graph::Cyclic => {}
    }
    for (kind, values) in [("prefix", prefix), ("suffix", suffix)] {
        for (index, id) in values.iter().enumerate() {
            issues.reference(&known, id, &[&"language", &kind, &index]);
        }
    }
}

fn validate_finite_traces(spec: &Specification, issues: &mut Issues) {
    let Language::FiniteTraces { variants } = &spec.language else {
        return;
    };
    let known = spec
        .events
        .iter()
        .map(|event| event.id.as_str())
        .collect::<HashSet<_>>();
    let mut variant_ids = HashSet::new();
    let mut variant_traces = HashSet::new();
    for (variant_index, (id, trace)) in variants.iter().enumerate() {
        if !variant_ids.insert(id.as_str()) {
            issues.add(
                &[&"language", &"variants", &variant_index, &"id"],
                "finite trace variant ids must be unique",
            );
        }
        let canonical = canonical_trace(&Value::Array(trace.iter().map(Token::to_value).collect()));
        if !variant_traces.insert(canonical) {
            issues.add(
                &[&"language", &"variants", &variant_index, &"trace"],
                "finite trace variants must not duplicate a trace",
            );
        }
        for (token_index, token) in trace.iter().enumerate() {
            for (event_index, event) in token.ids().iter().enumerate() {
                match token {
                    Token::Id(_) => issues.reference(
                        &known,
                        event,
                        &[
                            &"language",
                            &"variants",
                            &variant_index,
                            &"trace",
                            &token_index,
                        ],
                    ),
                    Token::Unordered(_) => issues.reference(
                        &known,
                        event,
                        &[
                            &"language",
                            &"variants",
                            &variant_index,
                            &"trace",
                            &token_index,
                            &"unordered",
                            &event_index,
                        ],
                    ),
                }
            }
        }
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for token in trace {
            for event in token.ids() {
                *counts.entry(event.as_str()).or_default() += 1;
            }
        }
        for event in &spec.events {
            let (minimum, maximum) = event.cardinality.bounds();
            let count = counts.get(event.id.as_str()).copied().unwrap_or_default();
            if count < minimum || count > maximum {
                issues.add(
                    &[&"language", &"variants", &variant_index, &"trace"],
                    format!("variant {id} violates {} cardinality", event.id),
                );
            }
        }
    }
}

/// Every refinement of a schema-shaped specification, in Zod order.
pub fn refinements(value: &Value) -> Vec<Refinement> {
    let spec = Specification::from_value(value);
    let mut issues = Issues(Vec::new());
    // Nested `.refine` checks run during the shape parse, in shape order.
    for (index, event) in spec.events.iter().enumerate() {
        if let Some(fields) = &event.ignore_fields
            && fields.iter().collect::<HashSet<_>>().len() != fields.len()
        {
            issues.add(
                &[&"events", &index, &"ignore_fields"],
                "ignored event fields must be unique",
            );
        }
        if let Cardinality::Range(min, max) = event.cardinality
            && min > max
        {
            issues.add(
                &[&"events", &index, &"cardinality", &"min"],
                "cardinality min must not exceed max",
            );
        }
    }
    let mut ids = HashSet::new();
    let mut predicates = HashSet::new();
    let mut ignored_by_source: HashMap<&str, String> = HashMap::new();
    for (index, event) in spec.events.iter().enumerate() {
        if !ids.insert(event.id.as_str()) {
            issues.add(&[&"events", &index, &"id"], "event ids must be unique");
        }
        let mut ignored = event.ignored().to_vec();
        ignored.sort();
        let exact_object = event.exact.as_object();
        if !ignored.is_empty() && exact_object.is_none() {
            issues.add(
                &[&"events", &index, &"ignore_fields"],
                "ignored schedule fields require an exact object payload",
            );
        }
        let ignored_key = canonical_trace(&json!(ignored));
        if let Some(prior) = ignored_by_source.get(event.source.as_str())
            && *prior != ignored_key
        {
            issues.add(
                &[&"events", &index, &"ignore_fields"],
                "events from one source must use the same ignored schedule fields",
            );
        }
        ignored_by_source.insert(event.source.as_str(), ignored_key);
        if ignored
            .iter()
            .any(|field| exact_object.is_some_and(|exact| exact.contains_key(field)))
        {
            issues.add(
                &[&"events", &index, &"exact"],
                "exact payload must omit every ignored schedule field",
            );
        }
        let predicate = format!(
            "{}\0{}",
            event.source,
            canonical_trace(&comparable_payload(&event.exact, &ignored))
        );
        if !predicates.insert(predicate) {
            issues.add(
                &[&"events", &index],
                "exact event predicates must not overlap",
            );
        }
    }
    validate_partial_order(&spec, &mut issues);
    validate_finite_traces(&spec, &mut issues);
    issues.0
}
