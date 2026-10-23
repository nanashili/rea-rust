//! `api-surface` views over retained HAR `inspect_web_network_capture` Evidence.
//!
//! Compatibility owners: `src/domain/analysisView/webNetworkApiSurfaceView.ts`
//! and `WebNetworkApiSurfaceAccumulator.ts`. Grouping reads only retained
//! request lines; format matches do not establish handler identity.
use super::web_network::budget::Budget;
use super::web_network::capture::admit_har_capture_parent;
use super::web_network::ordering::compare;
use super::web_network::routes::{
    CAPTURE_CONTAINER_BYTES, ENTRY_BYTES, GROUP_BYTES, RECORD_SCRATCH_BYTES, RequestLine,
    RouteTemplate, SEGMENT_BYTES, media_type_essence, read_query_parameter_names,
    read_recorded_request_line, scan_route_template, sorted_numbers, text_bytes_of,
};
use crate::common::view::{Parent, offset_limit, page_coverage};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Budget subject of the original accumulator.
pub const SUBJECT: &str = "API-surface";

/// Admit the complete inline envelope before it is authenticated; returns the
/// retained reservation the projection continues from.
pub fn admit_inline(view: &Value, evidence: &Value) -> Result<usize, AnalysisError> {
    let _ = view;
    let mut budget = Budget::new(SUBJECT);
    budget.admit_inline_evidence(evidence)?;
    Ok(budget.retained())
}

struct Segment {
    segment_index: usize,
    rule: &'static str,
    values: BTreeSet<String>,
}

struct Group {
    method: String,
    origin: String,
    path_template: String,
    segments: Vec<Segment>,
    ordinals: Vec<Value>,
    statuses: Vec<f64>,
    content_types: BTreeSet<String>,
    query_names: Option<BTreeMap<String, Vec<Value>>>,
}

/// `WebNetworkApiSurfaceAccumulator`.
struct Accumulator {
    budget: Budget,
    include_query: bool,
    buckets: HashMap<(String, String, String, String), usize>,
    groups: Vec<Group>,
    excluded: Vec<Value>,
    unavailable_response: bool,
}

impl Accumulator {
    fn exclude(&mut self, ordinal: &Value, reason: &str) -> Result<(), AnalysisError> {
        if !self.budget.retain(ENTRY_BYTES + RECORD_SCRATCH_BYTES) {
            return Err(self.budget.over_budget());
        }
        self.excluded
            .push(json!({ "ordinal": ordinal, "reason": reason }));
        Ok(())
    }

    fn add(&mut self, record: &Value) -> Result<(), AnalysisError> {
        self.budget.add_limitations(crate::common::json::strings(
            record.get("limitations").unwrap_or(&Value::Null),
        ))?;
        let result = self.add_line(record);
        self.budget.release_temporary();
        result
    }

    fn add_line(&mut self, record: &Value) -> Result<(), AnalysisError> {
        let ordinal = record.get("ordinal").cloned().unwrap_or(Value::Null);
        let reported = record.get("reported").unwrap_or(&Value::Null);
        let budget = &mut self.budget;
        let line = read_recorded_request_line(reported, self.include_query, &mut |bytes| {
            budget.temporary(bytes)
        });
        let line = match line {
            None => return Err(self.budget.over_budget()),
            Some(RequestLine::Excluded(reason)) => return self.exclude(&ordinal, reason),
            Some(RequestLine::Line(line)) => line,
        };
        let budget = &mut self.budget;
        let Some(route) = scan_route_template(&line.path, &mut |bytes| budget.temporary(bytes))
        else {
            return Err(self.budget.over_budget());
        };
        let budget = &mut self.budget;
        let Some(query_names) =
            read_query_parameter_names(line.query.as_deref(), &mut |bytes| budget.temporary(bytes))
        else {
            return Err(self.budget.over_budget());
        };
        let mime = media_type_essence(&line.raw_mime);
        self.append(
            ordinal,
            line.method,
            line.origin,
            route,
            line.status,
            mime,
            query_names,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        ordinal: Value,
        method: String,
        origin: String,
        route: RouteTemplate,
        status: Option<f64>,
        mime: Option<String>,
        query_names: Option<BTreeSet<String>>,
    ) -> Result<(), AnalysisError> {
        let key = (
            method.clone(),
            origin.clone(),
            route.template.clone(),
            route.rules.clone(),
        );
        let existing = self.buckets.get(&key).copied();
        let group = existing.map(|index| &self.groups[index]);
        let mut bytes = ENTRY_BYTES;
        match group {
            None => {
                bytes += GROUP_BYTES
                    + text_bytes_of(&method)
                    + text_bytes_of(&origin)
                    + text_bytes_of(&route.template)
                    + text_bytes_of(&route.rules);
                for segment in &route.segments {
                    bytes += SEGMENT_BYTES + ENTRY_BYTES + text_bytes_of(&segment.value);
                }
            }
            Some(group) => {
                for (index, segment) in route.segments.iter().enumerate() {
                    if !group.segments[index].values.contains(&segment.value) {
                        bytes += ENTRY_BYTES + text_bytes_of(&segment.value);
                    }
                }
            }
        }
        if let Some(status) = status
            && !group.is_some_and(|group| group.statuses.contains(&status))
        {
            bytes += ENTRY_BYTES;
        }
        if let Some(mime) = &mime
            && !group.is_some_and(|group| group.content_types.contains(mime))
        {
            bytes += ENTRY_BYTES + text_bytes_of(mime);
        }
        if let Some(names) = &query_names {
            if group.is_none() {
                bytes += CAPTURE_CONTAINER_BYTES;
            }
            for name in names {
                bytes += ENTRY_BYTES;
                if !group
                    .and_then(|group| group.query_names.as_ref())
                    .is_some_and(|known| known.contains_key(name))
                {
                    bytes += ENTRY_BYTES + text_bytes_of(name);
                }
            }
        }
        if !self.budget.retain(bytes) {
            return Err(self.budget.over_budget());
        }
        let index = match existing {
            Some(index) => {
                for (position, segment) in route.segments.iter().enumerate() {
                    self.groups[index].segments[position]
                        .values
                        .insert(segment.value.clone());
                }
                index
            }
            None => {
                self.groups.push(Group {
                    method,
                    origin,
                    path_template: route.template.clone(),
                    segments: route
                        .segments
                        .iter()
                        .map(|segment| Segment {
                            segment_index: segment.segment_index,
                            rule: segment.rule,
                            values: BTreeSet::from([segment.value.clone()]),
                        })
                        .collect(),
                    ordinals: Vec::new(),
                    statuses: Vec::new(),
                    content_types: BTreeSet::new(),
                    query_names: query_names.as_ref().map(|_| BTreeMap::new()),
                });
                self.buckets.insert(key, self.groups.len() - 1);
                self.groups.len() - 1
            }
        };
        let group = &mut self.groups[index];
        group.ordinals.push(ordinal.clone());
        if status.is_none() || mime.is_none() {
            self.unavailable_response = true;
        }
        if let Some(status) = status
            && !group.statuses.contains(&status)
        {
            group.statuses.push(status);
        }
        if let Some(mime) = mime {
            group.content_types.insert(mime);
        }
        if let (Some(names), Some(known)) = (query_names, group.query_names.as_mut()) {
            for name in names {
                known.entry(name).or_default().push(ordinal.clone());
            }
        }
        Ok(())
    }

    /// `page(offset, limit)`.
    fn page(&mut self, offset: usize, limit: usize) -> Map<String, Value> {
        self.groups.sort_by(|left, right| {
            compare(&left.origin, &right.origin)
                .then_with(|| compare(&left.path_template, &right.path_template))
                .then_with(|| compare(&left.method, &right.method))
        });
        let start = offset.min(self.groups.len());
        let end = offset.saturating_add(limit).min(self.groups.len());
        let groups: Vec<Value> = self.groups[start..end]
            .iter()
            .map(|group| {
                let mut row = Map::new();
                row.insert("method".into(), json!(group.method));
                row.insert("origin".into(), json!(group.origin));
                row.insert("path_template".into(), json!(group.path_template));
                row.insert(
                    "templated_segments".into(),
                    Value::Array(
                        group
                            .segments
                            .iter()
                            .map(|segment| {
                                json!({
                                    "segment_index": segment.segment_index,
                                    "rule": segment.rule,
                                    "basis": "inferred",
                                    "observed_values": segment.values.iter().collect::<Vec<_>>(),
                                })
                            })
                            .collect(),
                    ),
                );
                row.insert("record_ordinals".into(), Value::Array(group.ordinals.clone()));
                row.insert("statuses".into(), Value::Array(sorted_numbers(group.statuses.iter().copied())));
                row.insert("content_types".into(), json!(group.content_types.iter().collect::<Vec<_>>()));
                if let Some(names) = &group.query_names {
                    row.insert(
                        "query_parameter_names".into(),
                        Value::Array(
                            names
                                .iter()
                                .map(|(name, ordinals)| json!({ "name": name, "record_ordinals": ordinals }))
                                .collect(),
                        ),
                    );
                }
                let mut flags = Vec::new();
                if group.ordinals.len() == 1 {
                    flags.push("single-sample");
                }
                if group.statuses.len() > 1 {
                    flags.push("mixed-statuses");
                }
                if group.content_types.len() > 1 {
                    flags.push("mixed-content-types");
                }
                row.insert("flags".into(), json!(flags));
                Value::Object(row)
            })
            .collect();
        let mut out = Map::new();
        out.insert(
            "coverage".into(),
            page_coverage(offset, groups.len(), self.groups.len()),
        );
        out.insert("groups".into(), Value::Array(groups));
        out.insert(
            "templated_groups".into(),
            json!(
                self.groups
                    .iter()
                    .filter(|group| !group.segments.is_empty())
                    .count()
            ),
        );
        out.insert(
            "excluded_records".into(),
            Value::Array(self.excluded.clone()),
        );
        out.insert(
            "limitations".into(),
            json!(self.budget.sorted_limitations()),
        );
        out.insert(
            "unknowns".into(),
            if self.unavailable_response {
                json!(["Some retained records have unavailable status or content type values."])
            } else {
                json!([])
            },
        );
        out
    }
}

/// `projectWebNetworkApiSurfaceView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let include_query = view
        .get("include_query_parameter_names")
        .and_then(Value::as_bool)
        == Some(true);
    let mut budget = Budget::new(SUBJECT);
    if !budget.retain(parent.admitted_bytes) {
        return Err(budget.over_budget());
    }
    let capture = admit_har_capture_parent(parent, "api-surface", &mut budget)?;
    let records = capture
        .get("records")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let total_records = capture.get("total_records").cloned().unwrap_or(Value::Null);
    let mut limitations: Vec<String> = parent.limitations.clone();
    limitations.extend(crate::common::json::strings(
        capture.get("limitations").unwrap_or(&Value::Null),
    ));
    limitations.push(
        "Grouping does not establish handler identity, URL-space schemas or causality.".into(),
    );
    if include_query {
        limitations.push(
            "Observed query parameter names do not establish required parameters, value types or a complete API schema.".into(),
        );
    }
    if (records.len() as f64) < total_records.as_f64().unwrap_or(0.0) {
        limitations.push(
            "Parent contains an ordinal subset; the surface covers only retained records.".into(),
        );
    }
    budget.add_limitations(limitations)?;
    let mut accumulator = Accumulator {
        budget,
        include_query,
        buckets: HashMap::new(),
        groups: Vec::new(),
        excluded: Vec::new(),
        unavailable_response: false,
    };
    for record in records {
        accumulator.add(record)?;
    }
    let (offset, limit) = offset_limit(view);
    // The parsed request carries this view's own `limit` default (50).
    let page = accumulator.page(offset, limit);
    let artifact = capture.get("artifact").unwrap_or(&Value::Null);
    let mut out = Map::new();
    out.insert("kind".into(), json!("api-surface"));
    out.insert("view".into(), view.clone());
    out.insert("parent_evidence_id".into(), json!(parent.evidence_id));
    out.insert(
        "parent_operation".into(),
        json!("inspect_web_network_capture"),
    );
    out.insert("parent_digest".into(), json!(parent.digest()));
    out.insert(
        "artifact".into(),
        json!({
            "path": artifact.get("path").cloned().unwrap_or(Value::Null),
            "sha256": artifact.get("sha256").cloned().unwrap_or(Value::Null),
        }),
    );
    out.insert(
        "records".into(),
        json!({
            "examined": records.len(),
            "total": total_records,
            "excluded": accumulator.excluded.len(),
        }),
    );
    out.extend(page);
    Ok(Value::Object(out))
}
