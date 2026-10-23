//! Shared analysis-view primitives.
//!
//! Compatibility owners: `AnalysisViewParent` in
//! `src/domain/analysisView/analysisView.ts`, `analysisViewErrors.ts`,
//! `analysisViewCoverage.ts`, `analysisViewText.ts` and
//! `analysisViewParent.ts`.
use super::json::{js_len, unique_sorted};
use super::schema;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Value, json};
use std::any::Any;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// `INSPECT_ANALYSIS_VIEW_OPERATION`.
pub const OPERATION: &str = "inspect_analysis_view";

/// Parent record already resolved from inline Evidence or a session reference.
pub struct Parent<'a> {
    pub evidence_id: &'a str,
    pub operation: &'a str,
    pub normalized_result: &'a Value,
    /// Authenticated subject; `Value::Null` records explicit absence.
    pub subject: &'a Value,
    pub limitations: Vec<String>,
    /// Parent Evidence parameters (`Value::Null` when not recorded).
    pub parameters: &'a Value,
    /// The parent is immutable retained Evidence (the original `sealedResult`).
    pub sealed: bool,
    /// Session-owned cache for validated facts of sealed parents.
    pub cache: Option<&'a ViewCache>,
    /// Bytes a grouping view's accumulator already reserved while admitting
    /// the inline envelope (`admitInlineEvidence`); zero otherwise.
    pub admitted_bytes: usize,
}

impl Parent<'_> {
    /// `parent.evidenceId.slice(3)`.
    pub fn digest(&self) -> &str {
        self.evidence_id.get(3..).unwrap_or_default()
    }

    /// The parent recorded a subject (`parent.subject != null`).
    pub fn has_subject(&self) -> bool {
        self.subject.is_object()
    }

    /// `parent.artifact`: subject local path and digest, when recorded.
    pub fn artifact(&self) -> Option<(&str, &str)> {
        let subject = self.subject.as_object()?;
        let path = subject.get("local_path")?.as_str()?;
        let sha256 = subject.get("digest")?.get("sha256")?.as_str()?;
        Some((path, sha256))
    }

    /// Subject format (`parent.subject.format`).
    pub fn subject_format(&self) -> Option<&str> {
        self.subject.get("format").and_then(Value::as_str)
    }

    /// Reuse validated facts for an immutable parent; recompute otherwise.
    pub fn cached<T, F>(&self, key: &'static str, compute: F) -> Result<Arc<T>, AnalysisError>
    where
        T: Any + Send + Sync,
        F: FnOnce() -> Result<T, AnalysisError>,
    {
        match (self.sealed, self.cache) {
            (true, Some(cache)) => cache.get_or_insert(self.evidence_id, key, compute),
            _ => compute().map(Arc::new),
        }
    }

    /// `parseAnalysisViewResult(ownerSchema, parent)`: parse the parent result
    /// with the owning tool's frozen result contract; issues point into the view
    /// source. Sealed parents are parsed once per session cache lifetime.
    pub fn parse_result(&self, tool: &'static str) -> Result<Arc<Value>, AnalysisError> {
        self.cached(tool, || parse_owned_result(tool, self.normalized_result))
    }
}

/// Parse a normalized result with `tool`'s complete result contract.
pub fn parse_owned_result(tool: &str, result: &Value) -> Result<Value, AnalysisError> {
    let Some(root) = schema::tool_result_schema(tool) else {
        return Err(AnalysisError::output(
            OPERATION,
            format!("The {tool} result contract is unavailable."),
        ));
    };
    schema::parse_stripped(&root, result).map_err(|issues| {
        let issues = schema::prefix_issues(issues, &["source", "normalized_result"]);
        let input = json!({ "source": { "normalized_result": result } });
        schema::input_error_from_issues(OPERATION, &issues, &input, Vec::new())
    })
}

struct CacheEntry {
    evidence_id: String,
    key: &'static str,
    value: Arc<dyn Any + Send + Sync>,
}

/// Bounded, session-owned cache of validated facts for immutable parents.
///
/// Retained Evidence is content-addressed and never changes, so an entry is
/// exact for its lifetime; the bound keeps at most a few parent copies alive.
pub struct ViewCache {
    entries: Mutex<VecDeque<CacheEntry>>,
    capacity: usize,
}

impl Default for ViewCache {
    fn default() -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
            capacity: 16,
        }
    }
}

impl ViewCache {
    fn get_or_insert<T, F>(
        &self,
        evidence_id: &str,
        key: &'static str,
        compute: F,
    ) -> Result<Arc<T>, AnalysisError>
    where
        T: Any + Send + Sync,
        F: FnOnce() -> Result<T, AnalysisError>,
    {
        {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(index) = entries
                .iter()
                .position(|entry| entry.key == key && entry.evidence_id == evidence_id)
                && let Some(entry) = entries.remove(index)
            {
                let value = Arc::clone(&entry.value);
                entries.push_back(entry);
                if let Ok(typed) = value.downcast::<T>() {
                    return Ok(typed);
                }
            }
        }
        let computed = Arc::new(compute()?);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.push_back(CacheEntry {
            evidence_id: evidence_id.to_owned(),
            key,
            value: Arc::clone(&computed) as Arc<dyn Any + Send + Sync>,
        });
        while entries.len() > self.capacity {
            entries.pop_front();
        }
        Ok(computed)
    }
}

/// One caller-correction issue at a named path.
pub fn issue(path: &[&str], reason: &'static str, message: impl Into<String>) -> InputIssue {
    InputIssue::new(path, reason, message)
}

/// `analysisViewInputError(issues)`.
pub fn input_error(issues: Vec<InputIssue>) -> AnalysisError {
    AnalysisError::input(OPERATION, issues)
}

/// One-issue `analysisViewInputError`.
pub fn view_error(
    path: &[&str],
    reason: &'static str,
    message: impl Into<String>,
) -> AnalysisError {
    input_error(vec![issue(path, reason, message)])
}

/// `completeWithinViewCoverage(examined, total)`.
pub fn complete_within_view(examined: usize, total: usize) -> Value {
    json!({
        "status": "complete-within-view",
        "examined": examined,
        "total": total,
        "next_offset": null,
        "exhausted": true,
    })
}

/// `pageViewCoverage(offset, examined, total)`, including offsets past the end.
pub fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({
        "status": if examined == 0 { "empty" } else { "page" },
        "examined": examined,
        "total": total,
        "next_offset": if exhausted { Value::Null } else { json!(offset + examined) },
        "exhausted": exhausted,
    })
}

/// `ANALYSIS_VIEW_MESSAGE_BYTE_LIMIT`.
pub const MESSAGE_BYTE_LIMIT: usize = 256 * 1024;

fn message_wire_bytes(value: &str) -> usize {
    (js_len(value) * 18 + 6) * 3
}

/// `boundedViewMessages`: deduplicate and bound messages by repeated wire bytes.
pub fn bounded_view_messages(
    values: &[String],
    parent_evidence_id: &str,
    field: &str,
    required: &[String],
) -> Vec<String> {
    let priority = unique_sorted(required.iter().cloned());
    let unique = unique_sorted(priority.iter().cloned().chain(values.iter().cloned()));
    let notice = |omitted: usize| {
        format!(
            "{omitted} additional {field} omitted from this view; consult source parent Evidence {parent_evidence_id} for the complete list (the caller-supplied record, or its retaining session)."
        )
    };
    let total: usize = unique.iter().map(|value| message_wire_bytes(value)).sum();
    if total <= MESSAGE_BYTE_LIMIT {
        return unique;
    }
    let mut remaining =
        MESSAGE_BYTE_LIMIT as i64 - message_wire_bytes(&notice(unique.len())) as i64;
    let mut retained: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for value in priority.iter().chain(unique.iter()) {
        if seen.contains(value.as_str()) {
            continue;
        }
        let bytes = message_wire_bytes(value) as i64;
        if bytes > remaining {
            continue;
        }
        seen.insert(value.as_str());
        retained.push(value.clone());
        remaining -= bytes;
    }
    let omitted = unique.len() - retained.len();
    if omitted == 0 {
        return unique;
    }
    let mut bounded = unique_sorted(retained);
    bounded.push(notice(omitted));
    bounded
}

/// `analysisTextPage`: slice text by UTF-16 code units without splitting a
/// Unicode character. Returns the page item and its coverage.
pub fn text_page(
    body: &str,
    offset: usize,
    limit: usize,
    label: &str,
) -> Result<(Value, Value), AnalysisError> {
    let units: Vec<u16> = body.encode_utf16().collect();
    let length = units.len();
    let start = offset.min(length);
    let high = |unit: u16| (0xd800..=0xdbff).contains(&unit);
    let low = |unit: u16| (0xdc00..=0xdfff).contains(&unit);
    if start > 0 && start < length && high(units[start - 1]) && low(units[start]) {
        return Err(view_error(
            &["view"],
            "invalid_value",
            format!("{label} offset splits a UTF-16 surrogate pair."),
        ));
    }
    let mut end = start.saturating_add(limit).min(length);
    if end > start && end < length && high(units[end - 1]) && low(units[end]) {
        end -= 1;
    }
    if end == start && start < length {
        return Err(view_error(
            &["view"],
            "invalid_value",
            format!(
                "Increase {} limit to include the next complete Unicode character.",
                label.to_lowercase()
            ),
        ));
    }
    let text = String::from_utf16_lossy(&units[start..end]);
    Ok((
        json!({ "text": text, "unit": "utf16-code-units" }),
        page_coverage(start, end - start, length),
    ))
}

/// `view.offset` / `view.limit` with the request schema's defaults.
pub fn offset_limit(view: &Value) -> (usize, usize) {
    let offset = view
        .get("offset")
        .and_then(Value::as_u64)
        .map_or(0, |value| usize::try_from(value).unwrap_or(usize::MAX));
    let limit = view
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(64, |value| usize::try_from(value).unwrap_or(usize::MAX));
    (offset, limit)
}

/// Slice `rows[offset..offset + limit]` with ECMAScript `slice` clamping.
pub fn page<T: Clone>(rows: &[T], offset: usize, limit: usize) -> Vec<T> {
    let start = offset.min(rows.len());
    let end = offset.saturating_add(limit).min(rows.len());
    rows[start..end].to_vec()
}

/// View kind (`view.kind`).
pub fn view_kind(view: &Value) -> &str {
    view.get("kind").and_then(Value::as_str).unwrap_or_default()
}
