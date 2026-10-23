//! Views over retained `inspect_pcap_capture` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/pcapCaptureView.ts`.
//! Historical packet facts are paged without reopening the source or rerunning
//! Wireshark.
use crate::common::json::{js_len, without};
use crate::common::schema;
use crate::common::view::{
    OPERATION, Parent, complete_within_view, offset_limit, page, page_coverage, text_page,
    view_error, view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::sync::Arc;

const PARENT_OPERATION: &str = "inspect_pcap_capture";
const PAGE_SCOPE: &str = "Page totals count retained rows or UTF-16 diagnostic code units. Exhaustion does not prove whole-network completeness; source coverage and examined counts remain separate.";
const SAVED_SCOPE: &str = "Saved packet observations do not establish process identity, causality, encrypted payload contents or traffic missing from the recording.";

/// `projectPcapCaptureView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "pcap" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "Packet summary parents support summary and pcap fact pages.",
        ));
    }
    let capture = parse_parent(parent)?;
    let target = capture.get("target").unwrap_or(&Value::Null);
    let mut limitations = parent.limitations.clone();
    limitations.push(PAGE_SCOPE.to_owned());
    let mut out = Map::new();
    out.insert("kind".into(), json!(kind));
    out.insert("view".into(), view.clone());
    out.insert("parent_evidence_id".into(), json!(parent.evidence_id));
    out.insert("parent_operation".into(), json!(PARENT_OPERATION));
    out.insert("parent_digest".into(), json!(parent.digest()));
    out.insert(
        "artifact".into(),
        json!({
            "path": target.get("path").cloned().unwrap_or(Value::Null),
            "sha256": target.get("sha256").cloned().unwrap_or(Value::Null),
        }),
    );
    out.insert("limitations".into(), json!(limitations));
    out.insert("unknowns".into(), json!([SAVED_SCOPE]));
    if kind == "summary" {
        out.insert("summary".into(), summarize(&capture));
        out.insert("coverage".into(), complete_within_view(1, 1));
        return Ok(Value::Object(out));
    }
    let source_coverage = capture.get("coverage").cloned().unwrap_or(Value::Null);
    let facet = view
        .get("facet")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (offset, limit) = offset_limit(view);
    if facet == "diagnostics" {
        let key = if view.get("stream").and_then(Value::as_str) == Some("tshark") {
            "tshark_stderr"
        } else {
            "capinfos_stderr"
        };
        let value = capture
            .get("diagnostics")
            .and_then(|diagnostics| diagnostics.get(key))
            .and_then(Value::as_str);
        let (item, coverage) = text_page(value.unwrap_or_default(), offset, limit, "Diagnostics")?;
        out.insert("source_coverage".into(), source_coverage);
        out.insert(
            "page".into(),
            json!({
                "facet": "diagnostics",
                "text": item.get("text").cloned().unwrap_or(Value::Null),
                "status": if value.is_none() { "unknown" } else { "retained" },
            }),
        );
        out.insert("coverage".into(), coverage);
        if value.is_none() {
            out.insert(
                "unknowns".into(),
                json!([
                    SAVED_SCOPE,
                    "The parent did not retain diagnostics; an empty text page does not establish their absence."
                ]),
            );
        }
        return Ok(Value::Object(out));
    }
    let (items, total) = select_rows(&capture, view, facet, offset, limit)?;
    let examined = items.len();
    out.insert("source_coverage".into(), source_coverage);
    out.insert("page".into(), json!({ "facet": facet, "items": items }));
    out.insert("coverage".into(), page_coverage(offset, examined, total));
    Ok(Value::Object(out))
}

/// `parseParent`: the strict capture result bound to its recorded subject.
fn parse_parent(parent: &Parent<'_>) -> Result<Arc<Value>, AnalysisError> {
    let capture = parent.cached("pcap_capture", || {
        let Some(root) = schema::tool_result_schema(PARENT_OPERATION) else {
            return Err(AnalysisError::output(
                OPERATION,
                format!("The {PARENT_OPERATION} result contract is unavailable."),
            ));
        };
        // Issues keep result-relative paths over the normalized result itself.
        schema::parse_strict(&root, parent.normalized_result).map_err(|issues| {
            schema::input_error_from_issues(
                OPERATION,
                &issues,
                parent.normalized_result,
                Vec::new(),
            )
        })
    })?;
    let target = capture.get("target").unwrap_or(&Value::Null);
    if !parent.subject.is_object()
        || parent.subject.get("local_path") != target.get("path")
        || parent
            .subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            != target.get("sha256")
    {
        return Err(view_error(
            &["source", "subject"],
            "invalid_value",
            "Packet parent subject must identify the report's exact path and SHA-256.",
        ));
    }
    Ok(capture)
}

fn rows<'a>(capture: &'a Value, key: &str) -> &'a [Value] {
    capture
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// `summarize`: metadata with retained counts and diagnostic code-unit lengths.
fn summarize(capture: &Value) -> Value {
    let mut summary = without(
        capture,
        &[
            "endpoints",
            "dns_queries",
            "tls_sni_values",
            "protocol_distribution",
            "http_request_uris",
            "unattributed_dns_addresses",
            "diagnostics",
        ],
    );
    summary.insert(
        "retained_counts".into(),
        json!({
            "endpoints": rows(capture, "endpoints").len(),
            "dns_queries": rows(capture, "dns_queries").len(),
            "tls_sni_values": rows(capture, "tls_sni_values").len(),
            "protocol_distribution": rows(capture, "protocol_distribution").len(),
            "http_request_uris": rows(capture, "http_request_uris").len(),
            "unattributed_dns_addresses": rows(capture, "unattributed_dns_addresses").len(),
        }),
    );
    let length = |diagnostics: &Value, key: &str| {
        js_len(
            diagnostics
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
    };
    summary.insert(
        "diagnostics_code_units".into(),
        match capture.get("diagnostics") {
            None => Value::Null,
            Some(diagnostics) => json!({
                "tshark": length(diagnostics, "tshark_stderr"),
                "capinfos": length(diagnostics, "capinfos_stderr"),
            }),
        },
    );
    Value::Object(summary)
}

/// `selectRows`: one retained fact page and its total.
fn select_rows(
    capture: &Value,
    view: &Value,
    facet: &str,
    offset: usize,
    limit: usize,
) -> Result<(Vec<Value>, usize), AnalysisError> {
    let plain = |key: &str| {
        let all = rows(capture, key);
        (page(all, offset, limit), all.len())
    };
    Ok(match facet {
        "endpoints" => plain("endpoints"),
        "tls-sni" => plain("tls_sni_values"),
        "protocols" => plain("protocol_distribution"),
        "http-uris" => plain("http_request_uris"),
        "unattributed-addresses" => plain("unattributed_dns_addresses"),
        "dns-queries" => {
            let all = rows(capture, "dns_queries");
            let items = page(all, offset, limit)
                .iter()
                .map(|query| {
                    let mut row = without(query, &["response_addresses"]);
                    row.insert(
                        "retained_response_address_count".into(),
                        json!(rows(query, "response_addresses").len()),
                    );
                    Value::Object(row)
                })
                .collect();
            (items, all.len())
        }
        _ => {
            let selected = view.get("query");
            let matches: Vec<&Value> = rows(capture, "dns_queries")
                .iter()
                .filter(|query| query.get("query") == selected)
                .collect();
            let [query] = matches.as_slice() else {
                return Err(view_error(
                    &["view", "query"],
                    "invalid_value",
                    "Select one unambiguous exact retained DNS question.",
                ));
            };
            let addresses = rows(query, "response_addresses");
            (page(addresses, offset, limit), addresses.len())
        }
    })
}
