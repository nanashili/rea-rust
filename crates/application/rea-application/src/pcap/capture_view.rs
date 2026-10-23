//! Authenticated, bounded views over retained packet-capture Evidence.
//!
//! This module only projects the normalized result of `inspect_pcap_capture`.
//! It never opens a capture, invokes Wireshark, or derives facts outside the
//! rows and diagnostics retained by the parent Evidence record.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";

pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;
    if !record.operation_matches("inspect_pcap_capture") {
        return Err(invalid(
            "Packet-capture views require inspect_pcap_capture Evidence.",
        ));
    }

    let capture: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("PCAP normalized result is invalid: {error}")))?;
    validate_parent_subject(&record, &capture)?;
    let requested = parse_view(view)?;
    let shared = shared(&record, &capture);
    let body = match requested.kind.as_str() {
        "summary" => summary(&capture, requested.normalized, shared),
        "pcap" => page(&capture, requested, shared)?,
        _ => {
            return Err(invalid(
                "Packet summary parents support summary and pcap views.",
            ));
        }
    };

    create_view_evidence(&record, view, body)
}

struct RequestedView {
    kind: String,
    facet: Option<String>,
    query: Option<String>,
    stream: Option<String>,
    offset: usize,
    limit: usize,
    normalized: Value,
}

fn parse_view(view: &Value) -> Result<RequestedView, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("Packet view must be an object."))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Packet view kind is required."))?;
    if kind == "summary" {
        if object.len() != 1 {
            return Err(invalid("Summary packet views do not accept extra fields."));
        }
        return Ok(RequestedView {
            kind: kind.to_owned(),
            facet: None,
            query: None,
            stream: None,
            offset: 0,
            limit: 64,
            normalized: json!({"kind": "summary"}),
        });
    }
    if kind != "pcap" {
        return Err(invalid(
            "Packet summary parents support summary and pcap views.",
        ));
    }

    let facet = object
        .get("facet")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Packet-capture facet is required."))?;
    let allowed = [
        "endpoints",
        "dns-queries",
        "tls-sni",
        "protocols",
        "http-uris",
        "unattributed-addresses",
        "dns-addresses",
        "diagnostics",
    ];
    if !allowed.contains(&facet) {
        return Err(invalid("Unknown packet-capture facet."));
    }
    let offset = parse_nonnegative_usize(object.get("offset"), "offset")?.unwrap_or(0);
    let limit = parse_nonnegative_usize(object.get("limit"), "limit")?.unwrap_or(64);
    if limit == 0 {
        return Err(invalid("Packet-capture view limit must be positive."));
    }

    let query = object
        .get("query")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let stream = object
        .get("stream")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if facet == "dns-addresses" && query.as_deref().is_none_or(str::is_empty) {
        return Err(invalid(
            "DNS-address views require a non-empty exact query.",
        ));
    }
    if facet == "diagnostics" && !matches!(stream.as_deref(), Some("tshark") | Some("capinfos")) {
        return Err(invalid(
            "Diagnostics views require a tshark or capinfos stream.",
        ));
    }
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "kind" | "facet" | "offset" | "limit" | "query" | "stream"
        ) {
            return Err(invalid("Packet-capture views do not accept extra fields."));
        }
    }
    let mut normalized = Map::new();
    normalized.insert("kind".into(), json!("pcap"));
    normalized.insert("facet".into(), json!(facet));
    normalized.insert("offset".into(), json!(offset));
    normalized.insert("limit".into(), json!(limit));
    if let Some(query) = &query {
        normalized.insert("query".into(), json!(query));
    }
    if let Some(stream) = &stream {
        normalized.insert("stream".into(), json!(stream));
    }
    Ok(RequestedView {
        kind: kind.to_owned(),
        facet: Some(facet.to_owned()),
        query,
        stream,
        offset,
        limit,
        normalized: Value::Object(normalized),
    })
}

fn parse_nonnegative_usize(value: Option<&Value>, name: &str) -> Result<Option<usize>, Failure> {
    let Some(value) = value else { return Ok(None) };
    let number = value
        .as_u64()
        .ok_or_else(|| invalid(&format!("Packet-capture view {name} must be non-negative.")))?;
    usize::try_from(number)
        .map(Some)
        .map_err(|_| invalid(&format!("Packet-capture view {name} is too large.")))
}

fn validate_parent_subject(record: &EvidenceRecord, capture: &Value) -> Result<(), Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let matches = subject["format"].as_str() == Some("file")
        && subject["local_path"] == capture["target"]["path"]
        && subject["digest"]["sha256"] == capture["target"]["sha256"];
    if matches {
        Ok(())
    } else {
        Err(invalid(
            "Packet parent subject must identify the report's exact path and SHA-256.",
        ))
    }
}

fn shared(record: &EvidenceRecord, capture: &Value) -> Value {
    let mut limitations = capture["limitations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    limitations.push(json!("Page totals count retained rows or UTF-16 diagnostic code units. Exhaustion does not prove whole-network completeness; source coverage and examined counts remain separate."));
    json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": "inspect_pcap_capture",
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {"path": capture["target"]["path"], "sha256": capture["target"]["sha256"]},
        "limitations": limitations,
        "unknowns": ["Saved packet observations do not establish process identity, causality, encrypted payload contents or traffic missing from the recording."]
    })
}

fn summary(capture: &Value, view: Value, shared: Value) -> Value {
    let mut summary = capture.as_object().cloned().unwrap_or_default();
    for field in [
        "endpoints",
        "dns_queries",
        "tls_sni_values",
        "protocol_distribution",
        "http_request_uris",
        "unattributed_dns_addresses",
        "diagnostics",
    ] {
        summary.remove(field);
    }
    summary.insert(
        "retained_counts".into(),
        json!({
            "endpoints": array_len(capture, "endpoints"),
            "dns_queries": array_len(capture, "dns_queries"),
            "tls_sni_values": array_len(capture, "tls_sni_values"),
            "protocol_distribution": array_len(capture, "protocol_distribution"),
            "http_request_uris": array_len(capture, "http_request_uris"),
            "unattributed_dns_addresses": array_len(capture, "unattributed_dns_addresses"),
        }),
    );
    let diagnostics = capture.get("diagnostics");
    summary.insert(
        "diagnostics_code_units".into(),
        diagnostics.map_or(Value::Null, |value| {
            json!({"tshark": utf16_len(value["tshark_stderr"].as_str().unwrap_or_default()), "capinfos": utf16_len(value["capinfos_stderr"].as_str().unwrap_or_default())})
        }),
    );
    let mut output =
        json!({"kind":"summary","view":view,"summary":summary,"coverage":complete_coverage(1)});
    extend_shared(&mut output, shared);
    output
}

fn page(capture: &Value, requested: RequestedView, shared: Value) -> Result<Value, Failure> {
    let facet = requested.facet.as_deref().expect("pcap facet validated");
    if facet == "diagnostics" {
        let stream = requested
            .stream
            .as_deref()
            .expect("diagnostic stream validated");
        let value = capture["diagnostics"][if stream == "tshark" {
            "tshark_stderr"
        } else {
            "capinfos_stderr"
        }]
        .as_str();
        let text = value.unwrap_or_default();
        let (item, examined) = utf16_page(text, requested.offset, requested.limit)?;
        let mut output = json!({"kind":"pcap","view":requested.normalized,"source_coverage":capture["coverage"],"page":{"facet":"diagnostics","text":item,"status":if value.is_some() {"retained"} else {"unknown"}},"coverage":page_coverage(requested.offset, examined, utf16_len(text))});
        if value.is_none() {
            output["unknowns"] = json!([
                "Saved packet observations do not establish process identity, causality, encrypted payload contents or traffic missing from the recording.",
                "The parent did not retain diagnostics; an empty text page does not establish their absence."
            ]);
        }
        extend_shared(&mut output, shared);
        return Ok(output);
    }

    let (rows, total) = selected_rows(capture, facet, requested.query.as_deref())?;
    let items = rows
        .iter()
        .skip(requested.offset)
        .take(requested.limit)
        .cloned()
        .collect::<Vec<_>>();
    let examined = items.len();
    let coverage = page_coverage(requested.offset, examined, total);
    let mut output = json!({"kind":"pcap","view":requested.normalized,"source_coverage":capture["coverage"],"page":{"facet":facet,"items":items},"coverage":coverage});
    extend_shared(&mut output, shared);
    Ok(output)
}

fn selected_rows(
    capture: &Value,
    facet: &str,
    query: Option<&str>,
) -> Result<(Vec<Value>, usize), Failure> {
    if facet == "dns-addresses" {
        let matches = capture["dns_queries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| row["query"].as_str() == query)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(invalid(
                "Select one unambiguous exact retained DNS question.",
            ));
        }
        let rows = matches[0]["response_addresses"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        return Ok((rows.clone(), rows.len()));
    }
    let field = match facet {
        "endpoints" => "endpoints",
        "dns-queries" => "dns_queries",
        "tls-sni" => "tls_sni_values",
        "protocols" => "protocol_distribution",
        "http-uris" => "http_request_uris",
        "unattributed-addresses" => "unattributed_dns_addresses",
        _ => return Err(invalid("Unknown packet-capture facet.")),
    };
    let rows = capture[field].as_array().cloned().unwrap_or_default();
    let total = rows.len();
    if facet == "dns-queries" {
        return Ok((
            rows.into_iter()
                .map(|mut row| {
                    let count = row["response_addresses"].as_array().map_or(0, Vec::len);
                    if let Some(object) = row.as_object_mut() {
                        object.remove("response_addresses");
                        object.insert("retained_response_address_count".into(), json!(count));
                    }
                    row
                })
                .collect(),
            total,
        ));
    }
    Ok((rows, total))
}

fn create_view_evidence(
    record: &EvidenceRecord,
    view: &Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let unsigned = json!({"subject":null,"provider":{"id":"analysis-view","name":"REA retained analysis view","version":"1"},"analysis_profile":null,"predicate_type":"rea.analysis-view","operation":OPERATION,"parameters":{"parent_evidence_id":record.evidence_id(),"view":view},"raw_result":null,"normalized_result":body,"confidence":"derived","authority":"analyst-inference","environment":null,"limitations":[],"relationship_coverage":null,"locations":[],"evidence_links":[record.evidence_id()]});
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
            .expect("validated Evidence"),
    )
}

fn extend_shared(output: &mut Value, shared: Value) {
    if let (Some(output), Some(shared)) = (output.as_object_mut(), shared.as_object()) {
        output.extend(shared.clone());
    }
}
fn array_len(capture: &Value, field: &str) -> usize {
    capture[field].as_array().map_or(0, Vec::len)
}
fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}
fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
}
fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
}

fn utf16_page(text: &str, offset: usize, limit: usize) -> Result<(String, usize), Failure> {
    let units = text.encode_utf16().collect::<Vec<_>>();
    let start = offset.min(units.len());
    let mut end = (start + limit).min(units.len());
    if start > 0
        && start < units.len()
        && (0xDC00..=0xDFFF).contains(&units[start])
        && (0xD800..=0xDBFF).contains(&units[start - 1])
    {
        return Err(invalid(
            "Diagnostics offset splits a UTF-16 surrogate pair.",
        ));
    }
    if end < units.len()
        && end > start
        && (0xD800..=0xDBFF).contains(&units[end - 1])
        && (0xDC00..=0xDFFF).contains(&units[end])
    {
        end -= 1;
    }
    if end == start && start < units.len() {
        return Err(invalid(
            "Increase diagnostics limit to include the next complete Unicode character.",
        ));
    }
    Ok((String::from_utf16_lossy(&units[start..end]), end - start))
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the view and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
