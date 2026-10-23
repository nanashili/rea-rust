//! Views over retained `inspect_binary_layout` Evidence.
//!
//! Compatibility owners: `src/domain/analysisView/binaryLayoutView.ts` and the
//! `binaryLayoutSchema` refinements in `src/domain/native/binaryLayout.ts`
//! (`safeParseOwnedBinaryLayout`).
use crate::common::json::{self, object};
use crate::common::view::{
    Parent, bounded_view_messages, complete_within_view, input_error, issue, offset_limit, page,
    page_coverage, view_error, view_kind,
};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;

/// `safeParseOwnedBinaryLayout`: the owning result contract plus the public
/// boundary refinements. Sealed parents are validated once per cache lifetime.
fn parse_layout(parent: &Parent<'_>) -> Result<Arc<Value>, AnalysisError> {
    let mismatch = || {
        view_error(
            &["source"],
            "invalid_value",
            "Parent Evidence result does not match inspect_binary_layout.",
        )
    };
    let layout = parent
        .parse_result("inspect_binary_layout")
        .map_err(|_| mismatch())?;
    let valid = parent.cached("inspect_binary_layout:refined", || {
        Ok(refinements_hold(&layout))
    })?;
    if *valid { Ok(layout) } else { Err(mismatch()) }
}

/// `BigInt` of a validated `unsignedHex` string (at most 16 hex digits).
fn hex(value: Option<&Value>) -> Option<u128> {
    let text = value?.as_str()?;
    u128::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

fn uint(value: Option<&Value>) -> Option<u64> {
    value?.as_u64()
}

fn type_is(row: Option<&Value>, name: &str) -> bool {
    row.and_then(|row| row.get("type")).and_then(Value::as_str) == Some(name)
}

/// Port of the `binaryLayoutSchema.superRefine` checks; any failure rejects
/// the parent with one projected issue, so only validity is recorded.
fn refinements_hold(value: &Value) -> bool {
    let Some(size) = uint(
        value
            .get("artifact")
            .and_then(|artifact| artifact.get("bytes")),
    ) else {
        return false;
    };
    let size = u128::from(size);
    let check = |offset: Option<&Value>, length: Option<&Value>| -> bool {
        match (hex(offset), hex(length)) {
            (Some(start), Some(bytes)) => start <= size && bytes <= size - start,
            _ => false,
        }
    };
    let check_location = |location: Option<&Value>| -> bool {
        let location = location.unwrap_or(&Value::Null);
        check(location.get("offset"), location.get("bytes"))
    };
    let check_name = |reported: Option<&Value>| -> bool {
        match reported.and_then(|name| name.get("location")) {
            Some(Value::Null) | None => true,
            location => check_location(location),
        }
    };
    let image_type = json::str_at(value, "image_type");
    let entry = value.get("entry_point").unwrap_or(&Value::Null);
    let expected_meaning = if image_type == Some("ET_REL") {
        "not-applicable"
    } else if json::str_at(entry, "reported_value") == Some("0x0") {
        "absent"
    } else {
        "linked-virtual-address"
    };
    if json::str_at(entry, "meaning") != Some(expected_meaning) {
        return false;
    }
    let sections = json::array_at(value, "sections");
    for (index, section) in sections.iter().enumerate() {
        if (type_is(Some(section), "SHT_SYMTAB") || type_is(Some(section), "SHT_DYNSYM"))
            && !type_is(
                uint(section.get("link"))
                    .and_then(|link| usize::try_from(link).ok())
                    .and_then(|link| sections.get(link)),
                "SHT_STRTAB",
            )
        {
            return false;
        }
        if uint(section.get("index")) != Some(index as u64) {
            return false;
        }
        if !check_location(section.get("header_location")) || !check_name(section.get("name")) {
            return false;
        }
        if json::str_at(section, "file_backing") == Some("file")
            && !check(section.get("offset"), section.get("size"))
        {
            return false;
        }
    }
    for (index, segment) in json::array_at(value, "segments").iter().enumerate() {
        if uint(segment.get("index")) != Some(index as u64) {
            return false;
        }
        if !check_location(segment.get("header_location")) {
            return false;
        }
        let is_null = type_is(Some(segment), "PT_NULL");
        let has_file_bytes = !is_null && hex(segment.get("file_size")) != Some(0);
        let backing = if has_file_bytes { "file" } else { "none" };
        if json::str_at(segment, "file_backing") != Some(backing) {
            return false;
        }
        if is_null != segment.get("permissions").is_none_or(Value::is_null) {
            return false;
        }
        if has_file_bytes && !check(segment.get("offset"), segment.get("file_size")) {
            return false;
        }
    }
    let symbols = json::array_at(value, "symbols");
    for symbol in symbols {
        if !check_location(symbol.get("location")) || !check_name(symbol.get("name")) {
            return false;
        }
    }
    let relocations = json::array_at(value, "relocations");
    if !relocations
        .iter()
        .all(|relocation| check_location(relocation.get("location")))
    {
        return false;
    }
    if !relocation_references_hold(value, sections, symbols, relocations) {
        return false;
    }
    if !packed_relative_tables_hold(value, sections, &check_location) {
        return false;
    }
    let linkage = value.get("linkage").unwrap_or(&Value::Null);
    ["needed_libraries", "interpreters"].iter().all(|facet| {
        json::array_at(linkage, facet)
            .iter()
            .all(|name| check_name(Some(name)))
    })
}

/// `validateRelocationReferences`.
fn relocation_references_hold(
    value: &Value,
    sections: &[Value],
    symbols: &[Value],
    relocations: &[Value],
) -> bool {
    let section_at = |index: Option<u64>| {
        index
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| sections.get(index))
    };
    let known: HashSet<(u64, u64)> = symbols
        .iter()
        .filter_map(|symbol| {
            Some((
                uint(symbol.get("table_index"))?,
                uint(symbol.get("entry_index"))?,
            ))
        })
        .collect();
    let relocatable = json::str_at(value, "image_type") == Some("ET_REL");
    for relocation in relocations {
        let owner = section_at(uint(relocation.get("section_index")));
        let owner_info = owner.and_then(|owner| uint(owner.get("info")));
        let target = relocation.get("target").unwrap_or(&Value::Null);
        let target_kind = json::str_at(target, "kind");
        let reported = relocation.get("reported_offset");
        let target_matches = if relocatable {
            match target_kind {
                Some("section-offset") => {
                    let target_index = uint(target.get("section_index"));
                    target_index != Some(0)
                        && target_index.is_some()
                        && target_index == owner_info
                        && section_at(target_index)
                            .is_some_and(|section| !type_is(Some(section), "SHT_NULL"))
                        && target.get("offset") == reported
                }
                Some("unknown-section") => {
                    let reported_index = uint(target.get("reported_section_index"));
                    let reason = json::str_at(target, "unknown_reason");
                    reported_index.is_some()
                        && reported_index == owner_info
                        && target.get("offset") == reported
                        && if reported_index == Some(0) {
                            reason == Some("undefined-section-reference")
                        } else {
                            type_is(section_at(reported_index), "SHT_NULL")
                                && reason == Some("inactive-section-header")
                        }
                }
                _ => false,
            }
        } else {
            target_kind == Some("linked-virtual-address") && target.get("address") == reported
        };
        if !target_matches {
            return false;
        }
        let table_index = uint(relocation.get("symbol_table_index"));
        let symbol_index = uint(relocation.get("symbol_index"));
        let table = section_at(table_index);
        let table_exists = table_index != Some(0)
            && (type_is(table, "SHT_SYMTAB") || type_is(table, "SHT_DYNSYM"));
        let positive_reference_exists = table_exists
            && match (
                table.and_then(|table| hex(table.get("entry_size"))),
                table.and_then(|table| hex(table.get("size"))),
                symbol_index,
                table_index,
            ) {
                (Some(entry_size), Some(size), Some(symbol), Some(table_index)) => {
                    entry_size >= 24
                        && u128::from(symbol) < size / entry_size
                        && known.contains(&(table_index, symbol))
                }
                _ => false,
            };
        let owner_is_relocation = type_is(owner, "SHT_REL") || type_is(owner, "SHT_RELA");
        let expected_meaning = if symbol_index == Some(0) {
            "zero-symbol-value"
        } else {
            "symbol-table-entry"
        };
        if !owner_is_relocation
            || owner.and_then(|owner| uint(owner.get("link"))) != table_index
            || (table_index != Some(0) && !table_exists)
            || (symbol_index != Some(0) && !positive_reference_exists)
            || json::str_at(relocation, "symbol_reference_meaning") != Some(expected_meaning)
        {
            return false;
        }
    }
    true
}

/// `validatePackedRelativeTables`.
fn packed_relative_tables_hold(
    value: &Value,
    sections: &[Value],
    check_location: &dyn Fn(Option<&Value>) -> bool,
) -> bool {
    for table in json::array_at(value, "packed_relative_relocations") {
        let location = table.get("location").unwrap_or(&Value::Null);
        if !check_location(Some(location)) {
            return false;
        }
        let encoded = json::str_at(table, "encoded_bytes_base64").unwrap_or_default();
        let length = json::js_len(encoded);
        let padding = if encoded.ends_with("==") {
            2
        } else if encoded.ends_with('=') {
            1
        } else {
            0
        };
        // `(length * 3) / 4 - padding` must be an integer equal to the range.
        if (length * 3) % 4 != 0
            || ((length * 3 / 4) as u128).checked_sub(padding) != hex(location.get("bytes"))
        {
            return false;
        }
        let section = uint(table.get("section_index"))
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| sections.get(index));
        if !type_is(section, "SHT_RELR")
            || section.and_then(|section| section.get("offset")) != location.get("offset")
            || section.and_then(|section| section.get("size")) != location.get("bytes")
        {
            return false;
        }
        for (decoded, entry) in json::array_at(table, "entries").iter().enumerate() {
            if uint(entry.get("decoded_index")) != Some(decoded as u64) {
                return false;
            }
        }
    }
    true
}

fn layout_unknowns(layout: &Value) -> Vec<String> {
    let mut unknowns: Vec<String> = [
        "runtime_load_base is unknown",
        "entry_point.execution_status is unknown",
        "relocation_inventory_completeness is unknown",
        "linkage.convenience_maps_completeness is unknown",
        "linkage.runtime_library_paths are unknown",
    ]
    .map(str::to_owned)
    .to_vec();
    let mitigations = layout.get("mitigations").unwrap_or(&Value::Null);
    if mitigations.get("nx_indicator").is_none_or(Value::is_null) {
        unknowns.push("mitigations.nx_indicator is unknown".to_owned());
    }
    if mitigations.get("relro").is_none_or(Value::is_null) {
        unknowns.push("mitigations.relro is unknown".to_owned());
    }
    unknowns
}

fn incompatible(detail: &str) -> AnalysisError {
    view_error(&["view"], "invalid_value", detail)
}

/// `selectIndexed`.
fn select_indexed(collection: &str, rows: &[Value], index: &Value) -> Result<Value, AnalysisError> {
    if let Some(row) = index
        .as_u64()
        .and_then(|index| usize::try_from(index).ok())
        .and_then(|index| rows.get(index))
    {
        return Ok(row.clone());
    }
    let maximum = rows.len().saturating_sub(1);
    let rendered = match index.as_u64() {
        Some(number) => number.to_string(),
        None => index.to_string(),
    };
    let mut issue: InputIssue = issue(
        &["view", "selector", "index"],
        "out_of_range",
        format!(
            "{collection} index {rendered} is outside 0..{maximum} ({} entries).",
            rows.len()
        ),
    );
    issue.minimum = Some(0.0);
    issue.maximum = Some(maximum as f64);
    Err(input_error(vec![issue]))
}

/// `selectNamed`: exact names whose bytes resolved (`unknown_reason === null`).
fn select_named(collection: &str, rows: &[Value], name: &str) -> Result<Value, AnalysisError> {
    let matches: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            let reported = row.get("name").unwrap_or(&Value::Null);
            reported.get("unknown_reason").is_some_and(Value::is_null)
                && json::str_at(reported, "display") == Some(name)
        })
        .map(|(index, _)| index)
        .collect();
    let quoted = Value::String(name.to_owned()).to_string();
    match matches.as_slice() {
        [only] => Ok(rows[*only].clone()),
        [] => Err(view_error(
            &["view", "selector", "name"],
            "invalid_value",
            format!(
                "No {collection} named {quoted}. Collection has {} entries; page it to inspect exact indexes and names.",
                rows.len()
            ),
        )),
        many => {
            let mut issue = issue(
                &["view", "selector", "name"],
                "invalid_value",
                format!("Multiple {collection} named {quoted}; select one by index."),
            );
            issue.expected = Some(Value::Array(
                many.iter().map(|index| json!({ "index": index })).collect(),
            ));
            Err(input_error(vec![issue]))
        }
    }
}

/// `projectBinaryLayoutView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let layout = parse_layout(parent)?;
    let artifact = layout.get("artifact").unwrap_or(&Value::Null);
    let mut limitations = parent.limitations.clone();
    limitations.extend(json::strings(
        layout.get("limitations").unwrap_or(&Value::Null),
    ));
    let shared = [
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!("inspect_binary_layout")),
        ("parent_digest", json!(parent.digest())),
        (
            "artifact",
            json!({
                "path": artifact.get("path").cloned().unwrap_or(Value::Null),
                "sha256": artifact.get("sha256").cloned().unwrap_or(Value::Null),
            }),
        ),
        (
            "limitations",
            json!(bounded_view_messages(
                &limitations,
                parent.evidence_id,
                "limitations",
                &[]
            )),
        ),
        (
            "unknowns",
            json!(bounded_view_messages(
                &layout_unknowns(&layout),
                parent.evidence_id,
                "unknowns",
                &[]
            )),
        ),
    ];
    let with_shared = |entries: Vec<(&'static str, Value)>| {
        object(entries.into_iter().chain(shared.iter().cloned()))
    };
    let sections = json::array_at(&layout, "sections");
    let symbols = json::array_at(&layout, "symbols");
    let kind = view_kind(view);
    match kind {
        "native" => {
            return Err(incompatible(
                "Native views require analyze_function Evidence.",
            ));
        }
        "inventory" => return Err(incompatible("Inventory views require artifact Evidence.")),
        "wasm" => {
            return Err(incompatible(
                "WASM views require inspect_wasm_artifact Evidence.",
            ));
        }
        "evm" => {
            return Err(incompatible(
                "EVM views require inspect_evm_interface Evidence.",
            ));
        }
        _ => {}
    }
    if kind == "summary" {
        let segments = json::array_at(&layout, "segments").len();
        let relocations = json::array_at(&layout, "relocations").len();
        let total = sections.len() + segments + symbols.len() + relocations;
        let summary = json!({
            "bytes": artifact.get("bytes").cloned().unwrap_or(Value::Null),
            "format": layout.get("format").cloned().unwrap_or(Value::Null),
            "architecture": layout.get("architecture").cloned().unwrap_or(Value::Null),
            "image_type": layout.get("image_type").cloned().unwrap_or(Value::Null),
            "entry": layout.get("entry_point").cloned().unwrap_or(Value::Null),
            "counts": {
                "sections": sections.len(),
                "segments": segments,
                "symbols": symbols.len(),
                "relocations": relocations,
            },
            "limitation_count": json::array_at(&layout, "limitations").len(),
        });
        return Ok(with_shared(vec![
            ("kind", json!("summary")),
            ("view", view.clone()),
            ("summary", summary),
            ("coverage", complete_within_view(total, total)),
        ]));
    }
    if kind == "facet" {
        let facet = if json::str_at(view, "facet") == Some("mitigations") {
            "mitigations"
        } else {
            "linkage"
        };
        return Ok(with_shared(vec![
            ("kind", json!("facet")),
            ("view", view.clone()),
            ("facet", layout.get(facet).cloned().unwrap_or(Value::Null)),
            ("coverage", complete_within_view(1, 1)),
        ]));
    }
    let collection = json::str_at(view, "collection").unwrap_or_default();
    if kind == "item" {
        if collection == "modules" {
            return Err(incompatible(
                "modules collection applies to analyze_javascript_application Evidence.",
            ));
        }
        let (name, rows) = if collection == "sections" {
            ("sections", sections)
        } else {
            ("symbols", symbols)
        };
        let selector = view.get("selector").unwrap_or(&Value::Null);
        let item = if let Some(index) = selector.get("index") {
            select_indexed(name, rows, index)?
        } else if let Some(selected) = selector.get("name") {
            select_named(name, rows, selected.as_str().unwrap_or_default())?
        } else {
            return Err(incompatible(
                "Section and symbol items are selected by index or exact name.",
            ));
        };
        return Ok(with_shared(vec![
            ("kind", json!("item")),
            ("view", view.clone()),
            ("item", item),
            ("coverage", complete_within_view(1, rows.len())),
        ]));
    }
    if kind != "page" {
        return Err(incompatible(
            "Layout views require summary, facet, item or page selections.",
        ));
    }
    if matches!(collection, "modules" | "procedures" | "strings") {
        return Err(incompatible(
            "modules collection applies to analyze_javascript_application Evidence; procedures and strings apply to their matching list operation Evidence.",
        ));
    }
    let rows = if collection == "sections" {
        sections
    } else {
        symbols
    };
    let (offset, limit) = offset_limit(view);
    let items = page(rows, offset, limit);
    let examined = items.len();
    Ok(with_shared(vec![
        ("kind", json!("page")),
        ("view", view.clone()),
        ("items", Value::Array(items)),
        ("coverage", page_coverage(offset, examined, rows.len())),
    ]))
}
