//! Compose a captured IL2CPP reconstruction report.
//!
//! This workflow is intentionally a reporting boundary.  It does not decode
//! an artifact, choose a preferred parser result, or infer relationships from
//! row order, filenames, or display names. Metadata method row positions are
//! used only where the metadata contract explicitly defines them as
//! MethodIndex identities. Every supplied projection remains attached to its
//! source and unresolved facts stay unresolved.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "build_il2cpp_static_report";
const MAX_ROWS: usize = 200_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_METHOD_IDENTITY_LENGTH: usize = 240;

/// Build a report from already captured IL2CPP projections.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    let (metadata, metadata_source) = metadata_projection(root)?;
    let modules = rows(root, &["codegen_modules", "modules"], "codegen_modules")?;
    let method_addresses = rows(
        root,
        &["method_addresses", "method_address_rows", "methods"],
        "method_addresses",
    )?;
    let members = member_rows(root, &metadata)?;
    let limitations = text_rows(root.get("limitations"), "limitations")?;

    let mut unknowns = Vec::new();
    let mut ambiguities = Vec::new();
    let mut disagreements = Vec::new();
    let mut source_evidence = Vec::new();

    if let Some(source) = metadata_source.clone() {
        source_evidence.push(source);
    }
    collect_row_sources(std::slice::from_ref(&metadata), &mut source_evidence);
    collect_row_sources(&modules, &mut source_evidence);
    collect_row_sources(&method_addresses, &mut source_evidence);
    collect_row_sources(&members, &mut source_evidence);

    if modules.is_empty() {
        unknowns.push("No CodeGenModule identity rows were supplied.".to_owned());
    }
    if method_addresses.is_empty() {
        unknowns.push("No method-address rows were supplied.".to_owned());
    }
    if members.is_empty() {
        unknowns.push("No type/member rows were supplied.".to_owned());
    }

    detect_duplicate_module_identities(&modules, &mut ambiguities);
    detect_identity_disagreements(&metadata, &modules, &mut disagreements);
    let (method_correlations, represented_address_rows) = correlate_methods(
        &metadata,
        &method_addresses,
        &mut unknowns,
        &mut ambiguities,
    )?;
    let method_coverage = correlation_coverage(
        &method_correlations,
        &method_addresses,
        &represented_address_rows,
    );

    if method_coverage.unresolved > 0 {
        unknowns.push(format!(
            "{} metadata method rows have no matching method-address row.",
            method_coverage.unresolved
        ));
    }

    if method_coverage.address_rows_without_metadata > 0 {
        unknowns.push(format!(
            "{} method-address rows have no matching metadata method row.",
            method_coverage.address_rows_without_metadata
        ));
    }
    let module_provenance = row_provenance(&modules, metadata_source.as_ref());
    let method_provenance = row_provenance(&method_addresses, metadata_source.as_ref());
    let member_provenance = row_provenance(&members, metadata_source.as_ref());

    let partial = !unknowns.is_empty()
        || !ambiguities.is_empty()
        || !disagreements.is_empty()
        || !limitations.is_empty();

    Ok(json!({
        "operation": OPERATION,
        "status": if partial { "partial" } else { "complete" },
        "metadata": metadata,
        "codegen_modules": modules,
        "method_addresses": method_addresses,
        "members": members,
        "method_correlations": method_correlations,
        "provenance": {
            "codegen_modules": module_provenance,
            "method_addresses": method_provenance,
            "members": member_provenance,
        },
        "source_evidence": deduplicate_values(source_evidence),
        "coverage": {
            "codegen_modules": modules.len(),
            "method_addresses": method_addresses.len(),
            "members": members.len(),
            "method_correlations": method_correlations.len(),
            "method_correlations_matched": method_coverage.matched,
            "method_correlations_unresolved": method_coverage.unresolved,
            "method_correlations_ambiguous": method_coverage.ambiguous,
            "method_address_rows_without_metadata": method_coverage.address_rows_without_metadata,
            "limitations": limitations.len(),
        },
        "unknowns": unknowns,
        "ambiguities": ambiguities,
        "disagreements": disagreements,
        "limitations": limitations,
    }))
}

pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn metadata_projection(root: &Map<String, Value>) -> Result<(Value, Option<Value>), Failure> {
    let value = selected_alias_value(root, &["metadata_evidence", "metadata"], "metadata")?
        .ok_or_else(|| {
            invalid(
                "metadata",
                "Metadata Evidence or a projected metadata object is required",
            )
        })?;

    let evidence = value
        .as_object()
        .and_then(|object| object.get("evidence"))
        .unwrap_or(value);
    if !evidence.is_object() {
        return Err(invalid("metadata", "Expected an object"));
    }
    if evidence.get("evidence_id").is_some() || evidence.get("operation").is_some() {
        let raw = serde_json::value::to_raw_value(evidence)
            .map_err(|error| invalid("metadata", &error.to_string()))?;
        let record =
            EvidenceRecord::parse(&raw).map_err(|error| invalid("metadata", &error.to_string()))?;
        let normalized: Value = serde_json::from_str(record.normalized_result().get())
            .map_err(|error| invalid("metadata.normalized_result", &error.to_string()))?;
        let source = json!({
            "evidence_id": record.evidence_id(),
            "operation": serde_json::from_str::<String>(record.operation().get())
                .map_err(|error| invalid("metadata.operation", &error.to_string()))?,
        });
        return Ok((normalized, Some(source)));
    }
    Ok((value.clone(), None))
}

fn member_rows(root: &Map<String, Value>, metadata: &Value) -> Result<Vec<Value>, Failure> {
    let aliases = ["members", "member_rows", "type_members"];
    if aliases.iter().any(|alias| root.contains_key(*alias)) {
        return rows(root, &aliases, "members");
    }

    metadata_member_rows(metadata)
}

fn metadata_member_rows(metadata: &Value) -> Result<Vec<Value>, Failure> {
    let Some(metadata) = metadata.as_object() else {
        return Ok(Vec::new());
    };

    let categories = [
        (
            "field",
            ["fields", "field_definitions", "fieldDefinitions"].as_slice(),
        ),
        (
            "property",
            ["properties", "property_definitions", "propertyDefinitions"].as_slice(),
        ),
        (
            "event",
            ["events", "event_definitions", "eventDefinitions"].as_slice(),
        ),
        (
            "parameter",
            [
                "parameters",
                "parameter_definitions",
                "parameterDefinitions",
            ]
            .as_slice(),
        ),
    ];
    let mut projected = Vec::new();

    for (kind, aliases) in categories {
        let Some(values) = selected_alias_value(metadata, aliases, kind)? else {
            continue;
        };
        let values = values
            .as_array()
            .ok_or_else(|| invalid(&format!("metadata.{kind}"), "Expected an array"))?;
        let projected_count = projected
            .len()
            .checked_add(values.len())
            .ok_or_else(|| resource("members", "Collection size overflowed"))?;
        if projected_count > MAX_ROWS {
            return Err(resource(
                "members",
                "Collection exceeds the supported bound",
            ));
        }

        for (index, value) in values.iter().enumerate() {
            let mut row = value.as_object().cloned().ok_or_else(|| {
                invalid(
                    &format!("metadata.{kind}[{index}]"),
                    "Expected an object row",
                )
            })?;
            row.insert("member_kind".into(), Value::String(kind.into()));
            projected.push(Value::Object(row));
        }
    }

    Ok(projected)
}

fn selected_alias_value<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<Option<&'a Value>, Failure> {
    let mut selected = None;

    for alias in aliases {
        let Some(candidate) = object.get(*alias) else {
            continue;
        };
        if let Some(existing) = selected {
            if existing != candidate {
                return Err(invalid(field, "Equivalent aliases disagree"));
            }
        } else {
            selected = Some(candidate);
        }
    }

    Ok(selected)
}

fn rows<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<Vec<Value>, Failure> {
    let Some(value) = selected_alias_value(root, aliases, field)? else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if values.len() > MAX_ROWS {
        return Err(resource(field, "Collection exceeds the supported bound"));
    }
    if let Some(index) = values.iter().position(|row| !row.is_object()) {
        return Err(invalid(
            &format!("{field}[{index}]"),
            "Expected an object row",
        ));
    }
    Ok(values.clone())
}

fn text_rows(value: Option<&Value>, field: &str) -> Result<Vec<String>, Failure> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(resource(field, "Collection exceeds the supported bound"));
    }
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            row.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("{field}[{index}]"), "Expected text"))
        })
        .collect()
}

fn collect_row_sources(rows: &[Value], output: &mut Vec<Value>) {
    for row in rows {
        let Some(object) = row.as_object() else {
            continue;
        };

        for field in ["source_evidence", "evidence"] {
            if let Some(source) = object.get(field) {
                output.push(source.clone());
            }
        }

        if let Some(source_id) = object.get("source_evidence_id") {
            output.push(source_id.clone());
        }

        if let Some(source_ids) = object.get("source_evidence_ids") {
            if let Some(source_ids) = source_ids.as_array() {
                output.extend(source_ids.iter().cloned());
            }
        }
    }
}

fn detect_duplicate_module_identities(modules: &[Value], ambiguities: &mut Vec<String>) {
    let mut identities = BTreeMap::<String, usize>::new();
    for module in modules {
        if let Some(identity) = identity_key(module) {
            *identities.entry(identity).or_default() += 1;
        }
    }
    for (identity, count) in identities {
        if count > 1 {
            ambiguities.push(format!(
                "CodeGenModule identity {identity} has {count} supplied rows."
            ));
        }
    }
}

fn detect_identity_disagreements(
    metadata: &Value,
    modules: &[Value],
    disagreements: &mut Vec<String>,
) {
    let Some(metadata_object) = metadata.as_object() else {
        return;
    };
    for module in modules {
        if let Some(module_object) = module.as_object() {
            for field in [
                "image_index",
                "image_name",
                "module_name",
                "binary_sha256",
                "sha256",
                "address_space",
            ] {
                let Some(metadata_value) = metadata_object.get(field) else {
                    continue;
                };
                let Some(module_value) = module_object.get(field) else {
                    continue;
                };
                if metadata_value != module_value {
                    disagreements.push(format!(
                        "Metadata {field} {metadata_value} disagrees with CodeGenModule {field} {module_value}."
                    ));
                }
            }
        }
    }
}

fn correlate_methods(
    metadata: &Value,
    addresses: &[Value],
    unknowns: &mut Vec<String>,
    ambiguities: &mut Vec<String>,
) -> Result<(Vec<Value>, BTreeSet<usize>), Failure> {
    let metadata_object = metadata
        .as_object()
        .ok_or_else(|| invalid("metadata", "Expected an object"))?;
    let methods: &[Value] = match selected_alias_value(
        metadata_object,
        &["methods", "method_definitions", "methodDefinitions"],
        "metadata.methods",
    )? {
        Some(value) => value
            .as_array()
            .ok_or_else(|| invalid("metadata.methods", "Expected an array"))?,
        None => &[],
    };

    if methods.len() > MAX_ROWS {
        return Err(resource(
            "metadata.methods",
            "Collection exceeds the supported bound",
        ));
    }

    if methods.is_empty()
        && !metadata_object.keys().any(|field| {
            matches!(
                field.as_str(),
                "methods" | "method_definitions" | "methodDefinitions"
            )
        })
    {
        unknowns.push("Metadata does not contain a method projection.".to_owned());
    }

    let mut metadata_identity_counts = BTreeMap::<String, usize>::new();
    for (index, method) in methods.iter().enumerate() {
        let identity = match method_key(method) {
            MethodKeyClaim::Identified(key) => Some(key),
            MethodKeyClaim::Missing => Some(method_index_key(
                u64::try_from(index).expect("method row index fits u64"),
            )),
            MethodKeyClaim::Invalid | MethodKeyClaim::Conflicting => None,
        };
        if let Some(identity) = identity {
            *metadata_identity_counts.entry(identity).or_default() += 1;
        }
    }
    let duplicate_metadata_identities: BTreeSet<String> = metadata_identity_counts
        .into_iter()
        .filter_map(|(key, count)| (count > 1).then_some(key))
        .collect();
    for key in &duplicate_metadata_identities {
        ambiguities.push(format!(
            "Metadata method identity {key} is shared by multiple method rows."
        ));
    }

    let mut indexed = BTreeMap::<String, Vec<(usize, Value)>>::new();
    for (address_index, row) in addresses.iter().enumerate() {
        match method_key(row) {
            MethodKeyClaim::Identified(key) => {
                indexed
                    .entry(key)
                    .or_default()
                    .push((address_index, row.clone()));
            }
            MethodKeyClaim::Conflicting => {
                ambiguities
                    .push("A method-address row has conflicting identity aliases.".to_owned());
            }
            MethodKeyClaim::Missing | MethodKeyClaim::Invalid => {
                unknowns.push(
                    "A method-address row has no usable explicit method identity.".to_owned(),
                );
            }
        }
    }
    let mut output = Vec::new();
    let mut represented_address_rows = BTreeSet::new();
    for (index, method) in methods.iter().enumerate() {
        if !method.is_object() {
            return Err(invalid(
                &format!("metadata.methods[{index}]"),
                "Expected a method row object",
            ));
        }

        let (key, identity_status) = match method_key(method) {
            MethodKeyClaim::Identified(key) => (key, None),
            MethodKeyClaim::Missing => (
                method_index_key(u64::try_from(index).expect("method row index fits u64")),
                None,
            ),
            MethodKeyClaim::Invalid => {
                unknowns.push(format!(
                    "Metadata method row {index} has an invalid identity claim."
                ));
                (format!("unresolved-method-row:{index}"), Some("unresolved"))
            }
            MethodKeyClaim::Conflicting => {
                ambiguities.push(format!(
                    "Metadata method row {index} has conflicting identity aliases."
                ));
                (format!("ambiguous-method-row:{index}"), Some("ambiguous"))
            }
        };
        let matches = if identity_status.is_none() {
            indexed.get(&key).cloned().unwrap_or_default()
        } else {
            Vec::new()
        };
        represented_address_rows.extend(matches.iter().map(|(address_index, _)| *address_index));
        let duplicate_metadata_identity = duplicate_metadata_identities.contains(&key);
        let status = match identity_status {
            Some(status) => status,
            None if duplicate_metadata_identity => "ambiguous",
            None => match matches.len() {
                0 => "unresolved",
                1 => "matched",
                _ => {
                    ambiguities.push(format!("Method identity {key} has multiple address rows."));
                    "ambiguous"
                }
            },
        };
        let mut provenance = Vec::new();
        collect_row_sources(std::slice::from_ref(method), &mut provenance);
        let matching_rows: Vec<Value> = matches
            .iter()
            .map(|(_, address_row)| address_row.clone())
            .collect();
        collect_row_sources(&matching_rows, &mut provenance);
        output.push(json!({
            "method_key": key,
            "status": status,
            "method": method,
            "address_rows": matching_rows,
            "source_evidence": deduplicate_values(provenance),
        }));
    }
    Ok((output, represented_address_rows))
}

#[derive(Default)]
struct CorrelationCoverage {
    matched: usize,
    unresolved: usize,
    ambiguous: usize,
    address_rows_without_metadata: usize,
}

fn correlation_coverage(
    rows: &[Value],
    address_rows: &[Value],
    represented_address_rows: &BTreeSet<usize>,
) -> CorrelationCoverage {
    let mut coverage = CorrelationCoverage::default();

    for row in rows {
        match row.get("status").and_then(Value::as_str) {
            Some("matched") => coverage.matched += 1,
            Some("ambiguous") => coverage.ambiguous += 1,
            _ => coverage.unresolved += 1,
        }
    }

    coverage.address_rows_without_metadata = address_rows
        .iter()
        .enumerate()
        .filter(|(index, _)| !represented_address_rows.contains(index))
        .count();

    coverage
}

fn row_provenance(rows: &[Value], metadata_source: Option<&Value>) -> Vec<Value> {
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            let mut sources = Vec::new();
            if let Some(source) = metadata_source {
                sources.push(source.clone());
            }
            collect_row_sources(std::slice::from_ref(row), &mut sources);
            json!({ "row": index, "source_evidence": deduplicate_values(sources) })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MethodKeyClaim {
    Missing,
    Identified(String),
    Invalid,
    Conflicting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AliasClaim<T> {
    Missing,
    Value(T),
    Invalid,
    Conflicting,
}

fn method_key(value: &Value) -> MethodKeyClaim {
    let Some(object) = value.as_object() else {
        return MethodKeyClaim::Invalid;
    };
    let nested_method = object.get("method").and_then(Value::as_object);
    let mut sources = vec![object];
    if let Some(nested_method) = nested_method {
        sources.push(nested_method);
    }

    let method_index = alias_claim(
        &sources,
        &[
            "metadata_index",
            "metadataIndex",
            "method_index",
            "methodIndex",
        ],
        safe_index,
    );
    let token_index = token_method_index_claim(&sources);

    match (method_index, token_index) {
        (AliasClaim::Conflicting, _) | (_, AliasClaim::Conflicting) => {
            return MethodKeyClaim::Conflicting;
        }
        (AliasClaim::Invalid, _) | (_, AliasClaim::Invalid) => {
            return MethodKeyClaim::Invalid;
        }
        (AliasClaim::Value(index), AliasClaim::Value(token_index)) => {
            if index != token_index {
                return MethodKeyClaim::Conflicting;
            }
            return MethodKeyClaim::Identified(method_index_key(index));
        }
        (AliasClaim::Value(index), AliasClaim::Missing) => {
            return MethodKeyClaim::Identified(method_index_key(index));
        }
        (AliasClaim::Missing, AliasClaim::Value(index)) => {
            return MethodKeyClaim::Identified(method_index_key(index));
        }
        (AliasClaim::Missing, AliasClaim::Missing) => {}
    }

    match alias_claim(&sources, &["method_id", "methodId"], method_id_component) {
        AliasClaim::Value(id) => MethodKeyClaim::Identified(format!("method-id:{id}")),
        AliasClaim::Conflicting => MethodKeyClaim::Conflicting,
        AliasClaim::Invalid => MethodKeyClaim::Invalid,
        AliasClaim::Missing => MethodKeyClaim::Missing,
    }
}

fn token_method_index_claim(sources: &[&Map<String, Value>]) -> AliasClaim<u64> {
    let token = alias_claim(
        sources,
        &["method_token", "methodToken", "token"],
        parse_u32_identity,
    );
    let rid = alias_claim(
        sources,
        &["method_token_rid", "methodTokenRid"],
        parse_method_token_rid,
    );

    match (token, rid) {
        (AliasClaim::Conflicting, _) | (_, AliasClaim::Conflicting) => AliasClaim::Conflicting,
        (AliasClaim::Invalid, _) | (_, AliasClaim::Invalid) => AliasClaim::Invalid,
        (AliasClaim::Value(token), AliasClaim::Value(rid)) => match method_definition_rid(token) {
            Some(token_rid) if token_rid == rid => AliasClaim::Value(u64::from(rid - 1)),
            Some(_) | None => AliasClaim::Conflicting,
        },
        (AliasClaim::Value(token), AliasClaim::Missing) => match method_definition_rid(token) {
            Some(rid) => AliasClaim::Value(u64::from(rid - 1)),
            None => AliasClaim::Invalid,
        },
        (AliasClaim::Missing, AliasClaim::Value(rid)) => AliasClaim::Value(u64::from(rid - 1)),
        (AliasClaim::Missing, AliasClaim::Missing) => AliasClaim::Missing,
    }
}

fn alias_claim<T>(
    sources: &[&Map<String, Value>],
    aliases: &[&str],
    parse: impl Fn(&Value) -> Option<T>,
) -> AliasClaim<T>
where
    T: PartialEq,
{
    let mut selected = None;

    for source in sources {
        for alias in aliases {
            let Some(value) = source.get(*alias).filter(|value| !value.is_null()) else {
                continue;
            };
            let Some(value) = parse(value) else {
                return AliasClaim::Invalid;
            };
            if selected.as_ref().is_some_and(|existing| existing != &value) {
                return AliasClaim::Conflicting;
            }
            selected = Some(value);
        }
    }

    selected.map_or(AliasClaim::Missing, AliasClaim::Value)
}

fn safe_index(value: &Value) -> Option<u64> {
    let index = value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_u64_identity))?;
    (index <= MAX_SAFE_INTEGER).then_some(index)
}

fn parse_method_token_rid(value: &Value) -> Option<u32> {
    let rid = value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_u64_identity))?;
    if rid == 0 || rid > 0x00ff_ffff {
        return None;
    }

    u32::try_from(rid).ok()
}

fn parse_u32_identity(value: &Value) -> Option<u32> {
    let token = value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_u64_identity))?;
    u32::try_from(token).ok()
}

fn parse_u64_identity(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(digits) => u64::from_str_radix(digits, 16).ok(),
        None => value.parse().ok(),
    }
}

fn method_definition_rid(token: u32) -> Option<u32> {
    let rid = token & 0x00ff_ffff;
    (token >> 24 == 0x06 && rid > 0).then_some(rid)
}

fn method_index_key(index: u64) -> String {
    format!("method-index:{index}")
}

fn method_id_component(value: &Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        let value = value.trim();
        if value.is_empty() || value.len() > MAX_METHOD_IDENTITY_LENGTH {
            return None;
        }
        return Some(format!("text:{value}"));
    }

    let number = value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))?;
    Some(format!("number:{number}"))
}

fn identity_key(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    let mut parts = Vec::new();
    for field in [
        "image_index",
        "image_name",
        "module_name",
        "binary_sha256",
        "sha256",
        "address_space",
    ] {
        if let Some(value) = object.get(field) {
            parts.push(format!("{field}={value}"));
        }
    }
    (!parts.is_empty()).then(|| parts.join("|"))
}

fn deduplicate_values(values: Vec<Value>) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.to_string()))
        .collect()
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP static report input is invalid.".into(),
        false,
        "Supply bounded captured IL2CPP projections and authenticated metadata Evidence.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}

fn resource(field: &str, reason: &str) -> Failure {
    Failure::new(
        "resource_exhausted",
        "input_limit",
        "IL2CPP static report input exceeds its bound.".into(),
        false,
        "Reduce the captured row collection and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
