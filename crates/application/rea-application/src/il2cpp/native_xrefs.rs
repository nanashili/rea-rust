//! Join captured native cross-reference facts to IL2CPP method addresses.
//!
//! This module owns no disassembly or control-flow interpretation.  It only
//! correlates caller-supplied rows when the binary digest, address space, and
//! exact target address agree.  Duplicate references and unresolved targets
//! remain visible in the result.

use rea_core::{
    evidence::is_sha256,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "map_il2cpp_native_xrefs";

const MAX_ROWS: usize = 200_000;
const MAX_TEXT_LENGTH: usize = 512;

/// Correlate native xref targets with captured IL2CPP method-address rows.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    let methods = rows(
        root,
        &["methods", "method_addresses", "mappings"],
        "methods",
    )?;
    let xrefs = rows(root, &["xrefs", "native_xrefs", "call_references"], "xrefs")?;
    let method_rows = parse_methods(methods)?;
    let xref_rows = parse_xrefs(xrefs)?;

    let mut items = Vec::with_capacity(method_rows.len());
    let mut mapped = 0usize;
    let mut ambiguous = 0usize;
    let mut unknown = 0usize;
    let mut unmapped = 0usize;

    for method in &method_rows {
        let matches: Vec<Value> = xref_rows
            .iter()
            .filter(|xref| xref.matches_target(method))
            .map(XrefRow::output)
            .collect();

        let status = match matches.len() {
            0 if xref_rows
                .iter()
                .any(|xref| xref.same_binary(&method.binary_sha256)) =>
            {
                unknown += 1;
                "unknown"
            }
            0 => {
                unmapped += 1;
                "unmapped"
            }
            1 => {
                mapped += 1;
                "mapped"
            }
            _ => {
                ambiguous += 1;
                "ambiguous"
            }
        };

        let mut item = Map::new();
        item.insert("method".into(), method.source.clone());
        item.insert("status".into(), Value::String(status.into()));
        item.insert("xrefs".into(), Value::Array(matches));
        if status == "unknown" {
            item.insert(
                "unknowns".into(),
                Value::Array(vec![Value::String(
                    "Native xref evidence used the same binary but no exact address-space and target-address match was retained.".into(),
                )]),
            );
        }
        items.push(Value::Object(item));
    }

    Ok(serde_json::json!({
        "status": if ambiguous > 0
            || unknown > 0
            || unmapped > 0
            || xref_rows.iter().any(XrefRow::source_is_unresolved)
        { "partial" } else { "complete" },
        "items": items,
        "coverage": {
            "method_rows": method_rows.len(),
            "xref_rows": xref_rows.len(),
            "mapped": mapped,
            "ambiguous": ambiguous,
            "unknown": unknown,
            "unmapped": unmapped,
            "unresolved_xref_targets": xref_rows
                .iter()
                .filter(|xref| {
                    xref.same_binary_as_any_method(&method_rows)
                        && !xref.has_method_target(&method_rows)
                })
                .count(),
        },
        "limitations": [
            "Rows are static provider observations; a reference does not prove runtime execution.",
            "This projection does not infer control flow, indirect targets, or calling convention semantics."
        ]
    }))
}

/// Alias used by operation-oriented adapters.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

#[derive(Clone)]
struct MethodRow {
    binary_sha256: String,
    address_space: String,
    start_address: String,
    identity_conflicted: bool,
    source: Value,
}

#[derive(Clone)]
struct XrefRow {
    binary_sha256: String,
    address_space: String,
    target_address: String,
    source_address: Option<String>,
    source_candidates: Vec<String>,
    direction: Option<String>,
    identity_conflicted: bool,
    source_conflicted: bool,
    source: Value,
}

impl XrefRow {
    fn same_binary(&self, digest: &str) -> bool {
        self.binary_sha256 == digest
    }

    fn matches_target(&self, method: &MethodRow) -> bool {
        !self.identity_conflicted
            && !method.identity_conflicted
            && self.binary_sha256 == method.binary_sha256
            && self.address_space == method.address_space
            && self.target_address == method.start_address
    }

    fn source_is_unresolved(&self) -> bool {
        self.source_address.is_none() || self.source_conflicted
    }

    fn output(&self) -> Value {
        let mut output = self.source.clone();
        let Some(object) = output.as_object_mut() else {
            return output;
        };

        if let Some(source_address) = &self.source_address {
            object
                .entry("source_address")
                .or_insert_with(|| Value::String(source_address.clone()));
        }
        if self.source_candidates.len() > 1 {
            object.insert(
                "source_addresses".into(),
                Value::Array(
                    self.source_candidates
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        object
            .entry(String::from("target_address"))
            .or_insert_with(|| Value::String(self.target_address.clone()));
        if let Some(direction) = &self.direction {
            object
                .entry(String::from("direction"))
                .or_insert_with(|| Value::String(direction.clone()));
        }

        output
    }

    fn has_method_target(&self, methods: &[MethodRow]) -> bool {
        methods.iter().any(|method| self.matches_target(method))
    }

    fn same_binary_as_any_method(&self, methods: &[MethodRow]) -> bool {
        methods
            .iter()
            .any(|method| self.same_binary(&method.binary_sha256))
    }
}

fn parse_methods(rows: &[Value]) -> Result<Vec<MethodRow>, Failure> {
    rows.iter()
        .enumerate()
        .map(|(index, value)| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid_row("methods", index, "Expected an object"))?;
            validate_aliases(object, &DIGEST_FIELDS, index, "methods")?;
            validate_aliases(object, &["address_space", "space"], index, "methods")?;
            validate_aliases(
                object,
                &["start_address", "address", "method_pointer"],
                index,
                "methods",
            )?;
            let (binary_sha256, digest_conflicted) = digest(object, index, "methods")?;
            let (address_space, address_space_conflicted) =
                aliased_text(object, &["address_space", "space"]);
            let address_space = address_space.ok_or_else(|| {
                invalid_row("methods", index, "address_space must be non-empty text")
            })?;
            let (start_address, start_address_conflicted) =
                aliased_text(object, &["start_address", "address", "method_pointer"]);
            let start_address = start_address.ok_or_else(|| {
                invalid_row("methods", index, "start_address must be non-empty text")
            })?;
            Ok(MethodRow {
                binary_sha256,
                address_space,
                start_address,
                identity_conflicted: digest_conflicted
                    || address_space_conflicted
                    || start_address_conflicted,
                source: value.clone(),
            })
        })
        .collect()
}

fn parse_xrefs(rows: &[Value]) -> Result<Vec<XrefRow>, Failure> {
    rows.iter()
        .enumerate()
        .map(|(index, value)| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid_row("xrefs", index, "Expected an object"))?;
            validate_aliases(object, &DIGEST_FIELDS, index, "xrefs")?;
            validate_aliases(object, &["address_space", "space"], index, "xrefs")?;
            validate_aliases(object, &["target_address", "target", "to"], index, "xrefs")?;
            validate_aliases(
                object,
                &["source_address", "source", "from"],
                index,
                "xrefs",
            )?;
            let (binary_sha256, digest_conflicted) = digest(object, index, "xrefs")?;
            let (address_space, address_space_conflicted) =
                aliased_text(object, &["address_space", "space"]);
            let address_space = address_space.ok_or_else(|| {
                invalid_row("xrefs", index, "address_space must be non-empty text")
            })?;
            let (target_address, target_conflicted) =
                aliased_text(object, &["target_address", "target", "to"]);
            let target_address = target_address.ok_or_else(|| {
                invalid_row("xrefs", index, "target_address must be non-empty text")
            })?;
            let source_aliases = ["source_address", "source", "from"];
            let (source_address, source_conflicted) = aliased_text(object, &source_aliases);
            let source_candidates = alias_candidates(object, &source_aliases);
            let (direction, _direction_conflicted) =
                aliased_text(object, &["direction", "kind", "type"]);
            Ok(XrefRow {
                binary_sha256,
                address_space,
                target_address,
                source_address,
                source_candidates,
                direction,
                identity_conflicted: digest_conflicted
                    || address_space_conflicted
                    || target_conflicted,
                source_conflicted,
                source: value.clone(),
            })
        })
        .collect()
}

fn rows<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let value = aliases.iter().find_map(|alias| root.get(*alias));
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.is_empty() {
        return Err(invalid(field, "Collection must contain at least one row"));
    }
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Collection exceeds the 200000 row limit"));
    }
    Ok(rows)
}

fn digest(
    object: &Map<String, Value>,
    row: usize,
    collection: &str,
) -> Result<(String, bool), Failure> {
    let (digest, conflicted) =
        aliased_text(object, &["binary_sha256", "artifact_sha256", "sha256"]);
    let digest = digest
        .ok_or_else(|| invalid_row(collection, row, "binary_sha256 must be non-empty text"))?;
    if !is_sha256(&digest) {
        return Err(invalid_row(
            collection,
            row,
            "binary_sha256 must be a lowercase SHA-256 digest",
        ));
    }
    Ok((digest, conflicted))
}

const DIGEST_FIELDS: [&str; 3] = ["binary_sha256", "artifact_sha256", "sha256"];

fn validate_aliases(
    object: &Map<String, Value>,
    fields: &[&str],
    row: usize,
    collection: &str,
) -> Result<(), Failure> {
    for field in fields {
        if let Some(value) = object.get(*field) {
            let Some(text) = value.as_str() else {
                return Err(invalid_row(
                    collection,
                    row,
                    &format!("{field} must be non-empty text when supplied"),
                ));
            };

            if text.is_empty() {
                return Err(invalid_row(
                    collection,
                    row,
                    &format!("{field} must be non-empty text when supplied"),
                ));
            }

            if text.chars().count() > MAX_TEXT_LENGTH {
                return Err(invalid_row(
                    collection,
                    row,
                    &format!("{field} must be at most {MAX_TEXT_LENGTH} characters"),
                ));
            }
        }
    }
    Ok(())
}

fn aliased_text(object: &Map<String, Value>, fields: &[&str]) -> (Option<String>, bool) {
    let values = alias_candidates(object, fields);
    let first = values.first().cloned();
    let conflicted = first
        .as_ref()
        .is_some_and(|value| values.iter().any(|candidate| candidate != value));
    (first, conflicted)
}

fn alias_candidates(object: &Map<String, Value>, fields: &[&str]) -> Vec<String> {
    fields
        .iter()
        .filter_map(|field| {
            object
                .get(*field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        "IL2CPP native-xref mapping input is invalid.".into(),
        false,
        "Supply bounded method-address and native-xref rows with exact identity fields and retry."
            .into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
