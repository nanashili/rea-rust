//! Attribute caller-ordered Ghidra batch items to IL2CPP method metadata.
//!
//! This projection joins only explicit identities retained by the two
//! producers.  Native addresses are preferred; metadata indices and method
//! tokens are accepted when the batch item carries them.  Display names are
//! deliberately never used as a join key, because names are not unique.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "attribute_il2cpp_decompilation";
const MAX_ROWS: usize = 200_000;

/// Join ordered batch items with normalized IL2CPP method rows.
///
/// The input accepts `methods` or `metadata_methods`, and a normalized batch
/// result under `batch`, `result`, or `decompilation_result`.  An Evidence
/// envelope may be supplied under `evidence`; its normalized result is used
/// while the complete envelope is retained in each output's source field.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let methods = selected_collection(root, &["methods", "metadata_methods"], "methods")?;
    let (batch, source_evidence) = selected_batch(root)?;

    if methods.len() > MAX_ROWS {
        return Err(resource("method rows exceed the supported limit"));
    }
    let batch_items = batch
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("batch.items", "Batch result must contain an items array"))?;
    if batch_items.len() > MAX_ROWS {
        return Err(resource("batch items exceed the supported limit"));
    }

    let index = MethodIndex::build(methods)?;
    let mut items = Vec::with_capacity(batch_items.len());
    let mut coverage = Coverage::default();

    for (batch_index, batch_item) in batch_items.iter().enumerate() {
        let attribution = index.attribute(batch_item)?;
        coverage.record(attribution.status);

        let mut output = Map::new();
        output.insert("batch_index".into(), Value::from(batch_index));
        output.insert(
            "selector".into(),
            batch_item.get("address").cloned().unwrap_or(Value::Null),
        );
        output.insert("batch_item".into(), batch_item.clone());
        output.insert("status".into(), Value::String(attribution.status.into()));
        output.insert("method".into(), attribution.method.unwrap_or(Value::Null));
        output.insert("identity".into(), attribution.identity);
        if let Some(reason) = attribution.reason {
            output.insert("reason".into(), Value::String(reason.into()));
        }
        if let Some(evidence) = source_evidence {
            output.insert("source_evidence".into(), evidence.clone());
        }
        items.push(Value::Object(output));
    }

    Ok(serde_json::json!({
        "operation": OPERATION,
        "status": coverage.status(),
        "items": items,
        "coverage": coverage.value(methods.len()),
        "batch_result": batch,
        "source_evidence": source_evidence.cloned().unwrap_or(Value::Null),
    }))
}

/// Alias used by operation-oriented application adapters.
pub fn attribute(input: &Value) -> Result<Value, Failure> {
    project(input)
}

struct MethodIndex {
    methods: Vec<Value>,
    by_address: BTreeMap<String, Vec<usize>>,
    by_metadata_index: BTreeMap<u64, Vec<usize>>,
    by_token: BTreeMap<String, Vec<usize>>,
}

impl MethodIndex {
    fn build(methods: &[Value]) -> Result<Self, Failure> {
        let mut index = Self {
            methods: methods.to_vec(),
            by_address: BTreeMap::new(),
            by_metadata_index: BTreeMap::new(),
            by_token: BTreeMap::new(),
        };
        for (row, method) in methods.iter().enumerate() {
            let object = method
                .as_object()
                .ok_or_else(|| invalid_row("methods", row, "Expected an object"))?;
            if let Some(address) = explicit_address(object, "methods", row)? {
                index
                    .by_address
                    .entry(address_identity_key(&address))
                    .or_default()
                    .push(row);
            }
            if let Some(metadata_index) = unique_u64(
                object,
                &["metadata_index", "metadataIndex", "method_index"],
                "metadata_index",
                row,
            )? {
                index
                    .by_metadata_index
                    .entry(metadata_index)
                    .or_default()
                    .push(row);
            }
            if let Some(token) = unique_identity(
                object,
                &["method_token", "methodToken", "metadata_token", "token"],
                "method_token",
                row,
            )? {
                index.by_token.entry(token).or_default().push(row);
            }

            // Validate metadata identity aliases while the source row is
            // still available.  The identity is applied during attribution
            // so equal native addresses from different images cannot cross.
            method_identity(object, row)?;
        }
        Ok(index)
    }

    fn attribute(&self, batch_item: &Value) -> Result<Attribution, Failure> {
        let object = batch_item
            .as_object()
            .ok_or_else(|| invalid("batch.items", "Each batch item must be an object"))?;
        let identity = batch_identity(object)?;
        let candidates = if let Some(address) = identity.address.as_deref() {
            self.by_address
                .get(&address_identity_key(address))
                .cloned()
                .unwrap_or_default()
        } else if let Some(index) = identity.metadata_index {
            self.by_metadata_index
                .get(&index)
                .cloned()
                .unwrap_or_default()
        } else if let Some(token) = identity.token.as_deref() {
            self.by_token.get(token).cloned().unwrap_or_default()
        } else {
            Vec::new()
        };
        let candidates = candidates
            .into_iter()
            .filter(|row| {
                self.methods
                    .get(*row)
                    .and_then(Value::as_object)
                    .and_then(|method| method_identity(method, *row).ok())
                    .is_some_and(|method| identities_compatible(&identity, &method))
            })
            .collect::<Vec<_>>();

        let identity_value = identity.value();
        match candidates.as_slice() {
            [] => Ok(Attribution {
                status: "unresolved",
                method: None,
                identity: identity_value,
                reason: Some("No method row matched an explicit native or metadata identity."),
            }),
            [row] => Ok(Attribution {
                status: "matched",
                method: Some(self.methods[*row].clone()),
                identity: identity_value,
                reason: None,
            }),
            _ => Ok(Attribution {
                status: "ambiguous",
                method: None,
                identity: identity_value,
                reason: Some("Multiple method rows share the supplied identity."),
            }),
        }
    }
}

struct Attribution {
    status: &'static str,
    method: Option<Value>,
    identity: Value,
    reason: Option<&'static str>,
}

#[derive(Default)]
struct Coverage {
    matched: usize,
    ambiguous: usize,
    unresolved: usize,
}

impl Coverage {
    fn record(&mut self, status: &str) {
        match status {
            "matched" => self.matched += 1,
            "ambiguous" => self.ambiguous += 1,
            _ => self.unresolved += 1,
        }
    }

    fn status(&self) -> &'static str {
        if self.ambiguous == 0 && self.unresolved == 0 {
            "complete"
        } else {
            "partial"
        }
    }

    fn value(&self, methods: usize) -> Value {
        serde_json::json!({
            "methods": methods,
            "batch_items": self.matched + self.ambiguous + self.unresolved,
            "matched": self.matched,
            "ambiguous": self.ambiguous,
            "unresolved": self.unresolved,
        })
    }
}

struct BatchIdentity {
    address: Option<String>,
    metadata_index: Option<u64>,
    token: Option<String>,
    image_index: Option<u64>,
    image_name: Option<String>,
    module_name: Option<String>,
}

impl BatchIdentity {
    fn value(&self) -> Value {
        let mut value = Map::new();
        if let Some(address) = &self.address {
            value.insert("native_address".into(), Value::String(address.clone()));
        }
        if let Some(index) = self.metadata_index {
            value.insert("metadata_index".into(), Value::from(index));
        }
        if let Some(token) = &self.token {
            value.insert("method_token".into(), Value::String(token.clone()));
        }
        if let Some(index) = self.image_index {
            value.insert("image_index".into(), Value::from(index));
        }
        if let Some(name) = &self.image_name {
            value.insert("image_name".into(), Value::String(name.clone()));
        }
        if let Some(name) = &self.module_name {
            value.insert("module_name".into(), Value::String(name.clone()));
        }
        Value::Object(value)
    }
}

fn batch_identity(object: &Map<String, Value>) -> Result<BatchIdentity, Failure> {
    let procedure = object.get("procedure").and_then(Value::as_object);
    let address_fields = [
        "native_address",
        "method_pointer",
        "start_address",
        "address",
    ];
    // The batch contract gives item.address the caller's original selector,
    // which may be a symbol name.  The nested resolved procedure owns the
    // canonical address used for attribution, so do not treat those two
    // values as contradictory aliases.  Within either owner, however, all
    // address aliases must still agree.
    let address = match procedure {
        Some(procedure) => unique_text(procedure, &address_fields, "native_address", 0)?,
        None => unique_text(object, &address_fields, "native_address", 0)?,
    };
    let metadata_index = unique_u64_from_sources(
        &[object, procedure.unwrap_or(object)],
        &["metadata_index", "metadataIndex", "method_index"],
        "metadata_index",
    )?;
    let token = unique_text_from_sources(
        &[object, procedure.unwrap_or(object)],
        &["method_token", "methodToken", "metadata_token", "token"],
        "method_token",
    )?;
    let image_index = unique_u64_from_sources(
        &[object, procedure.unwrap_or(object)],
        &["image_index", "image_id"],
        "image_index",
    )?;
    let image_name = unique_text_from_sources(
        &[object, procedure.unwrap_or(object)],
        &["image_name", "assembly_name", "image"],
        "image_name",
    )?;
    let module_name = unique_text_from_sources(
        &[object, procedure.unwrap_or(object)],
        &["module_name", "module"],
        "module_name",
    )?;
    Ok(BatchIdentity {
        address,
        metadata_index,
        token,
        image_index,
        image_name,
        module_name,
    })
}

fn method_identity(object: &Map<String, Value>, row: usize) -> Result<BatchIdentity, Failure> {
    let image_index = unique_u64(object, &["image_index", "image_id"], "image_index", row)?;
    let image_name = unique_text(
        object,
        &["image_name", "assembly_name", "image"],
        "image_name",
        row,
    )?;
    let module_name = unique_text(object, &["module_name", "module"], "module_name", row)?;
    Ok(BatchIdentity {
        address: None,
        metadata_index: None,
        token: None,
        image_index,
        image_name,
        module_name,
    })
}

fn identities_compatible(left: &BatchIdentity, right: &BatchIdentity) -> bool {
    identity_matches(left.image_index, right.image_index)
        && identity_matches(left.image_name.as_deref(), right.image_name.as_deref())
        && identity_matches(left.module_name.as_deref(), right.module_name.as_deref())
}

fn identity_matches<T: PartialEq>(left: Option<T>, right: Option<T>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn address_identity_key(address: &str) -> String {
    parse_address_text(address)
        .map(|value| format!("0x{value:x}"))
        .unwrap_or_else(|| address.to_owned())
}

fn parse_address_text(value: &str) -> Option<u64> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

fn selected_batch<'a>(
    root: &'a Map<String, Value>,
) -> Result<(&'a Value, Option<&'a Value>), Failure> {
    if let Some(evidence) = root.get("evidence") {
        let evidence_object = evidence
            .as_object()
            .ok_or_else(|| invalid("evidence", "Evidence must be an object"))?;
        let batch = evidence_object
            .get("normalized_result")
            .or_else(|| evidence_object.get("result"))
            .or_else(|| evidence_object.get("value"))
            .ok_or_else(|| invalid("evidence", "Evidence is missing its normalized result"))?;
        return Ok((batch, Some(evidence)));
    }
    for field in ["batch", "result", "decompilation_result"] {
        if let Some(batch) = root.get(field) {
            return Ok((batch, None));
        }
    }
    Err(invalid(
        "batch",
        "A normalized batch result or Evidence is required",
    ))
}

fn selected_collection<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let values = aliases
        .iter()
        .filter_map(|alias| root.get(*alias).map(|value| (*alias, value)))
        .collect::<Vec<_>>();
    if values.len() > 1 {
        return Err(invalid(field, "Multiple aliases were supplied"));
    }
    values
        .first()
        .and_then(|(_, value)| value.as_array().map(Vec::as_slice))
        .ok_or_else(|| invalid(field, "An array of method rows is required"))
}

fn explicit_address(
    object: &Map<String, Value>,
    field: &str,
    row: usize,
) -> Result<Option<String>, Failure> {
    unique_text(
        object,
        &[
            "native_address",
            "method_pointer",
            "start_address",
            "address",
        ],
        field,
        row,
    )
}

fn unique_text(
    object: &Map<String, Value>,
    fields: &[&str],
    field: &str,
    row: usize,
) -> Result<Option<String>, Failure> {
    unique_text_from_sources(&[object], fields, field)
        .map_err(|_| invalid_row(field, row, "Identity aliases disagree or are malformed"))
}

fn unique_text_from_sources(
    sources: &[&Map<String, Value>],
    fields: &[&str],
    field: &str,
) -> Result<Option<String>, Failure> {
    let mut values = Vec::new();
    for source in sources {
        for name in fields {
            if let Some(value) = source.get(*name) {
                if value.is_null() {
                    continue;
                }
                let text = match value {
                    Value::String(text) => Some(text.as_str()),
                    Value::Object(object) if *name == "method_pointer" => object
                        .get("native_address")
                        .or_else(|| object.get("address"))
                        .or_else(|| object.get("start_address"))
                        .and_then(Value::as_str),
                    _ => None,
                }
                .ok_or_else(|| {
                    invalid(field, "Identity aliases must be strings or pointer objects")
                })?;
                if !text.is_empty() {
                    values.push(text.to_owned());
                }
            }
        }
    }
    if values.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(invalid(field, "Identity aliases disagree"));
    }
    Ok(values.into_iter().next())
}

fn unique_identity(
    object: &Map<String, Value>,
    fields: &[&str],
    field: &str,
    row: usize,
) -> Result<Option<String>, Failure> {
    unique_text(object, fields, field, row)
}

fn unique_u64(
    object: &Map<String, Value>,
    fields: &[&str],
    field: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    unique_u64_from_sources(&[object], fields, field)
        .map_err(|_| invalid_row(field, row, "Identity aliases disagree or are malformed"))
}

fn unique_u64_from_sources(
    sources: &[&Map<String, Value>],
    fields: &[&str],
    field: &str,
) -> Result<Option<u64>, Failure> {
    let mut values = Vec::new();
    for source in sources {
        for name in fields {
            if let Some(value) = source.get(*name) {
                if value.is_null() {
                    continue;
                }
                values.push(parse_identity_u64(value).ok_or_else(|| {
                    invalid(field, "Identity index must be a non-negative integer")
                })?);
            }
        }
    }
    if values.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(invalid(field, "Identity aliases disagree"));
    }
    Ok(values.into_iter().next())
}

fn parse_identity_u64(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    let text = value.as_str()?.trim();
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or_else(
            || text.parse::<u64>().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

fn invalid_row(field: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{field}[{row}]"), reason)
}

fn resource(reason: &str) -> Failure {
    Failure::new_with_details(
        "resource_exhausted",
        "resource_limit",
        reason.into(),
        false,
        "Reduce the retained row set and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        "IL2CPP decompilation attribution input is invalid.".into(),
        false,
        "Provide explicit method identities and a normalized batch result and retry.".into(),
        BTreeMap::from([
            (String::from("operation"), Detail::Text(OPERATION.into())),
            (String::from("field"), Detail::Text(field.into())),
            (String::from("reason"), Detail::Text(reason.into())),
        ]),
    )
}
