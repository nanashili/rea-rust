//! Join IL2CPP method-address rows with caller-supplied native facts.
//!
//! This operation deliberately sits below the provider adapters.  It consumes
//! an already captured function inventory and optional decompilation facts,
//! and only joins rows whose binary identity, address space, and start address
//! are all equal.  Missing or conflicting facts remain visible in the result;
//! no provider is asked to discover a function or produce pseudocode.

use rea_core::{
    evidence::is_sha256,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "join_il2cpp_native_functions";

const MAX_ROWS: usize = 200_000;

/// Join method-address mappings with a captured native function inventory.
///
/// The canonical input is `{ "mappings": [...], "functions": [...],
/// "decompilations": [...] }`.  `method_addresses`, `native_functions`, and
/// `native_inventory` are accepted as aliases for the first two collections;
/// `decompilation_facts` is accepted for the third collection.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    reject_unknown_fields(root)?;

    let mappings = required_rows(root, &["mappings", "method_addresses"], "mappings")?;
    let functions = required_rows(
        root,
        &["functions", "native_functions", "native_inventory"],
        "functions",
    )?;
    let decompilations = optional_rows(
        root,
        &["decompilations", "decompilation_facts"],
        "decompilations",
    )?;
    let decompilation_facts_provided = ["decompilations", "decompilation_facts"]
        .iter()
        .any(|field| root.contains_key(*field));

    if mappings.len() > MAX_ROWS || functions.len() > MAX_ROWS || decompilations.len() > MAX_ROWS {
        return Err(resource(
            "captured IL2CPP join rows exceed the supported limit",
        ));
    }

    let native = index_facts(functions, "functions")?;
    let decompiled = index_facts(decompilations, "decompilations")?;
    let mut items = Vec::with_capacity(mappings.len());
    let mut coverage = Coverage::default();

    for (index, value) in mappings.iter().enumerate() {
        let mapping = value
            .as_object()
            .ok_or_else(|| invalid_row("mappings", index, "Expected an object"))?;
        let key = exact_key(mapping, "mappings", index)?;
        let native_matches = matching_values(&native, &key);
        let decompilation_matches = matching_values(&decompiled, &key);
        let native_status = status(native_matches.len());
        let decompilation_status =
            decompilation_status(decompilation_matches.len(), decompilation_facts_provided);

        coverage.observe(native_status, decompilation_status);

        let mut item = Map::new();
        item.insert("mapping".into(), value.clone());
        item.insert("native_status".into(), Value::String(native_status.into()));
        item.insert(
            "decompilation_status".into(),
            Value::String(decompilation_status.into()),
        );
        item.insert("native_functions".into(), Value::Array(native_matches));
        item.insert("decompilations".into(), Value::Array(decompilation_matches));
        if native_status == "missing_function" {
            item.insert(
                "unknowns".into(),
                Value::Array(vec![Value::String(
                    "No captured native function matched the exact binary identity and address."
                        .into(),
                )]),
            );
        }
        if decompilation_status == "missing_decompilation" {
            item.insert(
                "limitations".into(),
                Value::Array(vec![Value::String(
                    "No captured decompilation fact matched the exact native function identity."
                        .into(),
                )]),
            );
        }
        if decompilation_status == "unavailable" {
            item.insert(
                "limitations".into(),
                Value::Array(vec![Value::String(
                    "No decompilation facts were supplied for this captured join.".into(),
                )]),
            );
        }
        items.push(Value::Object(item));
    }

    Ok(serde_json::json!({
        "status": if coverage.is_complete() { "complete" } else { "partial" },
        "items": items,
        "coverage": coverage.value(mappings.len(), functions.len(), decompilations.len()),
    }))
}

fn reject_unknown_fields(root: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED_FIELDS: &[&str] = &[
        "mappings",
        "method_addresses",
        "functions",
        "native_functions",
        "native_inventory",
        "decompilations",
        "decompilation_facts",
    ];

    if let Some(field) = root
        .keys()
        .find(|field| !ALLOWED_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(
            field,
            "Unknown input field is not accepted by the public contract",
        ));
    }

    Ok(())
}

/// Alias used by runtime adapters that expose the operation as an inspection.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct FactKey {
    binary_sha256: String,
    address_space: String,
    start_address: String,
}

struct Fact {
    key: FactKey,
    value: Value,
}

fn index_facts(rows: &[Value], collection: &str) -> Result<Vec<Fact>, Failure> {
    rows.iter()
        .enumerate()
        .map(|(index, value)| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid_row(collection, index, "Expected an object"))?;
            let key = exact_key(object, collection, index)?;
            Ok(Fact {
                key,
                value: value.clone(),
            })
        })
        .collect()
}

fn matching_values(facts: &[Fact], key: &FactKey) -> Vec<Value> {
    facts
        .iter()
        .filter(|fact| fact.key == *key)
        .map(|fact| fact.value.clone())
        .collect()
}

fn exact_key(
    object: &Map<String, Value>,
    collection: &str,
    index: usize,
) -> Result<FactKey, Failure> {
    let sources = source_objects(object);
    let digest = unique_digest(&sources, collection, index)?
        .filter(|value| is_sha256(value))
        .ok_or_else(|| invalid_row(collection, index, "binary_sha256 must be lowercase SHA-256"))?;
    let address_space = unique_identity_value(
        &sources,
        &["address_space"],
        collection,
        index,
        "address_space",
    )?
    .filter(|value| !value.is_empty() && value.len() <= 128)
    .ok_or_else(|| {
        invalid_row(
            collection,
            index,
            "address_space must be non-empty text of at most 128 bytes",
        )
    })?;
    let start_address = unique_identity_value(
        &sources,
        &[
            "start_address",
            "address",
            "entrypoint",
            "function_address",
            "native_address",
        ],
        collection,
        index,
        "start_address",
    )?
    .filter(|value| !value.is_empty() && value.len() <= 128)
    .ok_or_else(|| {
        invalid_row(
            collection,
            index,
            "start_address must be non-empty text of at most 128 bytes",
        )
    })?;

    Ok(FactKey {
        binary_sha256: digest.to_owned(),
        address_space: address_space.to_owned(),
        start_address: start_address.to_owned(),
    })
}

fn source_objects<'a>(object: &'a Map<String, Value>) -> Vec<&'a Map<String, Value>> {
    let mut sources = vec![object];
    let mut index = 0;

    // Retained native Evidence commonly wraps the identity in a result or
    // procedure object. Walk those wrappers without flattening their source
    // rows so offsets and producer fields remain intact in the returned match.
    while index < sources.len() {
        let source = sources[index];
        for wrapper in [
            "result",
            "normalized_result",
            "dossier",
            "procedure",
            "function",
            "native_function",
        ] {
            if let Some(nested) = source.get(wrapper).and_then(Value::as_object) {
                sources.push(nested);
            }
        }
        index += 1;
    }

    sources
}

fn unique_digest<'a>(
    sources: &[&'a Map<String, Value>],
    collection: &str,
    index: usize,
) -> Result<Option<&'a str>, Failure> {
    let mut values = BTreeMap::new();
    for source in sources {
        for field in ["binary_sha256", "artifact_sha256", "sha256"] {
            if let Some(value) = source.get(field) {
                let text = value.as_str().ok_or_else(|| {
                    invalid_row(collection, index, "binary_sha256 aliases must be text")
                })?;
                values.insert(text, ());
            }
        }
        if let Some(value) = source
            .get("artifact")
            .and_then(Value::as_object)
            .and_then(|artifact| artifact.get("sha256"))
        {
            let text = value
                .as_str()
                .ok_or_else(|| invalid_row(collection, index, "artifact.sha256 must be text"))?;
            values.insert(text, ());
        }
    }
    if values.len() > 1 {
        return Err(invalid_row(
            collection,
            index,
            "binary SHA-256 aliases disagree across retained facts",
        ));
    }
    Ok(values.into_keys().next())
}

fn unique_identity_value<'a>(
    sources: &[&'a Map<String, Value>],
    fields: &[&str],
    collection: &str,
    index: usize,
    name: &str,
) -> Result<Option<&'a str>, Failure> {
    let mut values = BTreeMap::new();
    for source in sources {
        for field in fields {
            if let Some(value) = source.get(*field) {
                let text = value.as_str().ok_or_else(|| {
                    invalid_row(collection, index, &format!("{name} aliases must be text"))
                })?;
                values.insert(text, ());
            }
        }
    }
    if values.len() > 1 {
        return Err(invalid_row(
            collection,
            index,
            &format!("{name} aliases disagree across retained facts"),
        ));
    }
    Ok(values.into_keys().next())
}

fn required_rows<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let value = select_rows(root, aliases, field)?
        .ok_or_else(|| invalid(field, "Collection is required"))?;
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(field, "Collection must be an array"))
}

fn optional_rows<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let Some(value) = select_rows(root, aliases, field)? else {
        return Ok(&[]);
    };
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(field, "Collection must be an array"))
}

fn select_rows<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<Option<&'a Value>, Failure> {
    let present = aliases
        .iter()
        .filter_map(|alias| root.get(*alias).map(|value| (*alias, value)))
        .collect::<Vec<_>>();

    if present.len() > 1 {
        return Err(invalid(
            field,
            "Multiple aliases were supplied for the same collection",
        ));
    }

    Ok(present.first().map(|(_, value)| *value))
}

fn status(matches: usize) -> &'static str {
    match matches {
        0 => "missing_function",
        1 => "matched",
        _ => "ambiguous",
    }
}

fn decompilation_status(matches: usize, facts_provided: bool) -> &'static str {
    match matches {
        0 if facts_provided => "missing_decompilation",
        0 => "unavailable",
        1 => "matched",
        _ => "ambiguous",
    }
}

#[derive(Default)]
struct Coverage {
    native_matched: usize,
    native_ambiguous: usize,
    native_missing: usize,
    decompilation_matched: usize,
    decompilation_ambiguous: usize,
    decompilation_missing: usize,
}

impl Coverage {
    fn observe(&mut self, native: &str, decompilation: &str) {
        match native {
            "matched" => self.native_matched += 1,
            "ambiguous" => self.native_ambiguous += 1,
            "missing_function" => self.native_missing += 1,
            _ => {}
        }
        match decompilation {
            "matched" => self.decompilation_matched += 1,
            "ambiguous" => self.decompilation_ambiguous += 1,
            "missing_decompilation" => self.decompilation_missing += 1,
            _ => {}
        }
    }

    fn is_complete(&self) -> bool {
        self.native_missing == 0
            && self.native_ambiguous == 0
            && self.decompilation_missing == 0
            && self.decompilation_ambiguous == 0
    }

    fn value(&self, mappings: usize, functions: usize, decompilations: usize) -> Value {
        serde_json::json!({
            "mapping_rows": mappings,
            "native_function_rows": functions,
            "decompilation_rows": decompilations,
            "native_matched": self.native_matched,
            "native_ambiguous": self.native_ambiguous,
            "native_missing_function": self.native_missing,
            "decompilation_matched": self.decompilation_matched,
            "decompilation_ambiguous": self.decompilation_ambiguous,
            "decompilation_missing": self.decompilation_missing,
        })
    }
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn resource(reason: &str) -> Failure {
    Failure::new_with_details(
        "resource_exhausted",
        "resource_limit",
        reason.into(),
        false,
        "Reduce the retained IL2CPP row set and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP native-function join input is invalid.".into(),
        false,
        "Provide captured mapping and native facts with exact identities and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("field", Detail::Text(field.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::project;
    use serde_json::json;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn identity(address: &str) -> serde_json::Value {
        json!({
            "binary_sha256": DIGEST,
            "address_space": "text",
            "start_address": address,
        })
    }

    #[test]
    fn joins_only_the_exact_binary_space_and_start_identity() {
        let result = project(&json!({
            "mappings": [identity("0x1000")],
            "functions": [identity("0x1000")],
        }))
        .expect("matching identity should project");

        assert_eq!(result["status"], "complete");
        assert_eq!(result["items"][0]["native_status"], "matched");
        assert_eq!(result["coverage"]["native_matched"], 1);
    }

    #[test]
    fn retains_missing_and_ambiguous_identity_states() {
        let result = project(&json!({
            "mappings": [identity("0x1000"), identity("0x2000")],
            "functions": [identity("0x1000"), identity("0x1000")],
        }))
        .expect("identity states should project");

        assert_eq!(result["status"], "partial");
        assert_eq!(result["items"][0]["native_status"], "ambiguous");
        assert_eq!(result["items"][1]["native_status"], "missing_function");
        assert_eq!(result["coverage"]["native_ambiguous"], 1);
        assert_eq!(result["coverage"]["native_missing_function"], 1);
    }

    #[test]
    fn rejects_multiple_aliases_instead_of_choosing_one() {
        let error = project(&json!({
            "mappings": [identity("0x1000")],
            "method_addresses": [identity("0x1000")],
            "functions": [identity("0x1000")],
        }))
        .expect_err("conflicting collection aliases must be rejected");

        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn joins_identity_retained_inside_procedure_wrappers() {
        let result = project(&json!({
            "mappings": [identity("0x1000")],
            "functions": [{
                "result": {
                    "procedure": identity("0x1000")
                },
                "offset": 24
            }]
        }))
        .expect("wrapped identity should project");

        assert_eq!(result["items"][0]["native_status"], "matched");
        assert_eq!(result["items"][0]["native_functions"][0]["offset"], 24);
    }

    #[test]
    fn rejects_conflicting_wrapped_identity_instead_of_selecting_one() {
        let error = project(&json!({
            "mappings": [identity("0x1000")],
            "functions": [{
                "binary_sha256": DIGEST,
                "address_space": "text",
                "start_address": "0x1000",
                "procedure": {
                    "start_address": "0x2000"
                }
            }]
        }))
        .expect_err("conflicting wrapped identity must be rejected");

        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn retains_native_address_alias_and_other_function_fields() {
        let result = project(&json!({
            "mappings": [identity("0x1000")],
            "functions": [{
                "binary_sha256": DIGEST,
                "address_space": "text",
                "start_address": "0x1000",
                "native_address": "0x1000",
                "offset": 24,
                "name": "Game.Update"
            }]
        }))
        .expect("native address identity should project");

        assert_eq!(result["items"][0]["native_status"], "matched");
        assert_eq!(
            result["items"][0]["native_functions"][0]["native_address"],
            "0x1000"
        );
        assert_eq!(result["items"][0]["native_functions"][0]["offset"], 24);
        assert_eq!(
            result["items"][0]["native_functions"][0]["name"],
            "Game.Update"
        );
    }

    #[test]
    fn rejects_conflicting_native_address_alias() {
        let error = project(&json!({
            "mappings": [identity("0x1000")],
            "functions": [{
                "binary_sha256": DIGEST,
                "address_space": "text",
                "start_address": "0x1000",
                "native_address": "0x2000"
            }]
        }))
        .expect_err("conflicting native address must remain unresolved");

        assert_eq!(error.code(), "invalid_request");
    }
}
