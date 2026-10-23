//! Execution-free Swift nominal type categorization.
//!
//! The provider adapter supplies the already authenticated procedure and
//! symbol inventories. This module only decodes the retained names; it never
//! opens a binary, invokes a demangler, or executes a target.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "analyze_swift_types";

const CATEGORIES: [&str; 6] = [
    "classes",
    "structs",
    "enums",
    "protocols",
    "extensions",
    "other",
];

/// Validate the adapter-facing projection input.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    parse_input(input).map(|_| ())
}

/// Project Swift categories from inline inventories or retained inventory Evidence.
pub fn project(input: &Value) -> Result<Value, Failure> {
    analyze(input)
}

/// Categorize provider procedure names and same-address Swift aliases.
pub fn analyze(input: &Value) -> Result<Value, Failure> {
    let parsed = parse_input(input)?;
    let mut groups: BTreeMap<&str, Vec<Value>> = CATEGORIES
        .iter()
        .map(|category| (*category, Vec::new()))
        .collect();
    let mut seen_names = BTreeSet::new();
    let mut unclassified_names = BTreeSet::new();
    let mut unclassified = Vec::new();

    for procedure in &parsed.procedures {
        if seen_names.contains(&procedure.name) {
            continue;
        }

        let mut mangled_names = Vec::new();
        if is_swift_symbol_name(&procedure.name) {
            mangled_names.push(procedure.name.clone());
        }
        if let Some(aliases) = parsed.aliases.get(&procedure.address) {
            for alias in aliases {
                if !mangled_names.contains(alias) {
                    mangled_names.push(alias.clone());
                }
            }
        }
        if mangled_names.is_empty() {
            continue;
        }
        if let Some(pattern) = parsed.pattern.as_deref()
            && !std::iter::once(&procedure.name)
                .chain(mangled_names.iter())
                .any(|name| name.contains(pattern))
        {
            continue;
        }

        let decoded: BTreeSet<&str> = mangled_names
            .iter()
            .filter_map(|name| match classify_swift_symbol(name) {
                Some(Some(category)) => Some(category),
                _ => None,
            })
            .collect();
        let category = if decoded.len() == 1 {
            decoded.iter().next().copied()
        } else {
            None
        };
        let item = json!({
            "address": procedure.address,
            "name": procedure.name,
            "mangled_names": mangled_names,
        });

        if category.is_none() && unclassified_names.insert(procedure.name.clone()) {
            unclassified.push(json!({
                "address": procedure.address,
                "name": procedure.name,
                "mangled_names": item["mangled_names"],
                "reason": if decoded.len() > 1 { "conflicting_categories" } else { "category_not_decoded" },
            }));
        }

        let bucket = category.unwrap_or("other");
        let category_matches = match parsed.category.as_deref() {
            Some(filter) => filter == bucket,
            None => true,
        };
        if category_matches {
            seen_names.insert(procedure.name.clone());
            groups.entry(bucket).or_default().push(item);
        }
    }

    let mut categories = Map::new();
    for category in CATEGORIES {
        let items = groups.remove(category).unwrap_or_default();
        categories.insert(
            category.to_owned(),
            json!({ "count": items.len(), "items": items }),
        );
    }

    let mut limitations = vec![Value::String(
        "Identification uses Swift mangled procedure names or same-address symbol aliases. Demangled names without retained Swift manglings cannot be identified. Counts deduplicate procedure names, not source declarations.".into(),
    )];
    if !unclassified.is_empty() {
        limitations.push(Value::String(
            "Some Swift categories could not be established from the retained manglings. Unclassified observations remain inline regardless of the category filter.".into(),
        ));
    }

    let total = categories
        .values()
        .map(|value| value["count"].as_u64().unwrap_or(0))
        .sum::<u64>();
    Ok(json!({
        "total": total,
        "categories": categories,
        "unclassified": unclassified,
        "limitations": limitations,
    }))
}

/// Validate a retained normalized result before an adapter wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = result
        .as_object()
        .ok_or_else(|| invalid("Swift type result must be an object"))?;
    for key in ["total", "categories", "unclassified", "limitations"] {
        if !object.contains_key(key) {
            return Err(invalid(&format!("Swift type result is missing {key}")));
        }
    }
    Ok(result)
}

#[derive(Clone)]
struct Procedure {
    address: String,
    name: String,
}

struct ParsedInput {
    procedures: Vec<Procedure>,
    aliases: BTreeMap<String, Vec<String>>,
    category: Option<String>,
    pattern: Option<String>,
}

fn parse_input(input: &Value) -> Result<ParsedInput, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("Swift type input must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "procedures" | "symbols" | "category" | "pattern" | "evidence"
        ) {
            return Err(invalid(&format!("unknown Swift type input field: {key}")));
        }
    }
    let evidence = object.get("evidence").map(parse_evidence).transpose()?;
    if evidence.is_some() && (object.contains_key("procedures") || object.contains_key("symbols")) {
        return Err(invalid(
            "Swift type input cannot combine retained Evidence with inline inventories",
        ));
    }
    let procedures_value = object
        .get("procedures")
        .or_else(|| {
            evidence
                .as_ref()
                .and_then(|facts| facts.procedures.as_ref())
        })
        .ok_or_else(|| invalid("procedures or retained inventory Evidence is required"))?;
    let procedures_array = procedures_value
        .as_array()
        .ok_or_else(|| invalid("procedures must be an array"))?;
    if procedures_array.len() > 200_000 {
        return Err(invalid("procedures exceeds the 200000 record limit"));
    }
    let procedures = procedures_array
        .iter()
        .map(parse_addressed_name)
        .collect::<Result<Vec<_>, _>>()?;

    let mut aliases = BTreeMap::new();
    if let Some(symbols) = object
        .get("symbols")
        .or_else(|| evidence.as_ref().and_then(|facts| facts.symbols.as_ref()))
    {
        let symbols = symbols
            .as_array()
            .ok_or_else(|| invalid("symbols must be an array"))?;
        if symbols.len() > 200_000 {
            return Err(invalid("symbols exceeds the 200000 record limit"));
        }
        for symbol in symbols {
            let symbol = parse_addressed_name(symbol)?;
            if !is_swift_symbol_name(&symbol.name) {
                continue;
            }
            aliases
                .entry(symbol.address)
                .or_insert_with(Vec::new)
                .push(symbol.name);
        }
    }

    let category = optional_string(object, "category")?;
    if let Some(category) = category.as_deref()
        && !CATEGORIES.contains(&category)
    {
        return Err(invalid("category is not a supported Swift category"));
    }
    let pattern = optional_string(object, "pattern")?;
    Ok(ParsedInput {
        procedures,
        aliases,
        category,
        pattern,
    })
}

struct EvidenceFacts {
    procedures: Option<Value>,
    symbols: Option<Value>,
}

fn parse_evidence(value: &Value) -> Result<EvidenceFacts, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid(&format!("retained inventory Evidence is not JSON: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("retained inventory Evidence is invalid: {error}")))?;
    let operation: String = serde_json::from_str(record.operation().get())
        .map_err(|_| invalid("retained inventory Evidence operation must be a string"))?;
    if !matches!(operation.as_str(), "list_procedures" | "list_names") {
        return Err(invalid(
            "retained inventory Evidence operation must be list_procedures or list_names",
        ));
    }
    let result: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(&format!(
                "retained inventory Evidence result is invalid JSON: {error}"
            ))
        })?;
    let (procedures, symbols) = match result {
        Value::Array(_) => match operation.as_str() {
            "list_procedures" => (Some(result.clone()), None),
            "list_names" => (None, Some(result.clone())),
            _ => unreachable!("operation was validated above"),
        },
        Value::Object(result) => (
            result
                .get("procedures")
                .cloned()
                .or_else(|| inventory_items(&result, operation.as_str(), "list_procedures")),
            result
                .get("symbols")
                .cloned()
                .or_else(|| result.get("names").cloned())
                .or_else(|| inventory_items(&result, operation.as_str(), "list_names")),
        ),
        _ => (None, None),
    };

    if procedures.is_none() && symbols.is_none() {
        return Err(invalid(
            "retained inventory Evidence must contain procedures, symbols, names, or items",
        ));
    }

    Ok(EvidenceFacts {
        procedures,
        symbols,
    })
}

fn inventory_items(
    result: &Map<String, Value>,
    operation: &str,
    expected_operation: &str,
) -> Option<Value> {
    (operation == expected_operation)
        .then(|| result.get("items"))
        .flatten()
        .cloned()
}

fn parse_addressed_name(value: &Value) -> Result<Procedure, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("addressed name must be an object"))?;
    let address = object
        .get("address")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("addressed name requires a non-empty address"))?;
    let name = object
        .get("name")
        .or_else(|| object.get("value"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("addressed name requires a non-empty name"))?;
    Ok(Procedure {
        address: address.to_owned(),
        name: name.to_owned(),
    })
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Result<Option<String>, Failure> {
    object
        .get(key)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("{key} must be a string")))
        })
        .transpose()
}

fn is_swift_symbol_name(name: &str) -> bool {
    [
        "_T0",
        "__T0",
        "$S",
        "_$S",
        "$s",
        "_$s",
        "@__swiftmacro_",
        "$e",
        "_$e",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
        || name.contains("_Tt")
        || classify_swift_symbol(name).is_some()
}

fn classify_swift_symbol(name: &str) -> Option<Option<&'static str>> {
    if name.contains("_Tt") {
        return Some(
            match [
                ("_TtC", "classes"),
                ("_TtV", "structs"),
                ("_TtO", "enums"),
                ("_TtP", "protocols"),
                ("_TtE", "extensions"),
            ]
            .iter()
            .find_map(|(prefix, category)| name.starts_with(prefix).then_some(*category))
            {
                Some(category) => Some(category),
                None => None,
            },
        );
    }
    let prefix = ["_$s", "_$S", "$s", "$S", "__T0", "_T0"]
        .iter()
        .find(|prefix| name.starts_with(**prefix))?;
    let mangling = &name[prefix.len()..];
    let mut offset = identifier_end(mangling, 0)?;
    let mut category = None;
    loop {
        let end = match identifier_end(mangling, offset) {
            Some(end) => end,
            None => break,
        };
        match mangling.as_bytes().get(end).copied() {
            Some(b'C') => category = Some("classes"),
            Some(b'V') => category = Some("structs"),
            Some(b'O') => category = Some("enums"),
            Some(b'P') => category = Some("protocols"),
            Some(b'E') if category.is_some() => {
                // The TypeScript classifier treats the extension marker as
                // the terminal nominal context. Continuing into later
                // identifiers could overwrite `extensions` with a second
                // nominal marker and produce a different category.
                category = Some("extensions");
                break;
            }
            _ if &mangling[end..] == "Mp" => category = Some("protocols"),
            _ => break,
        }
        offset = end + 1;
    }
    Some(category)
}

fn identifier_end(mangling: &str, offset: usize) -> Option<usize> {
    let bytes = mangling.as_bytes();
    let mut cursor = offset;
    if !bytes
        .get(cursor)
        .is_some_and(|byte| (b'1'..=b'9').contains(byte))
    {
        return None;
    }
    while bytes.get(cursor).is_some_and(|byte| byte.is_ascii_digit()) {
        cursor += 1;
    }
    let length = std::str::from_utf8(&bytes[offset..cursor])
        .ok()?
        .parse::<usize>()
        .ok()?;
    let end = cursor.checked_add(length)?;
    let identifier = bytes.get(cursor..end)?;
    if identifier.is_empty() || !identifier[0].is_ascii_alphabetic() && identifier[0] != b'_' {
        return None;
    }
    if !identifier[1..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return None;
    }
    Some(end)
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the input and retry.".into(),
        std::collections::BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
