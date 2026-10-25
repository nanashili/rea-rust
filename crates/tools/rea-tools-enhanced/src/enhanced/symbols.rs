//! Symbol-inventory workflows: Objective-C classes and protocols, Swift type
//! categories and name-resolved cross references.
//!
//! Compatibility owners: `#objcClasses`, `#objcProtocols`,
//! `#analyzeSwiftTypes`, `#findXrefs` and `#allAddressed`
//! (`EnhancedTools.ts`) and `domain/symbolAnalysis.ts`.
use crate::analysis::{Analysis, is_capability_unavailable, params};
use crate::domain::swift;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

/// One provider address/name entry.
#[derive(Clone, Debug)]
pub struct AddressedName {
    pub address: String,
    pub name: String,
}

/// `#allAddressed`: a complete `{address, value}` inventory.
pub fn all_addressed(
    analysis: &Analysis<'_>,
    tool: &str,
) -> Result<Vec<AddressedName>, AnalysisError> {
    let value = analysis.call(tool, &Map::new(), false)?;
    parse_addressed_names(&value, tool)
}

fn parse_addressed_names(value: &Value, tool: &str) -> Result<Vec<AddressedName>, AnalysisError> {
    let invalid = || AnalysisError::output(tool, "provider returned an invalid inventory");
    let Value::Array(entries) = value else {
        return Err(invalid());
    };
    entries
        .iter()
        .map(|entry| {
            let Some(object) = entry.as_object() else {
                return Err(invalid());
            };
            let Some(Value::String(address)) = object.get("address") else {
                return Err(invalid());
            };
            let Some(Value::String(name)) = object.get("value") else {
                return Err(invalid());
            };
            Ok(AddressedName {
                address: address.clone(),
                name: name.clone(),
            })
        })
        .collect()
}

const OBJC_CLASS_MARKER: &str = "OBJC_CLASS_$_";
const LEGACY_OBJC_CLASS_PREFIX: &str = "l_OBJC_CLASS_";
const OBJC_PROTOCOL_MARKER: &str = "OBJC_PROTOCOL_$_";

/// `/^l_OBJC_CLASS_NAME_(?:\.\d+)?$/u`.
fn is_legacy_class_name_label(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("l_OBJC_CLASS_NAME_") else {
        return false;
    };
    rest.is_empty()
        || rest.strip_prefix('.').is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn unique_by_name<'a>(
    entries: impl IntoIterator<Item = &'a AddressedName>,
) -> Vec<&'a AddressedName> {
    let mut seen = HashSet::new();
    entries
        .into_iter()
        .filter(|entry| seen.insert(entry.name.as_str()))
        .collect()
}

fn entry_json(entry: &AddressedName) -> Value {
    json!({ "address": entry.address, "name": entry.name })
}

/// `discoverObjcClasses`.
pub fn discover_objc_classes(names: &[AddressedName], pattern: &str) -> Value {
    let classes = unique_by_name(names.iter().filter(|entry| {
        let name = entry.name.as_str();
        (name.contains(OBJC_CLASS_MARKER)
            || (name.starts_with(LEGACY_OBJC_CLASS_PREFIX)
                && name.len() > LEGACY_OBJC_CLASS_PREFIX.len()
                && !is_legacy_class_name_label(name)))
            && (pattern.is_empty() || name.contains(pattern))
    }));
    json!({
        "count": classes.len(),
        "classes": classes.into_iter().map(entry_json).collect::<Vec<_>>(),
    })
}

/// `discoverObjcProtocols`.
pub fn discover_objc_protocols(names: &[AddressedName]) -> Value {
    let protocols = unique_by_name(names.iter().filter(|entry| {
        let name = entry.name.as_str();
        name.contains(OBJC_PROTOCOL_MARKER)
            || name.contains("_TtP")
            || (name.ends_with("Mp") && swift::classify(name) == Some(Some("protocols")))
    }));
    json!({
        "count": protocols.len(),
        "protocols": protocols.into_iter().map(entry_json).collect::<Vec<_>>(),
    })
}

const CATEGORIES: [&str; 6] = [
    "classes",
    "structs",
    "enums",
    "protocols",
    "extensions",
    "other",
];

/// `categorizeSwiftTypes`.
pub fn categorize_swift_types(
    procedures: &[AddressedName],
    category_filter: Option<&str>,
    pattern: Option<&str>,
    symbols: &[AddressedName],
) -> Value {
    let mut groups: Vec<(&'static str, Vec<Value>)> = CATEGORIES
        .iter()
        .map(|category| (*category, Vec::new()))
        .collect();
    let mut aliases: HashMap<&str, Vec<&str>> = HashMap::new();
    for symbol in symbols {
        if swift::is_symbol_name(&symbol.name) {
            aliases
                .entry(symbol.address.as_str())
                .or_default()
                .push(symbol.name.as_str());
        }
    }
    let mut seen = HashSet::new();
    let mut unclassified_names = HashSet::new();
    let mut unclassified = Vec::new();
    for entry in procedures {
        if seen.contains(entry.name.as_str()) {
            continue;
        }
        let mut mangled_names: Vec<&str> = Vec::new();
        if swift::is_symbol_name(&entry.name) {
            mangled_names.push(entry.name.as_str());
        }
        for alias in aliases.get(entry.address.as_str()).into_iter().flatten() {
            if !mangled_names.contains(alias) {
                mangled_names.push(alias);
            }
        }
        if mangled_names.is_empty() {
            continue;
        }
        if let Some(pattern) = pattern
            && !std::iter::once(entry.name.as_str())
                .chain(mangled_names.iter().copied())
                .any(|name| name.contains(pattern))
        {
            continue;
        }
        let mut kinds: Vec<&'static str> = Vec::new();
        for name in &mangled_names {
            if let Some(Some(decoded)) = swift::classify(name)
                && !kinds.contains(&decoded)
            {
                kinds.push(decoded);
            }
        }
        let category = if kinds.len() == 1 {
            Some(kinds[0])
        } else {
            None
        };
        let item = json!({
            "address": entry.address,
            "name": entry.name,
            "mangled_names": mangled_names,
        });
        if category.is_none() && unclassified_names.insert(entry.name.as_str()) {
            let mut unresolved = item.as_object().cloned().unwrap_or_default();
            unresolved.insert(
                "reason".into(),
                json!(if kinds.len() > 1 {
                    "conflicting_categories"
                } else {
                    "category_not_decoded"
                }),
            );
            unclassified.push(Value::Object(unresolved));
        }
        let bucket = category.unwrap_or("other");
        if category_filter.is_none_or(|filter| filter == bucket) {
            seen.insert(entry.name.as_str());
            if let Some((_, items)) = groups.iter_mut().find(|(name, _)| *name == bucket) {
                items.push(item);
            }
        }
    }
    let total = groups.iter().map(|(_, items)| items.len()).sum::<usize>();
    let mut categories = Map::new();
    for (category, items) in groups {
        categories.insert(
            category.into(),
            json!({ "count": items.len(), "items": items }),
        );
    }
    let mut limitations = vec![json!(
        "Identification uses Swift mangled procedure names or same-address symbol aliases. Demangled names without retained Swift manglings cannot be identified. Counts deduplicate procedure names, not source declarations."
    )];
    if !unclassified.is_empty() {
        limitations.push(json!(
            "Some Swift categories could not be established from the retained manglings. Unclassified observations remain inline regardless of the category filter."
        ));
    }
    json!({
        "total": total,
        "categories": categories,
        "unclassified": unclassified,
        "limitations": limitations,
    })
}

/// `#objcClasses`.
pub fn objc_classes(analysis: &Analysis<'_>, pattern: &str) -> Result<Value, AnalysisError> {
    let names = all_addressed(analysis, "list_names")?;
    Ok(discover_objc_classes(&names, pattern))
}

/// `#objcProtocols`.
pub fn objc_protocols(analysis: &Analysis<'_>) -> Result<Value, AnalysisError> {
    let names = all_addressed(analysis, "list_names")?;
    Ok(discover_objc_protocols(&names))
}

/// `#analyzeSwiftTypes`.
pub fn analyze_swift_types(
    analysis: &Analysis<'_>,
    category: Option<&str>,
    pattern: Option<&str>,
) -> Result<Value, AnalysisError> {
    let procedures = all_addressed(analysis, "list_procedures")?;
    let symbols = all_addressed(analysis, "list_names");
    if let Err(error) = &symbols
        && !is_capability_unavailable(error)
    {
        return Err(error.clone());
    }
    let joined = symbols.as_deref().unwrap_or(&[]);
    let result = categorize_swift_types(&procedures, category, pattern, joined);
    let Err(error) = symbols else {
        return Ok(result);
    };
    let mut object = result.as_object().cloned().unwrap_or_default();
    object.insert("symbol_inventory_error".into(), error.project());
    if let Some(Value::Array(limitations)) = object.get_mut("limitations") {
        limitations.push(json!(
            "The provider's symbol inventory is unavailable; demangled procedures could not be joined to their Swift aliases."
        ));
    }
    Ok(Value::Object(object))
}

/// `#findXrefs`.
pub fn find_xrefs(analysis: &Analysis<'_>, name: &str) -> Result<Value, AnalysisError> {
    let names = all_addressed(analysis, "list_names")?;
    let Some(resolved) = names.iter().find(|entry| entry.name == name) else {
        return Ok(json!({ "status": "unresolved", "name": name, "reason": "name_not_found" }));
    };
    let xrefs = analysis.call(
        "xrefs",
        &params([("address", json!(resolved.address))]),
        false,
    )?;
    let valid = xrefs
        .as_array()
        .is_some_and(|entries| entries.iter().all(Value::is_string));
    if !valid {
        return Err(AnalysisError::output(
            "xrefs",
            "provider returned an invalid address list",
        ));
    }
    Ok(json!({
        "status": "resolved",
        "name": name,
        "address": resolved.address,
        "xrefs": xrefs,
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        AddressedName, discover_objc_classes, discover_objc_protocols, parse_addressed_names,
    };
    use serde_json::json;

    fn name(address: &str, value: &str) -> AddressedName {
        AddressedName {
            address: address.to_owned(),
            name: value.to_owned(),
        }
    }

    #[test]
    fn class_projection_keeps_real_class_symbols_and_applies_pattern() {
        let entries = vec![
            name("0x1000", "__OBJC_CLASS_$_Widget"),
            name("0x1001", "__OBJC_CLASS_$_Widget"),
            name("0x1002", "l_OBJC_CLASS_NAME_.12"),
            name("0x1003", "__OBJC_METACLASS_$_Widget"),
            name("0x1004", "__OBJC_CLASS_$_Other"),
        ];

        let result = discover_objc_classes(&entries, "Widget");

        assert_eq!(result["count"], 1);
        assert_eq!(result["classes"][0]["address"], "0x1000");
        assert_eq!(result["classes"][0]["name"], "__OBJC_CLASS_$_Widget");
    }

    #[test]
    fn protocol_projection_keeps_objc_and_swift_protocol_symbols() {
        let entries = vec![
            name("0x2000", "__OBJC_PROTOCOL_$_Renderable"),
            name("0x2001", "_$s4Demo10RenderableMp"),
            name("0x2002", "ordinary_symbol"),
        ];

        let result = discover_objc_protocols(&entries);

        assert_eq!(result["count"], 2);
        assert_eq!(
            result["protocols"][0]["name"],
            "__OBJC_PROTOCOL_$_Renderable"
        );
        assert_eq!(result["protocols"][1]["name"], "_$s4Demo10RenderableMp");
    }

    #[test]
    fn canonical_list_names_rows_feed_the_symbol_projection() {
        let inventory = json!([
            {"address": "0x1000", "value": "__OBJC_CLASS_$_Widget"},
            {"address": "0x1001", "value": "__OBJC_PROTOCOL_$_Renderable"}
        ]);

        let names = parse_addressed_names(&inventory, "list_names").expect("canonical inventory");
        let classes = discover_objc_classes(&names, "");
        let protocols = discover_objc_protocols(&names);

        assert_eq!(classes["count"], 1);
        assert_eq!(protocols["count"], 1);
        assert!(
            parse_addressed_names(
                &json!([{"address": "0x1000", "name": "__OBJC_CLASS_$_Widget"}]),
                "list_names"
            )
            .is_err()
        );
    }
}
