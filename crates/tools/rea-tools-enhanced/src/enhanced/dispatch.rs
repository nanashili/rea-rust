//! Objective-C/Swift dispatch metadata from binary metadata or symbols.
//!
//! Compatibility owners: `inspectNativeDispatch`
//! (`native/NativeDispatchMetadataInspection.ts`) and the schemas plus
//! `inspectNativeDispatchMetadata` of `domain/native/objcSwiftMetadata.ts`.
use crate::analysis::{Analysis, is_capability_unavailable, params};
use crate::domain::dossier::native_call_reference;
use crate::js::{compare_utf16, composite_key};
use crate::zod::{
    Schema, array, array_min, boolean, defaulted, empty_array, enumeration, false_value, field,
    int, int_min, literal_str, null_value, nullable, object, optional, positive_int, strict,
    string, string_matching, string_min, union, zero,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::sync::OnceLock;

const OPERATION: &str = "inspect_native_dispatch_metadata";

fn is_sha256(text: &str) -> bool {
    crate::zod::is_lower_sha256(text)
}

fn objc_method() -> Schema {
    strict(vec![
        field("selector", string_min(1)),
        field(
            "method_type",
            enumeration(&["instance", "class", "ivar_getter", "ivar_setter"]),
        ),
        field("address", nullable(int())),
        field("is_required", nullable(boolean())),
        field("is_optional", nullable(boolean())),
    ])
}

fn objc_property() -> Schema {
    strict(vec![
        field("name", string_min(1)),
        field("type_encoding", nullable(string())),
        field(
            "attributes",
            array(strict(vec![
                field("name", string_min(1)),
                field("value", string()),
            ])),
        ),
        field("atomicity", nullable(enumeration(&["atomic", "nonatomic"]))),
        field("is_readonly", nullable(boolean())),
        field("getter", nullable(string())),
        field("setter", nullable(string())),
    ])
}

fn location_object(strict_keys: bool) -> Schema {
    let fields = vec![
        field("address", nullable(string())),
        field("file_offset", nullable(int_min(0))),
    ];
    if strict_keys {
        strict(fields)
    } else {
        object(fields)
    }
}

fn decode_schema(strict_keys: bool) -> Schema {
    let fields = vec![
        field(
            "status",
            enumeration(&["decoded", "partial", "unsupported", "invalid"]),
        ),
        field("reason", nullable(string())),
    ];
    if strict_keys {
        strict(fields)
    } else {
        object(fields)
    }
}

fn objc_class() -> Schema {
    strict(vec![
        field("name", string_min(1)),
        field("super_class", nullable(string())),
        field("is_meta_class", nullable(boolean())),
        field("is_root_class", nullable(boolean())),
        defaulted("methods", array(objc_method()), empty_array),
        defaulted("properties", array(objc_property()), empty_array),
        defaulted("protocols", array(string()), empty_array),
        field("ivar_count", nullable(int_min(0))),
        field("instance_size", nullable(int_min(0))),
        optional("location", location_object(false)),
        optional("superclass_address", nullable(string())),
        optional("metaclass_address", nullable(string())),
        optional("decode", decode_schema(false)),
        optional(
            "evidence",
            array(object(vec![
                field("kind", literal_str("binary_metadata")),
                field("description", string()),
                field("location", location_object(false)),
                field("artifact_path", string()),
                field("artifact_sha256", string()),
            ])),
        ),
    ])
}

fn metadata_evidence() -> Schema {
    strict(vec![
        field(
            "kind",
            enumeration(&[
                "binary_metadata",
                "interface_builder_resource",
                "symbol",
                "reference",
                "decompiler",
            ]),
        ),
        field("description", string_min(1)),
        optional(
            "provider",
            strict(vec![
                field("id", string_min(1)),
                field("name", string_min(1)),
                field("version", nullable(string())),
            ]),
        ),
        field("location", location_object(true)),
        optional("reported_address", string()),
        optional("call_reference", native_call_reference()),
        defaulted("artifact_path", nullable(string_min(1)), null_value),
        defaulted(
            "artifact_sha256",
            nullable(string_matching(is_sha256)),
            null_value,
        ),
    ])
}

fn evidence_list() -> Schema {
    array_min(metadata_evidence(), 1)
}

fn build_metadata_schema() -> Schema {
    let location = || location_object(true);
    let decode = || decode_schema(true);
    let objc_protocol = strict(vec![
        field("name", string_min(1)),
        defaulted("methods", array(objc_method()), empty_array),
        defaulted("optional_methods", array(objc_method()), empty_array),
        defaulted("properties", array(objc_property()), empty_array),
    ]);
    let objc_category = strict(vec![
        field("name", string_min(1)),
        field("class_name", nullable(string_min(1))),
        field(
            "class_source",
            enumeration(&["local", "external", "unresolved"]),
        ),
        field("instance_methods", array(string())),
        field("class_methods", array(string())),
        field("protocols", array(string())),
        field("properties", array(objc_property())),
        field("location", location()),
        field("decode", decode()),
        field("evidence", evidence_list()),
    ]);
    let swift_decl = strict(vec![
        field(
            "kind",
            enumeration(&[
                "class",
                "struct",
                "enum",
                "protocol",
                "extension",
                "actor",
                "global_var",
                "global_func",
            ]),
        ),
        field("name", string_min(1)),
        field("module", nullable(string())),
        defaulted(
            "access_level",
            enumeration(&["private", "fileprivate", "internal", "public", "open"]),
            || json!("internal"),
        ),
        field("super_class", nullable(string())),
        defaulted("protocols", array(string()), empty_array),
        defaulted("is_final", boolean(), false_value),
        defaulted("is_required", boolean(), false_value),
        defaulted("is_convenience_init", boolean(), false_value),
        defaulted("is_override", boolean(), false_value),
    ]);
    let objc_ivar = strict(vec![
        field("class_name", string_min(1)),
        field("name", string_min(1)),
        field("type_encoding", nullable(string())),
        field("offset", nullable(int_min(0))),
        defaulted("size", nullable(int_min(0)), null_value),
        defaulted("alignment", nullable(positive_int()), null_value),
        field("location", location()),
        field("decode", decode()),
        field("evidence", evidence_list()),
    ]);
    let protocol_record = strict(vec![
        field("name", string()),
        field("adopted_protocols", array(string())),
        field("methods", array(objc_method())),
        field("optional_methods", array(objc_method())),
        field("location", location()),
        field("decode", decode()),
        field("evidence", evidence_list()),
    ]);
    let dispatch_implementation = strict(vec![
        field("class_name", string_min(1)),
        field("selector", string_min(1)),
        field("method_type", enumeration(&["instance", "class"])),
        field("implementation_address", nullable(string())),
        optional("category", nullable(string())),
        field("location", location()),
        field("decode", decode()),
        field("evidence", evidence_list()),
    ]);
    let conformance = strict(vec![
        field("type_name", string_min(1)),
        field("protocol_name", string_min(1)),
        field("module", nullable(string())),
        field("witness_table", location()),
        field("location", location()),
        field("decode", decode()),
        field("evidence", evidence_list()),
    ]);
    let dispatch_slot = strict(vec![
        field("owner", string_min(1)),
        field(
            "table_kind",
            enumeration(&["witness_table", "class_vtable"]),
        ),
        field("slot_index", int_min(0)),
        field("requirement", nullable(string())),
        field("implementation", nullable(string())),
        field("implementation_address", nullable(string())),
        field("thunk_address", nullable(string())),
        field("location", location()),
        field("decode", decode()),
        field("evidence", evidence_list()),
    ]);
    let relative_pointer = strict(vec![
        field("field", location()),
        field("target", location()),
        field("displacement", int()),
        field("indirectable", boolean()),
        field("indirect", nullable(boolean())),
        field("decode", decode()),
        field("evidence", evidence_list()),
    ]);
    let swift_symbol = strict(vec![
        field("mangled_name", string_min(1)),
        field("address", nullable(string_min(1))),
        field("decode", decode()),
        field("evidence", evidence_list()),
    ]);
    let coverage = strict(vec![
        field("facet", string_min(1)),
        field(
            "status",
            enumeration(&["complete", "partial", "unsupported", "not_requested"]),
        ),
        field("reason", nullable(string())),
        field("examined", int_min(0)),
        field("decoded", int_min(0)),
    ]);
    let db_save = strict(vec![
        field(
            "operation",
            enumeration(&[
                "save",
                "readback",
                "open_database",
                "close_database",
                "export",
                "import",
            ]),
        ),
        field("succeeded", boolean()),
        defaulted("preserved_names", int_min(0), zero),
        defaulted("preserved_comments", int_min(0), zero),
        defaulted("preserved_bookmarks", int_min(0), zero),
        field("database_path", nullable(string())),
        field("error", nullable(string())),
    ]);
    strict(vec![
        defaulted("objc_classes", array(objc_class()), empty_array),
        defaulted("objc_protocols", array(objc_protocol), empty_array),
        defaulted("objc_categories", array(objc_category), empty_array),
        defaulted("swift_decls", array(swift_decl), empty_array),
        defaulted("objc_ivars", array(objc_ivar), empty_array),
        defaulted("objc_protocol_records", array(protocol_record), empty_array),
        defaulted(
            "objc_dispatch_implementations",
            array(dispatch_implementation),
            empty_array,
        ),
        defaulted("swift_conformances", array(conformance), empty_array),
        defaulted("swift_dispatch_slots", array(dispatch_slot), empty_array),
        defaulted("swift_symbols", array(swift_symbol), empty_array),
        defaulted("relative_pointers", array(relative_pointer), empty_array),
        defaulted("coverage", array(coverage), empty_array),
        field("db_save_result", nullable(db_save)),
    ])
}

/// `objcSwiftMetadataSchema` (built once).
pub fn objc_swift_metadata() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(build_metadata_schema)
}

fn build_result_schema() -> Schema {
    strict(vec![
        field("target_sha256", nullable(string_matching(is_sha256))),
        field(
            "provider",
            strict(vec![
                field("id", string_min(1)),
                field("name", string_min(1)),
                field("version", nullable(string())),
            ]),
        ),
        field("analysis_profile_digest", nullable(string_min(1))),
        field("result", objc_swift_metadata().clone()),
    ])
}

/// `nativeDispatchMetadataResultSchema` (built once).
pub fn native_dispatch_metadata_result() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(build_result_schema)
}

fn addressed_name_schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let symbol = object(vec![
            field("primary", boolean()),
            field("dynamic", boolean()),
            field("external", boolean()),
            field("type", string()),
            field(
                "source",
                enumeration(&["default", "analysis", "ai", "imported", "user_defined"]),
            ),
        ]);
        let procedure = object(vec![
            field("external", boolean()),
            field("thunk", boolean()),
            field("thunk_target", nullable(string())),
        ]);
        let string_fact = object(vec![
            field("encoding", string()),
            field(
                "termination",
                enumeration(&["missing", "present_or_not_required"]),
            ),
            field("byte_length", int_min(0)),
        ]);
        let tail = |name_key: &'static str| {
            strict(vec![
                field("address", string()),
                field(name_key, string()),
                optional("symbol", symbol.clone()),
                optional("procedure", procedure.clone()),
                optional("string", string_fact.clone()),
            ])
        };
        // `addressedValue.strict()` or the same shape with `name` replacing `value`.
        let named = {
            let Schema::Object(shape) = tail("value") else {
                unreachable!("object schema")
            };
            let mut shape = (*shape).omitted(&["value"]);
            shape.fields.push(field("name", string()));
            crate::zod::from_shape(shape)
        };
        array(union(vec![tail("value"), named]))
    })
}

fn is_js_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// `/(?:OBJC_CLASS_|OBJC_METACLASS_)\$_([^\s]+)/u` capture.
fn class_symbol(name: &str) -> Option<&str> {
    for (index, _) in name.char_indices() {
        let rest = &name[index..];
        let marker = ["OBJC_CLASS_$_", "OBJC_METACLASS_$_"]
            .into_iter()
            .find(|marker| rest.starts_with(marker));
        let Some(marker) = marker else {
            continue;
        };
        let tail = &rest[marker.len()..];
        let end = tail
            .char_indices()
            .find(|(_, character)| is_js_whitespace(*character))
            .map_or(tail.len(), |(end, _)| end);
        if end > 0 {
            return Some(&tail[..end]);
        }
    }
    None
}

/// `/^([+-])\[([^\s\]]+)\s+([^\]]+)\]$/u` captures.
fn method_symbol(name: &str) -> Option<(char, &str, &str)> {
    let mut characters = name.chars();
    let kind = characters.next().filter(|kind| matches!(kind, '+' | '-'))?;
    let rest = name[1..].strip_prefix('[')?;
    let class_end = rest
        .char_indices()
        .find(|(_, character)| is_js_whitespace(*character) || *character == ']')
        .map_or(rest.len(), |(end, _)| end);
    if class_end == 0 {
        return None;
    }
    let class_name = &rest[..class_end];
    let after = &rest[class_end..];
    let spaces = after
        .char_indices()
        .find(|(_, character)| !is_js_whitespace(*character))
        .map_or(after.len(), |(end, _)| end);
    if spaces == 0 {
        return None;
    }
    let tail = &after[spaces..];
    let body = tail.strip_suffix(']')?;
    if body.contains(']') {
        return None;
    }
    if !body.is_empty() {
        return Some((kind, class_name, body));
    }
    // Backtrack one whitespace character into the selector when the
    // whitespace run is longer than one character.
    let run = &after[..spaces];
    let last = run.char_indices().last()?;
    if last.0 == 0 {
        return None;
    }
    Some((kind, class_name, &run[last.0..]))
}

/// `parseMetadataAddress`.
fn parse_metadata_address(address: Option<&str>) -> Value {
    let Some(address) = address else {
        return Value::Null;
    };
    let candidate = std::iter::once(0)
        .chain(address.match_indices(':').map(|(index, _)| index + 1))
        .find_map(|start| {
            let rest = &address[start..];
            let digits = rest
                .strip_prefix("0x")
                .or_else(|| rest.strip_prefix("0X"))?;
            (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then_some(digits)
        });
    let Some(digits) = candidate else {
        return Value::Null;
    };
    let trimmed = digits.trim_start_matches('0');
    if trimmed.len() > 14 {
        return Value::Null;
    }
    match u64::from_str_radix(if trimmed.is_empty() { "0" } else { trimmed }, 16) {
        Ok(value) if value as f64 <= crate::zod::MAX_SAFE_INTEGER => json!(value),
        _ => Value::Null,
    }
}

/// `inspectNativeDispatchMetadata`: facts visible in a name inventory.
pub fn inspect_native_dispatch_metadata(
    names: &[(String, String)],
    max_records: usize,
) -> Result<Value, AnalysisError> {
    let symbol_evidence = |name: &str, reported: &str, address: Option<&str>| {
        let mut evidence = Map::new();
        evidence.insert("kind".into(), json!("symbol"));
        evidence.insert(
            "description".into(),
            json!(format!("Provider symbol {name}")),
        );
        evidence.insert(
            "location".into(),
            json!({ "address": address, "file_offset": null }),
        );
        if address.is_none() {
            evidence.insert("reported_address".into(), json!(reported));
        }
        evidence.insert("artifact_path".into(), Value::Null);
        evidence.insert("artifact_sha256".into(), Value::Null);
        json!([evidence])
    };
    let mut class_names: Vec<String> = Vec::new();
    let mut implementations: Vec<(String, Value)> = Vec::new();
    let mut swift_symbols = Vec::new();
    let examined = &names[..names.len().min(max_records)];
    for (reported, name) in examined {
        let address = (!reported.is_empty()).then_some(reported.as_str());
        if let Some(class_name) = class_symbol(name)
            && !class_names.iter().any(|existing| existing == class_name)
        {
            class_names.push(class_name.to_owned());
        }
        if let Some((kind, class_name, selector)) = method_symbol(name) {
            let method_type = if kind == '+' { "class" } else { "instance" };
            let key = format!("{class_name}:{selector}:{method_type}");
            let implementation = json!({
                "class_name": class_name,
                "selector": selector,
                "method_type": method_type,
                "implementation_address": address,
                "location": { "address": address, "file_offset": null },
                "decode": { "status": "partial", "reason": "symbol_name_only" },
                "evidence": symbol_evidence(name, reported, address),
            });
            match implementations
                .iter_mut()
                .find(|(existing, _)| *existing == key)
            {
                Some((_, existing)) => *existing = implementation,
                None => implementations.push((key, implementation)),
            }
            if !class_names.iter().any(|existing| existing == class_name) {
                class_names.push(class_name.to_owned());
            }
        }
        if crate::domain::swift::is_mangled_symbol_name(name) || name.starts_with("_Tt") {
            swift_symbols.push(json!({
                "mangled_name": name,
                "address": address,
                "decode": { "status": "partial", "reason": "mangled_symbol_not_demangled" },
                "evidence": symbol_evidence(name, reported, address),
            }));
        }
    }
    let mut methods_by_class: Vec<(String, Vec<Value>)> = Vec::new();
    for (_, implementation) in &implementations {
        let class_name = implementation["class_name"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let method = json!({
            "selector": implementation["selector"],
            "method_type": implementation["method_type"],
            "address": parse_metadata_address(implementation["implementation_address"].as_str()),
            "is_required": null,
            "is_optional": null,
        });
        match methods_by_class
            .iter_mut()
            .find(|(existing, _)| *existing == class_name)
        {
            Some((_, methods)) => methods.push(method),
            None => methods_by_class.push((class_name, vec![method])),
        }
    }
    let mut sorted_classes = class_names;
    sorted_classes.sort_by(|left, right| compare_utf16(left, right));
    let classes = sorted_classes
        .iter()
        .map(|name| {
            let methods = methods_by_class
                .iter()
                .find(|(existing, _)| existing == name)
                .map(|(_, methods)| methods.clone())
                .unwrap_or_default();
            json!({
                "name": name,
                "super_class": null,
                "is_meta_class": null,
                "is_root_class": null,
                "methods": methods,
                "properties": [],
                "protocols": [],
                "ivar_count": null,
                "instance_size": null,
            })
        })
        .collect::<Vec<_>>();
    let mut decoded = implementations
        .into_iter()
        .map(|(_, implementation)| implementation)
        .collect::<Vec<_>>();
    let key = |implementation: &Value| {
        composite_key(&[
            implementation["class_name"].as_str().unwrap_or_default(),
            implementation["selector"].as_str().unwrap_or_default(),
        ])
    };
    // Stable: equal class/selector keys keep their insertion order.
    decoded.sort_by(|left, right| key(left).cmp(&key(right)));
    let limited = names.len() > examined.len();
    let swift = !swift_symbols.is_empty();
    let metadata = json!({
        "objc_classes": classes,
        "objc_dispatch_implementations": decoded,
        "swift_symbols": swift_symbols,
        "coverage": [
            {
                "facet": "objc_class_symbols",
                "status": "partial",
                "reason": if limited {
                    "record_limit_reached_and_symbol_names_are_not_runtime_class_metadata"
                } else {
                    "symbol_names_do_not_recover_all_runtime_class_metadata"
                },
                "examined": examined.len(),
                "decoded": sorted_classes.len(),
            },
            {
                "facet": "objc_dispatch_implementations",
                "status": if decoded.is_empty() { "unsupported" } else { "partial" },
                "reason": if limited {
                    "record_limit_reached_and_only_symbolized_methods_are_resolved"
                } else if !decoded.is_empty() {
                    "only_symbolized_methods_are_resolved"
                } else {
                    "provider_name_inventory_has_no_objc_method_symbols"
                },
                "examined": examined.len(),
                "decoded": decoded.len(),
            },
            {
                "facet": "objc_ivar_layouts",
                "status": "unsupported",
                "reason": "symbol_inventory_does_not_expose_runtime_ivar_layouts",
                "examined": 0,
                "decoded": 0,
            },
            {
                "facet": "swift_declarations",
                "status": if swift { "partial" } else { "unsupported" },
                "reason": if swift {
                    "symbols_are_not_demangled_declarations"
                } else {
                    "no_swift_symbols_observed"
                },
                "examined": swift_symbols.len(),
                "decoded": 0,
            },
            {
                "facet": "swift_dispatch_tables",
                "status": "unsupported",
                "reason": "provider_name_inventory_does_not_decode_witness_or_class_vtables",
                "examined": 0,
                "decoded": 0,
            },
            {
                "facet": "relative_pointers",
                "status": "unsupported",
                "reason": "provider_name_inventory_does_not_decode_binary_relative_pointers",
                "examined": 0,
                "decoded": 0,
            },
        ],
        "db_save_result": null,
    });
    objc_swift_metadata().parse(&metadata).map_err(|issue| {
        AnalysisError::output(
            "list_names",
            format!("provider symbols do not satisfy the dispatch metadata contract: {issue}"),
        )
    })
}

/// `inspectNativeDispatch`.
pub fn inspect(analysis: &Analysis<'_>, max_records: u64) -> Result<Value, AnalysisError> {
    match analysis.execute(
        OPERATION,
        &params([("max_records", json!(max_records))]),
        false,
    ) {
        Ok(execution) => {
            return native_dispatch_metadata_result()
                .parse(&execution.result)
                .map_err(|issue| {
                    AnalysisError::output(
                        OPERATION,
                        format!("provider returned an invalid dispatch metadata result: {issue}"),
                    )
                });
        }
        Err(error) if !is_capability_unavailable(&error) => return Err(error),
        Err(_) => {}
    }
    let execution = analysis.execute("list_names", &Map::new(), false)?;
    let names = addressed_name_schema()
        .parse(&execution.result)
        .map_err(|_| {
            AnalysisError::output("list_names", "provider returned an invalid inventory")
        })?;
    let names = names
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            let name = entry
                .get("value")
                .or_else(|| entry.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            (
                entry["address"].as_str().unwrap_or_default().to_owned(),
                name.to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let metadata = inspect_native_dispatch_metadata(&names, max_records as usize)?;
    let result = json!({
        "target_sha256": execution.subject.as_ref().map(|subject| subject.sha256.clone()),
        "provider": execution.provider.to_json(),
        "analysis_profile_digest": execution
            .analysis_profile
            .as_ref()
            .and_then(|profile| profile.get("digest"))
            .cloned()
            .unwrap_or(Value::Null),
        "result": metadata,
    });
    native_dispatch_metadata_result()
        .parse(&result)
        .map_err(|issue| {
            AnalysisError::output(
                OPERATION,
                format!("dispatch metadata does not satisfy its result contract: {issue}"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::inspect_native_dispatch_metadata;

    #[test]
    fn symbol_projection_reports_partial_objc_dispatch_facts() {
        let names = vec![
            ("0x1000".to_owned(), "__OBJC_CLASS_$_Widget".to_owned()),
            ("0x1001".to_owned(), "-[Widget renderInContext:]".to_owned()),
            ("0x1002".to_owned(), "_$s4Demo8ProtocolMp".to_owned()),
        ];

        let result = inspect_native_dispatch_metadata(&names, 100).expect("valid metadata");

        assert_eq!(result["objc_classes"][0]["name"], "Widget");
        assert_eq!(
            result["objc_dispatch_implementations"][0]["class_name"],
            "Widget"
        );
        assert_eq!(
            result["objc_dispatch_implementations"][0]["selector"],
            "renderInContext:"
        );
        assert_eq!(result["coverage"][0]["status"], "partial");
        assert_eq!(
            result["swift_symbols"][0]["mangled_name"],
            "_$s4Demo8ProtocolMp"
        );
    }

    #[test]
    fn symbol_projection_exposes_record_limit_as_partial_coverage() {
        let names = vec![
            ("0x1000".to_owned(), "__OBJC_CLASS_$_Widget".to_owned()),
            ("0x1001".to_owned(), "__OBJC_CLASS_$_Other".to_owned()),
        ];

        let result = inspect_native_dispatch_metadata(&names, 1).expect("valid metadata");

        assert_eq!(result["objc_classes"].as_array().map(Vec::len), Some(1));
        assert_eq!(result["coverage"][0]["status"], "partial");
        assert_eq!(result["coverage"][0]["examined"], 1);
    }
}
