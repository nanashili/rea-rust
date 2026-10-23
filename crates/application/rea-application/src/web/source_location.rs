//! Contract boundary for source-map location tracing in exported web scripts.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const OPERATION: &str = "trace_web_source_location";
const MAX_MAP_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROWS: usize = 262_144;
const MAX_SEGMENTS: usize = 262_144;

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web source location input must be an object"))?;

    reject_unknown_fields(
        object,
        &[
            "manifest_path",
            "script_index",
            "source_map",
            "source_map_text",
            "artifacts",
            "generated_position",
        ],
        "web source location input",
    )?;
    absolute_path(object.get("manifest_path"), "manifest_path")?;
    if object.get("script_index").and_then(Value::as_u64).is_none() {
        return Err(invalid("script_index must be a non-negative integer"));
    }

    let source_map = object
        .get("source_map")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("source_map must be an object"))?;
    reject_unknown_fields(source_map, &["path", "url"], "source_map")?;
    absolute_path(source_map.get("path"), "source_map.path")?;
    let url = non_empty_string(source_map.get("url"), "source_map.url")?;
    if !has_absolute_url_scheme(url) {
        return Err(invalid("source_map.url must be an absolute URL"));
    }

    let position = object
        .get("generated_position")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("generated_position must be an object"))?;
    reject_unknown_fields(position, &["line", "column"], "generated_position")?;
    let line = position
        .get("line")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("generated_position.line must be a positive integer"))?;
    if line == 0 {
        return Err(invalid(
            "generated_position.line must be a positive integer",
        ));
    }
    position
        .get("column")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("generated_position.column must be a non-negative integer"))?;

    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web source location result must be an object"));
    }
    Ok(result)
}

/// Trace a selected generated position through a regular version-3 source map.
///
/// The map text is caller-selected evidence. This function never fetches a
/// source or executes script content. All segments at the greatest generated
/// position not greater than the request are retained, including duplicate
/// positions and generated-only segments.
pub fn trace_web_source_location(input: &Value, source_map_text: &str) -> Result<Value, Failure> {
    validate_input(input)?;
    if source_map_text.len() > MAX_MAP_BYTES {
        return Err(invalid("source map exceeds the 4 MiB decoder budget"));
    }

    let source_map = input
        .get("source_map")
        .and_then(Value::as_object)
        .expect("validate_input established source_map");
    let url = source_map
        .get("url")
        .and_then(Value::as_str)
        .expect("validate_input established source_map.url");
    let map_path = source_map
        .get("path")
        .and_then(Value::as_str)
        .expect("validate_input established source_map.path");
    let position = input
        .get("generated_position")
        .and_then(Value::as_object)
        .expect("validate_input established generated_position");
    let requested_line = position
        .get("line")
        .and_then(Value::as_u64)
        .expect("validate_input established generated_position.line")
        as usize;
    let requested_column = position
        .get("column")
        .and_then(Value::as_u64)
        .expect("validate_input established generated_position.column")
        as usize;

    let map: Value = serde_json::from_str(source_map_text)
        .map_err(|error| invalid(&format!("source map is not valid JSON: {error}")))?;
    let object = map
        .as_object()
        .ok_or_else(|| invalid("source map must be an object"))?;
    if object.get("version").and_then(Value::as_u64) != Some(3) {
        return Err(invalid("source map version must be 3"));
    }
    if object.get("sections").is_some() {
        return Ok(unknown_report(
            source_map_text,
            url,
            requested_line,
            requested_column,
            "indexed source-map sections are not supported by this native producer",
        ));
    }

    let sources = object
        .get("sources")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("source map sources must be an array"))?;
    let names = object
        .get("names")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mappings = object
        .get("mappings")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("source map mappings must be a string"))?;
    let declarations = declarations(
        sources,
        object.get("sourcesContent"),
        object.get("sourceRoot"),
        object
            .get("ignoreList")
            .or_else(|| object.get("x_google_ignoreList")),
    )?;
    let segments = decode_mappings(mappings)?;
    let matched = greatest_position(&segments, requested_line, requested_column);
    let matches = matched
        .map(|(line, column)| {
            segments
                .iter()
                .filter(|segment| segment.line == line && segment.column == column)
                .map(|segment| original_match(segment, &declarations, &names, url))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let mut diagnostics = Vec::new();
    if matched.is_none() {
        diagnostics
            .push("No generated mapping exists at or before the requested position.".to_owned());
    }
    if matches
        .iter()
        .any(|item| item.get("state") == Some(&Value::String("generated-only".into())))
    {
        diagnostics
            .push("The selected generated position has no original source mapping.".to_owned());
    }
    let digest = hex_digest(source_map_text.as_bytes());
    Ok(serde_json::json!({
        "source_map_sha256": digest,
        "source_map_path": map_path,
        "url_context": url,
        "engine": { "id": "rea-native-source-map", "version": "1" },
        "format": "regular",
        "reported_file": object.get("file").and_then(Value::as_str),
        "lookup": {
            "requested": { "line": requested_line, "column": requested_column },
            "matched_generated_position": matched.map(|(line, column)| serde_json::json!({ "line": line, "column": column })),
            "semantics": "greatest generated position <= requested, across lines; all equal-position segments",
            "location_units": "one-based lines; zero-based UTF-16 columns"
        },
        "matches": matches,
        "diagnostics": diagnostics,
        "coverage": "complete",
        "unknowns": []
    }))
}

#[derive(Clone, Debug)]
struct MappingSegment {
    line: usize,
    column: usize,
    source: Option<usize>,
    original_line: Option<usize>,
    original_column: Option<usize>,
    name: Option<usize>,
}

#[derive(Clone, Debug)]
struct SourceDeclaration {
    source: Option<String>,
    root: Option<String>,
    content: Option<String>,
    ignored: bool,
}

fn declarations(
    sources: &[Value],
    contents: Option<&Value>,
    root: Option<&Value>,
    ignored_indices: Option<&Value>,
) -> Result<Vec<SourceDeclaration>, Failure> {
    let contents = contents.and_then(Value::as_array);
    let root = root.and_then(Value::as_str).map(str::to_owned);
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| {
            let source = match source {
                Value::Null => None,
                Value::String(value) => Some(value.clone()),
                _ => return Err(invalid("source map sources must contain strings or null")),
            };
            let content = contents
                .and_then(|values| values.get(index))
                .and_then(|value| value.as_str().map(str::to_owned));
            let ignored = ignored_indices
                .and_then(Value::as_array)
                .and_then(|indices| {
                    indices
                        .iter()
                        .find(|value| value.as_u64() == Some(index as u64))
                })
                .is_some();
            Ok(SourceDeclaration {
                source,
                root: root.clone(),
                content,
                ignored,
            })
        })
        .collect()
}

fn decode_mappings(mappings: &str) -> Result<Vec<MappingSegment>, Failure> {
    let mut output = Vec::new();
    let mut source = 0i64;
    let mut original_line = 0i64;
    let mut original_column = 0i64;
    let mut name = 0i64;
    for (line_index, row) in mappings.split(';').enumerate() {
        if line_index + 1 > MAX_ROWS {
            return Err(invalid(
                "source map exceeds the generated-row decoder budget",
            ));
        }
        let mut generated_column = 0i64;
        for encoded in row.split(',').filter(|value| !value.is_empty()) {
            if output.len() >= MAX_SEGMENTS {
                return Err(invalid("source map exceeds the decoded-segment budget"));
            }
            let values = decode_vlq_segment(encoded)?;
            if !matches!(values.len(), 1 | 4 | 5) {
                return Err(invalid(
                    "source-map segment must contain one, four, or five values",
                ));
            }
            generated_column += values[0];
            if generated_column < 0 {
                return Err(invalid("source-map generated column became negative"));
            }
            let (segment_source, segment_line, segment_column, segment_name) = if values.len() > 1 {
                source += values[1];
                original_line += values[2];
                original_column += values[3];
                if source < 0 || original_line < 0 || original_column < 0 {
                    return Err(invalid("source-map relative location became negative"));
                }
                if values.len() == 5 {
                    name += values[4];
                    if name < 0 {
                        return Err(invalid("source-map name index became negative"));
                    }
                }
                (
                    Some(source as usize),
                    Some(original_line as usize),
                    Some(original_column as usize),
                    (values.len() == 5).then_some(name as usize),
                )
            } else {
                (None, None, None, None)
            };
            output.push(MappingSegment {
                line: line_index + 1,
                column: generated_column as usize,
                source: segment_source,
                original_line: segment_line,
                original_column: segment_column,
                name: segment_name,
            });
        }
    }
    Ok(output)
}

fn decode_vlq_segment(encoded: &str) -> Result<Vec<i64>, Failure> {
    let mut values = Vec::new();
    let mut value = 0i64;
    let mut shift = 0u32;
    for character in encoded.bytes() {
        let digit = vlq_digit(character)
            .ok_or_else(|| invalid("source-map mappings contain an invalid VLQ character"))?;
        value |= ((digit & 31) as i64) << shift;
        if digit & 32 == 0 {
            let negative = value & 1 != 0;
            let magnitude = value >> 1;
            values.push(if negative { -magnitude } else { magnitude });
            value = 0;
            shift = 0;
        } else {
            shift += 5;
            if shift > 30 {
                return Err(invalid(
                    "source-map VLQ exceeds the supported integer width",
                ));
            }
        }
    }
    if shift != 0 {
        return Err(invalid(
            "source-map VLQ ends with an unfinished continuation",
        ));
    }
    Ok(values)
}

fn vlq_digit(byte: u8) -> Option<u8> {
    Some(match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

fn greatest_position(
    segments: &[MappingSegment],
    requested_line: usize,
    requested_column: usize,
) -> Option<(usize, usize)> {
    segments
        .iter()
        .filter(|segment| {
            segment.line < requested_line
                || (segment.line == requested_line && segment.column <= requested_column)
        })
        .max_by_key(|segment| (segment.line, segment.column))
        .map(|segment| (segment.line, segment.column))
}

fn original_match(
    segment: &MappingSegment,
    declarations: &[SourceDeclaration],
    names: &[Value],
    base_url: &str,
) -> Result<Value, Failure> {
    let Some(source_index) = segment.source else {
        return Ok(serde_json::json!({ "state": "generated-only" }));
    };
    let declaration = declarations
        .get(source_index)
        .ok_or_else(|| invalid("source-map mapping references an absent source declaration"))?;
    let line = segment
        .original_line
        .expect("mapped segment has original line")
        + 1;
    let column = segment
        .original_column
        .expect("mapped segment has original column");
    let content = declaration.content.as_ref().map(|text| {
        serde_json::json!({
            "state": "embedded",
            "text": text,
            "utf8_sha256": hex_digest(text.as_bytes()),
            "utf8_bytes": text.len(),
            "representation": "UTF-8 encoding of decoded sourcesContent text"
        })
    }).unwrap_or_else(|| serde_json::json!({ "state": "unavailable", "reason": "sourcesContent-not-retained" }));
    let offset = declaration
        .content
        .as_deref()
        .and_then(|text| utf16_offset(text, line, column));
    let content_position = if declaration.content.is_none() {
        "content-unavailable"
    } else if offset.is_some() {
        "verified-in-embedded-text"
    } else {
        "outside-embedded-text"
    };
    let reported_source = declaration.source.clone();
    let resolved_url = reported_source
        .as_deref()
        .map(|source| resolve_source_url(base_url, declaration.root.as_deref(), source));
    Ok(serde_json::json!({
        "state": "mapped",
        "flattened_source_index": source_index,
        "section_path": [],
        "source_index": source_index,
        "reported_source": reported_source,
        "reported_source_root": declaration.root,
        "resolved_url": resolved_url,
        "ignored": declaration.ignored,
        "content": content,
        "original_position": {
            "line": line,
            "column": column,
            "offset": offset,
            "content_position": content_position
        },
        "name": segment.name.and_then(|index| names.get(index).and_then(Value::as_str))
    }))
}

fn utf16_offset(text: &str, line: usize, column: usize) -> Option<usize> {
    let mut starts = vec![0];
    let mut characters = text.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        let next = match character {
            '\r' if characters.peek().is_some_and(|(_, next)| *next == '\n') => {
                characters.next().map_or(text.len(), |(next, _)| next + 1)
            }
            '\n' | '\r' | '\u{2028}' | '\u{2029}' => index + character.len_utf8(),
            _ => continue,
        };
        starts.push(next);
    }
    let line_start = *starts.get(line.checked_sub(1)?)?;
    let line_end = starts.get(line).copied().unwrap_or(text.len());
    let content = text[line_start..line_end]
        .trim_end_matches(|character| matches!(character, '\n' | '\r' | '\u{2028}' | '\u{2029}'));
    (column <= content.encode_utf16().count())
        .then(|| text[..line_start].encode_utf16().count() + column)
}

fn resolve_source_url(base: &str, root: Option<&str>, source: &str) -> String {
    let joined = join_source_root(root, source);

    // Source-map URLs follow URL resolution rules.  In particular, an
    // absolute-path sourceRoot is relative to the selected map origin, while
    // a protocol-relative source keeps the map's scheme.  Treating every
    // leading slash as an already-resolved value loses that origin.
    if has_absolute_url_scheme(&joined) {
        return joined;
    }
    if joined.starts_with("//") {
        return base
            .split_once(':')
            .map(|(scheme, _)| format!("{scheme}:{joined}"))
            .unwrap_or(joined);
    }

    let (prefix, base_path) = split_url_prefix(base);
    let path = if joined.starts_with('/') {
        joined
    } else {
        let directory = base_path
            .rsplit_once('/')
            .map(|(directory, _)| directory)
            .unwrap_or("");
        format!("{directory}/{joined}")
    };
    format!("{prefix}{}", normalize_url_path(&path))
}

fn join_source_root(root: Option<&str>, source: &str) -> String {
    match root.filter(|root| !root.is_empty()) {
        Some(root) if root.ends_with('/') || source.starts_with('/') => {
            format!("{root}{source}")
        }
        Some(root) => format!("{root}/{source}"),
        None => source.to_owned(),
    }
}

fn split_url_prefix(value: &str) -> (String, String) {
    let Some(scheme_end) = value.find("://") else {
        return (String::new(), value.to_owned());
    };
    let authority_start = scheme_end + 3;
    let path_start = value[authority_start..]
        .find('/')
        .map(|index| authority_start + index)
        .unwrap_or(value.len());
    (
        value[..path_start].to_owned(),
        value[path_start..].to_owned(),
    )
}

fn normalize_url_path(path: &str) -> String {
    let suffix_start = path.find(['?', '#']).unwrap_or(path.len());
    let (raw_path, suffix) = path.split_at(suffix_start);
    let absolute = raw_path.starts_with('/');
    let mut parts = Vec::new();
    for part in raw_path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if !parts.is_empty() && parts.last().copied() != Some("..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            value => parts.push(value),
        }
    }
    let mut normalized = parts.join("/");
    if absolute {
        normalized.insert(0, '/');
    }
    if raw_path.ends_with('/') && !normalized.ends_with('/') {
        normalized.push('/');
    }
    format!("{normalized}{suffix}")
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unknown_report(text: &str, url: &str, line: usize, column: usize, reason: &str) -> Value {
    serde_json::json!({
        "source_map_sha256": hex_digest(text.as_bytes()),
        "url_context": url,
        "engine": { "id": "rea-native-source-map", "version": "1" },
        "format": "indexed",
        "reported_file": null,
        "lookup": {
            "requested": { "line": line, "column": column },
            "matched_generated_position": null,
            "semantics": "greatest generated position <= requested, across lines; all equal-position segments",
            "location_units": "one-based lines; zero-based UTF-16 columns"
        },
        "matches": [],
        "diagnostics": [reason],
        "coverage": "partial",
        "unknowns": [reason]
    })
}

fn absolute_path(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let path = non_empty_string(value, field)?;
    if path.contains('\0') || !path.starts_with('/') {
        return Err(invalid(&format!("{field} must be absolute")));
    }
    Ok(())
}

fn has_absolute_url_scheme(value: &str) -> bool {
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || index > 0
                    && (byte == b'+' || byte == b'-' || byte == b'.' || byte.is_ascii_digit())
        })
        && !remainder.is_empty()
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.iter().any(|allowed| allowed == field))
    {
        return Err(invalid(&format!("{label} contains unknown field {field}")));
    }
    Ok(())
}

fn non_empty_string<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide an exported web-script manifest, source map, and generated UTF-16 position."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "manifest_path": "/analysis/scripts/manifest.json",
            "script_index": 0,
            "source_map": {
                "path": "/analysis/app.js.map",
                "url": "https://example.test/app.js.map"
            },
            "generated_position": {"line": 1, "column": 25}
        })
    }

    #[test]
    fn accepts_source_location_request() {
        validate_input(&input()).expect("valid source location input");
        assert!(retain_result(&input(), serde_json::json!({"matches": []})).is_ok());
    }

    #[test]
    fn rejects_relative_source_map_path() {
        let mut invalid_input = input();
        invalid_input["source_map"]["path"] = serde_json::json!("app.js.map");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_zero_generated_line() {
        let mut invalid_input = input();
        invalid_input["generated_position"]["line"] = serde_json::json!(0);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_missing_generated_column() {
        let mut invalid_input = input();
        invalid_input["generated_position"] = serde_json::json!({"line": 1});
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn traces_mapped_location_with_source_provenance() {
        let map = serde_json::json!({
            "version": 3,
            "file": "app.js",
            "sourceRoot": "../src/",
            "sources": ["main.ts"],
            "sourcesContent": ["const value = 1;"],
            "names": [],
            "mappings": "AAAA"
        })
        .to_string();
        let result = trace_web_source_location(&input(), &map).expect("trace map");
        assert_eq!(
            result["lookup"]["matched_generated_position"],
            serde_json::json!({"line": 1, "column": 0})
        );
        assert_eq!(result["matches"][0]["state"], "mapped");
        assert_eq!(result["matches"][0]["reported_source"], "main.ts");
        assert_eq!(
            result["matches"][0]["original_position"]["content_position"],
            "verified-in-embedded-text"
        );
    }

    #[test]
    fn retains_generated_only_match_as_explicit_unmapped_outcome() {
        let map = serde_json::json!({
            "version": 3,
            "sources": [],
            "names": [],
            "mappings": "A"
        })
        .to_string();
        let result = trace_web_source_location(&input(), &map).expect("trace map");
        assert_eq!(result["matches"][0]["state"], "generated-only");
        assert!(
            !result["diagnostics"]
                .as_array()
                .expect("diagnostics")
                .is_empty()
        );
    }

    #[test]
    fn preserves_ambiguous_equal_position_candidates() {
        let map = serde_json::json!({
            "version": 3,
            "sources": ["first.ts", "second.ts"],
            "sourcesContent": ["a", "b"],
            "names": [],
            "mappings": "AAAA,ACAA"
        })
        .to_string();
        let result = trace_web_source_location(&input(), &map).expect("trace map");
        assert_eq!(result["matches"].as_array().expect("matches").len(), 2);
    }
}
