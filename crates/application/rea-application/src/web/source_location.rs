//! Contract boundary for source-map location tracing in exported web scripts.

use std::collections::BTreeMap;

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::javascript::resolution::source_map_paths;

pub const OPERATION: &str = "trace_web_source_location";
const MAX_MAP_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROWS: usize = 262_144;
const MAX_SEGMENTS: usize = 262_144;
const MAX_RECORDS: usize = 262_144;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

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

/// Trace a selected generated position through a version-3 source map.
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

    let map: Value = serde_json::from_str(source_map_json_text(source_map_text))
        .map_err(|error| invalid(&format!("source map is not valid JSON: {error}")))?;
    let object = map
        .as_object()
        .ok_or_else(|| invalid("source map must be an object"))?;
    if object.get("version").and_then(Value::as_u64) != Some(3) {
        return Err(invalid("source map version must be 3"));
    }
    let indexed = object.get("sections").is_some();
    let mut state = DecodeState::default();
    decode_map(object, 0, 0, None, &mut Vec::new(), &mut state)?;
    let matched = greatest_position(&state.segments, requested_line, requested_column);
    let matches = matched
        .map(|(line, column)| {
            state
                .segments
                .iter()
                .filter(|segment| segment.line == line && segment.column == column)
                .map(|segment| original_match(segment, &state.declarations, url))
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
        "runtime": { "id": "rea-native-rust", "version": env!("CARGO_PKG_VERSION") },
        "format": if indexed { "indexed" } else { "regular" },
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
    name: Option<String>,
    section_path: Vec<usize>,
    flattened_source_index: Option<usize>,
}

#[derive(Clone, Debug)]
struct SourceDeclaration {
    section_path: Vec<usize>,
    source_index: usize,
    flattened_source_index: usize,
    source: Option<String>,
    root: Option<String>,
    content: Option<String>,
    ignored: bool,
}

#[derive(Default)]
struct DecodeState {
    declarations: Vec<SourceDeclaration>,
    segments: Vec<MappingSegment>,
    decoded_segments: usize,
    decoded_records: usize,
}

fn source_map_json_text(text: &str) -> &str {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Some(_) = text.strip_prefix(")]}'") else {
        return text;
    };
    text.find(['\r', '\n']).map_or("", |index| &text[index..])
}

fn consume_records(records: &mut usize, count: usize) -> Result<(), Failure> {
    if count > MAX_RECORDS.saturating_sub(*records) {
        return Err(invalid(
            "source-map structure exceeds the 262144-record decoder budget",
        ));
    }
    *records += count;
    Ok(())
}

fn declarations(
    sources: &[Value],
    contents: Option<&Value>,
    root: Option<&Value>,
    ignored_indices: Option<&Value>,
) -> Result<Vec<SourceDeclaration>, Failure> {
    let contents = match contents {
        None | Some(Value::Null) => None,
        Some(value) => {
            let values = value
                .as_array()
                .ok_or_else(|| invalid("source map sourcesContent must be an array or null"))?;
            if values
                .iter()
                .any(|value| !value.is_null() && !value.is_string())
            {
                return Err(invalid(
                    "source map sourcesContent must contain strings or null",
                ));
            }
            Some(values)
        }
    };
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
                section_path: Vec::new(),
                source_index: index,
                flattened_source_index: index,
                source,
                root: root.clone(),
                content,
                ignored,
            })
        })
        .collect()
}

fn decode_map(
    object: &serde_json::Map<String, Value>,
    offset_line: usize,
    offset_column: usize,
    stop: Option<(usize, usize)>,
    section_path: &mut Vec<usize>,
    state: &mut DecodeState,
) -> Result<(), Failure> {
    if object.get("version").and_then(Value::as_u64) != Some(3) {
        return Err(invalid("source map version must be 3"));
    }
    if section_path.len() > 64 {
        return Err(invalid(
            "indexed source-map nesting exceeds the 64-level decoder stack budget",
        ));
    }
    if object
        .get("file")
        .is_some_and(|file| !file.is_null() && !file.is_string())
    {
        return Err(invalid("source map file must be a string or null"));
    }
    if object.get("sections").is_some() {
        return decode_sections(
            object,
            offset_line,
            offset_column,
            stop,
            section_path,
            state,
        );
    }

    decode_regular_map(
        object,
        offset_line,
        offset_column,
        stop,
        section_path,
        state,
    )
}

fn decode_sections(
    object: &serde_json::Map<String, Value>,
    offset_line: usize,
    offset_column: usize,
    stop: Option<(usize, usize)>,
    section_path: &mut Vec<usize>,
    state: &mut DecodeState,
) -> Result<(), Failure> {
    let sections = object
        .get("sections")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("indexed source-map sections must be an array"))?;
    consume_records(&mut state.decoded_records, sections.len())?;
    if section_path.len() >= 64 && !sections.is_empty() {
        return Err(invalid(
            "indexed source-map nesting exceeds the 64-level decoder stack budget",
        ));
    }
    let offsets = section_offsets(sections)?;
    for (index, section) in sections.iter().enumerate() {
        let section = section.as_object().expect("validated section object");
        if section.get("url").is_some() {
            return Err(invalid("external source-map section URL is not fetched"));
        }
        let child = section
            .get("map")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("indexed source-map section requires an embedded map"))?;
        let (local_line, local_column) = offsets[index];
        let absolute_line = offset_line.checked_add(local_line).ok_or_else(|| {
            invalid("indexed source-map offset exceeds the generated-row decoder budget")
        })?;
        let absolute_column = if local_line == 0 {
            offset_column.checked_add(local_column).ok_or_else(|| {
                invalid("indexed source-map offset exceeds the generated-column range")
            })?
        } else {
            local_column
        };
        if absolute_line >= MAX_ROWS {
            return Err(invalid(
                "indexed source-map offset exceeds the generated-row decoder budget",
            ));
        }
        if stop.is_some_and(|boundary| (absolute_line, absolute_column) >= boundary) {
            return Err(invalid(
                "nested source-map section overlaps its enclosing boundary",
            ));
        }
        let next_stop = match offsets.get(index + 1) {
            None => None,
            Some((next_line, next_column)) => {
                let line = offset_line.checked_add(*next_line).ok_or_else(|| {
                    invalid("indexed source-map offset exceeds the generated-row range")
                })?;
                if line >= MAX_ROWS {
                    return Err(invalid(
                        "indexed source-map offset exceeds the generated-row decoder budget",
                    ));
                }
                let column = if *next_line == 0 {
                    offset_column.checked_add(*next_column).ok_or_else(|| {
                        invalid("indexed source-map offset exceeds the generated-column range")
                    })?
                } else {
                    *next_column
                };
                Some((line, column))
            }
        };
        let child_stop = match (stop, next_stop) {
            (Some(parent), Some(next)) => Some(parent.min(next)),
            (Some(parent), None) => Some(parent),
            (None, next) => next,
        };
        section_path.push(index);
        decode_map(
            child,
            absolute_line,
            absolute_column,
            child_stop,
            section_path,
            state,
        )?;
        section_path.pop();
    }
    Ok(())
}

fn section_offsets(sections: &[Value]) -> Result<Vec<(usize, usize)>, Failure> {
    let mut offsets = Vec::with_capacity(sections.len());
    for section in sections {
        let section = section
            .as_object()
            .ok_or_else(|| invalid("indexed source-map section must be an object"))?;
        let offset = section
            .get("offset")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("indexed source-map section offset must be an object"))?;
        let line = offset
            .get("line")
            .and_then(Value::as_u64)
            .filter(|line| *line <= MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                invalid("indexed source-map section line must be a safe non-negative integer")
            })?;
        let column = offset
            .get("column")
            .and_then(Value::as_u64)
            .filter(|column| *column <= MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                invalid("indexed source-map section column must be a safe non-negative integer")
            })?;
        let offset = (
            usize::try_from(line)
                .map_err(|_| invalid("indexed source-map section line is too large"))?,
            usize::try_from(column)
                .map_err(|_| invalid("indexed source-map section column is too large"))?,
        );
        if offsets.last().is_some_and(|previous| offset <= *previous) {
            return Err(invalid(
                "indexed source-map section offsets must be strictly increasing",
            ));
        }
        offsets.push(offset);
    }
    Ok(offsets)
}

fn decode_regular_map(
    object: &serde_json::Map<String, Value>,
    offset_line: usize,
    offset_column: usize,
    stop: Option<(usize, usize)>,
    section_path: &[usize],
    state: &mut DecodeState,
) -> Result<(), Failure> {
    let sources = object
        .get("sources")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("source map sources must be an array"))?;
    let names = match object.get("names") {
        None => &[][..],
        Some(value) => value
            .as_array()
            .ok_or_else(|| invalid("source map names must be an array"))?,
    };
    if names.iter().any(|value| !value.is_string()) {
        return Err(invalid("source map names must contain strings"));
    }
    let mappings = object
        .get("mappings")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("source map mappings must be a string"))?;
    let sources_content_count = object
        .get("sourcesContent")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    consume_records(
        &mut state.decoded_records,
        1usize
            .saturating_add(sources.len())
            .saturating_add(names.len())
            .saturating_add(sources_content_count),
    )?;
    if let Some(root) = object.get("sourceRoot")
        && !root.is_null()
        && !root.is_string()
    {
        return Err(invalid("source map sourceRoot must be a string or null"));
    }
    validate_ignore_indices(object.get("ignoreList"), "ignoreList")?;
    validate_ignore_indices(object.get("x_google_ignoreList"), "x_google_ignoreList")?;
    let mut declarations = declarations(
        sources,
        object.get("sourcesContent"),
        object.get("sourceRoot"),
        object
            .get("ignoreList")
            .or_else(|| object.get("x_google_ignoreList")),
    )?;
    let flattened_start = state.declarations.len();
    for declaration in &mut declarations {
        declaration.section_path = section_path.to_vec();
        declaration.flattened_source_index = flattened_start + declaration.source_index;
    }
    state.declarations.extend(declarations);
    let leaf_segments = decode_mappings(
        mappings,
        MappingDecodeContext {
            offset_line,
            offset_column,
            stop,
            names,
            section_path,
            flattened_start,
            source_count: sources.len(),
        },
        &mut state.decoded_segments,
        &mut state.decoded_records,
    )?;
    state.segments.extend(leaf_segments);
    Ok(())
}

fn validate_ignore_indices(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let indices = value
        .as_array()
        .ok_or_else(|| invalid(&format!("source map {field} must be an array")))?;
    if indices.iter().any(|index| index.as_u64().is_none()) {
        return Err(invalid(&format!(
            "source map {field} must contain non-negative integers"
        )));
    }
    Ok(())
}

struct MappingDecodeContext<'a> {
    offset_line: usize,
    offset_column: usize,
    stop: Option<(usize, usize)>,
    names: &'a [Value],
    section_path: &'a [usize],
    flattened_start: usize,
    source_count: usize,
}

fn decode_mappings(
    mappings: &str,
    context: MappingDecodeContext<'_>,
    decoded_segments: &mut usize,
    decoded_records: &mut usize,
) -> Result<Vec<MappingSegment>, Failure> {
    let mut output = Vec::new();
    let mut source = 0i64;
    let mut original_line = 0i64;
    let mut original_column = 0i64;
    let mut name = 0i64;
    for (line_index, row) in mappings.split(';').enumerate() {
        consume_records(decoded_records, 1)?;
        if line_index + 1 > MAX_ROWS {
            return Err(invalid(
                "source map exceeds the generated-row decoder budget",
            ));
        }
        let mut generated_column = 0i64;
        for encoded in row.split(',').filter(|value| !value.is_empty()) {
            consume_records(decoded_records, 1)?;
            *decoded_segments = decoded_segments.saturating_add(1);
            if *decoded_segments > MAX_SEGMENTS {
                return Err(invalid("source map exceeds the decoded-segment budget"));
            }
            let values = decode_vlq_segment(encoded)?;
            if !matches!(values.len(), 1 | 4 | 5) {
                return Err(invalid(
                    "source-map segment must contain one, four, or five values",
                ));
            }
            generated_column = generated_column
                .checked_add(values[0])
                .ok_or_else(|| invalid("source-map generated column overflowed"))?;
            if generated_column < 0 {
                return Err(invalid("source-map generated column became negative"));
            }
            let (segment_source, segment_line, segment_column, segment_name) = if values.len() > 1 {
                source = source
                    .checked_add(values[1])
                    .ok_or_else(|| invalid("source-map source index overflowed"))?;
                original_line = original_line
                    .checked_add(values[2])
                    .ok_or_else(|| invalid("source-map original line overflowed"))?;
                original_column = original_column
                    .checked_add(values[3])
                    .ok_or_else(|| invalid("source-map original column overflowed"))?;
                if source < 0 || original_line < 0 || original_column < 0 {
                    return Err(invalid("source-map relative location became negative"));
                }
                if values.len() == 5 {
                    name = name
                        .checked_add(values[4])
                        .ok_or_else(|| invalid("source-map name index overflowed"))?;
                    if name < 0 {
                        return Err(invalid("source-map name index became negative"));
                    }
                }
                (
                    Some(usize::try_from(source).map_err(|_| {
                        invalid("source-map source index exceeds the supported range")
                    })?),
                    Some(usize::try_from(original_line).map_err(|_| {
                        invalid("source-map original line exceeds the supported range")
                    })?),
                    Some(usize::try_from(original_column).map_err(|_| {
                        invalid("source-map original column exceeds the supported range")
                    })?),
                    (values.len() == 5)
                        .then(|| usize::try_from(name))
                        .transpose()
                        .map_err(|_| {
                            invalid("source-map name index exceeds the supported range")
                        })?,
                )
            } else {
                (None, None, None, None)
            };
            if let Some(source_index) = segment_source {
                if source_index >= context.source_count {
                    return Err(invalid(
                        "source-map mapping references an absent source declaration",
                    ));
                }
            }
            let generated_line = context
                .offset_line
                .checked_add(line_index)
                .ok_or_else(|| invalid("source-map generated row became too large"))?;
            let generated_column = if line_index == 0 {
                context
                    .offset_column
                    .checked_add(generated_column as usize)
                    .ok_or_else(|| invalid("source-map generated column became too large"))?
            } else {
                usize::try_from(generated_column).map_err(|_| {
                    invalid("source-map generated column exceeds the supported range")
                })?
            };
            if generated_line >= MAX_ROWS {
                return Err(invalid(
                    "source-map exceeds the generated-row decoder budget",
                ));
            }
            if let Some((stop_line, stop_column)) = context.stop {
                if (generated_line, generated_column) >= (stop_line, stop_column) {
                    return Err(invalid(
                        "embedded source-map mappings overlap the following section boundary",
                    ));
                }
            }
            let name = match segment_name {
                Some(index) => Some(
                    context
                        .names
                        .get(index)
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid("source-map name index references an absent name"))?
                        .to_owned(),
                ),
                None => None,
            };
            output.push(MappingSegment {
                line: generated_line + 1,
                column: generated_column,
                source: segment_source,
                original_line: segment_line,
                original_column: segment_column,
                name,
                section_path: context.section_path.to_vec(),
                flattened_source_index: segment_source.map(|index| context.flattened_start + index),
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
        let payload = digit & 31;
        if (shift == 30 && payload > 3) || (shift > 30 && payload != 0) {
            return Err(invalid(
                "source-map VLQ exceeds the supported 32-bit quantity width",
            ));
        }
        if shift <= 30 {
            value |= (payload as i64) << shift;
        }
        if digit & 32 == 0 {
            let negative = value & 1 != 0;
            let magnitude = value >> 1;
            values.push(if negative { -magnitude } else { magnitude });
            value = 0;
            shift = 0;
        } else {
            shift += 5;
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
    base_url: &str,
) -> Result<Value, Failure> {
    let Some(_) = segment.source else {
        return Ok(serde_json::json!({ "state": "generated-only" }));
    };
    let flattened_source_index = segment
        .flattened_source_index
        .ok_or_else(|| invalid("source-map mapped segment has no source declaration"))?;
    let declaration = declarations
        .get(flattened_source_index)
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
        "flattened_source_index": declaration.flattened_source_index,
        "section_path": declaration.section_path.clone(),
        "source_index": declaration.source_index,
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
        "name": segment.name.clone()
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
    source_map_paths::resolve_source_map_url(Some(source), root, base)
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
    fn resolves_source_urls_with_trace_map_path_normalization() {
        let base = "https://host/maps/app.js.map?v=2#map";
        assert_eq!(
            resolve_source_url(base, Some("https://cdn.example/src//"), "../q.js"),
            "https://cdn.example/q.js"
        );
        assert_eq!(
            resolve_source_url(base, Some("https://cdn.example/src/"), "/a.js"),
            "https://cdn.example/src/a.js"
        );
        assert_eq!(
            resolve_source_url(base, Some("https://cdn.example/src/../source"), "a/../b.js"),
            "https://cdn.example/source/b.js"
        );
        assert_eq!(
            resolve_source_url(base, None, "//cdn.example/source.js"),
            "https://cdn.example/source.js"
        );
    }

    #[test]
    fn accepts_bom_and_source_map_transport_prefix() {
        let map = serde_json::json!({
            "version": 3,
            "sources": ["main.ts"],
            "names": [],
            "mappings": "AAAA"
        });
        let text = format!("\u{feff})]}}'transport prefix\r{map}");
        let result = trace_web_source_location(&input(), &text).expect("trace prefixed map");
        assert_eq!(result["matches"][0]["reported_source"], "main.ts");
    }

    #[test]
    fn rejects_vlq_payload_beyond_32_bit_quantity_width() {
        assert!(decode_vlq_segment("ggggggE").is_err());
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

    #[test]
    fn traces_indexed_sections_with_absolute_offsets_and_provenance() {
        let map = serde_json::json!({
            "version": 3,
            "file": "app.js",
            "sections": [
                {
                    "offset": {"line": 0, "column": 0},
                    "map": {
                        "version": 3,
                        "sources": ["first.ts"],
                        "sourcesContent": ["first"],
                        "names": [],
                        "mappings": "AAAA"
                    }
                },
                {
                    "offset": {"line": 1, "column": 2},
                    "map": {
                        "version": 3,
                        "sources": ["second.ts"],
                        "sourcesContent": ["second"],
                        "names": [],
                        "mappings": "AAAA"
                    }
                }
            ]
        })
        .to_string();
        let mut request = input();
        request["generated_position"] = serde_json::json!({"line": 2, "column": 2});
        let result = trace_web_source_location(&request, &map).expect("trace indexed map");
        assert_eq!(result["format"], "indexed");
        assert_eq!(
            result["lookup"]["matched_generated_position"],
            serde_json::json!({"line": 2, "column": 2})
        );
        assert_eq!(result["matches"][0]["section_path"], serde_json::json!([1]));
        assert_eq!(result["matches"][0]["flattened_source_index"], 1);
        assert_eq!(result["matches"][0]["source_index"], 0);
    }

    #[test]
    fn rejects_indexed_mappings_that_cross_the_next_section_boundary() {
        let map = serde_json::json!({
            "version": 3,
            "sections": [
                {
                    "offset": {"line": 0, "column": 0},
                    "map": {
                        "version": 3,
                        "sources": ["first.ts"],
                        "names": [],
                        "mappings": "AAAA,UAAA"
                    }
                },
                {
                    "offset": {"line": 0, "column": 5},
                    "map": {
                        "version": 3,
                        "sources": [],
                        "names": [],
                        "mappings": "A"
                    }
                }
            ]
        })
        .to_string();
        let error = trace_web_source_location(&input(), &map).expect_err("overlap must fail");
        assert!(error.to_string().contains("boundary"));
    }
}
