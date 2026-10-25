//! Replay of an authenticated environment manifest against retained capture data.
//!
//! This module owns record selection and response projection.  Adapters only provide
//! the already-authenticated manifest, parent capture and caller arguments.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "environment-serve";
const BODY_LIMIT: usize = 256 * 1024;
const METADATA_LIMIT: usize = 1024;
const BASE64_PREFIX_CHARS: usize = (BODY_LIMIT + 6) / 3 * 4;

pub fn replay(
    manifest: &Value,
    capture: &Value,
    tool_name: &str,
    arguments: &Value,
    evidence_id: &str,
) -> Result<Value, Failure> {
    let tool = manifest
        .get("tools")
        .and_then(Value::as_array)
        .and_then(|tools| tools.iter().find(|tool| tool["name"] == tool_name))
        .ok_or_else(|| invalid("tool is not present in the environment manifest"))?;
    let records = capture
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("retained capture has no records"))?;
    let ordinals = tool["record_ordinals"]
        .as_array()
        .ok_or_else(|| invalid("manifest tool has no record ordinals"))?;
    let selected = select_record(ordinals, records, tool, arguments)
        .ok_or_else(|| invalid("tool cites no retained record to replay"))?;
    let record = selected.record;
    let request = record.get("reported").unwrap_or(record);
    let response = request.get("response").unwrap_or(&Value::Null);
    let content = response.get("content").unwrap_or(&Value::Null);
    let body = replay_body(content, record);
    let (path, query) = request
        .get("request")
        .and_then(|request| request.get("url"))
        .and_then(Value::as_str)
        .map(request_target)
        .unwrap_or_else(|| (String::new(), None));
    let status = response.get("status").cloned().unwrap_or(Value::Null);
    let content_type = content.get("mimeType").cloned().unwrap_or(Value::Null);
    let content_type_truncated = content_type
        .as_str()
        .is_some_and(|value| value.len() > METADATA_LIMIT);
    let body_recorded = body_recorded(content, record);
    Ok(json!({
        "status": status,
        "content_type": truncate_metadata(content_type),
        "body": body.body,
        "replay": {
            "record_ordinal": record["ordinal"],
            "evidence_id": evidence_id,
            "exact_match": selected.exact,
            "recorded_path": truncate_metadata(Value::String(path.to_owned())),
            "recorded_query": query
                .clone()
                .map(|value| truncate_metadata(Value::String(value)))
                .unwrap_or(Value::Null),
            "recorded_line_truncated": path.len() > METADATA_LIMIT
                || query
                    .as_deref()
                    .is_some_and(|value| value.len() > METADATA_LIMIT),
            "content_type_truncated": content_type_truncated,
            "body_recorded": body_recorded,
            "body_encoding": body.encoding,
            "truncated": body.truncated,
        }
    }))
}

struct Selection<'a> {
    record: &'a Value,
    exact: bool,
    score: MatchScore,
}

#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd)]
struct MatchScore {
    path_matches: usize,
    verbatim_matches: usize,
    query_matches: usize,
}

fn select_record<'a>(
    ordinals: &[Value],
    records: &'a [Value],
    tool: &Value,
    arguments: &Value,
) -> Option<Selection<'a>> {
    let mut best = None;
    for ordinal in ordinals.iter().filter_map(Value::as_u64) {
        let Some(record) = records.iter().find(|record| record["ordinal"] == ordinal) else {
            continue;
        };
        let score = score(record, tool, arguments);
        if best
            .as_ref()
            .is_none_or(|current: &Selection<'_>| score > current.score)
        {
            best = Some(Selection {
                record,
                exact: score_is_exact(score, tool, arguments),
                score,
            });
        }
    }
    best
}

fn score(record: &Value, tool: &Value, arguments: &Value) -> MatchScore {
    let (path, query) = record
        .pointer("/reported/request/url")
        .and_then(Value::as_str)
        .map(request_target)
        .unwrap_or_else(|| (String::new(), None));
    let params = tool.get("params").and_then(Value::as_array);
    let (path_names, _) = argument_names(tool);
    let mut path_matches = 0;
    let mut verbatim_matches = 0;
    if let Some(params) = params {
        let segments = path_segments(&path);
        for param in params {
            let Some(index) = param.get("index").and_then(Value::as_u64) else {
                continue;
            };
            let Some(name) = param.get("name").and_then(Value::as_str) else {
                continue;
            };
            let argument_name = path_names
                .get(
                    params
                        .iter()
                        .rposition(|candidate| {
                            candidate.get("name").and_then(Value::as_str) == Some(name)
                        })
                        .unwrap_or_default(),
                )
                .cloned()
                .unwrap_or_else(|| name.to_owned());
            let Some(value) = arguments.get(&argument_name).and_then(Value::as_str) else {
                continue;
            };
            let Some(segment) = segments.get(index as usize) else {
                continue;
            };
            if segment == value {
                verbatim_matches += 1;
            }
            if segment == value || percent_decode(segment) == value {
                path_matches += 1;
            }
        }
    }
    let query_matches = query_matches(tool, arguments, query.as_deref());
    MatchScore {
        path_matches,
        verbatim_matches,
        query_matches,
    }
}

fn score_is_exact(score: MatchScore, tool: &Value, arguments: &Value) -> bool {
    let (path_names, query_names) = argument_names(tool);
    let path_provided = tool
        .get("params")
        .and_then(Value::as_array)
        .map(|params| {
            params
                .iter()
                .filter(|param| {
                    let Some(name) = param.get("name").and_then(Value::as_str) else {
                        return false;
                    };
                    let argument_name = path_names
                        .get(
                            params
                                .iter()
                                .rposition(|candidate| {
                                    candidate.get("name").and_then(Value::as_str) == Some(name)
                                })
                                .unwrap_or_default(),
                        )
                        .cloned()
                        .unwrap_or_else(|| name.to_owned());
                    arguments
                        .get(&argument_name)
                        .and_then(Value::as_str)
                        .is_some()
                })
                .count()
        })
        .unwrap_or(0);
    let query_provided = tool
        .get("query_parameter_names")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .enumerate()
                .filter(|(index, name)| {
                    let Some(name) = name.as_str() else {
                        return false;
                    };
                    arguments
                        .get(
                            &query_names
                                .get(*index)
                                .cloned()
                                .unwrap_or_else(|| name.to_owned()),
                        )
                        .and_then(Value::as_str)
                        .is_some()
                })
                .count()
        })
        .unwrap_or(0);
    score.path_matches == path_provided && score.query_matches == query_provided
}

fn argument_names(tool: &Value) -> (Vec<String>, Vec<String>) {
    let params = tool
        .get("params")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let query_names = tool
        .get("query_parameter_names")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut taken = Vec::new();
    let mut paths = Vec::new();
    for (index, param) in params.iter().enumerate() {
        let name = param
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let preferred = if name.chars().count() <= 64 {
            name.to_owned()
        } else {
            format!("path_{}", index + 1)
        };
        let argument = free_argument_name(&preferred, "path_", &taken);
        taken.push(argument.clone());
        paths.push(argument);
    }
    let mut queries = Vec::new();
    for (index, name) in query_names.iter().enumerate() {
        let name = name.as_str().unwrap_or_default();
        let preferred = if name.chars().count() <= 64 {
            name.to_owned()
        } else {
            format!("query_{}", index + 1)
        };
        let argument = free_argument_name(&preferred, "query_", &taken);
        taken.push(argument.clone());
        queries.push(argument);
    }
    (paths, queries)
}

fn free_argument_name(preferred: &str, prefix: &str, taken: &[String]) -> String {
    if !taken.iter().any(|name| name == preferred) {
        return preferred.to_owned();
    }
    let mut candidate = format!("{prefix}{preferred}");
    let mut suffix = 2;
    while taken.iter().any(|name| name == &candidate) {
        candidate = format!("{prefix}{preferred}_{suffix}");
        suffix += 1;
    }
    candidate
}

fn query_matches(tool: &Value, arguments: &Value, query: Option<&str>) -> usize {
    let Some(query) = query else {
        return 0;
    };
    let Some(names) = tool.get("query_parameter_names").and_then(Value::as_array) else {
        return 0;
    };
    let mut matches = 0;
    for (index, name) in names.iter().enumerate() {
        let Some(name) = name.as_str() else {
            continue;
        };
        let argument_name = argument_names(tool)
            .1
            .get(index)
            .cloned()
            .unwrap_or_else(|| name.to_owned());
        let Some(value) = arguments.get(&argument_name).and_then(Value::as_str) else {
            continue;
        };
        if parse_query(query)
            .any(|(candidate, candidate_value)| candidate == name && candidate_value == value)
        {
            matches += 1;
        }
    }
    matches
}

fn truncate_metadata(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(utf8_prefix(&text, METADATA_LIMIT)),
        other => other,
    }
}

struct ReplayBody {
    body: Value,
    encoding: &'static str,
    truncated: bool,
}

fn replay_body(content: &Value, record: &Value) -> ReplayBody {
    let Some(text) = content.get("text").and_then(Value::as_str) else {
        return ReplayBody {
            body: Value::Null,
            encoding: "utf-8",
            truncated: false,
        };
    };
    if content.get("encoding").and_then(Value::as_str) == Some("base64") {
        return replay_base64_body(record, content);
    }
    let prefix = utf8_prefix(text, BODY_LIMIT);
    if prefix.len() < text.len() {
        return ReplayBody {
            body: Value::String(prefix),
            encoding: "utf-8",
            truncated: true,
        };
    }
    let Some(content_type) = content.get("mimeType").and_then(Value::as_str) else {
        return ReplayBody {
            body: Value::String(text.to_owned()),
            encoding: "utf-8",
            truncated: false,
        };
    };
    if is_json_like(content_type) {
        if let Ok(parsed) = serde_json::from_str::<Value>(text) {
            return ReplayBody {
                body: parsed,
                encoding: "utf-8",
                truncated: false,
            };
        }
    }
    ReplayBody {
        body: Value::String(text.to_owned()),
        encoding: "utf-8",
        truncated: false,
    }
}

fn replay_base64_body(record: &Value, content: &Value) -> ReplayBody {
    let Some(encoded) = record
        .get("binary_fields")
        .and_then(Value::as_array)
        .and_then(|fields| {
            fields.iter().find_map(|field| {
                (field.get("pointer").and_then(Value::as_str) == Some("/response/content/text")
                    && field.get("state").and_then(Value::as_str) == Some("retained"))
                .then(|| field.get("content_base64").and_then(Value::as_str))
                .flatten()
            })
        })
    else {
        return ReplayBody {
            body: Value::Null,
            encoding: "utf-8",
            truncated: false,
        };
    };
    let cut = encoded.len() > BASE64_PREFIX_CHARS;
    let encoded = if cut {
        &encoded[..BASE64_PREFIX_CHARS]
    } else {
        encoded
    };
    let Ok(bytes) = BASE64.decode(encoded) else {
        return ReplayBody {
            body: Value::String(encoded.to_owned()),
            encoding: "base64",
            truncated: cut,
        };
    };
    let truncated = cut;
    match std::str::from_utf8(&bytes) {
        Ok(text) if !truncated => {
            let body = if content
                .get("mimeType")
                .and_then(Value::as_str)
                .is_some_and(is_json_like)
            {
                serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
            } else {
                Value::String(text.to_owned())
            };
            ReplayBody {
                body,
                encoding: "utf-8",
                truncated: false,
            }
        }
        Ok(text) => ReplayBody {
            body: Value::String(text.to_owned()),
            encoding: "utf-8",
            truncated: true,
        },
        Err(error) if truncated && error.error_len().is_none() => ReplayBody {
            body: Value::String(
                std::str::from_utf8(&bytes[..error.valid_up_to()])
                    .unwrap_or_default()
                    .to_owned(),
            ),
            encoding: "utf-8",
            truncated: true,
        },
        Err(_) => ReplayBody {
            body: Value::String(encoded.to_owned()),
            encoding: "base64",
            truncated,
        },
    }
}

fn body_recorded(content: &Value, record: &Value) -> bool {
    if content.get("encoding").and_then(Value::as_str) != Some("base64") {
        return content.get("text").is_some_and(|value| !value.is_null());
    }
    if content.get("text").and_then(Value::as_str).is_none() {
        return false;
    }
    record
        .get("binary_fields")
        .and_then(Value::as_array)
        .is_some_and(|fields| {
            fields.iter().any(|field| {
                field.get("pointer").and_then(Value::as_str) == Some("/response/content/text")
                    && field.get("state").and_then(Value::as_str) == Some("retained")
                    && field
                        .get("content_base64")
                        .and_then(Value::as_str)
                        .is_some()
            })
        })
}

fn is_json_like(value: &str) -> bool {
    let essence = value
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
}

fn request_target(url: &str) -> (String, Option<String>) {
    let without_fragment = url.split('#').next().unwrap_or(url);
    let query_index = without_fragment.find('?');
    let path_end = query_index.unwrap_or(without_fragment.len());
    let target = &without_fragment[..path_end];
    let path = if let Some(scheme) = target.find("://") {
        target[scheme + 3..]
            .find('/')
            .map(|index| &target[scheme + 3 + index..])
            .unwrap_or("/")
    } else {
        target
    };
    let path = if path.is_empty() { "/" } else { path };
    let query = query_index.map(|index| format!("?{}", &without_fragment[index + 1..]));
    (path.to_owned(), query)
}

fn path_segments(path: &str) -> Vec<String> {
    path.trim_start_matches('/')
        .split('/')
        .map(str::to_owned)
        .collect()
}

fn parse_query(query: &str) -> impl Iterator<Item = (String, String)> + '_ {
    query.trim_start_matches('?').split('&').filter_map(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = percent_decode(name);
        if name.is_empty() {
            None
        } else {
            Some((name, percent_decode(value)))
        }
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'+' {
            output.push(b' ');
            index += 1;
        } else if index + 2 < bytes.len() && bytes[index] == b'%' {
            if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                output.push(byte);
                index += 3;
            } else {
                output.push(bytes[index]);
                index += 1;
            }
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn utf8_prefix(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the environment manifest, retained capture and arguments, then retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(message.into())),
        ]),
    )
}
