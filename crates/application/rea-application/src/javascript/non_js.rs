//! Artifact-byte observations that accompany JavaScript source analysis.
//!
//! This module owns the non-executable portions of the artifact analysis
//! contract: package manifests, JSON modules, HTML script declarations, and
//! local source maps.  It deliberately returns the graph's ordered [`Json`]
//! value so JavaScript UTF-16 strings remain lossless at this boundary.

use super::artifact_files::{JavaScriptArtifactFile, JavaScriptText};
use super::graph::json::{Json, Obj, sha256_hex};
use super::html::html_artifact_references;
use super::resolution::source_map_paths::resolve_source_map_references_exact;
use super::semantic::value_types::JsString;

pub(crate) fn package_observation(file: &JavaScriptArtifactFile) -> Json {
    let unavailable = |reason: &str, status: &str| {
        Obj::new()
            .with("path", JsString::from(file.path.clone()))
            .with("sha256", file.sha256.clone())
            .with("status", status)
            .with("name", Json::Null)
            .with("version", Json::Null)
            .with("main", Json::Null)
            .with("renderer", Json::Null)
            .with("limitation", reason)
            .into()
    };
    let JavaScriptText::Included(text) = &file.text else {
        return unavailable("Package metadata text was unavailable.", "unavailable");
    };
    let Some(text) = text.as_str() else {
        return unavailable("Package metadata was not valid UTF-8.", "invalid");
    };
    let value = match super::graph::json::parse(text) {
        Ok(Json::Object(object)) => object,
        Ok(_) => return unavailable("package.json root is not an object.", "invalid"),
        Err(_) => return unavailable("package.json is not valid JSON.", "invalid"),
    };
    let optional = |key: &str| {
        value
            .get(key)
            .filter(|value| value.as_js_string().is_some_and(|value| !value.is_empty()))
            .cloned()
            .unwrap_or(Json::Null)
    };
    let renderer = value
        .get("renderer")
        .filter(|value| value.as_js_string().is_some_and(|value| !value.is_empty()))
        .cloned()
        .or_else(|| {
            value
                .get("browser")
                .filter(|value| value.as_js_string().is_some_and(|value| !value.is_empty()))
                .cloned()
        })
        .or_else(|| {
            value
                .get("module")
                .filter(|value| value.as_js_string().is_some_and(|value| !value.is_empty()))
                .cloned()
        })
        .unwrap_or(Json::Null);
    Obj::new()
        .with("path", JsString::from(file.path.clone()))
        .with("sha256", file.sha256.clone())
        .with("status", "included")
        .with("name", optional("name"))
        .with("version", optional("version"))
        .with("main", optional("main"))
        .with("renderer", renderer)
        .with("limitation", Json::Null)
        .into()
}

pub(crate) fn json_module_observation(file: &JavaScriptArtifactFile) -> Json {
    let unavailable = |reason: String, status: &str, omitted: Json| {
        Obj::new()
            .with("path", JsString::from(file.path.clone()))
            .with("sha256", file.sha256.clone())
            .with("status", status)
            .with("top_level_keys", Json::Array(Vec::new()))
            .with("omitted_top_level_keys", omitted)
            .with("limitation", reason)
            .into()
    };
    let JavaScriptText::Included(text) = &file.text else {
        return unavailable(
            format!(
                "JSON module text was unavailable: {}.",
                exclusion_reason(&file.text)
            ),
            "unavailable",
            Json::Null,
        );
    };
    let Some(text) = text.as_str() else {
        return unavailable(
            "JSON module text was not valid UTF-8.".to_owned(),
            "invalid",
            0_usize.into(),
        );
    };
    let value = match super::graph::json::parse(text) {
        Ok(value) => value,
        Err(_) => {
            return unavailable(
                "JSON module is not valid JSON.".to_owned(),
                "invalid",
                0_usize.into(),
            );
        }
    };
    let mut keys = value
        .as_obj()
        .map(|object| {
            object
                .iter()
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    keys.sort_by(JsString::compare_code_points);
    Obj::new()
        .with("path", JsString::from(file.path.clone()))
        .with("sha256", file.sha256.clone())
        .with("status", "included")
        .with(
            "top_level_keys",
            Json::Array(keys.into_iter().map(Json::from).collect()),
        )
        .with("omitted_top_level_keys", 0_usize)
        .with("limitation", Json::Null)
        .into()
}

fn exclusion_reason(text: &JavaScriptText) -> &'static str {
    match text {
        JavaScriptText::Included(_) => "included",
        JavaScriptText::Excluded(reason) => match reason {
            super::artifact_files::TextExclusionReason::NotApplicable => "not-applicable",
            super::artifact_files::TextExclusionReason::InvalidUtf8 => "invalid-utf8",
            super::artifact_files::TextExclusionReason::OutsideAnalysisScope => {
                "outside-analysis-scope"
            }
        },
    }
}

pub(crate) fn html_observations(file: &JavaScriptArtifactFile) -> (Vec<Json>, Option<Json>) {
    let JavaScriptText::Included(text) = &file.text else {
        return (Vec::new(), None);
    };
    let Some(text) = text.as_str() else {
        return (Vec::new(), None);
    };
    let references = html_artifact_references(text);
    let scripts = references
        .scripts
        .into_iter()
        .map(|script| {
            Obj::new()
                .with("html_path", JsString::from(file.path.clone()))
                .with("script_path", JsString::from(script.script_path))
                .with(
                    "base_href",
                    references.base_href.clone().map(JsString::from),
                )
                .with("location", serialized(&script.location))
                .into()
        })
        .collect();
    let inline = (references.inline_script_count > 0).then(|| {
        Obj::new()
            .with("path", JsString::from(file.path.clone()))
            .with("script_count", references.inline_script_count)
            .with(
                "scripts",
                Json::Array(
                    references
                        .inline_scripts
                        .into_iter()
                        .map(|script| {
                            Obj::new()
                                .with("script_type", serialized(&script.script_type))
                                .with("location", serialized(&script.location))
                                .into()
                        })
                        .collect(),
                ),
            )
            .into()
    });
    (scripts, inline)
}

pub(crate) fn html_inline_limitation(observation: &Json) -> String {
    let path = observation.at("path").str();
    let count = observation.at("script_count").num().max(0.0) as usize;
    let lines = observation
        .at("scripts")
        .arr()
        .iter()
        .take(10)
        .map(|script| {
            (script.at("location").at("start").at("line").num().max(0.0) as usize).to_string()
        })
        .collect::<Vec<_>>();
    let suffix = count.saturating_sub(lines.len());
    let noun = if count == 1 { "body" } else { "bodies" };
    let verb = if count == 1 { "was" } else { "were" };
    format!(
        "{path} has {count} inline JavaScript {noun} starting at line{} {}{} that {verb} not analyzed; endpoints, storage, imports and other facts in {} are absent from the evidence.",
        if count == 1 { "" } else { "s" },
        lines.join(", "),
        if suffix > 0 {
            format!(" and {suffix} more")
        } else {
            String::new()
        },
        if count == 1 { "it" } else { "them" },
    )
}

pub(crate) fn source_map_observation(file: &JavaScriptArtifactFile) -> Json {
    let invalid = |reason: &str| {
        Obj::new()
            .with("path", JsString::from(file.path.clone()))
            .with("sha256", file.sha256.clone())
            .with("status", "invalid")
            .with("sources", Json::Array(Vec::new()))
            .with("limitation", reason)
            .into()
    };
    let JavaScriptText::Included(text) = &file.text else {
        return invalid("Source-map text could not be decoded as UTF-8.");
    };
    let Some(text) = text.as_str() else {
        return invalid("Source-map text could not be decoded as UTF-8.");
    };
    let json_text = source_map_json_text(text);
    let value = match super::graph::json::parse(json_text) {
        Ok(value) => value,
        Err(_) => return invalid("Source map is not valid JSON."),
    };
    let Some(version) = value.at("version").as_f64() else {
        return invalid("Source map is not a version 3 map.");
    };
    if version != 3.0 {
        return invalid("Source map is not a version 3 map.");
    }
    let Some(leaves) = source_map_leaves(&value) else {
        return invalid("Source map is not a version 3 map.");
    };
    let mut sources = Vec::new();
    let mut declaration_index = 0_usize;
    for leaf in leaves {
        let names = leaf.at("sources").arr();
        if !matches!(leaf.at("sources"), Json::Array(_)) {
            return invalid("Source map has no sources array.");
        }
        let contents = match leaf.get("sourcesContent") {
            None => None,
            Some(Json::Array(items)) => {
                if items
                    .iter()
                    .any(|item| !item.is_null() && item.as_js_string().is_none())
                {
                    return invalid(
                        "Source map sourcesContent must be an array of strings or null entries.",
                    );
                }
                Some(items.as_slice())
            }
            Some(_) => {
                return invalid(
                    "Source map sourcesContent must be an array of strings or null entries.",
                );
            }
        };
        let source_root = match leaf.get("sourceRoot") {
            None | Some(Json::Null) => None,
            Some(Json::String(root)) => Some(root.clone()),
            Some(_) => return invalid("Source map sourceRoot must be a string or null."),
        };
        let source_names = names
            .iter()
            .map(|name| name.as_js_string().cloned())
            .collect::<Vec<_>>();
        if names
            .iter()
            .any(|value| !value.is_null() && value.as_js_string().is_none())
        {
            return invalid("Source map contains a non-string source name.");
        }
        let references =
            resolve_source_map_references_exact(&source_names, source_root.as_ref(), &file.path);
        for (index, reference) in references.into_iter().enumerate() {
            let content = contents
                .and_then(|items| items.get(index))
                .and_then(Json::as_js_string)
                .cloned();
            sources.push(
                Obj::new()
                    .with("source_index", index)
                    .with("declaration_index", declaration_index as f64)
                    .with("reference", reference.map(|value| serialized(&value)))
                    .with("content", content.clone().map(Json::from))
                    .with("content_sha256", content.as_ref().map(js_string_sha256))
                    .into(),
            );
            declaration_index += 1;
        }
    }
    Obj::new()
        .with("path", JsString::from(file.path.clone()))
        .with("sha256", file.sha256.clone())
        .with("status", "included")
        .with("sources", Json::Array(sources))
        .with("limitation", Json::Null)
        .into()
}

fn js_string_sha256(value: &JsString) -> String {
    let utf8 = String::from_utf16_lossy(value.units());
    sha256_hex(utf8.as_bytes())
}

fn source_map_json_text(text: &str) -> &str {
    let without_bom = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Some(framed) = without_bom.strip_prefix(")]}'") else {
        return without_bom;
    };
    framed
        .find(['\r', '\n'])
        .map_or("", |newline| &framed[newline..])
}

fn source_map_leaves(value: &Json) -> Option<Vec<&Json>> {
    if value.at("version").as_f64() != Some(3.0) {
        return None;
    }
    if let Some(Json::Array(sections)) = value.get("sections") {
        let mut leaves = Vec::new();
        for section in sections {
            let map = section.get("map")?;
            leaves.extend(source_map_leaves(map)?);
        }
        return Some(leaves);
    }
    Some(vec![value])
}

fn serialized<T: serde::Serialize>(value: &T) -> Json {
    let text = serde_json::to_string(value).expect("non-JavaScript observation is serializable");
    super::graph::json::parse(&text).expect("non-JavaScript observation is valid JSON")
}
