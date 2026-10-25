//! Authenticated graph resolver backed by the JavaScript acquisition facts.
//!
//! The graph builder consumes [`super::super::graph::resolution::ArtifactPathResolver`]
//! while acquisition owns the typed inventory and file projection.  This
//! adapter is the boundary between those owners: it builds lookup indexes
//! once, preserves omission and unreadable-text facts, and delegates path
//! semantics to [`super::artifact_path`].  It never replays recorded resolver
//! output and never opens a filesystem path.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

use rea_core::artifact_inventory::ArtifactInventoryResult;

use super::super::semantic::value_types::JsString;
use super::{
    super::graph::json::{Json, Obj},
    super::graph::resolution::{ArtifactPathResolver, ResolveRequest},
    super::{
        acquisition::JavaScriptArtifactFileSet,
        artifact_files::{InventoryLookup, UnanalyzedArtifactLookup},
    },
    artifact_path::{
        ResolutionContext, ResolveInput, ResolverFile, ResolverFileText, UnanalyzedFile,
        UnanalyzedLookup, resolve_artifact_path,
    },
    mode::{ModuleReferenceKind, module_resolution_mode_for_reference},
};

/// A resolver constructed from one authenticated inventory and acquisition.
pub struct JavaScriptGraphResolver<'a> {
    files: HashMap<JsString, ResolverFile>,
    directory_paths: HashSet<JsString>,
    unanalyzed: InventoryLookupAdapter<'a>,
}

struct InventoryLookupAdapter<'a> {
    inner: RefCell<InventoryLookup<'a>>,
}

impl UnanalyzedLookup for InventoryLookupAdapter<'_> {
    fn get(&self, path: &str) -> Option<UnanalyzedFile> {
        self.inner
            .borrow_mut()
            .get(path)
            .map(|file| UnanalyzedFile {
                container_sha256: file.container_sha256,
                sha256: file.sha256,
                bytes: file.bytes,
                kind: file.kind.map(|kind| format!("{kind:?}")),
                hash_status: Some(file.hash_status),
                limitations: Some(file.limitations),
            })
    }

    fn has_directory(&self, path: &str, container_sha256: Option<&str>) -> bool {
        self.inner
            .borrow_mut()
            .has_directory(path, container_sha256)
    }
}

impl<'a> JavaScriptGraphResolver<'a> {
    /// Build the resolver indexes from the same snapshot used for acquisition.
    pub fn new(
        snapshot: &'a ArtifactInventoryResult,
        file_set: &JavaScriptArtifactFileSet<'a>,
    ) -> Self {
        let files = file_set
            .files
            .iter()
            .map(|file| {
                let text = match &file.text {
                    super::super::artifact_files::JavaScriptText::Included(value) => {
                        ResolverFileText::Included(prepare_package_json_text(
                            &encode_json_text_units(value),
                        ))
                    }
                    super::super::artifact_files::JavaScriptText::Excluded(reason) => {
                        ResolverFileText::Excluded(format!("{reason:?}"))
                    }
                };
                (
                    JsString::from(file.path.clone()),
                    ResolverFile {
                        container_sha256: file.container_sha256.clone(),
                        text,
                    },
                )
            })
            .collect();

        let directory_paths = inventory_directories(snapshot);
        Self {
            files,
            directory_paths,
            unanalyzed: InventoryLookupAdapter {
                inner: RefCell::new(InventoryLookup::new(snapshot, &file_set.containers)),
            },
        }
    }

    fn unavailable_resolution(request: &ResolveRequest<'_>, reason: &str) -> Json {
        Json::from(
            Obj::new()
                .with("declared_path", Json::String(request.declared_path.clone()))
                .with("resolution_context", Json::String(request.context.clone()))
                .with(
                    "limitations",
                    Json::Array(vec![Json::String(reason.into())]),
                )
                .with("resolved_path", Json::Null)
                .with("resolution_status", "unavailable"),
        )
    }
}

impl ArtifactPathResolver for JavaScriptGraphResolver<'_> {
    fn resolve(&self, request: &ResolveRequest<'_>) -> Json {
        let Some(declared_path) = request.declared_path.as_str() else {
            // JavaScript path strings may contain lone UTF-16 surrogates. They
            // remain valid lookup identities; when no inventoried candidate
            // matches, resolution is the ordinary not-found outcome. Keep
            // the distinction from unavailable, which means the inventory or
            // resolver input itself was unavailable.
            return Json::from(
                Obj::new()
                    .with("declared_path", Json::String(request.declared_path.clone()))
                    .with("resolution_context", Json::String(request.context.clone()))
                    .with(
                        "limitations",
                        Json::Array(vec![Json::String(
                            "No extension, directory package, or index candidate exists in the inventoried artifact container.".into(),
                        )]),
                    )
                    .with("resolved_path", Json::Null)
                    .with("resolution_status", "not-found"),
            );
        };
        let Some(source_path) = request.source_path.as_str() else {
            return Self::unavailable_resolution(
                request,
                "The resolver source path contains an unpaired UTF-16 surrogate.",
            );
        };
        let Some(context) = resolution_context(request.context.as_str().unwrap_or_default()) else {
            return Self::unavailable_resolution(request, "The resolution context is unknown.");
        };
        let module_kind = request
            .module_kind
            .as_deref()
            .and_then(|value| match value {
                "import" => Some(super::mode::ModuleResolutionMode::Import),
                "require" => Some(super::mode::ModuleResolutionMode::Require),
                "compiler-dependent" => Some(super::mode::ModuleResolutionMode::CompilerDependent),
                _ => None,
            });
        let runtime_path_kind = request.runtime_path_kind.and_then(|value| match value {
            "exact-file" => Some(super::artifact_path::RuntimePathKind::ExactFile),
            "node-entrypoint" => Some(super::artifact_path::RuntimePathKind::NodeEntrypoint),
            "url-resource" => Some(super::artifact_path::RuntimePathKind::UrlResource),
            _ => None,
        });
        let html_base_href = request
            .html_base_href
            .as_ref()
            .and_then(|value| value.as_js_string())
            .and_then(|value| value.as_str().map(str::to_owned));
        let input = ResolveInput {
            declared_path: &declared_path,
            source_path: &source_path,
            context,
            files: &self.files,
            directory_paths: Some(&self.directory_paths),
            unanalyzed_files: Some(&self.unanalyzed),
            html_base_href: html_base_href.as_deref(),
            module_kind,
            runtime_path_kind,
        };
        let result = resolve_artifact_path(&input);
        let mut object = Obj::new()
            .with("declared_path", Json::String(request.declared_path.clone()))
            .with("resolution_context", request.context.clone())
            .with(
                "limitations",
                Json::Array(
                    result
                        .limitations
                        .into_iter()
                        .map(|limitation| Json::String(limitation.into()))
                        .collect(),
                ),
            )
            .with(
                "resolved_path",
                result
                    .resolved_path
                    .map_or(Json::Null, |path| Json::String(path.into())),
            )
            .with(
                "resolution_status",
                resolution_status(result.resolution_status),
            );
        if let Some(candidate) = result.candidate_path {
            object.set("candidate_path", Json::String(candidate.into()));
        }
        if let Some(branches) = result.conditional_resolutions {
            object.set(
                "conditional_resolutions",
                Json::Array(
                    branches
                        .into_iter()
                        .map(|branch| {
                            let mut value = Obj::new()
                                .with("mode", conditional_mode(branch.mode))
                                .with(
                                    "resolution_status",
                                    resolution_status(branch.resolution_status),
                                )
                                .with(
                                    "resolved_path",
                                    branch
                                        .resolved_path
                                        .map_or(Json::Null, |path| Json::String(path.into())),
                                )
                                .with(
                                    "limitations",
                                    Json::Array(
                                        branch
                                            .limitations
                                            .into_iter()
                                            .map(|limitation| Json::String(limitation.into()))
                                            .collect(),
                                    ),
                                );
                            if let Some(candidate) = branch.candidate_path {
                                value.set("candidate_path", Json::String(candidate.into()));
                            }
                            value.into()
                        })
                        .collect(),
                ),
            );
        }
        object.into()
    }

    fn module_resolution_mode(
        &self,
        source_path: &super::super::semantic::value_types::JsString,
        reference_kind: &str,
        explicit_mode: Option<&str>,
    ) -> String {
        let Some(source_path) = source_path.as_str() else {
            return "compiler-dependent".to_owned();
        };
        let explicit = explicit_mode.and_then(|value| match value {
            "import" => Some(super::mode::ModuleResolutionMode::Import),
            "require" => Some(super::mode::ModuleResolutionMode::Require),
            "compiler-dependent" => Some(super::mode::ModuleResolutionMode::CompilerDependent),
            _ => None,
        });
        let kind = match reference_kind {
            "require" => ModuleReferenceKind::Require,
            "dynamic-import" => ModuleReferenceKind::DynamicImport,
            _ => ModuleReferenceKind::StaticImport,
        };
        module_resolution_mode_for_reference(source_path, kind, explicit)
            .as_str()
            .to_owned()
    }
}

fn resolution_context(value: &str) -> Option<ResolutionContext> {
    match value {
        "package-entrypoint" => Some(ResolutionContext::PackageEntrypoint),
        "filesystem-expression" => Some(ResolutionContext::FilesystemExpression),
        "module-specifier" => Some(ResolutionContext::ModuleSpecifier),
        "html-reference" => Some(ResolutionContext::HtmlReference),
        "url-reference" => Some(ResolutionContext::UrlReference),
        _ => None,
    }
}

fn resolution_status(value: super::artifact_path::ResolutionStatus) -> &'static str {
    match value {
        super::artifact_path::ResolutionStatus::Resolved => "resolved",
        super::artifact_path::ResolutionStatus::NotFound => "not-found",
        super::artifact_path::ResolutionStatus::Unavailable => "unavailable",
        super::artifact_path::ResolutionStatus::External => "external",
        super::artifact_path::ResolutionStatus::Rejected => "rejected",
    }
}

fn conditional_mode(value: super::artifact_path::ConditionalMode) -> &'static str {
    match value {
        super::artifact_path::ConditionalMode::Import => "import",
        super::artifact_path::ConditionalMode::Require => "require",
    }
}

fn inventory_directories(snapshot: &ArtifactInventoryResult) -> HashSet<JsString> {
    let mut directories = HashSet::new();
    for occurrence in &snapshot.occurrences {
        if occurrence.entry_kind == "directory" {
            directories.insert(occurrence.logical_path.clone());
        }
        let units = occurrence.logical_path.units();
        let mut end = units.len();
        while let Some(index) = units[..end].iter().rposition(|unit| *unit == b'/' as u16) {
            if index == 0 {
                break;
            }
            directories.insert(JsString::from_utf16(units[..index].to_vec()));
            end = index;
        }
    }
    directories
}

const INTERNAL_SURROGATE_MARKER: char = '\u{e000}';

fn encode_json_text_units(value: &JsString) -> String {
    value
        .code_points()
        .flat_map(|point| {
            if point <= 0xffff {
                encode_code_unit(point as u16).chars().collect::<Vec<_>>()
            } else {
                char::from_u32(point)
                    .map(|character| vec![character])
                    .unwrap_or_default()
            }
        })
        .collect()
}

fn encode_code_unit(unit: u16) -> String {
    if (0xd800..=0xdfff).contains(&unit) {
        format!("{INTERNAL_SURROGATE_MARKER}{unit:04x}")
    } else if unit == INTERNAL_SURROGATE_MARKER as u16 {
        format!("{INTERNAL_SURROGATE_MARKER}{INTERNAL_SURROGATE_MARKER}")
    } else {
        char::from_u32(u32::from(unit))
            .expect("non-surrogate UTF-16 code unit is a Unicode scalar")
            .to_string()
    }
}

#[cfg(test)]
fn decode_json_text_units(value: &str) -> JsString {
    let mut units = Vec::new();
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character != INTERNAL_SURROGATE_MARKER {
            let mut buffer = [0; 2];
            units.extend(character.encode_utf16(&mut buffer).iter().copied());
            continue;
        }
        if chars.next_if_eq(&INTERNAL_SURROGATE_MARKER).is_some() {
            units.push(INTERNAL_SURROGATE_MARKER as u16);
            continue;
        }
        let digits: String = chars.by_ref().take(4).collect();
        if digits.len() == 4 && digits.chars().all(|digit| digit.is_ascii_hexdigit()) {
            units.push(u16::from_str_radix(&digits, 16).expect("validated hexadecimal digits"));
        } else {
            units.push(INTERNAL_SURROGATE_MARKER as u16);
            units.extend(digits.encode_utf16());
        }
    }
    JsString::from_utf16(units)
}

fn prepare_package_json_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    let mut in_string = false;

    while let Some(character) = characters.next() {
        if !in_string {
            if character == '"' {
                in_string = true;
            }
            output.push(character);
            continue;
        }

        if character == '"' {
            in_string = false;
            output.push(character);
            continue;
        }

        if character == INTERNAL_SURROGATE_MARKER {
            output.push_str(&encode_code_unit(INTERNAL_SURROGATE_MARKER as u16));
            continue;
        }

        if character == '\\' {
            let Some(escape) = characters.next() else {
                output.push('\\');
                continue;
            };
            if escape != 'u' {
                output.push('\\');
                output.push(escape);
                continue;
            }

            let mut digits = String::new();
            for _ in 0..4 {
                let Some(digit) = characters.next() else {
                    output.push_str("\\u");
                    output.push_str(&digits);
                    break;
                };
                digits.push(digit);
            }
            if digits.len() != 4 || !digits.chars().all(|digit| digit.is_ascii_hexdigit()) {
                output.push_str("\\u");
                output.push_str(&digits);
                continue;
            }

            let unit = u16::from_str_radix(&digits, 16).expect("validated hexadecimal digits");
            if (0xd800..=0xdbff).contains(&unit) {
                let is_low_pair = characters.peek() == Some(&'\\');
                if is_low_pair {
                    let mut lookahead = characters.clone();
                    let _ = lookahead.next();
                    if lookahead.next() == Some('u') {
                        let low_digits: String = lookahead.take(4).collect();
                        let low = u16::from_str_radix(&low_digits, 16)
                            .ok()
                            .filter(|low| (0xdc00..=0xdfff).contains(low));
                        if low.is_some() {
                            output.push('\\');
                            output.push('u');
                            output.push_str(&digits);
                            continue;
                        }
                    }
                }
                output.push_str(&encode_code_unit(unit));
                continue;
            }
            if (0xdc00..=0xdfff).contains(&unit) {
                output.push_str(&encode_code_unit(unit));
                continue;
            }

            output.push('\\');
            output.push('u');
            output.push_str(&digits);
            continue;
        }

        output.push(character);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::{
        JsString, decode_json_text_units, encode_json_text_units, prepare_package_json_text,
    };

    #[test]
    fn json_text_unit_encoding_round_trips_unpaired_surrogates() {
        let original = JsString::from_utf16(vec![b's' as u16, 0xd800, b'/' as u16, 0xe000]);

        let encoded = encode_json_text_units(&original);

        assert_eq!(decode_json_text_units(&encoded), original);
    }

    #[test]
    fn package_json_keeps_unpaired_surrogate_escape_as_a_string_value() {
        let source = r#"{"exports":"./\uD800.js"}"#;
        let prepared = prepare_package_json_text(source);
        let parsed: serde_json::Value =
            serde_json::from_str(&prepared).expect("prepared package JSON remains valid");
        let target = parsed["exports"].as_str().expect("exports string");

        assert_eq!(
            decode_json_text_units(target),
            JsString::from_utf16(
                "./".encode_utf16()
                    .chain([0xd800])
                    .chain(".js".encode_utf16())
                    .collect::<Vec<_>>()
            ),
        );
    }

    #[test]
    fn package_json_escapes_literal_marker_and_lone_high_surrogate() {
        let source = "{\"exports\":\"./\\uD800.\u{e000}js\"}";
        let prepared = prepare_package_json_text(source);
        let parsed: serde_json::Value =
            serde_json::from_str(&prepared).expect("prepared package JSON remains valid");
        let target = parsed["exports"].as_str().expect("exports string");

        assert_eq!(
            decode_json_text_units(target),
            JsString::from_utf16(
                "./".encode_utf16()
                    .chain([0xd800])
                    .chain(".".encode_utf16())
                    .chain([0xe000])
                    .chain("js".encode_utf16())
                    .collect::<Vec<_>>(),
            ),
        );
    }

    #[test]
    fn package_json_preserves_a_literal_marker_followed_by_hex_digits() {
        let source = "{\"exports\":\"./\u{e000}d800.js\"}";
        let prepared = prepare_package_json_text(source);
        let parsed: serde_json::Value =
            serde_json::from_str(&prepared).expect("prepared package JSON remains valid");
        let target = parsed["exports"].as_str().expect("exports string");

        assert_eq!(
            decode_json_text_units(target),
            JsString::from("./\u{e000}d800.js"),
        );
    }

    #[test]
    fn package_json_does_not_rewrite_an_escaped_backslash_u_sequence() {
        let source = r#"{"exports":"./\\uD800.js"}"#;
        let prepared = prepare_package_json_text(source);
        let parsed: serde_json::Value =
            serde_json::from_str(&prepared).expect("prepared package JSON remains valid");
        let target = parsed["exports"].as_str().expect("exports string");

        assert_eq!(target, "./\\uD800.js");
    }
}
