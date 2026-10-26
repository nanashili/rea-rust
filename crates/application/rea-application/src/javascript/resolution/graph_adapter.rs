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
        ContainerDirectoryIndex, PackageMetadataCache, ResolutionContext, ResolveInput,
        ResolverFile, ResolverFileText, UnanalyzedFile, UnanalyzedLookup, resolve_artifact_path,
    },
    mode::{ModuleReferenceKind, module_resolution_mode_for_reference},
};

/// A resolver constructed from one authenticated inventory and acquisition.
pub struct JavaScriptGraphResolver<'a> {
    files: HashMap<JsString, ResolverFile>,
    directory_paths: HashSet<JsString>,
    container_directory_paths: ContainerDirectoryIndex,
    unanalyzed: InventoryLookupAdapter<'a>,
    package_metadata_cache: PackageMetadataCache,
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
                        ResolverFileText::Included(value.clone())
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

        let container_directory_paths = container_directory_index(&files);
        let directory_paths = inventory_directories(snapshot);
        Self {
            files,
            directory_paths,
            container_directory_paths,
            unanalyzed: InventoryLookupAdapter {
                inner: RefCell::new(InventoryLookup::new(snapshot, &file_set.containers)),
            },
            package_metadata_cache: PackageMetadataCache::default(),
        }
    }

    fn unavailable_resolution(request: &ResolveRequest<'_>, reason: &str) -> Json {
        Json::from(
            Obj::new()
                .with("declared_path", Json::String(request.declared_path.clone()))
                .with("resolution_context", Json::String(request.context.clone()))
                .with(
                    "limitations",
                    Json::array(vec![Json::String(reason.into())]),
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
                        Json::array(vec![Json::String(
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
            container_directory_paths: Some(&self.container_directory_paths),
            unanalyzed_files: Some(&self.unanalyzed),
            html_base_href: html_base_href.as_deref(),
            module_kind,
            runtime_path_kind,
            package_metadata_cache: &self.package_metadata_cache,
        };
        let result = resolve_artifact_path(&input);
        let mut object = Obj::new()
            .with("declared_path", Json::String(request.declared_path.clone()))
            .with("resolution_context", request.context.clone())
            .with(
                "limitations",
                Json::array(
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
                Json::array(
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
                                    Json::array(
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

fn container_directory_index(files: &HashMap<JsString, ResolverFile>) -> ContainerDirectoryIndex {
    let mut index = ContainerDirectoryIndex::new();

    for (path, file) in files {
        let units = path.units();
        for (position, unit) in units.iter().enumerate() {
            if *unit != b'/' as u16 {
                continue;
            }

            index
                .entry(file.container_sha256.clone())
                .or_default()
                .insert(JsString::from_utf16(units[..position].to_vec()));
        }
    }

    index
}

#[cfg(test)]
mod tests {
    use super::super::artifact_path::{
        decode_json_text_units, encode_json_text_units, prepare_package_json_text,
    };
    use crate::javascript::semantic::value_types::JsString;

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
