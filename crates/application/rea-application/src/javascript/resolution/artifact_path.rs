//! Artifact-confined path resolution without filesystem access: relative,
//! extension and index candidates, `file:` URLs, package `exports`/`imports`,
//! self-reference, legacy ESM subpaths, Node builtins, Electron
//! `loadURL`/`loadFile` runtime paths, HTML base href and TypeScript emitted
//! source candidates.
//!
//! Compatibility owner: `src/application/javascript/JavaScriptArtifactPathResolution.ts`.
//!
//! Rust strings cannot hold unpaired UTF-16 surrogates, so the TypeScript
//! branch that builds opaque structural URL segments for them has no input
//! here. Package JSON is parsed with `serde_json`; before parsing, the resolver
//! maps lone UTF-16 units to an internal marker so metadata remains readable
//! without copying every source file into an encoded representation.
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

use serde::Serialize;
use serde_json::Value;

use super::mode::{ModuleResolutionMode, is_relative_module_specifier};
use super::package_imports::{
    PackageImportLookup, PackageImportSpecifier, PackageImportTargetKind,
    classify_package_import_specifier, classify_package_import_target, lookup_exact_package_import,
};
use super::syntax::{
    admits_canonical_path_syntax, contains_percent_escape, decode_uri_component,
    encode_uri_component, has_scheme, html_url_text, is_numeric_condition_key, js_own_keys,
    json_string, json_stringify, logical_path_escapes_root, looks_external,
    normalize_joined_logical_path, percent_decode_url_path, posix_basename, posix_dirname,
    posix_join, posix_normalize, strip_query_and_fragment,
};
use super::web_url::{self, WebUrl};
use crate::javascript::emitted_source_candidates::{self, Candidate, CandidateKind};
use crate::javascript::semantic::value_types::JsString;

/// Syntax context that owns a declared path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionContext {
    PackageEntrypoint,
    FilesystemExpression,
    ModuleSpecifier,
    HtmlReference,
    UrlReference,
}

impl ResolutionContext {
    fn is_html(self) -> bool {
        self == Self::HtmlReference
    }
}

/// Explicit resolution outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionStatus {
    Resolved,
    NotFound,
    Unavailable,
    External,
    Rejected,
}

/// Loader owner of a runtime path, independent of source imports.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimePathKind {
    ExactFile,
    NodeEntrypoint,
    UrlResource,
}

/// One Node loader branch of a compiler-dependent TypeScript reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConditionalMode {
    Import,
    Require,
}

/// One retained loader branch; neither branch is an established target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConditionalModuleResolution {
    pub mode: ConditionalMode,
    pub resolution_status: ResolutionStatus,
    pub resolved_path: Option<String>,
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_path: Option<String>,
}

/// Explicit outcome of artifact-confined path resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactPathResolution {
    pub declared_path: String,
    pub resolution_context: ResolutionContext,
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditional_resolutions: Option<Vec<ConditionalModuleResolution>>,
    /// `Some` exactly when `resolution_status` is `Resolved`.
    pub resolved_path: Option<String>,
    pub resolution_status: ResolutionStatus,
}

/// Text availability of one inventoried file read by the resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolverFileText {
    Included(JsString),
    /// `not-applicable`, `invalid-utf8` or `outside-analysis-scope`.
    Excluded(String),
}

/// The resolver's view of one `JavaScriptArtifactFile`: container identity
/// and text. Other inventory fields do not affect resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverFile {
    pub container_sha256: String,
    pub text: ResolverFileText,
}

/// One inventoried regular file not backed by analyzed bytes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnanalyzedFile {
    pub container_sha256: String,
    pub sha256: Option<String>,
    pub bytes: Option<u64>,
    /// `JavaScriptArtifactFileKind` when the file is a relevant kind.
    pub kind: Option<String>,
    pub hash_status: Option<String>,
    pub limitations: Option<Vec<String>>,
}

/// Borrowed inventory lookup; metadata is materialized only for requested paths.
pub trait UnanalyzedLookup {
    fn get(&self, path: &str) -> Option<UnanalyzedFile>;
    fn has_directory(&self, path: &str, container_sha256: Option<&str>) -> bool;
}

/// Directory prefixes indexed by the container that owns their files.
///
/// The index contains one entry per path segment, so its size is bounded by
/// the total number of segments in the acquired file projection. It avoids
/// rescanning every file for each directory probe while retaining ownership.
pub type ContainerDirectoryIndex = HashMap<String, HashSet<JsString>>;

/// Values needed to resolve a declaration without filesystem access.
#[derive(Clone, Copy)]
pub struct ResolveInput<'a> {
    pub declared_path: &'a str,
    pub source_path: &'a str,
    pub context: ResolutionContext,
    pub files: &'a HashMap<JsString, ResolverFile>,
    /// Directory identities retained by the complete artifact inventory.
    pub directory_paths: Option<&'a HashSet<JsString>>,
    /// Directory prefixes derived from acquired files, keyed by owner.
    pub container_directory_paths: Option<&'a ContainerDirectoryIndex>,
    /// Inventoried files outside the JavaScript projection: present, never read.
    pub unanalyzed_files: Option<&'a dyn UnanalyzedLookup>,
    pub html_base_href: Option<&'a str>,
    /// Import/require semantics; runtime resource paths omit this provenance.
    pub module_kind: Option<ModuleResolutionMode>,
    pub runtime_path_kind: Option<RuntimePathKind>,
    pub(crate) package_metadata_cache: &'a PackageMetadataCache,
}

const PACKAGE_METADATA_CACHE_CAPACITY: usize = 64;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PackageMetadataCacheKey {
    directory: String,
    source_container_sha256: Option<String>,
}

/// Lazy package metadata shared by all resolution branches for one resolver.
///
/// The cache is deliberately bounded because a resolver can inspect an
/// arbitrary number of package directories. The source container identity is
/// part of the key because package visibility is scoped to that container.
#[derive(Debug, Default)]
pub(crate) struct PackageMetadataCache {
    entries: RefCell<HashMap<PackageMetadataCacheKey, PackageMetadata>>,
}

impl PackageMetadataCache {
    fn get(&self, key: &PackageMetadataCacheKey) -> Option<PackageMetadata> {
        self.entries.borrow().get(key).cloned()
    }

    fn insert(&self, key: PackageMetadataCacheKey, metadata: PackageMetadata) {
        let mut entries = self.entries.borrow_mut();
        if entries.len() >= PACKAGE_METADATA_CACHE_CAPACITY && !entries.contains_key(&key) {
            entries.clear();
        }
        entries.insert(key, metadata);
    }
}

/// `moduleResolutionModeProperties`: preserve a retained loader mode.
pub fn module_resolution_mode_properties(
    mode: Option<ModuleResolutionMode>,
) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    if let Some(mode) = mode {
        out.insert(
            "resolution_mode".into(),
            Value::String(mode.as_str().into()),
        );
    }
    out
}

/// `artifactPathResolutionProperties`: retained conditional identities
/// without flattening them into display text.
pub fn artifact_path_resolution_properties(
    resolution: Option<&ArtifactPathResolution>,
) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    let Some(resolution) = resolution else {
        return out;
    };
    if let Some(candidate) = &resolution.candidate_path {
        out.insert("candidate_path".into(), Value::String(candidate.clone()));
    }
    if let Some(branches) = &resolution.conditional_resolutions {
        out.insert(
            "conditional_resolutions".into(),
            serde_json::to_value(branches).unwrap_or(Value::Null),
        );
    }
    out
}

const EXTENSIONS: &[&str] = &[
    ".js", ".cjs", ".mjs", ".ts", ".tsx", ".json", ".html", ".node",
];
const NODE_MODULE_EXTENSIONS: &[&str] = &[".js", ".json", ".node"];
const NODE_PACKAGE_MAIN_SUFFIXES: &[&str] = &[
    "",
    ".js",
    ".json",
    ".node",
    "/index.js",
    "/index.json",
    "/index.node",
];
/// A private URL namespace for logical artifact paths, including root packages.
const PACKAGE_ARTIFACT_ROOT: &str = "file:///rea-artifact/";
const PACKAGE_ARTIFACT_ROOT_PATH: &str = "/rea-artifact/";

/// `require("node:module").builtinModules` on the pinned Node.js line, minus
/// the `node:`-only names (reachable only through a scheme, handled earlier).
const NODE_BUILTINS: &[&str] = &[
    "_http_agent",
    "_http_client",
    "_http_common",
    "_http_incoming",
    "_http_outgoing",
    "_http_server",
    "_tls_common",
    "_tls_wrap",
    "assert",
    "assert/strict",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "dns/promises",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "inspector",
    "inspector/promises",
    "module",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "readline/promises",
    "repl",
    "stream",
    "stream/consumers",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "sys",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "util/types",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

fn is_builtin(value: &str) -> bool {
    NODE_BUILTINS.contains(&value)
}

fn package_root() -> WebUrl {
    web_url::parse(PACKAGE_ARTIFACT_ROOT, None).expect("static package artifact root URL")
}

/// Encode inventory segments so filename punctuation remains literal in the base.
fn package_metadata_url(path: &str) -> Option<WebUrl> {
    let encoded = path
        .split('/')
        .map(encode_uri_component)
        .collect::<Vec<_>>()
        .join("/");
    web_url::parse(&encoded, Some(&package_root()))
}

/// `String#slice(n)` on an ASCII URL pathname.
fn slice_from(value: &str, start: usize) -> &str {
    value.get(start..).unwrap_or_default()
}

/// One selected package target URL retained until loader validation.
#[derive(Clone, Debug)]
struct PackageFileTarget {
    value: String,
    url: WebUrl,
}

/// Internal resolution; `resolved_path` is `Some` exactly when resolved.
#[derive(Clone, Debug)]
struct CandidateResolution {
    limitations: Vec<String>,
    candidate_path: Option<String>,
    conditional_resolutions: Option<Vec<ConditionalModuleResolution>>,
    resolved_path: Option<String>,
    status: ResolutionStatus,
    /// A truthy package main failed, so Node must not try ancestor packages.
    stops_ancestor_lookup: bool,
}

impl CandidateResolution {
    fn unresolved(status: ResolutionStatus, limitations: Vec<String>) -> Self {
        Self {
            limitations,
            candidate_path: None,
            conditional_resolutions: None,
            resolved_path: None,
            status,
            stops_ancestor_lookup: false,
        }
    }

    fn resolved(path: &str) -> Self {
        Self {
            limitations: Vec::new(),
            candidate_path: None,
            conditional_resolutions: None,
            resolved_path: Some(path.to_owned()),
            status: ResolutionStatus::Resolved,
            stops_ancestor_lookup: false,
        }
    }

    fn with_candidate(mut self, path: impl Into<String>) -> Self {
        self.candidate_path = Some(path.into());
        self
    }
}

fn unresolved(status: ResolutionStatus, limitation: impl Into<String>) -> CandidateResolution {
    CandidateResolution::unresolved(status, vec![limitation.into()])
}

type Contextual = Result<String, CandidateResolution>;

/// `resolveArtifactPathByContext`: resolve one declaration while preserving
/// its original input identity.
pub fn resolve_artifact_path(input: &ResolveInput<'_>) -> ArtifactPathResolution {
    let resolution = resolve_path(input);
    ArtifactPathResolution {
        declared_path: input.declared_path.to_owned(),
        resolution_context: input.context,
        limitations: resolution.limitations,
        candidate_path: resolution.candidate_path,
        conditional_resolutions: resolution.conditional_resolutions,
        resolved_path: resolution.resolved_path,
        resolution_status: resolution.status,
    }
}

fn file_for_path<'a>(input: &'a ResolveInput<'_>, path: &str) -> Option<&'a ResolverFile> {
    input.files.get(&JsString::from(path))
}

fn conditional_resolution(
    mode: ConditionalMode,
    result: CandidateResolution,
) -> ConditionalModuleResolution {
    ConditionalModuleResolution {
        mode,
        resolution_status: result.status,
        resolved_path: result.resolved_path,
        limitations: result.limitations,
        candidate_path: result.candidate_path,
    }
}

fn file_url_like(input: &ResolveInput<'_>) -> bool {
    !matches!(file_url_path(input.declared_path), FileUrlPath::NotFileUrl)
}

fn resolve_path(input: &ResolveInput<'_>) -> CandidateResolution {
    if input.runtime_path_kind == Some(RuntimePathKind::NodeEntrypoint) {
        return resolve_node_runtime_entrypoint(input);
    }
    if input.module_kind == Some(ModuleResolutionMode::CompilerDependent) {
        return resolve_compiler_dependent(input);
    }
    if input.runtime_path_kind == Some(RuntimePathKind::UrlResource) {
        return resolve_exact_url_resource(input);
    }
    if input.runtime_path_kind == Some(RuntimePathKind::ExactFile)
        && is_runtime_path_declaration(input)
    {
        return resolve_runtime_entrypoint(input);
    }
    // Package import keys are literal lookup identities, not artifact paths.
    if input.context == ResolutionContext::ModuleSpecifier && input.declared_path.starts_with('#') {
        return resolve_package_import_alias(input, input.declared_path);
    }
    let candidate = match contextual_candidate(input) {
        Ok(candidate) => candidate,
        Err(resolution) => return resolution,
    };
    let confined = match confine_candidate(&candidate) {
        Ok(confined) => confined,
        Err(resolution) => return resolution,
    };
    if matches!(
        input.context,
        ResolutionContext::HtmlReference | ResolutionContext::UrlReference
    ) {
        let kind = if input.context.is_html() {
            "HTML"
        } else {
            "URL"
        };
        return resolve_file_candidates(input, std::slice::from_ref(&confined)).unwrap_or_else(|| {
            unresolved(
                ResolutionStatus::NotFound,
                format!("The exact {kind} resource {confined} was not found among the selected application files."),
            )
        });
    }
    let is_module_url_path = input.context == ResolutionContext::ModuleSpecifier
        && (is_relative_module_specifier(input.declared_path)
            || input.declared_path.starts_with('/')
            || file_url_like(input));
    let emitted = if is_module_url_path && input.module_kind.is_some() {
        emitted_source_candidates::candidates(input.source_path, &confined)
    } else {
        Vec::new()
    };
    if is_module_url_path && input.module_kind == Some(ModuleResolutionMode::Import) {
        return resolve_runtime_source_candidates(input, &confined, &emitted)
            .unwrap_or_else(not_found_candidate);
    }
    resolve_candidate(input, &confined, &HashSet::new(), &emitted)
}

fn resolve_compiler_dependent(input: &ResolveInput<'_>) -> CandidateResolution {
    let imported = resolve_path(&ResolveInput {
        module_kind: Some(ModuleResolutionMode::Import),
        ..*input
    });
    let required = resolve_path(&ResolveInput {
        module_kind: Some(ModuleResolutionMode::Require),
        ..*input
    });
    let same_outcome = imported.status == required.status
        && imported.resolved_path == required.resolved_path
        && imported.candidate_path == required.candidate_path;
    let limitation = format!(
        "Static TypeScript loader mode is compiler-dependent without retained compiler options. {}",
        if same_outcome {
            "Node import and require resolution agree on this outcome."
        } else {
            "Node import and require resolution disagree; neither branch is an established target."
        }
    );
    if same_outcome {
        let mut limitations: Vec<String> = Vec::new();
        for value in imported
            .limitations
            .iter()
            .chain(&required.limitations)
            .cloned()
            .chain(std::iter::once(limitation))
        {
            if !limitations.contains(&value) {
                limitations.push(value);
            }
        }
        return CandidateResolution {
            limitations,
            ..imported
        };
    }
    CandidateResolution {
        conditional_resolutions: Some(vec![
            conditional_resolution(ConditionalMode::Import, imported),
            conditional_resolution(ConditionalMode::Require, required),
        ]),
        ..unresolved(ResolutionStatus::Unavailable, limitation)
    }
}

fn resolve_exact_url_resource(input: &ResolveInput<'_>) -> CandidateResolution {
    // Electron loadURL requires a protocol; filesystem paths belong to loadFile.
    if !has_scheme(input.declared_path) {
        return unresolved(
            ResolutionStatus::Unavailable,
            "Electron loadURL requires a URL protocol; relative filesystem paths belong to loadFile.",
        );
    }
    if !starts_with_file_scheme(input.declared_path) {
        return unresolved(
            ResolutionStatus::External,
            "Only file URLs can be mapped to selected local application artifacts.",
        );
    }
    let candidate = match contextual_candidate(input) {
        Ok(candidate) => candidate,
        Err(resolution) => return resolution,
    };
    let confined = match confine_candidate(&candidate) {
        Ok(confined) => confined,
        Err(resolution) => return resolution,
    };
    resolve_file_candidates(input, std::slice::from_ref(&confined)).unwrap_or_else(|| {
        unresolved(
            ResolutionStatus::NotFound,
            format!("The exact URL resource {confined} was not found among the selected application files."),
        )
        .with_candidate(confined.clone())
    })
}

/// `/^file:/iu`.
fn starts_with_file_scheme(value: &str) -> bool {
    value
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("file:"))
}

fn is_runtime_path_declaration(input: &ResolveInput<'_>) -> bool {
    input.context == ResolutionContext::FilesystemExpression
        || (input.context == ResolutionContext::ModuleSpecifier
            && (is_relative_module_specifier(input.declared_path)
                || input.declared_path.starts_with('/')
                || file_url_like(input)))
}

fn resolve_node_runtime_entrypoint(input: &ResolveInput<'_>) -> CandidateResolution {
    let runtime_input = ResolveInput {
        runtime_path_kind: None,
        module_kind: Some(ModuleResolutionMode::Require),
        ..*input
    };
    if !is_runtime_path_declaration(&runtime_input) {
        return resolve_path(&runtime_input);
    }
    let candidate = match contextual_candidate(&runtime_input) {
        Ok(candidate) => candidate,
        Err(resolution) => return resolution,
    };
    let confined = match confine_candidate(&candidate) {
        Ok(confined) => confined,
        Err(resolution) => return resolution,
    };
    // Node entrypoints use runtime probes and cannot select a source substitute.
    let resolution = resolve_candidate(&runtime_input, &confined, &HashSet::new(), &[]);
    if resolution.status == ResolutionStatus::NotFound && resolution.candidate_path.is_none() {
        return resolution.with_candidate(confined);
    }
    resolution
}

fn resolve_runtime_entrypoint(input: &ResolveInput<'_>) -> CandidateResolution {
    if let Some(rejected) = reject_declaration(input.declared_path, false, false) {
        return rejected;
    }
    if has_scheme(input.declared_path) || looks_external(input.declared_path) {
        return unresolved(
            ResolutionStatus::External,
            "Electron runtime entrypoints must identify local paths, not external URLs.",
        );
    }
    let candidate =
        match confine_candidate(&relative_candidate(input.source_path, input.declared_path)) {
            Ok(candidate) => candidate,
            Err(resolution) => return resolution,
        };
    resolve_file_candidates(input, std::slice::from_ref(&candidate)).unwrap_or_else(|| {
        unresolved(
            ResolutionStatus::NotFound,
            format!(
                "The declared Electron runtime entrypoint {candidate} was not found as an exact file among the selected application files; extension and directory fallback were not attempted."
            ),
        )
        .with_candidate(candidate.clone())
    })
}

fn resolve_runtime_source_candidates(
    input: &ResolveInput<'_>,
    exact_path: &str,
    source_candidates: &[Candidate],
) -> Option<CandidateResolution> {
    let exact = Candidate {
        path: exact_path.to_owned(),
        kind: CandidateKind::Implementation,
    };
    for candidate in std::iter::once(&exact).chain(source_candidates) {
        let Some(selected) = find_file_candidate(input, &candidate.path) else {
            continue;
        };
        return Some(if candidate.kind == CandidateKind::Declaration {
            unresolved(
                ResolutionStatus::Unavailable,
                "Only a TypeScript declaration fallback was found; it does not establish the requested runtime module.",
            )
            .with_candidate(candidate.path.clone())
        } else {
            selected
        });
    }
    None
}

fn reject_declaration(
    declared: &str,
    literal_percent: bool,
    allow_empty_path: bool,
) -> Option<CandidateResolution> {
    if declared.is_empty() && !allow_empty_path {
        return Some(unresolved(
            ResolutionStatus::Rejected,
            "The declared path is empty.",
        ));
    }
    if declared.contains('\0') || declared.contains('\\') {
        return Some(unresolved(
            ResolutionStatus::Rejected,
            "NUL and backslash path syntax are not admitted for canonical artifact paths.",
        ));
    }
    if !literal_percent && !admits_canonical_path_syntax(declared) {
        return Some(unresolved(
            ResolutionStatus::Rejected,
            "Encoded dot or separator bytes are rejected before artifact path resolution.",
        ));
    }
    None
}

/// Node's CommonJS loader never percent-decodes a request or a legacy
/// package main, so `%2e` and `%2f` there are literal filename bytes.
fn declares_literal_percent(input: &ResolveInput<'_>) -> bool {
    input.module_kind == Some(ModuleResolutionMode::Require)
        && matches!(
            input.context,
            ResolutionContext::ModuleSpecifier | ResolutionContext::PackageEntrypoint
        )
}

fn contextual_candidate(input: &ResolveInput<'_>) -> Contextual {
    let context = input.context;
    if context == ResolutionContext::HtmlReference {
        return html_candidate(input);
    }
    // URL suffixes are evidence, not pathname bytes.
    let mut declared: String = if context == ResolutionContext::UrlReference {
        strip_query_and_fragment(input.declared_path).to_owned()
    } else {
        input.declared_path.to_owned()
    };
    if context == ResolutionContext::UrlReference && declared.is_empty() {
        return Err(
            if input.runtime_path_kind == Some(RuntimePathKind::UrlResource) {
                unresolved(
                    ResolutionStatus::Unavailable,
                    "A suffix-only runtime URL requires the window's current document URL; the calling script does not establish that base.",
                )
            } else {
                unresolved(
                    ResolutionStatus::Rejected,
                    "The URL reference contains no pathname, and its base document is not established by this analysis.",
                )
            },
        );
    }
    if context == ResolutionContext::ModuleSpecifier && starts_with_file_scheme(&declared) {
        return match file_url_path(&declared) {
            FileUrlPath::Rejected => Err(unresolved(
                ResolutionStatus::Rejected,
                "The file URL path contains syntax that cannot identify a canonical artifact path.",
            )),
            FileUrlPath::Path(path) => {
                if input.module_kind == Some(ModuleResolutionMode::Require) {
                    Err(unresolved(
                        ResolutionStatus::External,
                        "Node CommonJS require specifiers do not resolve file URLs as local artifacts.",
                    ))
                } else {
                    Ok(path)
                }
            }
            FileUrlPath::NotFileUrl => Err(unresolved(
                ResolutionStatus::External,
                "File URL authorities or invalid file URL forms cannot be mapped to artifact-local paths.",
            )),
        };
    }
    let has_url_path_semantics = context == ResolutionContext::ModuleSpecifier
        && input.module_kind == Some(ModuleResolutionMode::Import);
    if has_url_path_semantics {
        declared = html_url_text(&declared);
    }
    if let Some(rejected) = reject_declaration(
        &declared,
        declares_literal_percent(input) || has_url_path_semantics,
        false,
    ) {
        return Err(rejected);
    }
    if context == ResolutionContext::ModuleSpecifier {
        if has_scheme(&declared) {
            return Err(unresolved(
                ResolutionStatus::External,
                "URL and Node builtin schemes are outside static artifact module resolution.",
            ));
        }
        if !is_relative_module_specifier(&declared) && !declared.starts_with('/') {
            return Err(bare_module_candidate(input));
        }
        if input.module_kind != Some(ModuleResolutionMode::Require) {
            let path = strip_query_and_fragment(&declared);
            if contains_percent_escape(path, &["2f", "5c"]) {
                return Err(unresolved(
                    ResolutionStatus::Rejected,
                    "ES module URL paths cannot contain percent-encoded slash or backslash bytes.",
                ));
            }
            declared = decode_module_url_path(path)?;
        }
    } else if looks_external(&declared) {
        return Err(unresolved(
            ResolutionStatus::External,
            "URL schemes and protocol-relative URLs are outside this local artifact path context.",
        ));
    }
    if context == ResolutionContext::UrlReference {
        // A file base gives raw drive-letter segments special meaning. Parse
        // before percent decoding so an encoded drive-like name stays literal.
        let source_url_path = input
            .source_path
            .split('/')
            .map(encode_uri_component)
            .collect::<Vec<_>>()
            .join("/");
        let file_reference = web_url::parse(&format!("file:///{source_url_path}"), None)
            .and_then(|base| web_url::parse(&declared, Some(&base)));
        let Some(file_reference) = file_reference else {
            return Err(unresolved(
                ResolutionStatus::Rejected,
                "The URL reference cannot be parsed as a URL.",
            ));
        };
        if is_drive_letter_url_path(file_reference.pathname()) {
            return Err(unresolved(
                ResolutionStatus::Unavailable,
                "Drive-letter URL paths cannot be mapped without the source URL scheme and filesystem root.",
            ));
        }
        let Some(decoded) = percent_decode_url_path(&declared) else {
            return Err(unresolved(
                ResolutionStatus::Rejected,
                "The URL reference path percent-decodes to NUL or to bytes that are not UTF-8.",
            ));
        };
        let candidate = url_relative_candidate(posix_dirname(input.source_path), &decoded)?;
        return exact_url_path_candidate(&decoded, candidate, "URL");
    }
    if has_url_path_semantics {
        let candidate = url_relative_candidate(posix_dirname(input.source_path), &declared)?;
        return exact_url_path_candidate(&declared, candidate, "module URL");
    }
    Ok(relative_candidate(input.source_path, &declared))
}

/// `/^\/[A-Za-z]:(?:\/|$)/u`.
fn is_drive_letter_url_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0] == b'/'
        && bytes[1].is_ascii_alphabetic()
        && bytes[2] == b':'
        && (bytes.len() == 3 || bytes[3] == b'/')
}

fn decode_module_url_path(declared: &str) -> Contextual {
    let Some(decoded) = decode_uri_component(declared) else {
        return Err(unresolved(
            ResolutionStatus::Rejected,
            "The module URL path contains malformed percent encoding.",
        ));
    };
    if decoded.contains('\0') {
        return Err(unresolved(
            ResolutionStatus::Rejected,
            "The decoded module URL path contains NUL.",
        ));
    }
    Ok(decoded)
}

fn relative_candidate(source_path: &str, declared: &str) -> String {
    match declared.strip_prefix('/') {
        Some(rest) => rest.to_owned(),
        None => posix_join(&[posix_dirname(source_path), declared]),
    }
}

/// A URL path during reference resolution. Above-root `..` markers are kept
/// apart from segments so a later `..` cannot cancel an escape.
#[derive(Clone, Debug)]
struct UrlPathState {
    escapes: usize,
    segments: Vec<String>,
}

fn url_directory_state(directory: &str) -> UrlPathState {
    UrlPathState {
        escapes: 0,
        segments: if directory.is_empty() || directory == "." {
            Vec::new()
        } else {
            directory.split('/').map(str::to_owned).collect()
        },
    }
}

/// Apply URL dot segments: `..` removes the previous segment even when it is
/// empty. A final `.` or `..` leaves directory form.
fn apply_url_reference(base: &UrlPathState, reference: &str) -> UrlPathState {
    let absolute = reference.starts_with('/');
    let mut segments = if absolute {
        Vec::new()
    } else {
        base.segments.clone()
    };
    let mut escapes = if absolute { 0 } else { base.escapes };
    let body = if absolute { &reference[1..] } else { reference };
    let parts: Vec<&str> = body.split('/').collect();
    let last = parts.len() - 1;
    for (index, part) in parts.into_iter().enumerate() {
        if part != "." && part != ".." {
            segments.push(part.to_owned());
            continue;
        }
        if part == ".." && segments.pop().is_none() {
            escapes += 1;
        }
        if index == last {
            segments.push(String::new());
        }
    }
    UrlPathState { escapes, segments }
}

/// A relative reference replaces the base URL's final path segment.
fn url_base_directory(base: &UrlPathState) -> UrlPathState {
    let mut segments = base.segments.clone();
    segments.pop();
    UrlPathState {
        escapes: base.escapes,
        segments,
    }
}

fn url_path_candidate(path: &UrlPathState) -> Contextual {
    let segments = if path.segments.last().is_some_and(String::is_empty) {
        &path.segments[..path.segments.len() - 1]
    } else {
        &path.segments[..]
    };
    if segments.iter().any(String::is_empty) {
        return Err(unresolved(
            ResolutionStatus::Unavailable,
            "Repeated URL path separators cannot be mapped to an exact canonical artifact file.",
        ));
    }
    let mut parts: Vec<&str> = std::iter::repeat_n("..", path.escapes).collect();
    parts.extend(segments.iter().map(String::as_str));
    Ok(parts.join("/"))
}

fn url_relative_candidate(directory: &str, reference: &str) -> Contextual {
    url_path_candidate(&apply_url_reference(
        &url_directory_state(directory),
        reference,
    ))
}

/// Derived package identity and dependency policy.
#[derive(Clone, Debug)]
struct BarePackageRequest {
    package_name: String,
    package_subpath: String,
    dependency_exports_eligible: bool,
}

fn bare_module_candidate(input: &ResolveInput<'_>) -> CandidateResolution {
    let request = parse_bare_package_request(input.declared_path, input.module_kind);
    let Some(request) = request.filter(|_| !is_builtin(input.declared_path)) else {
        return unresolved(
            ResolutionStatus::External,
            "The bare specifier is a Node builtin or invalid package name.",
        );
    };
    if input.module_kind == Some(ModuleResolutionMode::Import)
        && (request.package_name.starts_with('.') || request.package_name.contains('%'))
    {
        return unresolved(
            ResolutionStatus::Rejected,
            "ES module package names cannot start with a dot or contain percent signs.",
        );
    }
    if let Some(self_resolution) = package_self_candidate(input, &request) {
        return self_resolution;
    }
    // ESM constructs a package.json URL; its parsed identity is not a literal
    // dependency directory.
    let mut dependency_directory = posix_join(&["node_modules", &request.package_name]);
    if input.module_kind == Some(ModuleResolutionMode::Import) {
        let metadata_url = web_url::parse(
            &format!("./node_modules/{}/package.json", request.package_name),
            Some(&package_root()),
        )
        .filter(|url| url.pathname().ends_with("/package.json"));
        let Some(metadata_url) = metadata_url else {
            return unresolved(
                ResolutionStatus::External,
                format!(
                    "ESM package name {} produces a dependency URL whose pathname does not name package.json; no literal or suffix-stripped package directory was searched.",
                    json_string(&request.package_name)
                ),
            );
        };
        let decoded = match decode_module_url_path(slice_from(
            metadata_url.pathname(),
            PACKAGE_ARTIFACT_ROOT_PATH.len(),
        )) {
            Ok(decoded) => decoded,
            Err(resolution) => return resolution,
        };
        let confined = match confine_candidate(&decoded) {
            Ok(confined) => confined,
            Err(resolution) => return resolution,
        };
        dependency_directory = posix_dirname(&confined).to_owned();
    }
    let source = file_for_path(input, input.source_path);
    let mut nearest_not_found: Option<CandidateResolution> = None;
    for directory in package_lookup_directories(input) {
        let candidate = posix_join(&[&directory, &dependency_directory]);
        let metadata = read_package_metadata(input, &candidate);
        let continue_common_js_lookup = input.module_kind == Some(ModuleResolutionMode::Require)
            && match &metadata {
                PackageMetadata::Absent => true,
                PackageMetadata::Available(available) => {
                    !request.dependency_exports_eligible || available.exports.is_none()
                }
                PackageMetadata::Unavailable(_) => false,
            };
        let package_resolution = if !matches!(metadata, PackageMetadata::Absent)
            || has_container_directory(
                input,
                &candidate,
                source.map(|file| file.container_sha256.as_str()),
            ) {
            Some(resolve_package_dependency(
                input, &candidate, &request, &metadata,
            ))
        } else if request.package_subpath == "."
            && input.module_kind != Some(ModuleResolutionMode::Import)
        {
            resolve_file_candidates(input, &file_candidates(&candidate, input.module_kind))
        } else {
            None
        };
        if let Some(resolution) = package_resolution {
            if continue_common_js_lookup
                && resolution.status == ResolutionStatus::NotFound
                && !resolution.stops_ancestor_lookup
            {
                nearest_not_found.get_or_insert(resolution);
            } else {
                return resolution;
            }
        }
    }
    nearest_not_found.unwrap_or_else(|| {
        unresolved(
            ResolutionStatus::External,
            "No matching bare package was inventoried in an enclosing node_modules directory.",
        )
    })
}

fn package_lookup_directories(input: &ResolveInput<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut directory = posix_dirname(input.source_path).to_owned();
    loop {
        if input.module_kind != Some(ModuleResolutionMode::Require)
            || posix_basename(&directory) != "node_modules"
        {
            out.push(directory.clone());
        }
        // TypeScript loops forever on an absolute source path; stop at its root.
        if directory == "." || directory.is_empty() || directory == "/" || directory == "//" {
            return out;
        }
        directory = posix_dirname(&directory).to_owned();
    }
}

/// Nearest same-container package.json, stopping at a `node_modules`
/// directory so a nested package cannot inherit an ancestor's map.
fn enclosing_package_metadata(input: &ResolveInput<'_>) -> PackageMetadata {
    let mut directory = posix_dirname(input.source_path).to_owned();
    while posix_basename(&directory) != "node_modules" {
        let metadata = read_package_metadata(input, &directory);
        if !matches!(metadata, PackageMetadata::Absent) {
            return metadata;
        }
        if directory == "." || directory.is_empty() || directory == "/" || directory == "//" {
            break;
        }
        directory = posix_dirname(&directory).to_owned();
    }
    PackageMetadata::Absent
}

/// Resolve an exact `#alias` against the importer's enclosing `imports` map.
fn resolve_package_import_alias(input: &ResolveInput<'_>, specifier: &str) -> CandidateResolution {
    match classify_package_import_specifier(specifier) {
        PackageImportSpecifier::Invalid => {
            return unresolved(
                ResolutionStatus::Rejected,
                format!(
                    "The package import specifier {} is invalid; \"#\" and specifiers that end with \"/\" are not valid import aliases.",
                    json_string(specifier)
                ),
            );
        }
        PackageImportSpecifier::Pattern => {
            return unresolved(
                ResolutionStatus::External,
                format!(
                    "Wildcard and directory package import aliases remain unresolved; {} is not an exact imports key.",
                    json_string(specifier)
                ),
            );
        }
        PackageImportSpecifier::Exact { .. } => {}
    }
    let metadata = match enclosing_package_metadata(input) {
        PackageMetadata::Absent => {
            return unresolved(
                ResolutionStatus::External,
                format!(
                    "No enclosing package.json defines package import alias {specifier}; package import maps do not cross package scopes."
                ),
            );
        }
        PackageMetadata::Unavailable(limitation) => {
            return unresolved(ResolutionStatus::Unavailable, limitation);
        }
        PackageMetadata::Available(metadata) => metadata,
    };
    let path = &metadata.path;
    let target = match lookup_exact_package_import(metadata.imports.as_ref(), specifier) {
        PackageImportLookup::UndefinedMap => {
            return unresolved(
                ResolutionStatus::External,
                format!(
                    "Package metadata {path} does not define package import alias {specifier}."
                ),
            );
        }
        PackageImportLookup::MissingKey { declared } => {
            let declared = if declared.is_empty() {
                "no imports keys".to_owned()
            } else {
                declared.join(", ")
            };
            return unresolved(
                ResolutionStatus::External,
                format!(
                    "Package metadata {path} does not define package import alias {specifier}; it declares {declared}."
                ),
            );
        }
        PackageImportLookup::PatternUnresolved { .. } => {
            return unresolved(
                ResolutionStatus::External,
                format!(
                    "Wildcard package import aliases remain unresolved; package metadata {path} has no exact imports key {specifier}."
                ),
            );
        }
        PackageImportLookup::Found { target, .. } => target,
    };
    let selected = select_export_target(
        target,
        &package_export_conditions(input.module_kind),
        path,
        MapKind::Imports,
    );
    match selected {
        ExportTargetOutcome::Invalid(limitation)
        | ExportTargetOutcome::InvalidConfig(limitation) => unresolved(
            ResolutionStatus::Rejected,
            format!("Package metadata {path}: {limitation}"),
        ),
        ExportTargetOutcome::Unmatched(declared) => {
            let declared = if declared.is_empty() {
                "no conditions".to_owned()
            } else {
                declared.join(", ")
            };
            unresolved(
                ResolutionStatus::External,
                format!(
                    "Package metadata {path} declares no imports target for alias {specifier} under the active conditions; it declares {declared}."
                ),
            )
        }
        ExportTargetOutcome::Blocked(cause) => unresolved(
            ResolutionStatus::External,
            format!(
                "Package metadata {path} blocks import alias {specifier} with {}.",
                match cause {
                    BlockCause::Null => "an explicit null imports target",
                    BlockCause::EmptyArray => "an empty imports target array",
                }
            ),
        ),
        ExportTargetOutcome::NonRelative(value) => {
            let recursive =
                classify_package_import_target(&value) == PackageImportTargetKind::Recursive;
            unresolved(
                ResolutionStatus::External,
                if recursive {
                    format!(
                        "Recursive package import aliases remain unresolved; package metadata {path} maps {specifier} to {}.",
                        json_string(&value)
                    )
                } else {
                    format!(
                        "External-package import targets remain unresolved; package metadata {path} maps {specifier} to {}.",
                        json_string(&value)
                    )
                },
            )
        }
        ExportTargetOutcome::Value(target) => {
            resolve_export_target(input, path, &target, MapKind::Imports)
        }
    }
}

/// Self references use the nearest package scope before dependency lookup.
fn package_self_candidate(
    input: &ResolveInput<'_>,
    request: &BarePackageRequest,
) -> Option<CandidateResolution> {
    if input.module_kind.is_none() || file_for_path(input, input.source_path).is_none() {
        return None;
    }
    let metadata = match enclosing_package_metadata(input) {
        PackageMetadata::Absent => return None,
        PackageMetadata::Unavailable(limitation) => {
            return Some(unresolved(ResolutionStatus::Unavailable, limitation));
        }
        PackageMetadata::Available(metadata) => metadata,
    };
    let (Some(name), Some(exports)) = (&metadata.name, &metadata.exports) else {
        return None;
    };
    let subpath = if input.module_kind == Some(ModuleResolutionMode::Import) {
        if *name != request.package_name {
            return None;
        }
        request.package_subpath.clone()
    } else if input.declared_path == name {
        ".".to_owned()
    } else if let Some(rest) = input
        .declared_path
        .strip_prefix(name.as_str())
        .filter(|rest| rest.starts_with('/'))
    {
        format!(".{rest}")
    } else {
        return None;
    };
    // Self resolution does not apply the CommonJS dependency-name matcher.
    Some(resolve_package_exports(
        input,
        &metadata.path,
        &subpath,
        exports,
    ))
}

/// Resolve an installed dependency using one parsed request and its metadata.
fn resolve_package_dependency(
    input: &ResolveInput<'_>,
    directory: &str,
    request: &BarePackageRequest,
    metadata: &PackageMetadata,
) -> CandidateResolution {
    let subpath = &request.package_subpath;
    if request.dependency_exports_eligible
        && let PackageMetadata::Unavailable(limitation) = metadata
    {
        return unresolved(ResolutionStatus::Unavailable, limitation.clone());
    }
    let raw_exports = match metadata {
        PackageMetadata::Available(available) if request.dependency_exports_eligible => {
            available.exports.as_ref()
        }
        _ => None,
    };
    let Some(raw_exports) = raw_exports else {
        if subpath == "." {
            let file = if input.module_kind == Some(ModuleResolutionMode::Import) {
                None
            } else {
                resolve_file_candidates(input, &file_candidates(directory, input.module_kind))
            };
            return file
                .unwrap_or_else(|| resolve_directory(input, directory, metadata, &HashSet::new()));
        }
        if input.module_kind == Some(ModuleResolutionMode::Import) {
            return resolve_legacy_esm_subpath(input, directory, subpath);
        }
        return match confine_candidate(&format!("{directory}/{}", slice_from(subpath, 2))) {
            Ok(candidate) => resolve_candidate(input, &candidate, &HashSet::new(), &[]),
            Err(resolution) => resolution,
        };
    };
    resolve_package_exports(
        input,
        &posix_join(&[directory, "package.json"]),
        subpath,
        raw_exports,
    )
}

/// Legacy ESM package subpaths are exact URLs, never extension or directory lookups.
fn resolve_legacy_esm_subpath(
    input: &ResolveInput<'_>,
    directory: &str,
    subpath: &str,
) -> CandidateResolution {
    if let Some(rejected) = reject_declaration(
        strip_query_and_fragment(&html_url_text(subpath)),
        false,
        false,
    ) {
        return rejected;
    }
    let url = package_metadata_url(&posix_join(&[directory, "package.json"]))
        .and_then(|base| web_url::parse(subpath, Some(&base)));
    let Some(url) = url.filter(|url| url.pathname().starts_with(PACKAGE_ARTIFACT_ROOT_PATH)) else {
        return unresolved(
            ResolutionStatus::Rejected,
            "The resolved candidate escapes the canonical artifact root.",
        );
    };
    let encoded_path = slice_from(url.pathname(), PACKAGE_ARTIFACT_ROOT_PATH.len());
    if let Some(rejected) = reject_declaration(encoded_path, false, false) {
        return rejected;
    }
    let decoded = match decode_module_url_path(encoded_path) {
        Ok(decoded) => decoded,
        Err(resolution) => return resolution,
    };
    let candidate = match confine_candidate(&decoded) {
        Ok(candidate) => candidate,
        Err(resolution) => return resolution,
    };
    if url_path_is_directory(url.pathname()) {
        return unresolved(
            ResolutionStatus::Rejected,
            format!(
                "ESM package subpath {} has URL directory form; directory imports are unsupported and no exact-file, package main or index lookup was attempted.",
                json_string(input.declared_path)
            ),
        );
    }
    if let Some(file) = resolve_file_candidates(input, std::slice::from_ref(&candidate)) {
        return file;
    }
    let source = file_for_path(input, input.source_path);
    if has_container_directory(
        input,
        &candidate,
        source.map(|file| file.container_sha256.as_str()),
    ) {
        return unresolved(
            ResolutionStatus::Rejected,
            format!(
                "ESM package subpath {candidate} names a directory; directory imports are unsupported and package main or index lookup was not attempted."
            ),
        );
    }
    exact_package_target_not_found(&candidate, TargetKind::EsmSubpath)
}

fn resolve_package_exports(
    input: &ResolveInput<'_>,
    package_path: &str,
    subpath: &str,
    raw_exports: &Value,
) -> CandidateResolution {
    match select_package_export(raw_exports, subpath, input.module_kind, package_path) {
        PackageExportOutcome::Rejected(limitation) => unresolved(
            ResolutionStatus::Rejected,
            format!("Package metadata {package_path}: {limitation}"),
        ),
        PackageExportOutcome::Unmatched(declared) => {
            let target = if subpath == "." {
                "for the active conditions".to_owned()
            } else {
                format!("for subpath {subpath}")
            };
            let declared = if declared.is_empty() {
                "a root target only".to_owned()
            } else {
                declared.join(", ")
            };
            unresolved(
                ResolutionStatus::External,
                format!(
                    "Directory package metadata {package_path} declares no exports target {target}; exports encapsulation permits no file or index lookup. It declares {declared}."
                ),
            )
        }
        PackageExportOutcome::Blocked(cause) => unresolved(
            ResolutionStatus::External,
            format!(
                "Directory package metadata {package_path} blocks subpath {subpath} with {}.",
                match cause {
                    BlockCause::Null => "an explicit null exports target",
                    BlockCause::EmptyArray => "an empty exports target array",
                }
            ),
        ),
        PackageExportOutcome::Value(target) => {
            resolve_export_target(input, package_path, &target, MapKind::Exports)
        }
    }
}

/// An exports or imports target is a URL naming one exact file for both loaders.
fn resolve_export_target(
    input: &ResolveInput<'_>,
    package_path: &str,
    target: &PackageFileTarget,
    map_kind: MapKind,
) -> CandidateResolution {
    let with_target_source = |mut outcome: CandidateResolution| {
        outcome.limitations = outcome
            .limitations
            .iter()
            .map(|reason| {
                format!(
                    "Package metadata {package_path}, {} target {}: {reason}",
                    map_kind.as_str(),
                    json_string(&target.value)
                )
            })
            .collect();
        outcome
    };
    // CommonJS checks the serialized URL including suffixes; ESM only the pathname.
    if input.module_kind == Some(ModuleResolutionMode::Require)
        && contains_percent_escape(target.url.href(), &["2f", "5c"])
    {
        return with_target_source(unresolved(
            ResolutionStatus::Rejected,
            "The selected package URL contains encoded separator bytes.",
        ));
    }
    let encoded_path = slice_from(target.url.pathname(), PACKAGE_ARTIFACT_ROOT_PATH.len());
    if let Some(rejected) = reject_declaration(encoded_path, false, false) {
        return with_target_source(rejected);
    }
    let decoded = match decode_module_url_path(encoded_path) {
        Ok(decoded) => decoded,
        Err(resolution) => return with_target_source(resolution),
    };
    let candidate = match confine_candidate(&decoded) {
        Ok(candidate) => candidate,
        Err(resolution) => return with_target_source(resolution),
    };
    resolve_file_candidates(input, std::slice::from_ref(&candidate)).unwrap_or_else(|| {
        with_target_source(exact_package_target_not_found(
            &candidate,
            match map_kind {
                MapKind::Exports => TargetKind::Exports,
                MapKind::Imports => TargetKind::Imports,
            },
        ))
    })
}

/// The CommonJS exports matcher `/^((?:@[^/\\%]+\/)?[^./\\%][^/\\%]*)(\/.*)?$/`
/// capture 1, with ECMAScript backtracking over the optional scope.
fn common_js_exports_name(specifier: &str) -> Option<&str> {
    let excluded = |character: char| matches!(character, '/' | '\\' | '%');
    let rest_matches = |rest: &str| {
        rest.is_empty()
            || (rest.starts_with('/') && !rest.contains(['\n', '\r', '\u{2028}', '\u{2029}']))
    };
    let name_end = |from: usize| -> Option<usize> {
        let tail = &specifier[from..];
        let first = tail.chars().next()?;
        if first == '.' || excluded(first) {
            return None;
        }
        let length = tail.find(excluded).unwrap_or(tail.len());
        rest_matches(&tail[length..]).then_some(from + length)
    };
    if let Some(scope) = specifier.strip_prefix('@') {
        let length = scope.find(excluded).unwrap_or(scope.len());
        if length > 0
            && scope[length..].starts_with('/')
            && let Some(end) = name_end(length + 2)
        {
            return Some(&specifier[..end]);
        }
    }
    name_end(0).map(|end| &specifier[..end])
}

fn parse_bare_package_request(
    specifier: &str,
    module_kind: Option<ModuleResolutionMode>,
) -> Option<BarePackageRequest> {
    let segments: Vec<&str> = specifier.split('/').collect();
    let mut package_name = segments[0].to_owned();
    if package_name.is_empty() || package_name == "@" {
        return None;
    }
    if specifier.starts_with('@') {
        match segments.get(1) {
            Some(segment) if !segment.is_empty() => {
                package_name = format!("{package_name}/{segment}")
            }
            segment if module_kind != Some(ModuleResolutionMode::Require) => {
                segment?;
                package_name = format!("{package_name}/");
            }
            _ => {}
        }
    }
    // The CommonJS exports matcher excludes percent-containing package names.
    let dependency_exports_eligible = module_kind != Some(ModuleResolutionMode::Require)
        || common_js_exports_name(specifier) == Some(package_name.as_str());
    let package_subpath = format!(".{}", &specifier[package_name.len().min(specifier.len())..]);
    Some(BarePackageRequest {
        package_name,
        package_subpath,
        dependency_exports_eligible,
    })
}

fn has_container_directory(
    input: &ResolveInput<'_>,
    candidate: &str,
    container_sha256: Option<&str>,
) -> bool {
    if input
        .directory_paths
        .is_some_and(|paths| paths.contains(&JsString::from(candidate)))
    {
        return true;
    }
    let same_container = |file: &ResolverFile| {
        container_sha256.is_none_or(|container| file.container_sha256 == container)
    };
    let mut probes = index_candidates(candidate, None);
    probes.push(posix_join(&[candidate, "package.json"]));
    if probes
        .iter()
        .any(|path| file_for_path(input, path).is_some_and(same_container))
    {
        return true;
    }

    if let Some(index) = input.container_directory_paths {
        let indexed_match = match container_sha256 {
            Some(container) => index
                .get(container)
                .is_some_and(|paths| paths.contains(&JsString::from(candidate))),
            None => index
                .values()
                .any(|paths| paths.contains(&JsString::from(candidate))),
        };
        if indexed_match {
            return true;
        }

        return input
            .unanalyzed_files
            .is_some_and(|lookup| lookup.has_directory(candidate, container_sha256));
    }

    // Any same-container descendant establishes a package directory.
    let prefix = format!("{candidate}/");
    if input.files.iter().any(|(path, file)| {
        path.units().starts_with(JsString::from(&prefix).units()) && same_container(file)
    }) {
        return true;
    }
    input
        .unanalyzed_files
        .is_some_and(|lookup| lookup.has_directory(candidate, container_sha256))
}

fn html_candidate(input: &ResolveInput<'_>) -> Contextual {
    let html_text = html_url_text(input.declared_path);
    let declared = strip_query_and_fragment(&html_text);
    // HTML references are URL text, so percent bytes still encode.
    if let Some(rejected) = reject_declaration(declared, false, !input.declared_path.is_empty()) {
        return Err(rejected);
    }
    if looks_external(declared) {
        return Err(unresolved(
            ResolutionStatus::External,
            "External HTML references are not mapped to local artifact assets.",
        ));
    }
    let base_text = input.html_base_href.map(html_url_text);
    let base = base_text.as_deref().map(strip_query_and_fragment);
    if base.is_some_and(looks_external) {
        return Err(unresolved(
            ResolutionStatus::External,
            "The document base href is external, so its script reference is not a local artifact path.",
        ));
    }
    let Some(declared_path) = percent_decode_url_path(declared) else {
        return Err(unresolved(
            ResolutionStatus::Rejected,
            "The HTML reference path percent-decodes to NUL or to bytes that are not UTF-8.",
        ));
    };
    if declared_path.starts_with('/') {
        return url_relative_candidate("", &declared_path);
    }
    let base = match base {
        None | Some("") => {
            return if declared_path.is_empty() {
                Ok(input.source_path.to_owned())
            } else {
                url_relative_candidate(posix_dirname(input.source_path), &declared_path)
            };
        }
        Some(base) => base,
    };
    // A local base href is a second untrusted path input.
    if !admits_canonical_path_syntax(base) {
        return Err(unresolved(
            ResolutionStatus::Rejected,
            "The document base href uses NUL, backslash, or encoded dot and separator bytes that are not admitted for canonical artifact paths.",
        ));
    }
    let Some(decoded_base) = percent_decode_url_path(base) else {
        return Err(unresolved(
            ResolutionStatus::Rejected,
            "The document base href path percent-decodes to NUL or to bytes that are not UTF-8.",
        ));
    };
    let base_state = apply_url_reference(
        &url_directory_state(posix_dirname(input.source_path)),
        &decoded_base,
    );
    if declared_path.is_empty() {
        let base_path = url_path_candidate(&base_state)?;
        return exact_url_path_candidate(&decoded_base, base_path, "HTML");
    }
    url_path_candidate(&apply_url_reference(
        &url_base_directory(&base_state),
        &declared_path,
    ))
}

fn exact_url_path_candidate(declared: &str, candidate: String, kind: &str) -> Contextual {
    if !url_path_is_directory(declared) {
        return Ok(candidate);
    }
    let confined = confine_candidate(&candidate)?;
    Err(unresolved(
        ResolutionStatus::NotFound,
        format!(
            "The {kind} reference resolves to directory {}, not an exact selected application file.",
            if confined.is_empty() { "." } else { &confined }
        ),
    ))
}

/// Whether a URL path retains directory form after dot-segment normalization.
fn url_path_is_directory(path: &str) -> bool {
    path.ends_with('/')
        || path.ends_with("/.")
        || path.ends_with("/..")
        || path == "."
        || path == ".."
}

fn confine_candidate(candidate: &str) -> Contextual {
    let normalized = normalize_joined_logical_path(candidate);
    if logical_path_escapes_root(&normalized) {
        return Err(unresolved(
            ResolutionStatus::Rejected,
            "The resolved candidate escapes the canonical artifact root.",
        ));
    }
    Ok(if normalized == "." {
        String::new()
    } else {
        normalized
    })
}

#[derive(Clone, Debug)]
struct AvailableMetadata {
    path: String,
    name: Option<String>,
    exports: Option<Value>,
    imports: Option<Value>,
    main: Option<Value>,
    module: Option<Value>,
}

#[derive(Clone, Debug)]
enum PackageMetadata {
    Available(Box<AvailableMetadata>),
    Absent,
    Unavailable(String),
}

fn read_package_metadata(input: &ResolveInput<'_>, directory: &str) -> PackageMetadata {
    let source_container_sha256 =
        file_for_path(input, input.source_path).map(|file| file.container_sha256.clone());
    let key = PackageMetadataCacheKey {
        directory: directory.to_owned(),
        source_container_sha256,
    };
    if let Some(metadata) = input.package_metadata_cache.get(&key) {
        return metadata;
    }

    let metadata = read_package_metadata_uncached(input, directory);
    input.package_metadata_cache.insert(key, metadata.clone());
    metadata
}

fn read_package_metadata_uncached(input: &ResolveInput<'_>, directory: &str) -> PackageMetadata {
    let path = posix_join(&[directory, "package.json"]);
    let source = file_for_path(input, input.source_path);
    let Some(file) = file_for_path(input, &path) else {
        let unavailable = input.unanalyzed_files.and_then(|lookup| lookup.get(&path));
        if let (Some(source), Some(unavailable)) = (source, unavailable)
            && unavailable.container_sha256 == source.container_sha256
        {
            return PackageMetadata::Unavailable(
                unavailable
                    .limitations
                    .and_then(|limitations| limitations.into_iter().next())
                    .unwrap_or_else(|| {
                        format!("Directory package metadata {path} was inventoried but its bytes are unavailable.")
                    }),
            );
        }
        return PackageMetadata::Absent;
    };
    if source.is_some_and(|source| file.container_sha256 != source.container_sha256) {
        return PackageMetadata::Absent;
    }
    let text = match &file.text {
        ResolverFileText::Included(text) => {
            let encoded = encode_json_text_units(text);
            let prepared = prepare_package_json_text(&encoded);
            prepared
        }
        ResolverFileText::Excluded(reason) => {
            return PackageMetadata::Unavailable(format!(
                "Directory package metadata {path} was inventoried but its text is unavailable: {reason}."
            ));
        }
    };
    let invalid = || {
        PackageMetadata::Unavailable(format!(
            "Directory package metadata {path} is not valid package JSON."
        ))
    };
    // `JSON.parse` admits surrounding JSON whitespace only.
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return invalid();
    };
    let object = match &value {
        Value::Object(object) => Some(object),
        Value::Array(_) => None,
        _ => return invalid(),
    };
    let get = |key: &str| object.and_then(|object| object.get(key)).cloned();
    let name = get("name").and_then(|name| name.as_str().map(str::to_owned));
    // Node's package reader ignores scalar root exports other than strings.
    let exports = get("exports").filter(|exports| {
        matches!(
            exports,
            Value::String(_) | Value::Object(_) | Value::Array(_)
        )
    });
    // Import maps must be non-array objects.
    let imports = get("imports").filter(Value::is_object);
    let main = get("main").filter(|main| input.module_kind.is_none() || main.is_string());
    PackageMetadata::Available(Box::new(AvailableMetadata {
        path,
        name,
        exports,
        imports,
        main,
        module: get("module"),
    }))
}

/// File and directory lookup never interprets a nested directory's exports.
fn resolve_candidate(
    input: &ResolveInput<'_>,
    candidate: &str,
    package_chain: &HashSet<String>,
    emitted: &[Candidate],
) -> CandidateResolution {
    if !common_js_directory_request(input) {
        let file = resolve_file_candidates(input, &file_candidates(candidate, input.module_kind))
            .or_else(|| resolve_runtime_source_candidates(input, candidate, emitted));
        if let Some(file) = file {
            return file;
        }
    }
    resolve_directory(
        input,
        candidate,
        &read_package_metadata(input, candidate),
        package_chain,
    )
}

fn common_js_directory_request(input: &ResolveInput<'_>) -> bool {
    let declared = input.declared_path;
    input.context == ResolutionContext::ModuleSpecifier
        && input.module_kind == Some(ModuleResolutionMode::Require)
        && (declared.ends_with('/')
            || declared == "."
            || declared == ".."
            || declared.ends_with("/.")
            || declared.ends_with("/.."))
}

fn resolve_directory(
    input: &ResolveInput<'_>,
    directory: &str,
    metadata: &PackageMetadata,
    package_chain: &HashSet<String>,
) -> CandidateResolution {
    let metadata = match metadata {
        PackageMetadata::Absent => {
            return resolve_file_candidates(input, &index_candidates(directory, input.module_kind))
                .unwrap_or_else(not_found_candidate);
        }
        PackageMetadata::Unavailable(limitation) => {
            return unresolved(ResolutionStatus::Unavailable, limitation.clone());
        }
        PackageMetadata::Available(metadata) => metadata,
    };
    if package_chain.contains(&metadata.path) {
        return unresolved(
            ResolutionStatus::Unavailable,
            format!(
                "Directory package entrypoint cycle includes {}.",
                metadata.path
            ),
        );
    }
    let entry = match &metadata.main {
        Some(Value::String(main)) if main.is_empty() => None,
        Some(main) => Some(main),
        None if input.module_kind.is_none() => metadata.module.as_ref(),
        None => None,
    };
    let Some(entry) = entry else {
        return resolve_file_candidates(input, &index_candidates(directory, input.module_kind))
            .unwrap_or_else(not_found_candidate);
    };
    let Some(entry) = entry.as_str().filter(|entry| !entry.is_empty()) else {
        return unresolved(
            ResolutionStatus::Unavailable,
            format!(
                "Directory package metadata {} is not valid package JSON.",
                metadata.path
            ),
        );
    };
    let entry_input = ResolveInput {
        declared_path: entry,
        source_path: &metadata.path,
        context: ResolutionContext::PackageEntrypoint,
        files: input.files,
        directory_paths: input.directory_paths,
        container_directory_paths: input.container_directory_paths,
        unanalyzed_files: input.unanalyzed_files,
        html_base_href: None,
        module_kind: input.module_kind,
        runtime_path_kind: None,
        package_metadata_cache: input.package_metadata_cache,
    };
    let candidate = match contextual_candidate(&entry_input) {
        Ok(candidate) => candidate,
        Err(resolution) => return resolution,
    };
    let confined = match confine_candidate(&candidate) {
        Ok(confined) => confined,
        Err(resolution) => return resolution,
    };
    if input.module_kind.is_some() {
        return resolve_node_package_main(&entry_input, directory, &confined);
    }
    let mut probes = file_candidates(&confined, entry_input.module_kind);
    probes.extend(index_candidates(&confined, entry_input.module_kind));
    if let Some(selected) = resolve_file_candidates(&entry_input, &probes)
        .or_else(|| resolve_file_candidates(input, &index_candidates(directory, input.module_kind)))
    {
        return selected;
    }
    let mut chain = package_chain.clone();
    chain.insert(metadata.path.clone());
    resolve_candidate(&entry_input, &confined, &chain, &[])
}

fn resolve_node_package_main(
    input: &ResolveInput<'_>,
    directory: &str,
    main_path: &str,
) -> CandidateResolution {
    let normalized_main = main_path.strip_suffix('/').unwrap_or(main_path);
    for suffix in NODE_PACKAGE_MAIN_SUFFIXES {
        let is_directory_index = suffix.starts_with('/');
        if normalized_main.is_empty() && !is_directory_index {
            continue;
        }
        let probe = if is_directory_index {
            posix_join(&[normalized_main, &suffix[1..]])
        } else {
            posix_normalize(&format!("{normalized_main}{suffix}"))
        };
        let Some(selected) = resolve_file_candidates(input, std::slice::from_ref(&probe)) else {
            continue;
        };
        if input.module_kind == Some(ModuleResolutionMode::Require) {
            return selected;
        }
        // ESM appends the selected suffix to the original declaration.
        let finalized = match confine_candidate(&relative_candidate(
            input.source_path,
            &format!("{}{suffix}", input.declared_path),
        )) {
            Ok(finalized) => finalized,
            Err(resolution) => return resolution,
        };
        let exact = finalized.strip_suffix('/').unwrap_or(&finalized).to_owned();
        if let Some(file) = resolve_file_candidates(input, std::slice::from_ref(&exact)) {
            return file;
        }
        let source = file_for_path(input, input.source_path);
        if has_container_directory(
            input,
            &finalized,
            source.map(|file| file.container_sha256.as_str()),
        ) {
            return unresolved(
                ResolutionStatus::Rejected,
                format!(
                    "The selected legacy ESM package main finalizes to directory {finalized}; directory imports are unsupported and no later main or index candidate was tried."
                ),
            )
            .with_candidate(finalized);
        }
        return unresolved(
            ResolutionStatus::NotFound,
            format!(
                "The selected legacy ESM package main finalizes to {finalized}, which is not an inventoried file; no later main or index candidate was tried."
            ),
        );
    }
    if let Some(fallback) =
        resolve_file_candidates(input, &index_candidates(directory, input.module_kind))
    {
        return fallback;
    }
    let mut not_found = not_found_candidate();
    not_found.stops_ancestor_lookup = input.module_kind == Some(ModuleResolutionMode::Require);
    not_found
}

fn resolve_file_candidates(
    input: &ResolveInput<'_>,
    candidates: &[String],
) -> Option<CandidateResolution> {
    for path in candidates {
        let Some(selected) = find_file_candidate(input, path) else {
            continue;
        };
        return Some(
            if selected.status == ResolutionStatus::Resolved
                && is_runtime_declaration_path(input, path)
            {
                unresolved(
                    ResolutionStatus::Unavailable,
                    format!(
                        "The TypeScript declaration {path} is compile-time evidence and cannot identify a runtime module implementation."
                    ),
                )
                .with_candidate(path.clone())
            } else {
                selected
            },
        );
    }
    None
}

/// Candidate presence and container identity, independent of loader policy.
fn find_file_candidate(input: &ResolveInput<'_>, path: &str) -> Option<CandidateResolution> {
    let source = file_for_path(input, input.source_path);
    if let Some(target) = file_for_path(input, path)
        && source.is_none_or(|source| target.container_sha256 == source.container_sha256)
    {
        return Some(CandidateResolution::resolved(path));
    }
    let unanalyzed = input.unanalyzed_files.and_then(|lookup| lookup.get(path))?;
    if source.is_some_and(|source| unanalyzed.container_sha256 != source.container_sha256) {
        return None;
    }
    let mut limitations = unanalyzed.limitations.clone().unwrap_or_default();
    limitations.push(match &unanalyzed.kind {
        None => format!(
            "{path} exists in the inventoried artifact container (sha256 {}, {}) but is not a JavaScript, JSON, HTML, source map, or native add-on file; its contents were not analyzed.",
            unanalyzed.sha256.as_deref().unwrap_or("unknown"),
            unanalyzed
                .bytes
                .map_or_else(|| "unknown size".to_owned(), |bytes| format!("{bytes} bytes")),
        ),
        Some(kind) => format!(
            "{path} is an inventoried {kind} file, but its bytes are unavailable (hash status {}); resolution cannot be confirmed.",
            unanalyzed.hash_status.as_deref().unwrap_or("unknown"),
        ),
    });
    Some(
        CandidateResolution::unresolved(ResolutionStatus::Unavailable, limitations)
            .with_candidate(path),
    )
}

/// `/\.d\.(?:ts|mts|cts)$/iu` with an import or require loader.
fn is_runtime_declaration_path(input: &ResolveInput<'_>, path: &str) -> bool {
    if input.module_kind.is_none() {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".d.ts") || lower.ends_with(".d.mts") || lower.ends_with(".d.cts")
}

fn extensions(module_kind: Option<ModuleResolutionMode>) -> &'static [&'static str] {
    if module_kind.is_none() {
        EXTENSIONS
    } else {
        NODE_MODULE_EXTENSIONS
    }
}

fn file_candidates(candidate: &str, module_kind: Option<ModuleResolutionMode>) -> Vec<String> {
    std::iter::once(candidate.to_owned())
        .chain(
            extensions(module_kind)
                .iter()
                .map(|extension| format!("{candidate}{extension}")),
        )
        .collect()
}

fn index_candidates(candidate: &str, module_kind: Option<ModuleResolutionMode>) -> Vec<String> {
    extensions(module_kind)
        .iter()
        .map(|extension| posix_join(&[candidate, &format!("index{extension}")]))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockCause {
    Null,
    EmptyArray,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MapKind {
    Exports,
    Imports,
}

impl MapKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Exports => "exports",
            Self::Imports => "imports",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum TargetKind {
    Exports,
    Imports,
    EsmSubpath,
}

enum PackageExportOutcome {
    Value(PackageFileTarget),
    Rejected(String),
    Blocked(BlockCause),
    Unmatched(Vec<String>),
}

/// Only exact non-directory keys participate; wildcard expansion is unsupported.
fn select_package_export(
    value: &Value,
    subpath: &str,
    module_kind: Option<ModuleResolutionMode>,
    package_path: &str,
) -> PackageExportOutcome {
    let mut target = value;
    let mut declared: Vec<String> = Vec::new();
    if let Value::Object(map) = value {
        let keys = js_own_keys(map);
        let has_subpaths = keys.iter().any(|key| key.starts_with('.'));
        if has_subpaths && keys.iter().any(|key| !key.starts_with('.')) {
            return PackageExportOutcome::Rejected(
                "The package exports configuration mixes subpath keys and condition keys.".into(),
            );
        }
        declared = keys.iter().map(|key| (*key).to_owned()).collect();
        if has_subpaths {
            match map.get(subpath) {
                Some(selected) if !subpath.ends_with('/') && !subpath.contains('*') => {
                    target = selected
                }
                _ => return PackageExportOutcome::Unmatched(declared),
            }
        } else if subpath != "." {
            return PackageExportOutcome::Unmatched(declared);
        }
    } else if subpath != "." {
        return PackageExportOutcome::Unmatched(declared);
    }
    match select_export_target(
        target,
        &package_export_conditions(module_kind),
        package_path,
        MapKind::Exports,
    ) {
        ExportTargetOutcome::Invalid(limitation)
        | ExportTargetOutcome::InvalidConfig(limitation) => {
            PackageExportOutcome::Rejected(limitation)
        }
        ExportTargetOutcome::Unmatched(declared) => PackageExportOutcome::Unmatched(declared),
        ExportTargetOutcome::Blocked(cause) => PackageExportOutcome::Blocked(cause),
        ExportTargetOutcome::NonRelative(value) => PackageExportOutcome::Rejected(format!(
            "The package exports target {} must start with \"./\".",
            json_string(&value)
        )),
        ExportTargetOutcome::Value(target) => PackageExportOutcome::Value(target),
    }
}

enum ExportTargetOutcome {
    Value(PackageFileTarget),
    NonRelative(String),
    Blocked(BlockCause),
    Unmatched(Vec<String>),
    Invalid(String),
    InvalidConfig(String),
}

fn invalid_export_target(value: &Value, reason: &str, map_kind: MapKind) -> ExportTargetOutcome {
    ExportTargetOutcome::Invalid(format!(
        "The package {} target {} {reason}.",
        match map_kind {
            MapKind::Imports => "import",
            MapKind::Exports => "exports",
        },
        json_stringify(value)
    ))
}

/// Node checks raw target segments before URL normalization; `%XX` escapes
/// are decoded per byte to Latin-1 code points as `String.fromCharCode` does.
fn forbidden_export_segment(value: &str) -> Option<&str> {
    slice_from(value, 2).split(['\\', '/']).find(|raw| {
        let bytes = raw.as_bytes();
        let mut segment = String::with_capacity(raw.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%'
                && bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                let byte = u8::from_str_radix(&raw[index + 1..index + 3], 16).unwrap_or_default();
                segment.push(char::from(byte));
                index += 3;
                continue;
            }
            let character = raw[index..].chars().next().unwrap_or_default();
            segment.push(character);
            index += character.len_utf8();
        }
        segment == "." || segment == ".." || segment.to_lowercase() == "node_modules"
    })
}

fn select_string_package_target(
    value: &str,
    package_path: &str,
    map_kind: MapKind,
) -> ExportTargetOutcome {
    let json = Value::String(value.to_owned());
    if map_kind == MapKind::Imports {
        match classify_package_import_target(value) {
            PackageImportTargetKind::Invalid => {
                return invalid_export_target(
                    &json,
                    "cannot be parent-relative, absolute, or a URL",
                    map_kind,
                );
            }
            PackageImportTargetKind::Relative => {}
            _ => return ExportTargetOutcome::NonRelative(value.to_owned()),
        }
    } else if !value.starts_with("./") {
        return invalid_export_target(&json, "must start with \"./\"", map_kind);
    }
    if let Some(forbidden) = forbidden_export_segment(value) {
        return invalid_export_target(
            &json,
            &format!(
                "contains forbidden path segment {} before URL normalization",
                json_string(forbidden)
            ),
            map_kind,
        );
    }
    let package_url = package_metadata_url(package_path);
    let url = package_url
        .as_ref()
        .and_then(|base| web_url::parse(value, Some(base)));
    let directory = package_url
        .as_ref()
        .and_then(|base| web_url::parse(".", Some(base)));
    let (Some(url), Some(directory)) = (url, directory) else {
        return invalid_export_target(
            &json,
            "escapes the package root after URL normalization",
            map_kind,
        );
    };
    if !url.pathname().starts_with(directory.pathname()) {
        return invalid_export_target(
            &json,
            "escapes the package root after URL normalization",
            map_kind,
        );
    }
    ExportTargetOutcome::Value(PackageFileTarget {
        value: value.to_owned(),
        url,
    })
}

fn select_array_package_target(
    value: &[Value],
    conditions: &[&str],
    package_path: &str,
    map_kind: MapKind,
) -> ExportTargetOutcome {
    if value.is_empty() {
        return ExportTargetOutcome::Blocked(BlockCause::EmptyArray);
    }
    let mut last_refusal: Option<ExportTargetOutcome> = None;
    let mut declared: Vec<String> = Vec::new();
    for entry in value {
        match select_export_target(entry, conditions, package_path, map_kind) {
            // Node's array fallback catches invalid targets, not invalid configuration.
            outcome @ ExportTargetOutcome::InvalidConfig(_) => return outcome,
            ExportTargetOutcome::Unmatched(nested) => {
                for condition in nested {
                    if !declared.contains(&condition) {
                        declared.push(condition);
                    }
                }
            }
            outcome @ (ExportTargetOutcome::Invalid(_) | ExportTargetOutcome::Blocked(_)) => {
                last_refusal = Some(outcome);
            }
            outcome => return outcome,
        }
    }
    last_refusal.unwrap_or(ExportTargetOutcome::Unmatched(declared))
}

/// Resolve a target in Node's declared condition order.
fn select_export_target(
    value: &Value,
    conditions: &[&str],
    package_path: &str,
    map_kind: MapKind,
) -> ExportTargetOutcome {
    let map = match value {
        Value::String(text) => return select_string_package_target(text, package_path, map_kind),
        Value::Null => return ExportTargetOutcome::Blocked(BlockCause::Null),
        Value::Array(items) => {
            return select_array_package_target(items, conditions, package_path, map_kind);
        }
        Value::Object(map) => map,
        _ => {
            return invalid_export_target(
                value,
                "must be a relative string, object, array, or null",
                map_kind,
            );
        }
    };
    let keys = js_own_keys(map);
    if let Some(key) = keys.iter().find(|key| is_numeric_condition_key(key)) {
        return ExportTargetOutcome::InvalidConfig(format!(
            "The package exports configuration contains numeric condition key {}.",
            json_string(key)
        ));
    }
    let mut declared: Vec<String> = Vec::new();
    let add = |declared: &mut Vec<String>, name: &str| {
        if !declared.iter().any(|existing| existing == name) {
            declared.push(name.to_owned());
        }
    };
    for condition in keys {
        add(&mut declared, condition);
        if !conditions.contains(&condition) {
            continue;
        }
        match select_export_target(&map[condition], conditions, package_path, map_kind) {
            ExportTargetOutcome::Unmatched(nested) => {
                for name in &nested {
                    add(&mut declared, name);
                }
            }
            outcome => return outcome,
        }
    }
    ExportTargetOutcome::Unmatched(declared)
}

/// Active conditions for Node's built-in resolver, which also activates
/// `module-sync` on the supported runtimes.
fn package_export_conditions(module_kind: Option<ModuleResolutionMode>) -> Vec<&'static str> {
    let mut conditions = vec!["node", "node-addons", "module-sync"];
    if let Some(mode) = module_kind {
        conditions.push(mode.as_str());
    }
    conditions.push("default");
    conditions
}

fn not_found_candidate() -> CandidateResolution {
    unresolved(
        ResolutionStatus::NotFound,
        "No extension, directory package, or index candidate exists in the inventoried artifact container.",
    )
}

fn exact_package_target_not_found(path: &str, target_kind: TargetKind) -> CandidateResolution {
    let label = match target_kind {
        TargetKind::Imports => "import",
        TargetKind::Exports => "exports",
        TargetKind::EsmSubpath => "ESM subpath",
    };
    unresolved(
        ResolutionStatus::NotFound,
        format!(
            "The selected package {label} target {path} does not exist in the inventoried artifact container; {label} targets are exact files, so no extension or directory index was tried."
        ),
    )
}

enum FileUrlPath {
    /// Not a `file://` URL, or one with an authority or unparseable form.
    NotFileUrl,
    /// Syntax that cannot identify a canonical artifact path.
    Rejected,
    Path(String),
}

fn file_url_path(value: &str) -> FileUrlPath {
    let is_file_authority = value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("file://"));
    if !is_file_authority {
        return FileUrlPath::NotFileUrl;
    }
    // URL parsing removes tabs and newlines and normalizes encoded dots.
    let raw_path = strip_query_and_fragment(value);
    if value.contains('\0')
        || value.contains('\\')
        || raw_path.contains(['\t', '\n', '\r'])
        || !admits_canonical_path_syntax(raw_path)
    {
        return FileUrlPath::Rejected;
    }
    let Some(url) = web_url::parse(value, None) else {
        return FileUrlPath::NotFileUrl;
    };
    if url.protocol() != "file:" || !url.hostname().is_empty() {
        return FileUrlPath::NotFileUrl;
    }
    if !admits_canonical_path_syntax(url.pathname()) {
        return FileUrlPath::Rejected;
    }
    match decode_uri_component(url.pathname()) {
        Some(decoded) if !decoded.contains('\0') => {
            FileUrlPath::Path(decoded.trim_start_matches('/').to_owned())
        }
        Some(_) => FileUrlPath::Rejected,
        None => FileUrlPath::NotFileUrl,
    }
}

const INTERNAL_SURROGATE_MARKER: char = '\u{e000}';

pub(crate) fn encode_json_text_units(value: &JsString) -> String {
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
pub(crate) fn decode_json_text_units(value: &str) -> JsString {
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

pub(crate) fn prepare_package_json_text(value: &str) -> String {
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
    use super::*;

    fn input<'a>(
        files: &'a HashMap<JsString, ResolverFile>,
        cache: &'a PackageMetadataCache,
    ) -> ResolveInput<'a> {
        ResolveInput {
            declared_path: "./entry",
            source_path: "src/app.js",
            context: ResolutionContext::ModuleSpecifier,
            files,
            directory_paths: None,
            container_directory_paths: None,
            unanalyzed_files: None,
            html_base_href: None,
            module_kind: Some(ModuleResolutionMode::Require),
            runtime_path_kind: None,
            package_metadata_cache: cache,
        }
    }

    fn file(container_sha256: &str, text: &str) -> ResolverFile {
        ResolverFile {
            container_sha256: container_sha256.into(),
            text: ResolverFileText::Included(JsString::from(text)),
        }
    }

    #[test]
    fn package_metadata_cache_reuses_valid_metadata() {
        let mut files = HashMap::new();
        files.insert(JsString::from("src/app.js"), file("container-a", ""));
        files.insert(
            JsString::from("pkg/package.json"),
            file("container-a", r#"{"main":"entry.js"}"#),
        );
        let cache = PackageMetadataCache::default();
        let input = input(&files, &cache);

        let first = read_package_metadata(&input, "pkg");
        let second = read_package_metadata(&input, "pkg");

        assert!(matches!(first, PackageMetadata::Available(_)));
        assert!(matches!(second, PackageMetadata::Available(_)));
        assert_eq!(cache.entries.borrow().len(), 1);
    }

    #[test]
    fn package_metadata_cache_reuses_unavailable_metadata_error() {
        let mut files = HashMap::new();
        files.insert(JsString::from("src/app.js"), file("container-a", ""));
        files.insert(
            JsString::from("pkg/package.json"),
            file("container-a", "not package json"),
        );
        let cache = PackageMetadataCache::default();
        let input = input(&files, &cache);

        let first = read_package_metadata(&input, "pkg");
        let second = read_package_metadata(&input, "pkg");

        assert!(matches!(first, PackageMetadata::Unavailable(_)));
        assert!(matches!(second, PackageMetadata::Unavailable(_)));
        assert_eq!(cache.entries.borrow().len(), 1);
    }

    #[test]
    fn package_metadata_cache_separates_source_containers() {
        let mut files = HashMap::new();
        files.insert(JsString::from("src/app.js"), file("container-a", ""));
        files.insert(JsString::from("src/other.js"), file("container-b", ""));
        files.insert(
            JsString::from("pkg/package.json"),
            file("container-a", r#"{"main":"entry.js"}"#),
        );
        let cache = PackageMetadataCache::default();
        let input_a = input(&files, &cache);
        let input_b = ResolveInput {
            source_path: "src/other.js",
            ..input_a
        };

        assert!(matches!(
            read_package_metadata(&input_a, "pkg"),
            PackageMetadata::Available(_)
        ));
        assert!(matches!(
            read_package_metadata(&input_b, "pkg"),
            PackageMetadata::Absent
        ));
        assert_eq!(cache.entries.borrow().len(), 2);
    }

    #[test]
    fn container_directory_index_keeps_file_ownership() {
        let mut files = HashMap::new();
        files.insert(JsString::from("src/app.js"), file("container-a", ""));
        files.insert(JsString::from("pkg/entry.js"), file("container-a", ""));
        files.insert(JsString::from("pkg/other.js"), file("container-b", ""));
        let cache = PackageMetadataCache::default();
        let mut directories = ContainerDirectoryIndex::new();
        directories
            .entry("container-a".into())
            .or_default()
            .insert(JsString::from("pkg"));
        directories
            .entry("container-b".into())
            .or_default()
            .insert(JsString::from("pkg"));
        let input = ResolveInput {
            container_directory_paths: Some(&directories),
            ..input(&files, &cache)
        };

        assert!(has_container_directory(&input, "pkg", Some("container-a")));
        assert!(has_container_directory(&input, "pkg", Some("container-b")));
        assert!(!has_container_directory(&input, "pkg", Some("container-c")));
        assert!(has_container_directory(&input, "pkg", None));
    }

    #[test]
    fn container_directory_index_preserves_empty_absolute_prefix() {
        let mut files = HashMap::new();
        files.insert(JsString::from("/pkg/entry.js"), file("container-a", ""));
        let cache = PackageMetadataCache::default();
        let mut directories = ContainerDirectoryIndex::new();
        directories
            .entry("container-a".into())
            .or_default()
            .insert(JsString::from(""));
        let input = ResolveInput {
            container_directory_paths: Some(&directories),
            ..input(&files, &cache)
        };

        assert!(has_container_directory(&input, "", Some("container-a")));
    }
}
