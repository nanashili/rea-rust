//! Read-only, deterministic import of a caller-selected historical source tree.
use rea_core::{
    cancellation::Cancellation,
    canonical_json,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use super::reference_source_policy::{self, SourceImportPolicy};
use super::reference_source_reader::SourceTreeReader;
use super::reference_source_vcs;
use rea_host::fs::stable_directory::DirectoryEntryKind;

use crate::javascript::parser::{
    ModuleReferenceKind, RecoveredJavaScriptParseOutcome, parse_recovered_javascript_source,
};

pub const OPERATION: &str = "import_reference_source";
/// Import a source directory from `input.root` into a relocation-independent graph.
pub fn import(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    if cancellation.reason().is_some() {
        return Err(cancelled_failure(cancellation));
    }
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    let root_text = object
        .get("root")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid("root is required"))?;
    // Resolve the caller-selected root once. The stable reader then owns the
    // canonical directory handle and admits descendants relative to it.
    let canonical_root = fs::canonicalize(Path::new(root_text))
        .map_err(|error| stable_failure("could not resolve source root", error))?;
    let reader = SourceTreeReader::open(&canonical_root)
        .map_err(|error| stable_failure("could not open source root", error))?;
    let root = reader.root().canonical_path.clone();
    let policy = reference_source_policy::build(&reader, input, cancellation)
        .map_err(|error| invalid(&format!("reference source policy is invalid: {error}")))?;
    let mut state = ImportState::default();

    visit(&reader, &policy, cancellation, &mut state)?;

    parse_relationships(&mut state, cancellation)?;
    finalize_state(&mut state);

    let commitment = commitment_for(&state);
    let root_sha256 =
        canonical_json::digest(&commitment).map_err(|error| invalid(&error.to_string()))?;

    let output = graph_output(object, state, commitment, root_sha256, &root, cancellation)?;

    Ok(output)
}

fn finalize_state(state: &mut ImportState) {
    classify_source_directories(state);
    state
        .entries
        .sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    state
        .exclusions
        .sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    state.relationships.sort_by(|left, right| {
        left["from_path"]
            .as_str()
            .cmp(&right["from_path"].as_str())
            .then_with(|| left["to"].as_str().cmp(&right["to"].as_str()))
            .then_with(|| left["kind"].as_str().cmp(&right["kind"].as_str()))
    });
    state.relationships.dedup();
    state.manifests.sort();
}

fn commitment_for(state: &ImportState) -> Value {
    let committed_entries = state
        .entries
        .iter()
        .map(committed_entry)
        .collect::<Vec<_>>();
    json!({
        "entries": committed_entries,
        "exclusions": state.exclusions.clone(),
    })
}

fn committed_entry(entry: &Value) -> Value {
    match entry["kind"].as_str().unwrap_or("") {
        "file" => {
            json!({
                "kind": entry["kind"],
                "path": entry["path"],
                "sha256": entry["sha256"],
                "size": entry["size"],
                "content_state": entry["content_state"],
            })
        }
        "directory" => {
            json!({
                "kind": entry["kind"],
                "path": entry["path"],
                "tree_state": entry["tree_state"],
            })
        }
        "symlink" => {
            json!({
                "kind": entry["kind"],
                "path": entry["path"],
                "target": entry["target"],
                "target_state": entry["target_state"],
            })
        }
        _ => json!({
            "kind": entry["kind"],
            "path": entry["path"],
        }),
    }
}

fn graph_output(
    object: &serde_json::Map<String, Value>,
    state: ImportState,
    commitment: Value,
    root_sha256: String,
    root: &Path,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    let inventory_state = if state.limitations.is_empty() && state.exclusions.is_empty() {
        "complete"
    } else {
        "partial"
    };
    let mut languages = state.languages.into_iter().collect::<Vec<_>>();
    languages.sort();
    let vcs = reference_source_vcs::read(root, cancellation)?;
    Ok(json!({
        "schema": "HistoricalSourceGraph",
        "authority": "historical-reference",
        "root_alias": "$REFERENCE_ROOT",
        "root_sha256": root_sha256,
        "inventory_state": inventory_state,
        "entries": state.entries,
        "relationships": state.relationships,
        "parse_failures": state.parse_failures,
        "exclusions": commitment["exclusions"],
        "languages": languages,
        "manifests": state.manifests,
        "vcs": vcs,
        "provenance": {
            "importer": object.get("importer").and_then(Value::as_str).unwrap_or("rea-reference-source-import"),
            "importer_version": object.get("importer_version").cloned().unwrap_or(Value::Null),
            "caller": object.get("caller").and_then(Value::as_str).unwrap_or("rea-reference-source-import")
        },
        "limitations": state.limitations
    }))
}

#[derive(Default)]
struct ImportState {
    entries: Vec<Value>,
    exclusions: Vec<Value>,
    relationships: Vec<Value>,
    parse_failures: Vec<Value>,
    limitations: Vec<String>,
    languages: BTreeSet<String>,
    manifests: Vec<String>,
    sources: BTreeMap<String, Vec<u8>>,
}

fn visit(
    reader: &SourceTreeReader,
    policy: &SourceImportPolicy,
    cancellation: &Cancellation,
    state: &mut ImportState,
) -> Result<(), Failure> {
    const MAX_SOURCE_ENTRIES: usize = 1_000_000;
    let mut entries = reader
        .entries_filtered(MAX_SOURCE_ENTRIES, cancellation, |entry| {
            excluded_ancestor(&entry.path, entry.kind, policy).is_none()
        })
        .map_err(|error| stable_failure("could not enumerate source directory", error))?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let known_paths = entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();

    for entry in entries {
        if cancellation.reason().is_some() {
            return Err(cancelled_failure(cancellation));
        }
        admit_entry(reader, policy, cancellation, &known_paths, entry, state)?;
    }
    Ok(())
}

fn admit_entry(
    reader: &SourceTreeReader,
    policy: &SourceImportPolicy,
    cancellation: &Cancellation,
    known_paths: &BTreeSet<String>,
    entry: rea_host::fs::stable_directory::DirectoryEntry,
    state: &mut ImportState,
) -> Result<(), Failure> {
    let path = entry.path.clone();
    if let Some(root_path) = excluded_ancestor(&path, entry.kind, policy) {
        if root_path == path {
            record_exclusion(&path, entry.kind, policy, state);
        }
        return Ok(());
    }

    match entry.kind {
        DirectoryEntryKind::Regular => project_file(reader, cancellation, entry, state),
        DirectoryEntryKind::Symlink => {
            project_symlink(reader, cancellation, known_paths, entry, state)
        }
        DirectoryEntryKind::Directory => {
            project_directory(entry, state);
            Ok(())
        }
    }
}

fn record_exclusion(
    path: &str,
    kind: DirectoryEntryKind,
    policy: &SourceImportPolicy,
    state: &mut ImportState,
) {
    let matched = policy.match_path(path, kind);
    state.exclusions.push(json!({
        "path": path,
        "entry_kind": directory_entry_kind(kind),
        "reason": matched
            .as_ref()
            .map(|(_, reason)| *reason)
            .unwrap_or("caller-excluded"),
        "pattern": matched.map(|(pattern, _)| pattern),
    }));
}

fn project_directory(
    entry: rea_host::fs::stable_directory::DirectoryEntry,
    state: &mut ImportState,
) {
    state.entries.push(json!({
        "path": entry.path,
        "kind": "directory",
        "tree_state": "enumerated",
        "classifications": ["unknown"],
        "limitations": [],
    }));
}

fn project_symlink(
    reader: &SourceTreeReader,
    cancellation: &Cancellation,
    known_paths: &BTreeSet<String>,
    entry: rea_host::fs::stable_directory::DirectoryEntry,
    state: &mut ImportState,
) -> Result<(), Failure> {
    let path = entry.path.clone();
    let target = reader
        .read_symlink_target(&entry, cancellation)
        .map_err(|error| stable_failure("could not read source symlink", error))?;
    let target_path = normalize_relative_path(
        &Path::new(&path)
            .parent()
            .unwrap_or(Path::new(""))
            .join(&target),
    );
    let target_state = classify_symlink_target(&target, &target_path, known_paths);

    state.entries.push(json!({
        "path": path,
        "kind": "symlink",
        "target": target,
        "target_state": target_state,
        "classifications": ["unknown"],
        "limitations": [],
    }));
    Ok(())
}

fn classify_symlink_target(
    target: &str,
    normalized_target: &str,
    known_paths: &BTreeSet<String>,
) -> &'static str {
    if target.starts_with('/') {
        "external"
    } else if known_paths.contains(normalized_target) {
        "internal"
    } else if target.starts_with("../") {
        "external"
    } else {
        "missing"
    }
}

fn project_file(
    reader: &SourceTreeReader,
    cancellation: &Cancellation,
    entry: rea_host::fs::stable_directory::DirectoryEntry,
    state: &mut ImportState,
) -> Result<(), Failure> {
    let path = entry.path.clone();
    let bytes = reader
        .read_entry_bounded(&entry, cancellation)
        .map_err(|error| stable_failure("could not read source file", error))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = format!("{:x}", hasher.finalize());
    let language = language_for(&path);

    if let Some(value) = language {
        state.languages.insert(value.to_owned());
    }
    if is_manifest(&path) {
        state.manifests.push(path.clone());
    }

    state.entries.push(json!({
        "path": path,
        "kind": "file",
        "language": language,
        "sha256": digest,
        "size": bytes.len(),
        "content_state": "hashed",
        "classifications": classifications(&path),
        "limitations": [],
    }));
    state.sources.insert(path, bytes);
    Ok(())
}

fn excluded_ancestor(
    path: &str,
    kind: DirectoryEntryKind,
    policy: &SourceImportPolicy,
) -> Option<String> {
    let mut components = path.split('/');
    let mut current = String::new();
    for component in components.by_ref() {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        let component_kind = if current == path {
            kind
        } else {
            DirectoryEntryKind::Directory
        };
        if policy.excludes(&current, component_kind) {
            return Some(current);
        }
    }
    None
}

fn directory_entry_kind(kind: DirectoryEntryKind) -> &'static str {
    match kind {
        DirectoryEntryKind::Regular => "file",
        DirectoryEntryKind::Directory => "directory",
        DirectoryEntryKind::Symlink => "symlink",
    }
}

/// Extract imports through the shared parser owner, so strings and comments
/// cannot be mistaken for executable module references.
fn parse_relationships(
    state: &mut ImportState,
    cancellation: &Cancellation,
) -> Result<(), Failure> {
    let mut paths = state.sources.keys().cloned().collect::<Vec<_>>();
    paths.sort();
    for from in paths {
        if cancellation.reason().is_some() {
            return Err(cancelled_failure(cancellation));
        }
        let Some(bytes) = state.sources.get(&from) else {
            continue;
        };
        let Some(language) = language_for(&from) else {
            continue;
        };
        if !matches!(language, "TypeScript" | "TSX" | "JavaScript" | "JSX") {
            continue;
        }
        let Ok(source) = std::str::from_utf8(bytes) else {
            state.parse_failures.push(json!({"path":from,"parser":"utf-8","reason":"Source bytes are not valid UTF-8; import targets were not parsed."}));
            continue;
        };
        let (facts, module_only_errors) =
            match parse_recovered_javascript_source(source, Some(&from)) {
                RecoveredJavaScriptParseOutcome::Parsed {
                    facts,
                    module_only_errors,
                } => (facts, module_only_errors),
                RecoveredJavaScriptParseOutcome::Fatal { errors } => {
                    let reason = errors
                        .first()
                        .map(|error| error.message.clone())
                        .unwrap_or_else(|| {
                            "Source could not be parsed; import targets were not parsed.".to_owned()
                        });
                    state.parse_failures.push(json!({
                        "path": from,
                        "parser": "oxc",
                        "reason": reason,
                    }));
                    continue;
                }
            };
        let parse_state = if facts.errors.is_empty() && module_only_errors.is_empty() {
            "parsed"
        } else {
            "partial"
        };
        for reference in facts.module_references {
            let kind = match reference.kind {
                ModuleReferenceKind::DeclaresModule => {
                    if let Some(specifier) = reference.specifier {
                        state.relationships.push(json!({
                            "from_path": from.clone(),
                            "to": specifier,
                            "kind": "declares-module",
                            "resolution": "unknown",
                            "parse_state": parse_state,
                        }));
                    }
                    continue;
                }
                ModuleReferenceKind::Require | ModuleReferenceKind::ImportEquals => "requires",
                _ => "imports",
            };
            let mode = match reference.kind {
                ModuleReferenceKind::Require => ResolutionMode::RuntimeRequire,
                ModuleReferenceKind::ImportEquals => ResolutionMode::SourceRequire,
                _ => ResolutionMode::SourceImport,
            };
            let (to, resolution) = match reference.specifier.as_deref() {
                Some(specifier) => resolve_import_target(&from, specifier, &state.sources, mode),
                None => ("<dynamic-import>".to_owned(), "unknown"),
            };
            state.relationships.push(json!({"from_path":from.clone(),"to":to,"kind":kind,"resolution":resolution,"parse_state":parse_state}));
        }
        for diagnostic in facts.errors.into_iter().chain(module_only_errors) {
            state
                .parse_failures
                .push(json!({"path":from.clone(),"parser":"oxc","reason":diagnostic.message}));
        }
    }
    Ok(())
}

fn classify_source_directories(state: &mut ImportState) {
    let source_paths = state
        .entries
        .iter()
        .filter(|entry| {
            entry["kind"] == "file"
                && entry["classifications"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item == "source"))
        })
        .filter_map(|entry| entry["path"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    for entry in &mut state.entries {
        if entry["kind"] != "directory" || entry["classifications"] != json!(["unknown"]) {
            continue;
        }
        let Some(path) = entry["path"].as_str() else {
            continue;
        };
        if source_paths
            .iter()
            .any(|source| source.starts_with(&format!("{path}/")))
        {
            entry["classifications"] = json!(["source"]);
        }
    }
}

fn resolve_import_target(
    from: &str,
    specifier: &str,
    files: &BTreeMap<String, Vec<u8>>,
    mode: ResolutionMode,
) -> (String, &'static str) {
    if !(specifier.starts_with('.') || specifier.starts_with('/')) {
        return (specifier.to_owned(), "external");
    }
    let base = if specifier.starts_with('/') {
        PathBuf::from(specifier.trim_start_matches('/'))
    } else {
        Path::new(from)
            .parent()
            .unwrap_or(Path::new(""))
            .join(specifier)
    };
    let normalized = normalize_relative_path(&base);
    let candidates = resolution_candidates(&normalized, mode);
    let direct = candidates
        .iter()
        .find(|candidate| files.contains_key(*candidate))
        .cloned();
    let Some(found) = direct else {
        return resolve_package_main(&normalized, files, mode)
            .unwrap_or((normalized, "unresolved"));
    };
    if found.starts_with(&format!("{normalized}/index.")) {
        return resolve_package_main(&normalized, files, mode).unwrap_or((found, "internal"));
    }
    (found, "internal")
}

#[derive(Clone, Copy)]
enum ResolutionMode {
    SourceImport,
    SourceRequire,
    RuntimeRequire,
}

fn resolution_candidates(path: &str, mode: ResolutionMode) -> Vec<String> {
    let suffixes: &[&str] = match mode {
        ResolutionMode::RuntimeRequire => &["", ".js", ".json", ".node"],
        ResolutionMode::SourceImport => &[
            "", ".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".tsx", ".jsx",
        ],
        ResolutionMode::SourceRequire => &[
            "", ".ts", ".mts", ".cts", ".js", ".json", ".mjs", ".cjs", ".tsx", ".jsx",
        ],
    };
    let mut candidates = suffixes
        .iter()
        .map(|suffix| format!("{path}{suffix}"))
        .collect::<Vec<_>>();
    for suffix in suffixes.iter().filter(|suffix| !suffix.is_empty()) {
        candidates.push(format!("{path}/index{suffix}"));
    }
    candidates
}

fn resolve_package_main(
    directory: &str,
    files: &BTreeMap<String, Vec<u8>>,
    mode: ResolutionMode,
) -> Option<(String, &'static str)> {
    let Some(manifest) = files.get(&format!("{directory}/package.json")) else {
        return None;
    };
    let value: Value = match serde_json::from_slice(manifest) {
        Ok(value) => value,
        Err(_) => return Some((directory.to_owned(), "unresolved")),
    };
    let Some(main) = value.get("main").and_then(Value::as_str) else {
        return None;
    };
    let target = normalize_relative_path(&Path::new(directory).join(main));
    resolution_candidates(&target, mode)
        .into_iter()
        .find(|candidate| files.contains_key(candidate))
        .map(|candidate| (candidate, "internal"))
        .or_else(|| Some((target, "unresolved")))
}

fn normalize_relative_path(path: &Path) -> String {
    let mut parts = Vec::new();
    let text = path.to_string_lossy();
    for part in text.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            value => parts.push(value),
        }
    }
    parts.join("/")
}

fn classifications(path: &str) -> Vec<&'static str> {
    let lower = path.to_ascii_lowercase();
    let filename = lower.rsplit('/').next().unwrap_or(&lower);
    let mut result = BTreeSet::new();
    let parts = lower.split('/').collect::<Vec<_>>();
    if parts
        .iter()
        .any(|part| matches!(*part, "test" | "tests" | "__tests__" | "spec" | "specs"))
        || [".test.", ".spec."]
            .iter()
            .any(|marker| filename.contains(marker))
    {
        result.insert("test");
    }
    if ["node_modules", "vendor", "third_party", "third-party"]
        .iter()
        .any(|name| parts.contains(name))
    {
        result.insert("vendor");
    }
    if ["dist", "build", "coverage", "generated", "out"]
        .iter()
        .any(|name| parts.contains(name))
        || filename.ends_with(".min.js")
        || filename.ends_with(".map")
        || filename.ends_with(".d.ts")
    {
        result.insert("generated");
    }
    if ["docs", "doc", "documentation"]
        .iter()
        .any(|name| parts.contains(name))
        || [".md", ".markdown", ".rst", ".adoc", ".txt"]
            .iter()
            .any(|suffix| filename.ends_with(suffix))
        || matches!(filename, "readme" | "license" | "copying")
    {
        result.insert("documentation");
    }
    if is_manifest(path) {
        result.insert("manifest");
    }
    if [".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"]
        .iter()
        .any(|suffix| filename.ends_with(suffix))
        && !result.contains("manifest")
    {
        result.insert("config");
    }
    if language_for(path).is_some() && !is_manifest(path) {
        result.insert("source");
    }
    if result.is_empty() {
        result.insert("unknown");
    }
    result.into_iter().collect()
}
fn is_manifest(path: &str) -> bool {
    [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
        "composer.json",
        "composer.lock",
        "gemfile",
        "gemfile.lock",
        "Cargo.toml",
        "cargo.lock",
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "Package.swift",
        "makefile",
        "cmakelists.txt",
        "dockerfile",
    ]
    .iter()
    .any(|name| {
        path.to_ascii_lowercase()
            .ends_with(&name.to_ascii_lowercase())
    })
}
fn language_for(path: &str) -> Option<&'static str> {
    match Path::new(path).extension().and_then(|e| e.to_str()) {
        Some("ts") | Some("mts") | Some("cts") | Some("d.ts") => Some("TypeScript"),
        Some("tsx") => Some("TSX"),
        Some("js") | Some("mjs") | Some("cjs") => Some("JavaScript"),
        Some("jsx") => Some("JSX"),
        Some("rs") => Some("Rust"),
        Some("py") => Some("Python"),
        Some("go") => Some("Go"),
        Some("java") => Some("Java"),
        Some("kt") | Some("kts") => Some("Kotlin"),
        Some("c") | Some("h") => Some("C"),
        Some("cpp") | Some("hpp") | Some("cc") | Some("cxx") => Some("C++"),
        Some("swift") => Some("Swift"),
        Some("cs") => Some("C#"),
        Some("php") => Some("PHP"),
        Some("sh") => Some("Shell"),
        Some("json") | Some("jsonc") => Some("JSON"),
        Some("yaml") | Some("yml") => Some("YAML"),
        Some("toml") => Some("TOML"),
        Some("ini") | Some("cfg") | Some("conf") => Some("INI"),
        Some("md") | Some("markdown") => Some("Markdown"),
        Some("txt") => Some("Text"),
        Some("html") | Some("htm") => Some("HTML"),
        Some("css") => Some("CSS"),
        Some("scss") => Some("SCSS"),
        Some("sass") => Some("Sass"),
        Some("less") => Some("Less"),
        Some("xml") => Some("XML"),
        Some("svg") => Some("SVG"),
        _ if path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("dockerfile")) =>
        {
            Some("Dockerfile")
        }
        _ => None,
    }
}
fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a readable source directory and retry.".into(),
        std::collections::BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn stable_failure(context: &str, error: impl std::fmt::Display) -> Failure {
    Failure::new(
        "reference_source_io",
        "execution_failure",
        format!("{context}: {error}"),
        true,
        "Check source permissions and retry.".into(),
        std::collections::BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn cancelled_failure(cancellation: &Cancellation) -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        format!(
            "Reference source import cancelled: {}",
            cancellation
                .reason()
                .unwrap_or("caller requested cancellation")
        ),
        true,
        "Retry the import when the source tree is ready.".into(),
        std::collections::BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
