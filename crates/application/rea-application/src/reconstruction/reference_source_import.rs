//! Read-only, deterministic import of a caller-selected historical source tree.
use rea_core::{
    canonical_json,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub const OPERATION: &str = "import_reference_source";
const DEFAULT_IGNORES: &[&str] = &[
    ".git",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "target",
];

/// Import a source directory from `input.root` into a relocation-independent graph.
pub fn import(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    let root_text = object
        .get("root")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid("root is required"))?;
    let root = fs::canonicalize(root_text)
        .map_err(|error| io_failure("could not resolve source root", error))?;
    if !root.is_dir() {
        return Err(invalid("root must be a directory"));
    }
    let excludes = object
        .get("exclude_paths")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let secrets = object
        .get("policy")
        .and_then(Value::as_object)
        .and_then(|p| p.get("secret_patterns"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut state = ImportState::default();
    visit(&root, Path::new(""), &excludes, &secrets, &mut state)?;
    state
        .entries
        .sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    state
        .exclusions
        .sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    let committed_entries = state
        .entries
        .iter()
        .map(|entry| match entry["kind"].as_str().unwrap_or("") {
            "file" => json!({"kind":entry["kind"],"path":entry["path"],"sha256":entry["sha256"],"size":entry["size"],"content_state":entry["content_state"]}),
            "directory" => json!({"kind":entry["kind"],"path":entry["path"],"tree_state":entry["tree_state"]}),
            "symlink" => json!({"kind":entry["kind"],"path":entry["path"],"target":entry["target"],"target_state":entry["target_state"]}),
            _ => json!({"kind":entry["kind"],"path":entry["path"]}),
        })
        .collect::<Vec<_>>();
    let commitment = json!({"entries": committed_entries, "exclusions": state.exclusions});
    let root_sha256 =
        canonical_json::digest(&commitment).map_err(|error| invalid(&error.to_string()))?;
    let inventory_state = if state.limitations.is_empty() && state.exclusions.is_empty() {
        "complete"
    } else {
        "partial"
    };
    let mut languages = state.languages.into_iter().collect::<Vec<_>>();
    languages.sort();
    state.manifests.sort();
    Ok(
        json!({"schema":"HistoricalSourceGraph","authority":"historical-reference","root_alias":"$REFERENCE_ROOT","root_sha256":root_sha256,"inventory_state":inventory_state,"entries":state.entries,"relationships":state.relationships,"parse_failures":state.parse_failures,"exclusions":commitment["exclusions"],"languages":languages,"manifests":state.manifests,"vcs":read_vcs(&root),"provenance":{"importer":object.get("importer").and_then(Value::as_str).unwrap_or("rea-reference-source-import"),"importer_version":object.get("importer_version").cloned().unwrap_or(Value::Null),"caller":object.get("caller").and_then(Value::as_str).unwrap_or("rea-reference-source-import")},"limitations":state.limitations}),
    )
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
}

fn visit(
    root: &Path,
    relative: &Path,
    excludes: &[String],
    secrets: &[String],
    state: &mut ImportState,
) -> Result<(), Failure> {
    let mut children = fs::read_dir(root.join(relative))
        .map_err(|error| io_failure("could not enumerate source directory", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_failure("could not enumerate source directory", error))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let name = child.file_name().to_string_lossy().into_owned();
        let child_relative = relative.join(&name);
        let path = child_relative
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let metadata = fs::symlink_metadata(child.path())
            .map_err(|error| io_failure("could not inspect source entry", error))?;
        let secret = secrets
            .iter()
            .any(|pattern| matches_pattern(&path, pattern));
        if secret
            || DEFAULT_IGNORES
                .iter()
                .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
            || excludes
                .iter()
                .any(|pattern| matches_pattern(&path, pattern))
        {
            state.exclusions.push(if secret {
                json!({"path":path,"entry_kind":entry_kind(&metadata),"reason":"configured-secret"})
            } else {
                json!({"path":path,"entry_kind":entry_kind(&metadata),"reason":"caller-excluded"})
            });
            continue;
        }
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(child.path())
                .map_err(|error| io_failure("could not read source symlink", error))?;
            let target_text = target.to_string_lossy().into_owned();
            let target_state = if target.is_absolute() || target_text.starts_with("../") {
                "external"
            } else if root
                .join(child_relative.parent().unwrap_or(Path::new("")))
                .join(&target)
                .exists()
            {
                "internal"
            } else {
                "missing"
            };
            state.entries.push(json!({"path":path,"kind":"symlink","target":target_text,"target_state":target_state,"classifications":["unknown"],"limitations":[]}));
        } else if metadata.is_dir() {
            state.entries.push(json!({"path":path,"kind":"directory","tree_state":"enumerated","classifications":["unknown"],"limitations":[]}));
            visit(root, &child_relative, excludes, secrets, state)?;
        } else if metadata.is_file() {
            let bytes = fs::read(child.path())
                .map_err(|error| io_failure("could not read source file", error))?;
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
            state.entries.push(json!({"path":path,"kind":"file","language":language,"sha256":digest,"size":bytes.len(),"content_state":"hashed","classifications":classifications(&path),"limitations":[]}));
        }
    }
    Ok(())
}
fn matches_pattern(path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_matches('/');
    path == pattern
        || path.ends_with(&format!("/{pattern}"))
        || (pattern.starts_with("*.") && path.ends_with(&pattern[1..]))
}
fn entry_kind(metadata: &fs::Metadata) -> &'static str {
    if metadata.is_dir() {
        "directory"
    } else if metadata.file_type().is_symlink() {
        "symlink"
    } else if metadata.is_file() {
        "file"
    } else {
        "unknown"
    }
}
fn classifications(path: &str) -> Vec<&'static str> {
    if path.ends_with(".test.ts") || path.ends_with(".spec.ts") {
        vec!["source", "test"]
    } else if is_manifest(path) {
        vec!["manifest"]
    } else {
        vec!["source"]
    }
}
fn is_manifest(path: &str) -> bool {
    [
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "go.mod",
        "pom.xml",
        "Package.swift",
    ]
    .iter()
    .any(|name| path.ends_with(name))
}
fn language_for(path: &str) -> Option<&'static str> {
    match Path::new(path).extension().and_then(|e| e.to_str()) {
        Some("ts") | Some("tsx") => Some("typescript"),
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => Some("javascript"),
        Some("rs") => Some("rust"),
        Some("py") => Some("python"),
        Some("go") => Some("go"),
        Some("java") => Some("java"),
        _ => None,
    }
}
fn read_vcs(root: &Path) -> Value {
    let head = root.join(".git/HEAD");
    let Ok(text) = fs::read_to_string(head) else {
        return json!({"kind":"none","head":null,"dirty":null});
    };
    let commit = text
        .trim()
        .strip_prefix("ref: ")
        .and_then(|name| fs::read_to_string(root.join(".git").join(name)).ok())
        .map(|value| value.trim().to_owned())
        .or_else(|| Some(text.trim().to_owned()));
    match commit {
        Some(value) if value.len() == 40 || value.len() == 64 => {
            json!({"kind":"git","head":value,"dirty":null})
        }
        _ => json!({"kind":"unknown","head":null,"dirty":null}),
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
fn io_failure(context: &str, error: std::io::Error) -> Failure {
    Failure::new(
        "reference_source_io",
        "execution_failure",
        format!("{context}: {error}"),
        true,
        "Check source permissions and retry.".into(),
        std::collections::BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
