//! Differential golden harness against TypeScript stage dumps.
//!
//! Goldens come from `.cache/rust-migration/js-graph-golden/generate.mjs`,
//! which runs the real `rea analyze-javascript-application` CLI with
//! `REA_JS_GRAPH_GOLDEN_DIR` set. Override the location with
//! `REA_JS_GRAPH_GOLDEN_ROOT`. Every output is compared as canonical JSON, so
//! identifiers, digests and array order must match byte for byte.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::super::semantic::value_types::JsString;
use super::json::{Json, Obj, parse};
use super::resolution::{ArtifactPathResolver, ResolveRequest};
use super::{SemanticGraphProjection, SemanticLimits, build_application_graph, project_file};

#[test]
fn project_file_preserves_raw_property_metadata_across_repeated_binding_ids() {
    let property = Obj::new()
        .with_static("name", 7.0)
        .with_static("presence", Obj::new().with_static("raw", true))
        .with_static(
            "value",
            Obj::new()
                .with_static("status", "literal")
                .with_static("value", 1.0),
        );
    let binding = Obj::new()
        .with_static("bindingId", "binding-1")
        .with_static("kind", "variable")
        .with_static("name", "value")
        .with_static(
            "definitions",
            Json::array(vec![Obj::new().with_static("location", Json::Null).into()]),
        )
        .with_static(
            "value",
            Obj::new()
                .with_static("status", "object")
                .with_static("properties", Json::array(vec![property.into()]))
                .with_static("unknownProperties", false)
                .with_static("omittedProperties", 0.0),
        );
    let repeated_binding = binding.clone().with_static(
        "value",
        Obj::new()
            .with_static("status", "literal")
            .with_static("value", 9.0),
    );
    let ir = Obj::new()
        .with_static(
            "bindings",
            Json::array(vec![binding.into(), repeated_binding.into()]),
        )
        .into();
    let file = Obj::new()
        .with_static("path", "fixture.js")
        .with_static("sha256", "fixture-sha")
        .into();

    let projection = project_file(&file, &ir, 100, 100, &[]).expect("projection succeeds");
    let slot = projection
        .at("nodes")
        .arr()
        .iter()
        .find(|node| node.at("kind").str() == "property-slot")
        .expect("property slot is projected");
    let properties = slot.at("properties");

    assert_eq!(properties.at("name").as_f64(), Some(7.0));
    assert_eq!(properties.at("presence").at("raw").as_bool(), Some(true));
}

/// Replays the resolution owner's recorded results in call order per request.
struct RecordedResolver {
    results: HashMap<String, Vec<Json>>,
    cursors: RefCell<HashMap<String, usize>>,
    misses: RefCell<Vec<String>>,
}

impl RecordedResolver {
    fn new(records: &Json) -> Self {
        let mut results: HashMap<String, Vec<Json>> = HashMap::new();
        for record in records.arr() {
            results
                .entry(record.at("request").canonical())
                .or_default()
                .push(record.at("result").clone());
        }
        Self {
            results,
            cursors: RefCell::default(),
            misses: RefCell::default(),
        }
    }
}

impl ArtifactPathResolver for RecordedResolver {
    fn resolve(&self, request: &ResolveRequest<'_>) -> Json {
        let key = request.to_json().canonical();
        let Some(results) = self.results.get(&key) else {
            self.misses.borrow_mut().push(key);
            return parse(r#"{"declared_path":"","resolution_context":"module-specifier","limitations":[],"resolved_path":null,"resolution_status":"not-found"}"#)
                .unwrap_or(Json::Null);
        };
        let mut cursors = self.cursors.borrow_mut();
        let cursor = cursors.entry(key).or_insert(0);
        let result = results[(*cursor).min(results.len() - 1)].clone();
        *cursor += 1;
        result
    }

    // Harness-only replica of `moduleResolutionModeForJavaScriptReference`;
    // production callers supply the resolution package's implementation.
    fn module_resolution_mode(
        &self,
        source_path: &JsString,
        reference_kind: &str,
        explicit: Option<&str>,
    ) -> String {
        if let Some(mode) = explicit {
            return mode.to_owned();
        }
        match reference_kind {
            "require" => return "require".into(),
            "dynamic-import" => return "import".into(),
            _ => {}
        }
        let Some(source_path) = source_path.as_str() else {
            return "unknown".into();
        };
        let name = source_path.rsplit('/').next().unwrap_or(source_path);
        let extension = match name.rfind('.') {
            Some(index) if index > 0 => name[index..].to_lowercase(),
            _ => String::new(),
        };
        match extension.as_str() {
            ".cjs" | ".cts" => "require",
            ".mts" => "import",
            ".ts" | ".tsx" => "compiler-dependent",
            _ => "import",
        }
        .into()
    }
}

fn golden_root() -> PathBuf {
    std::env::var_os("REA_JS_GRAPH_GOLDEN_ROOT").map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../../.cache/rust-migration/js-graph-golden/golden")
        },
        PathBuf::from,
    )
}

/// First differing JSON path between two values.
fn first_difference(left: &Json, right: &Json, path: &str) -> Option<String> {
    match (left, right) {
        (Json::Object(a), Json::Object(b)) => {
            for (key, value) in a.iter() {
                match b.get(key) {
                    None => return Some(format!("{path}.{key}: missing on TypeScript side")),
                    Some(other) => {
                        if let Some(found) =
                            first_difference(value, other, &format!("{path}.{key}"))
                        {
                            return Some(found);
                        }
                    }
                }
            }
            b.iter()
                .find(|(key, _)| !a.has(key))
                .map(|(key, _)| format!("{path}.{key}: missing on Rust side"))
        }
        (Json::Array(a), Json::Array(b)) => {
            for (index, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                if let Some(found) = first_difference(x, y, &format!("{path}[{index}]")) {
                    return Some(found);
                }
            }
            (a.len() != b.len()).then(|| format!("{path}: length {} vs {}", a.len(), b.len()))
        }
        _ => (left.canonical() != right.canonical()).then(|| {
            format!(
                "{path}: rust {} vs ts {}",
                truncate(&left.stringify()),
                truncate(&right.stringify())
            )
        }),
    }
}

fn truncate(value: &str) -> String {
    value.chars().take(300).collect()
}

#[derive(Default)]
struct Tally {
    stages: HashMap<&'static str, (usize, usize)>,
    failures: Vec<String>,
}

impl Tally {
    fn record(&mut self, stage: &'static str, case: &str, rust: &Json, expected: &Json) {
        let entry = self.stages.entry(stage).or_default();
        entry.0 += 1;
        if rust.canonical() == expected.canonical() {
            entry.1 += 1;
        } else {
            let difference =
                first_difference(rust, expected, "$").unwrap_or_else(|| "key order only".into());
            self.failures.push(format!("{case} {stage}: {difference}"));
        }
    }
}

fn usize_of(value: &Json, default: usize) -> usize {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    value.as_f64().map_or(default, |value| value as usize)
}

fn read_case_directories(root: &Path) -> Vec<PathBuf> {
    let entries = std::fs::read_dir(root).unwrap_or_else(|error| {
        panic!(
            "graph goldens are required at {}; run generate.mjs to produce them: {error}",
            root.display()
        )
    });

    let mut cases = Vec::new();
    for entry in entries {
        let entry = entry.expect("read graph golden root entry");
        let file_type = entry.file_type().expect("inspect graph golden root entry");
        if file_type.is_dir() {
            cases.push(entry.path());
        } else if file_type.is_file() && entry.file_name() == OsStr::new("README.md") {
            // The generator may place explanatory metadata beside the case directories.
        } else {
            panic!(
                "unexpected entry in graph golden root: {}",
                entry.path().display()
            );
        }
    }

    cases.sort();
    assert!(
        !cases.is_empty(),
        "graph golden root {} contains no case directories",
        root.display()
    );
    cases
}

fn read_case_dumps(case: &Path) -> Vec<PathBuf> {
    let raw = case.join("raw");
    let entries = std::fs::read_dir(&raw).unwrap_or_else(|error| {
        panic!(
            "graph golden case {} is missing its raw directory: {error}",
            case.display()
        )
    });

    let mut dumps = Vec::new();
    for entry in entries {
        let entry = entry.expect("read graph golden raw entry");
        let file_type = entry.file_type().expect("inspect graph golden raw entry");
        if file_type.is_file() && entry.file_name() != OsStr::new("README.md") {
            dumps.push(entry.path());
        } else if file_type.is_dir() {
            panic!(
                "unexpected directory in graph golden raw directory: {}",
                entry.path().display()
            );
        } else if !file_type.is_file() {
            panic!(
                "unexpected entry in graph golden raw directory: {}",
                entry.path().display()
            );
        }
    }

    dumps.sort();
    assert!(
        !dumps.is_empty(),
        "graph golden case {} contains no raw dumps",
        case.display()
    );
    dumps
}

#[test]
#[ignore = "requires generated TypeScript graph goldens; run explicitly with --ignored"]
fn typescript_stage_goldens_match_byte_for_byte() {
    let root = golden_root();
    let cases = read_case_directories(&root);
    let mut tally = Tally::default();
    for case in &cases {
        let name = case
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let dumps = read_case_dumps(case);
        for dump in &dumps {
            let file = dump
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned();
            let text = std::fs::read_to_string(dump).expect("readable dump");
            let record = parse(&text).expect("valid dump JSON");
            let label = format!("{name}/{file}");
            if file.ends_with("-application-graph.json") {
                let input = record.at("input");
                let resolver = RecordedResolver::new(record.at("resolutions"));
                let graph = build_application_graph(
                    input.at("snapshot"),
                    input.at("file_set"),
                    input.at("analysis"),
                    &resolver,
                )
                .expect("inventory root");
                let misses = resolver.misses.borrow();
                assert!(
                    misses.is_empty(),
                    "{label}: unrecorded resolution requests {misses:?}"
                );
                tally.record("application-graph", &label, &graph, record.at("output"));
            } else if file.ends_with("-semantic-file.json") {
                let capacity = record.at("capacity");
                let projection = project_file(
                    record.at("file"),
                    record.at("ir"),
                    usize_of(capacity.at("nodes"), 0),
                    usize_of(capacity.at("unknowns"), 0),
                    record.at("paths").arr(),
                )
                .expect("valid capacity");
                tally.record("semantic-file", &label, &projection, record.at("output"));
            } else if file.ends_with("-semantic-graph.json") {
                let limits = record.at("limits");
                let defaults = SemanticLimits::default();
                let mut projection = SemanticGraphProjection::new(SemanticLimits {
                    total_nodes: usize_of(limits.at("totalNodes"), defaults.total_nodes),
                    file_nodes: usize_of(limits.at("fileNodes"), defaults.file_nodes),
                    total_unknowns: usize_of(limits.at("totalUnknowns"), defaults.total_unknowns),
                    file_unknowns: usize_of(limits.at("fileUnknowns"), defaults.file_unknowns),
                })
                .expect("valid limits");
                for event in record.at("events").arr() {
                    match event.at("kind").str() {
                        "adopt" => projection
                            .adopt_file_projection(event.at("projection"))
                            .expect("admissible projection"),
                        _ => projection.record_unavailable_file(
                            event.at("file"),
                            event.at("reason").str(),
                            event.at("limits"),
                            event.at("unknown_reason").str(),
                        ),
                    }
                }
                let application = record.at("application_graph");
                let graph = projection.finish(
                    record.at("root_artifact_sha256").str(),
                    application.at("graph_id").str(),
                    application.at("nodes").arr(),
                );
                tally.record("semantic-graph", &label, &graph, record.at("output"));
            } else {
                panic!("unexpected graph golden dump: {label}");
            }
        }
    }

    for stage in ["application-graph", "semantic-file", "semantic-graph"] {
        assert!(
            tally.stages.contains_key(stage),
            "graph goldens contain no {stage} dumps"
        );
    }

    let mut stages: Vec<_> = tally.stages.iter().collect();
    stages.sort();
    for (stage, (total, matched)) in stages {
        eprintln!("{stage}: {matched}/{total} byte-identical");
    }
    assert!(
        tally.failures.is_empty(),
        "golden mismatches:\n{}",
        tally.failures.join("\n")
    );
}
