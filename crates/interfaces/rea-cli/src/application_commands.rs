//! CLI workflows whose implementation belongs to the application layer.
//!
//! These helpers deliberately keep argument translation and presentation in
//! the CLI while delegating source import, Evidence authentication, and
//! debugger lifecycle ownership to the application/tool registries.

use crate::{
    analysis::outcome,
    invoke::Runner,
    util::{absolute_caller_path, labelled},
};
use rea_application::{
    ledger::{artifact_records::ArtifactRecords, bundle_import::BundleImporter},
    reconstruction::reference_source_import,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use std::{io, path::Path, sync::Arc};

#[cfg(unix)]
use rea_host::fs::unix_file::UnixFiles;
#[cfg(windows)]
use rea_host::fs::windows_file::WindowsFiles;

#[cfg(unix)]
type HostFiles = UnixFiles;
#[cfg(windows)]
type HostFiles = WindowsFiles;

fn operation_failure(label: &str, projection: Value) -> Value {
    labelled(label, projection)
}

/// Import a historical source tree through the canonical application owner.
pub fn import_reference_source(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let root = absolute_caller_path(args.get("root").and_then(Value::as_str).unwrap_or_default());
    let detail = options
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or("full");
    let outline_depth = options.get("outlineDepth").and_then(Value::as_u64);
    if outline_depth.is_some() && detail != "summary" {
        let mut projection = input_projection(
            "import-reference-source",
            &["outlineDepth"],
            "invalid_value",
            "--outline-depth requires --detail summary",
        );
        if let Some(object) = projection.as_object_mut() {
            object.insert(
                "message".to_owned(),
                Value::String("--outline-depth requires --detail summary".to_owned()),
            );
        }
        return operation_failure("Import failed", projection);
    }

    if let Err(error) = std::fs::metadata(Path::new(&root)) {
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
        ) {
            return missing_reference_root(&root, error);
        }
    }

    let mut input = Map::new();
    input.insert("root".to_owned(), Value::String(root));
    input.insert("caller".to_owned(), Value::String("rea-cli".to_owned()));
    input.insert(
        "importer".to_owned(),
        Value::String("rea-agents".to_owned()),
    );
    input.insert(
        "importer_version".to_owned(),
        Value::String(rea_mcp::catalog::catalog().server_version.clone()),
    );
    if let Some(policy) = options.get("policy") {
        input.insert("policy".to_owned(), policy.clone());
    } else if let Some(policy) = reference_source_policy_from_environment(runner) {
        let policy = match policy {
            Ok(policy) => policy,
            Err(error) => return operation_failure("Import failed", error),
        };
        input.insert("policy".to_owned(), policy);
    }

    let imported =
        match reference_source_import::import(&Value::Object(input), &runner.cancellation) {
            Ok(value) => value,
            Err(failure) => {
                return operation_failure("Import failed", AnalysisError::from(failure).project());
            }
        };

    if detail != "summary" {
        return imported;
    }
    match project_reference_summary(imported, outline_depth.unwrap_or(2)) {
        Ok(summary) => summary,
        Err(error) => operation_failure("Import failed", error),
    }
}

fn reference_source_policy_from_environment(runner: &Runner<'_>) -> Option<Result<Value, Value>> {
    let encoded = runner.session.env("REA_REFERENCE_SECRET_PATTERNS_JSON")?;
    let decoded = match serde_json::from_str::<Value>(encoded) {
        Ok(value) => value,
        Err(_) => {
            return Some(Err(input_projection(
                "import-reference-source",
                &["REA_REFERENCE_SECRET_PATTERNS_JSON"],
                "invalid_value",
                "REA_REFERENCE_SECRET_PATTERNS_JSON must be valid JSON encoding an array of non-empty strings",
            )));
        }
    };
    let Some(patterns) = decoded.as_array() else {
        return Some(Err(input_projection(
            "import-reference-source",
            &["REA_REFERENCE_SECRET_PATTERNS_JSON"],
            "invalid_value",
            "REA_REFERENCE_SECRET_PATTERNS_JSON must encode an array of non-empty strings",
        )));
    };
    if patterns
        .iter()
        .any(|pattern| pattern.as_str().is_none_or(str::is_empty))
    {
        return Some(Err(input_projection(
            "import-reference-source",
            &["REA_REFERENCE_SECRET_PATTERNS_JSON"],
            "invalid_value",
            "REA_REFERENCE_SECRET_PATTERNS_JSON must encode an array of non-empty strings",
        )));
    }
    Some(Ok(json!({"secretPatterns": patterns})))
}

fn missing_reference_root(path: &str, error: io::Error) -> Value {
    let (code, description) = match error.kind() {
        io::ErrorKind::NotADirectory => ("ENOTDIR", "not a directory"),
        _ => ("ENOENT", "no such file or directory"),
    };
    operation_failure(
        "Import failed",
        json!({
            "category": "invalid_input",
            "message": format!("Reference source root could not be resolved: {code}: {description}, stat '{path}' Reference source directory could not be opened. Check that the path exists, is readable, and points to a directory."),
        }),
    )
}

fn input_projection(
    operation: &'static str,
    path: &[&str],
    reason: &'static str,
    message: &str,
) -> Value {
    AnalysisError::input(
        operation,
        vec![rea_core::analysis_error::InputIssue {
            path: path
                .iter()
                .map(|part| Value::String((*part).to_owned()))
                .collect(),
            reason,
            message: Some(message.to_owned()),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    )
    .project()
}

fn project_reference_summary(graph: Value, depth: u64) -> Result<Value, Value> {
    let graph_sha256 = rea_core::canonical_json::digest(&graph).map_err(|error| {
        AnalysisError::output(
            "import-reference-source",
            format!("Unable to authenticate the imported reference graph: {error}"),
        )
        .project()
    })?;
    let entries = graph
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut counts = Map::new();
    let mut file_content_states = Map::new();
    let mut directory_tree_states = Map::new();
    let mut known_bytes = 0_u128;
    let mut unknown_file_count = 0_u64;
    counts.insert("entries".to_owned(), json!(entries.len()));
    counts.insert(
        "files".to_owned(),
        json!(
            entries
                .iter()
                .filter(|entry| entry["kind"] == "file")
                .count()
        ),
    );
    counts.insert(
        "directories".to_owned(),
        json!(
            entries
                .iter()
                .filter(|entry| entry["kind"] == "directory")
                .count()
        ),
    );
    counts.insert(
        "symlinks".to_owned(),
        json!(
            entries
                .iter()
                .filter(|entry| entry["kind"] == "symlink")
                .count()
        ),
    );
    counts.insert(
        "unknown".to_owned(),
        json!(
            entries
                .iter()
                .filter(|entry| entry["kind"] == "unknown")
                .count()
        ),
    );
    counts.insert(
        "relationships".to_owned(),
        json!(graph["relationships"].as_array().map_or(0, Vec::len)),
    );
    counts.insert(
        "parse_failures".to_owned(),
        json!(graph["parse_failures"].as_array().map_or(0, Vec::len)),
    );
    counts.insert(
        "exclusions".to_owned(),
        json!(graph["exclusions"].as_array().map_or(0, Vec::len)),
    );

    for entry in &entries {
        match entry["kind"].as_str() {
            Some("file") => {
                let state = entry["content_state"].as_str().unwrap_or("unknown");
                let count = file_content_states
                    .get(state)
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    + 1;
                file_content_states.insert(state.to_owned(), json!(count));
                match entry["size"].as_u64() {
                    Some(size) => known_bytes += u128::from(size),
                    None => unknown_file_count += 1,
                }
            }
            Some("directory") => {
                let state = entry["tree_state"].as_str().unwrap_or("unknown");
                let count = directory_tree_states
                    .get(state)
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    + 1;
                directory_tree_states.insert(state.to_owned(), json!(count));
            }
            _ => {}
        }
    }
    for state in [
        "hashed",
        "redacted-secret",
        "excluded",
        "unreadable",
        "unknown",
    ] {
        file_content_states
            .entry(state.to_owned())
            .or_insert(json!(0));
    }
    for state in ["enumerated", "partial", "excluded", "unreadable", "unknown"] {
        directory_tree_states
            .entry(state.to_owned())
            .or_insert(json!(0));
    }

    let outline = entries
        .iter()
        .filter(|entry| {
            entry["path"]
                .as_str()
                .is_some_and(|path| path.split('/').count() <= depth as usize)
        })
        .map(|entry| {
            if entry["kind"] != "file" {
                return entry.clone();
            }
            let mut projected = Map::new();
            for key in [
                "path",
                "kind",
                "language",
                "size",
                "content_state",
                "classifications",
                "limitations",
            ] {
                if let Some(value) = entry.get(key) {
                    projected.insert(key.to_owned(), value.clone());
                }
            }
            Value::Object(projected)
        })
        .collect::<Vec<_>>();

    let manifest_semantic = json!({
        "schema": "HistoricalSourceManifest",
        "authority": "historical-reference",
        "graph_sha256": graph_sha256,
        "root_sha256": graph["root_sha256"],
        "inventory_state": graph["inventory_state"],
        "entry_count": entries.len(),
        "relationship_count": graph["relationships"].as_array().map_or(0, Vec::len),
    });
    let manifest_id = rea_core::canonical_json::digest(&manifest_semantic)
        .map(|digest| format!("hsm_{digest}"))
        .map_err(|error| {
            AnalysisError::output(
                "import-reference-source",
                format!("Unable to authenticate the historical source manifest: {error}"),
            )
            .project()
        })?;
    let manifest = json!({
        "schema": "HistoricalSourceManifest",
        "authority": "historical-reference",
        "graph_sha256": manifest_semantic["graph_sha256"],
        "root_sha256": manifest_semantic["root_sha256"],
        "inventory_state": manifest_semantic["inventory_state"],
        "entry_count": manifest_semantic["entry_count"],
        "relationship_count": manifest_semantic["relationship_count"],
        "manifest_id": manifest_id,
    });

    Ok(json!({
        "schema": "HistoricalSourceSummary",
        "authority": graph["authority"],
        "root_alias": graph["root_alias"],
        "manifest": manifest,
        "inventory_state": graph["inventory_state"],
        "provenance": graph["provenance"],
        "vcs": graph["vcs"],
        "languages": graph["languages"],
        "manifests": graph["manifests"],
        "counts": counts,
        "file_content_states": file_content_states,
        "directory_tree_states": directory_tree_states,
        "file_sizes": {"known_bytes": known_bytes.to_string(), "unknown_file_count": unknown_file_count},
        "exclusions": graph["exclusions"],
        "limitations": graph["limitations"],
        "outline": {"depth": depth, "entries": outline, "omitted_entry_count": entries.len().saturating_sub(outline.len())}
    }))
}

/// Inspect a caller-selected Evidence bundle without mutating the active CLI session.
pub fn inspect_evidence_bundle(runner: &Runner<'_>, args: &Value) -> Value {
    let input = match args.get("inputJson").and_then(Value::as_str) {
        Some(value) => value,
        None => {
            return operation_failure(
                "Evidence bundle inspection failed",
                input_projection(
                    "get_evidence_bundle",
                    &["inputJson"],
                    "missing_argument",
                    "inputJson is required",
                ),
            );
        }
    };
    let decoded = match parse_json_input(input) {
        Ok(value) => value,
        Err(_) => {
            return operation_failure(
                "Application workflow failed",
                input_projection("inspect-evidence-bundle", &[], "invalid_format", "JSON"),
            );
        }
    };
    let path = decoded
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let detail = decoded
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or("complete");
    let filters = decoded.get("filters").and_then(Value::as_object);
    if detail == "complete" && filters.is_some() {
        return operation_failure(
            "Evidence bundle inspection failed",
            input_projection(
                "get_evidence_bundle",
                &["filters"],
                "invalid_value",
                "Record filters require detail: summary; complete returns the canonical bundle.",
            ),
        );
    }
    if detail != "complete" && detail != "summary" {
        return operation_failure(
            "Evidence bundle inspection failed",
            input_projection(
                "get_evidence_bundle",
                &["detail"],
                "invalid_value",
                "complete | summary",
            ),
        );
    }
    if let Some(error) = validate_record_filters(filters) {
        return operation_failure("Evidence bundle inspection failed", error);
    }
    let mut importer = BundleImporter::new(Arc::new(HostFiles {}));
    let resolved_path = absolute_caller_path(path);
    if let Err(error) = std::fs::metadata(Path::new(&resolved_path)) {
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
        ) {
            return missing_evidence_file(&resolved_path);
        }
    }
    let bundle = match importer.load(
        &resolved_path,
        &runner.cancellation,
        rea_application::binary::rust::Completion::OneShot,
    ) {
        Ok(bundle) => bundle,
        Err(failure) => return evidence_import_failure(failure),
    };
    if detail == "complete" {
        return match bundle_json(bundle) {
            Ok(value) => value,
            Err(error) => operation_failure("Evidence bundle inspection failed", error),
        };
    }
    let records = bundle
        .records()
        .iter()
        .filter(|record| record_matches_filters(record, filters))
        .map(|record| {
            let mut value = match serde_json::to_value(record.metadata()) {
                Ok(value) => value,
                Err(error) => {
                    return Err(operation_failure(
                        "Evidence bundle inspection failed",
                        AnalysisError::output("get_evidence_bundle", error.to_string()).project(),
                    ));
                }
            };
            if let Some(object) = value.as_object_mut() {
                object.insert("retention".to_owned(), json!("complete-record"));
                object.insert("native_dossier".to_owned(), native_summary(record));
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, Value>>();
    let records = match records {
        Ok(records) => records,
        Err(error) => return error,
    };
    json!({
        "kind": "evidence-bundle-summary",
        "filters": filters.cloned().map(Value::Object).unwrap_or_else(|| json!({})),
        "total_retained_records": bundle.records().len(),
        "matching_records": records.len(),
        "unknown_revisions": bundle.unknowns().len(),
        "records": records,
    })
}

fn missing_evidence_file(path: &str) -> Value {
    operation_failure(
        "Evidence bundle inspection failed",
        json!({
            "category": "invalid_input",
            "code": "invalid_request",
            "details": {"operation": "read", "path": path, "reason": "missing"},
            "message": "Evidence file does not exist at the selected path. Check the path and try again.",
            "remediation": {"action": "Evidence file does not exist at the selected path. Check the path and try again."},
            "retryable": true,
        }),
    )
}

fn evidence_import_failure(failure: rea_core::failure::Failure) -> Value {
    let mut projection = AnalysisError::from(failure).project();
    if projection.get("code").and_then(Value::as_str) == Some("evidence_integrity_mismatch") {
        if let Some(reason) = projection
            .get("details")
            .and_then(Value::as_object)
            .and_then(|details| {
                details
                    .get("validation_reason")
                    .or_else(|| details.get("reason"))
            })
            .and_then(Value::as_str)
        {
            let schema_path = projection
                .get("details")
                .and_then(Value::as_object)
                .and_then(|details| details.get("schema_path"))
                .and_then(Value::as_str)
                .unwrap_or("records");
            let message = format!(
                "Evidence bundle does not match the bundle schema at {schema_path}: {reason}. Supply an unmodified bundle written by export_evidence_bundle or rea evidence-export."
            );
            if let Some(object) = projection.as_object_mut() {
                object.insert("message".to_owned(), Value::String(message.clone()));
                object.insert("remediation".to_owned(), json!({"action": message}));
            }
        }
    }
    operation_failure("Evidence bundle inspection failed", projection)
}

fn parse_json_input(input: &str) -> Result<Value, io::Error> {
    if let Ok(value) = serde_json::from_str(input) {
        return Ok(value);
    }
    let text = std::fs::read_to_string(input)?;
    serde_json::from_str(&text).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn bundle_json(bundle: rea_core::evidence::bundle::EvidenceBundle) -> Result<Value, Value> {
    let records = ArtifactRecords::default();
    records.import(bundle).map_err(|error| {
        AnalysisError::output("get_evidence_bundle", error.to_string()).project()
    })?;
    let snapshot = records.snapshot().map_err(|error| {
        AnalysisError::output("get_evidence_bundle", error.to_string()).project()
    })?;
    let mut bytes = Vec::new();
    snapshot.write_canonical(&mut bytes).map_err(|error| {
        AnalysisError::output("get_evidence_bundle", error.to_string()).project()
    })?;
    let raw = RawValue::from_string(String::from_utf8(bytes).map_err(|error| {
        AnalysisError::output("get_evidence_bundle", error.to_string()).project()
    })?)
    .map_err(|error| AnalysisError::output("get_evidence_bundle", error.to_string()).project())?;
    Ok(rea_mcp::raw_cli_value(&raw))
}

fn validate_record_filters(filters: Option<&Map<String, Value>>) -> Option<Value> {
    let filters = filters?;
    for (field, value) in filters {
        if !matches!(
            field.as_str(),
            "evidence_id"
                | "operation"
                | "target_sha256"
                | "analysis_profile_digest"
                | "procedure_address"
        ) {
            return Some(input_projection(
                "get_evidence_bundle",
                &["filters"],
                "unrecognized_key",
                "Unknown evidence record filter.",
            ));
        }
        if !value.is_string() || value.as_str().is_some_and(str::is_empty) {
            return Some(input_projection(
                "get_evidence_bundle",
                &["filters"],
                "invalid_type",
                "Evidence record filters must be non-empty strings.",
            ));
        }
    }
    None
}

fn record_matches_filters(
    record: &rea_core::evidence::record::EvidenceRecord,
    filters: Option<&Map<String, Value>>,
) -> bool {
    let Some(filters) = filters else { return true };
    filters
        .get("evidence_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value == record.evidence_id())
        && filters
            .get("operation")
            .and_then(Value::as_str)
            .is_none_or(|value| record.operation_matches(value))
        && filters
            .get("target_sha256")
            .and_then(Value::as_str)
            .is_none_or(|value| record.subject_sha256() == Some(value))
        && filters
            .get("analysis_profile_digest")
            .and_then(Value::as_str)
            .is_none_or(|value| record.analysis_profile_digest() == Some(value))
        && filters
            .get("procedure_address")
            .and_then(Value::as_str)
            .is_none_or(|value| native_procedure_address(record).as_deref() == Some(value))
}

fn native_summary(record: &rea_core::evidence::record::EvidenceRecord) -> Value {
    if !record.operation_matches("analyze_function") {
        return json!({"available": false, "reason": "different-operation"});
    }
    let Ok(normalized) = serde_json::from_str::<Value>(record.normalized_result().get()) else {
        return json!({"available": false, "reason": "not-recorded-or-incompatible"});
    };
    let Some(procedure) = normalized.get("procedure").and_then(Value::as_object) else {
        return json!({"available": false, "reason": "not-recorded-or-incompatible"});
    };
    let Some(address) = procedure.get("address").and_then(Value::as_str) else {
        return json!({"available": false, "reason": "not-recorded-or-incompatible"});
    };
    let value_flow = match normalized.get("native_value_flow") {
        None => json!({"status": "not-recorded"}),
        Some(flow) if flow.get("available") == Some(&Value::Bool(true)) => json!({
            "status": "observed",
            "truncated": flow.get("truncated").and_then(Value::as_bool).unwrap_or(false),
            "omitted_operations_lower_bound": flow.get("omitted_operations_lower_bound").cloned().unwrap_or(Value::Null),
            "known_omitted_inputs": flow.get("known_omitted_inputs").cloned().unwrap_or(Value::Null),
            "known_omitted_edges": flow.get("known_omitted_edges").cloned().unwrap_or(Value::Null),
        }),
        Some(flow) if flow.get("available") == Some(&Value::Bool(false)) => json!({
            "status": "unavailable",
            "reason": flow.get("reason").cloned().unwrap_or(Value::String("unknown".to_owned())),
        }),
        Some(_) => {
            json!({"status": "unknown", "reason": "Value-flow metadata has an incompatible representation."})
        }
    };
    json!({"available": true, "procedure_address": address, "procedure_name": procedure.get("name").cloned().unwrap_or(Value::Null), "value_flow": value_flow})
}

fn native_procedure_address(record: &rea_core::evidence::record::EvidenceRecord) -> Option<String> {
    native_summary(record)
        .get("procedure_address")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Execute one GDB command in an ephemeral persistent session and always close it.
pub fn debug_with_gdb(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if gdb_command_may_invalidate_detach_proof(command) {
        return operation_failure(
            "GDB debugging failed",
            input_projection(
                "gdb_console",
                &["command"],
                "invalid_value",
                "The one-shot command may invalidate the configured inferior output sink.",
            ),
        );
    }
    let started = match outcome(runner.invoke(
        "start_gdb_session",
        json!({"inferior_tty": options.get("inferiorTty").cloned().unwrap_or(Value::Null)}),
    )) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Some(session_id) = started
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        return operation_failure(
            "GDB debugging failed",
            AnalysisError::output(
                "start_gdb_session",
                "Debugger startup did not return a session_id.",
            )
            .project(),
        );
    };
    let result = outcome(runner.invoke(
        "gdb_console",
        json!({"session_id": session_id, "command": command}),
    ));
    let closed = outcome(runner.invoke("close_gdb_session", json!({"session_id": session_id})));
    finish_debugger_command(result, closed)
}

fn gdb_command_may_invalidate_detach_proof(command: &str) -> bool {
    let first = command
        .split(|character: char| character.is_whitespace() || character == ';')
        .find(|token| !token.is_empty())
        .map(str::to_ascii_lowercase);
    let first_is = |name: &str| {
        first
            .as_deref()
            .is_some_and(|value| name.starts_with(value))
    };
    let setting = command
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|pair| pair[0] == "set" || pair[0] == "with")
        .map(|pair| pair[1].to_ascii_lowercase());
    let changes_tty = setting
        .as_deref()
        .is_some_and(|value| "inferior-tty".starts_with(value))
        || command.to_ascii_lowercase().contains("inferior-tty");
    changes_tty
        || first_is("tty")
        || first_is("source")
        || first_is("define")
        || first_is("alias")
        || first
            .as_deref()
            .is_some_and(|value| value == "py" || "python".starts_with(value))
        || first_is("run") && command.contains(['<', '>', '&'])
        || command.contains([';', '\r', '\n'])
        || command.contains(['<', '>'])
}

/// Execute one Rizin debugger command in an ephemeral persistent session and close it.
pub fn debug_with_rizin(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if command.contains(['\r', '\n']) {
        return operation_failure(
            "Rizin debugging failed",
            input_projection(
                "rizin_debug_command",
                &["command"],
                "invalid_format",
                "command must not contain carriage-return or newline",
            ),
        );
    }
    let mut start = Map::new();
    start.insert(
        "path".to_owned(),
        Value::String(absolute_caller_path(
            args.get("path").and_then(Value::as_str).unwrap_or_default(),
        )),
    );
    start.insert(
        "inferior_tty".to_owned(),
        options.get("inferiorTty").cloned().unwrap_or(Value::Null),
    );
    if let Some(backend) = options.get("backend") {
        start.insert("backend".to_owned(), backend.clone());
    }
    let started = match outcome(runner.invoke("start_rizin_debug_session", Value::Object(start))) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Some(session_id) = started
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        return operation_failure(
            "Rizin debugging failed",
            AnalysisError::output(
                "start_rizin_debug_session",
                "Debugger startup did not return a session_id.",
            )
            .project(),
        );
    };
    let result = outcome(runner.invoke("rizin_debug_command", json!({"session_id": session_id, "command": args.get("command").cloned().unwrap_or(Value::Null)})));
    let closed = outcome(runner.invoke(
        "close_rizin_debug_session",
        json!({"session_id": session_id}),
    ));
    finish_debugger_command(result, closed)
}

fn finish_debugger_command(result: Result<Value, Value>, closed: Result<Value, Value>) -> Value {
    match (result, closed) {
        (Ok(value), Ok(_)) => value,
        (Ok(value), Err(cleanup)) => merge_cleanup_failure(value, cleanup),
        (Err(primary), Ok(_)) => primary,
        (Err(primary), Err(cleanup)) => merge_cleanup_failure(primary, cleanup),
    }
}

fn merge_cleanup_failure(output: Value, cleanup: Value) -> Value {
    let mut result = match output {
        Value::Object(object) if object.get("error").is_some() => object,
        partial => Map::from_iter([
            (
                "error".to_owned(),
                Value::String("Analysis failed".to_owned()),
            ),
            ("partial_observation".to_owned(), partial),
        ]),
    };
    let mut details = result
        .remove("details")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    details.insert("cleanup".to_owned(), Value::String("incomplete".to_owned()));
    details.insert("cleanup_error".to_owned(), cleanup);
    result.insert(
        "code".to_owned(),
        Value::String("cleanup_incomplete".to_owned()),
    );
    result.insert("retryable".to_owned(), Value::Bool(false));
    result.insert("details".to_owned(), Value::Object(details));
    Value::Object(result)
}
