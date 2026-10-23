//! Runtime projection for captured SQLite inspection Evidence.
//!
//! SQLite parsing belongs to the application/provider producer. This adapter
//! authenticates captured results and never opens, executes, or writes a DB.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_sqlite_database";

pub fn dispatch(input: Value) -> Result<Value, Failure> {
    let object = request_object(&input)?;
    reject_unknown_fields(object)?;

    if let Some(evidence) = object.get("evidence") {
        return project_evidence(evidence);
    }

    let request = required_request(object)?;
    let result = object
        .get("database")
        .ok_or_else(|| invalid("database is required when Evidence is not supplied"))?;
    validate_result(result, request)?;

    Ok(json!({
        "result": result,
        "provenance": {
            "source": "caller-supplied-sqlite-observation",
            "execution": "none",
            "source_path": request["path"],
            "source_sha256": request["sha256"],
        },
    }))
}

fn request_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input.as_object().ok_or_else(|| invalid("input must be an object"))
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    if object.keys().any(|key| !matches!(key.as_str(), "request" | "database" | "evidence")) {
        return Err(invalid("input contains an unsupported field"));
    }
    if object.contains_key("evidence")
        && (object.contains_key("request") || object.contains_key("database"))
    {
        return Err(invalid("supply either Evidence or a database observation"));
    }
    Ok(())
}

fn required_request<'a>(
    object: &'a Map<String, Value>,
) -> Result<&'a Map<String, Value>, Failure> {
    let request = object
        .get("request")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("request must be an object"))?;
    if request.keys().any(|key| {
        !matches!(
            key.as_str(),
            "path" | "sha256" | "table" | "columns" | "schema_scope" | "row_limit"
        )
    }) {
        return Err(invalid("request contains an unsupported field"));
    }
    let path = request
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .ok_or_else(|| invalid("request.path must be non-empty text without NUL bytes"))?;
    if !std::path::Path::new(path).is_absolute() {
        return Err(invalid("request.path must be an absolute local path"));
    }
    let digest = request
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| invalid("request.sha256 must be a lowercase SHA-256 digest"))?;
    let _ = (path, digest);

    let table = request.get("table").and_then(Value::as_str);
    if request.contains_key("table") && table.is_none() {
        return Err(invalid("request.table must be text"));
    }
    if request.get("columns").is_some() && table.is_none() {
        return Err(invalid("request.columns requires request.table"));
    }
    if let Some(columns) = request.get("columns") {
        let values = columns
            .as_array()
            .filter(|values| !values.is_empty())
            .ok_or_else(|| invalid("request.columns must be a non-empty array"))?;
        if values.iter().any(|value| value.as_str().is_none()) {
            return Err(invalid("request.columns must contain only text"));
        }
    }
    if let Some(scope) = request.get("schema_scope") {
        let scope = scope
            .as_str()
            .ok_or_else(|| invalid("request.schema_scope must be text"))?;
        if !matches!(scope, "inventory" | "selected_table" | "database") {
            return Err(invalid("request.schema_scope is unsupported"));
        }
        if scope == "selected_table" && table.is_none() {
            return Err(invalid("request.schema_scope selected_table requires table"));
        }
    }
    if let Some(row_limit) = request.get("row_limit") {
        if table.is_none()
            || row_limit.as_u64().is_none_or(|value| value == 0)
            || row_limit.as_u64().is_some_and(|value| value > i64::MAX as u64)
        {
            return Err(invalid("request.row_limit requires a positive table selection"));
        }
    }
    Ok(request)
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity(&format!("Evidence serialization failed: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&format!("Evidence is malformed: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity(
            "Evidence operation does not match inspect_sqlite_database",
        ));
    }
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence result is malformed: {error}")))?;
    validate_result_shape(&result)?;
    Ok(json!({
        "evidence_id": record.evidence_id(),
        "result": result,
        "provenance": {
            "source": "authenticated-captured-evidence",
            "execution": "unknown",
        },
    }))
}

fn validate_result(result: &Value, request: &Map<String, Value>) -> Result<(), Failure> {
    validate_result_shape(result)?;
    let artifact = result
        .get("artifact")
        .and_then(Value::as_object)
        .ok_or_else(|| integrity("SQLite observation omitted artifact identity"))?;
    if artifact.get("path") != request.get("path") {
        return Err(integrity("SQLite observation changed the selected source path"));
    }
    if artifact.get("sha256") != request.get("sha256") {
        return Err(integrity("SQLite observation changed the selected source digest"));
    }
    let schema = result
        .get("schema")
        .and_then(Value::as_object)
        .ok_or_else(|| integrity("SQLite observation omitted schema"))?;
    let requested_scope = request
        .get("schema_scope")
        .and_then(Value::as_str)
        .unwrap_or(if request.contains_key("table") {
            "selected_table"
        } else {
            "inventory"
        });
    if schema.get("scope").and_then(Value::as_str) != Some(requested_scope) {
        return Err(integrity("SQLite observation changed the selected schema scope"));
    }
    if let Some(table) = request.get("table").and_then(Value::as_str) {
        let tables = schema
            .get("tables")
            .and_then(Value::as_array)
            .ok_or_else(|| integrity("SQLite observation omitted selected table facts"))?;
        if requested_scope == "selected_table"
            && (tables.len() != 1
                || tables[0].get("name").and_then(Value::as_str) != Some(table))
        {
            return Err(integrity("SQLite observation changed the selected table"));
        }
        let rows = result
            .get("rows")
            .and_then(Value::as_object)
            .ok_or_else(|| integrity("SQLite observation omitted selected rows"))?;
        if rows.get("table").and_then(Value::as_str) != Some(table) {
            return Err(integrity("SQLite observation changed the selected row table"));
        }
        if let Some(limit) = request.get("row_limit").and_then(Value::as_u64) {
            if rows.get("row_limit").and_then(Value::as_u64) != Some(limit) {
                return Err(integrity("SQLite observation changed the selected row limit"));
            }
        }
        if let Some(columns) = request.get("columns").and_then(Value::as_array) {
            if rows.get("columns") != Some(&Value::Array(columns.clone())) {
                return Err(integrity("SQLite observation changed the selected columns"));
            }
        }
    } else if !result.get("rows").is_some_and(Value::is_null) {
        return Err(integrity("SQLite inventory unexpectedly contains rows"));
    }
    Ok(())
}

fn validate_result_shape(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| integrity("SQLite observation must be an object"))?;
    for field in ["artifact", "wal", "engine", "database_encoding", "schema", "rows", "limitations"] {
        if !object.contains_key(field) {
            return Err(integrity(&format!("SQLite observation lacks {field}")));
        }
    }
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "artifact" | "wal" | "engine" | "database_encoding" | "schema" | "rows" | "limitations"
        )
    }) {
        return Err(integrity("SQLite observation contains an unsupported field"));
    }
    validate_artifact(object.get("artifact"), "artifact")?;
    if let Some(wal) = object.get("wal") {
        if !wal.is_null() {
            validate_artifact(Some(wal), "wal")?;
        }
    }
    let engine = object
        .get("engine")
        .and_then(Value::as_object)
        .ok_or_else(|| integrity("SQLite observation engine must be an object"))?;
    if engine.get("name").and_then(Value::as_str) != Some("SQLite")
        || engine.get("version").and_then(Value::as_str).is_none_or(str::is_empty)
        || engine.keys().any(|key| !matches!(key.as_str(), "name" | "version"))
    {
        return Err(integrity("SQLite observation engine is malformed"));
    }
    if !matches!(
        object.get("database_encoding").and_then(Value::as_str),
        Some("UTF-8" | "UTF-16le" | "UTF-16be")
    ) {
        return Err(integrity("SQLite observation encoding is malformed"));
    }
    if object.get("limitations").and_then(Value::as_array).is_none() {
        return Err(integrity("SQLite observation limitations must be an array"));
    }
    if object["limitations"].as_array().unwrap().iter().any(|value| value.as_str().is_none()) {
        return Err(integrity("SQLite observation limitations must contain only text"));
    }
    let schema = object["schema"]
        .as_object()
        .ok_or_else(|| integrity("SQLite observation schema must be an object"))?;
    if schema.keys().any(|key| !matches!(key.as_str(), "scope" | "completeness" | "tables" | "indexes" | "views" | "triggers"))
        || !matches!(schema.get("scope").and_then(Value::as_str), Some("inventory" | "selected_table" | "database"))
        || schema.get("completeness").and_then(Value::as_str) != Some("complete")
        || ["tables", "indexes", "views", "triggers"].iter().any(|key| schema.get(*key).and_then(Value::as_array).is_none())
    {
        return Err(integrity("SQLite observation schema is malformed"));
    }
    if let Some(rows) = object.get("rows") {
        if !rows.is_null() {
            let rows = rows.as_object().ok_or_else(|| integrity("SQLite rows must be an object or null"))?;
            if rows.keys().any(|key| !matches!(key.as_str(), "table" | "columns" | "values" | "row_limit" | "returned_rows" | "truncated" | "order"))
                || rows.get("table").and_then(Value::as_str).is_none()
                || rows.get("columns").and_then(Value::as_array).is_none()
                || rows.get("values").and_then(Value::as_array).is_none()
                || rows.get("row_limit").and_then(Value::as_u64).is_none_or(|value| value == 0)
                || rows.get("returned_rows").and_then(Value::as_u64).is_none()
                || rows.get("truncated").and_then(Value::as_bool).is_none()
                || rows.get("order").and_then(Value::as_str) != Some("unspecified")
            {
                return Err(integrity("SQLite observation rows are malformed"));
            }
            let values = rows["values"].as_array().unwrap();
            if rows["returned_rows"].as_u64().unwrap() as usize != values.len()
                || values.iter().any(|row| row.as_array().is_none())
                || values.iter().any(|row| row.as_array().unwrap().len() != rows["columns"].as_array().unwrap().len())
            {
                return Err(integrity("SQLite observation row dimensions are inconsistent"));
            }
        }
    }
    Ok(())
}

fn validate_artifact(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let artifact = value
        .and_then(Value::as_object)
        .ok_or_else(|| integrity(&format!("{field} must be an object")))?;
    if artifact
        .keys()
        .any(|key| !matches!(key.as_str(), "path" | "sha256" | "bytes"))
    {
        return Err(integrity(&format!("{field} contains an unsupported field")));
    }
    for key in ["path", "sha256", "bytes"] {
        if !artifact.contains_key(key) {
            return Err(integrity(&format!("{field} lacks {key}")));
        }
    }
    if artifact
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
        || artifact
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            .is_none()
        || artifact.get("bytes").and_then(Value::as_u64).is_none()
    {
        return Err(integrity(&format!("{field} identity is malformed")));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a caller-supplied SQLite observation and its selected artifact identity."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide intact inspect_sqlite_database Evidence or a matching captured observation."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
