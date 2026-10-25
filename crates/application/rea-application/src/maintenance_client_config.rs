//! Format-aware, read-only inspection of client MCP configuration.
//!
//! This module deliberately stops at an immutable inspection and mutation
//! intent. Filesystem transactions belong to the maintenance workflow owner;
//! callers must use the returned digest to prove that the inspected bytes are
//! still the bytes they are about to publish.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use toml_edit::{DocumentMut, Item, TableLike, Value as TomlValue};
use yaml_rust2::{Yaml, YamlLoader};

mod jsonc;
pub mod special;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigFormat {
    Json,
    Jsonc,
    Toml,
    Yaml,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationState {
    Missing,
    Absent,
    Owned,
    Foreign,
    Malformed(String),
    Unreadable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationInspection {
    pub path: std::path::PathBuf,
    pub format: ClientConfigFormat,
    pub server_path: Vec<String>,
    pub state: RegistrationState,
    pub source_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationOperation {
    Configure,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedClientChange {
    pub original_sha256: String,
    pub bytes: Vec<u8>,
    pub operation: RegistrationOperation,
}

/// Classify a parsed command using the same identity rules as the TypeScript
/// registration owner. Direct launchers are accepted only when both absolute
/// paths resolve to the current executable; failed resolution remains foreign.
pub fn is_owned_registration_command(
    command: &str,
    args: &[&str],
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> bool {
    if is_owned_command(command, args) {
        return true;
    }
    if args == ["mcp"] {
        if let Some(entrypoint) = current_entrypoint {
            return same_real_path(Path::new(command), entrypoint);
        }
    }
    if args.len() == 2 && args[1] == "mcp" {
        if let (Some(node), Some(entrypoint)) = (current_node, current_entrypoint) {
            return same_real_path(Path::new(command), node)
                && same_real_path(Path::new(args[0]), entrypoint);
        }
    }
    false
}

fn same_real_path(candidate: &Path, expected: &Path) -> bool {
    if !candidate.is_absolute() || !expected.is_absolute() {
        return false;
    }
    std::fs::canonicalize(candidate)
        .ok()
        .zip(std::fs::canonicalize(expected).ok())
        .is_some_and(|(left, right)| left == right)
}

/// Prepare a complete replacement document from the inspected source.
///
/// The transaction owner must compare `original_sha256` with the current file
/// before publishing `bytes`. Unknown or foreign registrations are never
/// removed, and malformed documents are never rewritten.
pub fn prepare_change(
    source: &[u8],
    format: ClientConfigFormat,
    server_path: &[&str],
    operation: RegistrationOperation,
) -> Result<PreparedClientChange, String> {
    prepare_change_with_dialect(source, format, server_path, operation, "")
}

/// Prepare a registration using a client-specific entry dialect.
pub fn prepare_change_with_dialect(
    source: &[u8],
    format: ClientConfigFormat,
    server_path: &[&str],
    operation: RegistrationOperation,
    dialect: &str,
) -> Result<PreparedClientChange, String> {
    prepare_change_with_dialect_and_environment(
        source,
        format,
        server_path,
        operation,
        dialect,
        &std::collections::BTreeMap::new(),
    )
}

/// Prepare a registration with the caller-approved environment fragment.
///
/// The empty map used by the compatibility wrapper above intentionally means
/// “emit no environment”. Callers that have validated an explicit fragment
/// should use this entry point so ambient process variables are never copied.
pub fn prepare_change_with_dialect_and_environment(
    source: &[u8],
    format: ClientConfigFormat,
    server_path: &[&str],
    operation: RegistrationOperation,
    dialect: &str,
    environment: &std::collections::BTreeMap<String, String>,
) -> Result<PreparedClientChange, String> {
    prepare_change_with_registration(
        source,
        format,
        server_path,
        operation,
        dialect,
        &[],
        environment,
    )
}

/// Prepare a registration with the exact launcher selected by setup.
///
/// An empty command retains the compatibility behavior of selecting the
/// existing owned launcher, or the pinned npx registration for a new entry.
/// A non-empty command is authoritative for configure operations; this lets
/// installed entrypoints and package-runner choices survive the native
/// migration without reconstructing them from ambient process state.
pub fn prepare_change_with_registration(
    source: &[u8],
    format: ClientConfigFormat,
    server_path: &[&str],
    operation: RegistrationOperation,
    dialect: &str,
    desired_command: &[String],
    environment: &std::collections::BTreeMap<String, String>,
) -> Result<PreparedClientChange, String> {
    let requested_command = (!desired_command.is_empty()).then_some(desired_command);
    prepare_change_with_registration_inner(
        source,
        format,
        server_path,
        operation,
        dialect,
        requested_command,
        environment,
        None,
        None,
    )
}

/// Prepare a selected registration while proving any existing direct
/// launcher against the caller's verified executable identities.
pub fn prepare_change_with_registration_and_identity(
    source: &[u8],
    format: ClientConfigFormat,
    server_path: &[&str],
    operation: RegistrationOperation,
    dialect: &str,
    desired_command: &[String],
    environment: &std::collections::BTreeMap<String, String>,
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> Result<PreparedClientChange, String> {
    let requested_command = (!desired_command.is_empty()).then_some(desired_command);
    prepare_change_with_registration_inner(
        source,
        format,
        server_path,
        operation,
        dialect,
        requested_command,
        environment,
        current_node,
        current_entrypoint,
    )
}

fn prepare_change_with_registration_inner(
    source: &[u8],
    format: ClientConfigFormat,
    server_path: &[&str],
    operation: RegistrationOperation,
    dialect: &str,
    desired_command: Option<&[String]>,
    environment: &std::collections::BTreeMap<String, String>,
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> Result<PreparedClientChange, String> {
    let text = std::str::from_utf8(source).map_err(|error| format!("invalid UTF-8: {error}"))?;
    let resolved_server_path = resolve_server_path(text, format, server_path, dialect);
    let dialect = effective_dialect(&resolved_server_path, dialect);
    let resolved_server_path = resolved_server_path
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let server_path = resolved_server_path.as_slice();
    let inspection = inspect_text_with_dialect_and_identity(
        text,
        format,
        server_path,
        dialect,
        current_node,
        current_entrypoint,
    );
    match (&operation, &inspection) {
        (_, RegistrationState::Malformed(detail)) => {
            return Err(format!(
                "cannot prepare a change from a malformed configuration: {detail}"
            ));
        }
        (RegistrationOperation::Configure, RegistrationState::Foreign) => {
            return Err("configuration contains a foreign REA registration".to_owned());
        }
        (RegistrationOperation::Remove, RegistrationState::Owned) => {}
        (RegistrationOperation::Remove, _) => {
            return Err("removal requires an exactly owned REA registration".to_owned());
        }
        _ => {}
    }
    let launcher = desired_command
        .map(|command| command.to_vec())
        .or_else(|| existing_launcher(text, format, server_path, dialect))
        .unwrap_or_else(default_registration_command);
    let mut desired = special::registration(dialect, &launcher, environment);
    preserve_existing_fields(text, format, server_path, dialect, &mut desired);
    merge_existing_environment(text, format, server_path, dialect, &mut desired);
    preserve_codex_timeouts(text, format, server_path, dialect, &mut desired);
    let bytes = match format {
        ClientConfigFormat::Json => prepare_json(text, server_path, operation, &desired)?,
        ClientConfigFormat::Jsonc if text.trim().is_empty() => {
            prepare_json(text, server_path, operation, &desired)?
        }
        ClientConfigFormat::Jsonc => jsonc::edit(
            text,
            server_path,
            matches!(operation, RegistrationOperation::Configure).then_some(&desired),
        )?,
        ClientConfigFormat::Toml => prepare_toml(text, server_path, operation, &desired)?,
        ClientConfigFormat::Yaml => prepare_yaml(text, operation, dialect, &desired)?,
    };
    Ok(PreparedClientChange {
        original_sha256: format!("{:x}", Sha256::digest(source)),
        bytes,
        operation,
    })
}

fn default_registration_command() -> Vec<String> {
    vec![
        "npx".to_owned(),
        "-y".to_owned(),
        "rea-agents@latest".to_owned(),
        "mcp".to_owned(),
    ]
}

fn prepare_json(
    text: &str,
    server_path: &[&str],
    operation: RegistrationOperation,
    desired: &Value,
) -> Result<Vec<u8>, String> {
    let mut document = if text.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str::<Value>(&normalize_jsonc(text))
            .map_err(|error| format!("invalid JSON configuration: {error}"))?
    };
    let root = document
        .as_object_mut()
        .ok_or_else(|| "configuration root is not an object".to_owned())?;
    let mut cursor = root;
    for key in server_path {
        let value = cursor
            .entry((*key).to_owned())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        cursor = value
            .as_object_mut()
            .ok_or_else(|| format!("{key} is not an object"))?;
    }
    match operation {
        RegistrationOperation::Configure => {
            cursor.insert("rea".to_owned(), desired.clone());
        }
        RegistrationOperation::Remove => {
            cursor.remove("rea");
        }
    }
    serde_json::to_vec_pretty(&document).map_err(|error| error.to_string())
}

fn prepare_toml(
    text: &str,
    server_path: &[&str],
    operation: RegistrationOperation,
    desired: &Value,
) -> Result<Vec<u8>, String> {
    let mut document = text
        .parse::<DocumentMut>()
        .map_err(|error| format!("invalid TOML configuration: {error}"))?;
    let mut table: &mut dyn TableLike = document.as_table_mut();
    for key in server_path {
        let item = table
            .entry(key)
            .or_insert(Item::Table(toml_edit::Table::new()));
        table = item
            .as_table_like_mut()
            .ok_or_else(|| format!("{key} is not a TOML table"))?;
    }
    match operation {
        RegistrationOperation::Configure => {
            let mut registration = toml_edit::Table::new();
            let Some(object) = desired.as_object() else {
                return Err("desired registration is not an object".to_owned());
            };
            for (name, value) in object {
                let item = toml_item_from_json(value)?;
                registration.insert(name, item);
            }
            table.insert("rea", Item::Table(registration));
        }
        RegistrationOperation::Remove => {
            table.remove("rea");
        }
    }
    Ok(document.to_string().into_bytes())
}

fn toml_item_from_json(value: &Value) -> Result<Item, String> {
    match value {
        Value::String(value) => Ok(Item::Value(TomlValue::String(toml_edit::Formatted::new(
            value.clone(),
        )))),
        Value::Bool(value) => Ok(Item::Value(TomlValue::Boolean(toml_edit::Formatted::new(
            *value,
        )))),
        Value::Array(values) => {
            let mut array = toml_edit::Array::new();
            for value in values {
                match value {
                    Value::String(value) => array.push(value.as_str()),
                    Value::Bool(value) => array.push(*value),
                    Value::Number(value) => {
                        let integer = value
                            .as_i64()
                            .ok_or_else(|| "unsupported TOML numeric value".to_owned())?;
                        array.push(integer);
                    }
                    _ => return Err("unsupported nested TOML registration value".to_owned()),
                }
            }
            Ok(Item::Value(TomlValue::Array(array)))
        }
        Value::Object(values) => {
            let mut table = toml_edit::InlineTable::new();
            for (name, value) in values {
                let item = toml_item_from_json(value)?;
                let value = item
                    .as_value()
                    .cloned()
                    .ok_or_else(|| "nested TOML registration object must be scalar".to_owned())?;
                table.insert(name, value);
            }
            Ok(Item::Value(TomlValue::InlineTable(table)))
        }
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                return Ok(Item::Value(TomlValue::Integer(toml_edit::Formatted::new(
                    integer,
                ))));
            }
            if let Some(float) = value.as_f64() {
                return Ok(Item::Value(TomlValue::Float(toml_edit::Formatted::new(
                    float,
                ))));
            }
            Err("unsupported TOML numeric value".to_owned())
        }
        Value::Null => Err("unsupported TOML registration value".to_owned()),
    }
}

fn merge_existing_environment(
    text: &str,
    format: ClientConfigFormat,
    server_path: &[&str],
    dialect: &str,
    desired: &mut Value,
) {
    let Some(existing) = existing_registration_value(text, format, server_path, dialect) else {
        return;
    };
    let environment_key = if dialect == "opencode" || dialect == "opencode_v2" {
        "environment"
    } else {
        "env"
    };
    let Some(existing_environment) = existing
        .as_object()
        .and_then(|object| object.get(environment_key))
        .and_then(Value::as_object)
    else {
        return;
    };
    let Some(desired_object) = desired.as_object_mut() else {
        return;
    };
    let environment = desired_object
        .entry(environment_key.to_owned())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(environment) = environment.as_object_mut() else {
        return;
    };
    for (name, value) in existing_environment {
        environment
            .entry(name.clone())
            .or_insert_with(|| value.clone());
    }
}

fn preserve_existing_fields(
    text: &str,
    format: ClientConfigFormat,
    server_path: &[&str],
    dialect: &str,
    desired: &mut Value,
) {
    let Some(existing) = existing_registration_value(text, format, server_path, dialect) else {
        return;
    };
    let Some(existing) = existing.as_object() else {
        return;
    };
    let Some(desired) = desired.as_object_mut() else {
        return;
    };
    for (name, value) in existing {
        desired.entry(name.clone()).or_insert_with(|| value.clone());
    }
}

fn preserve_codex_timeouts(
    text: &str,
    format: ClientConfigFormat,
    server_path: &[&str],
    dialect: &str,
    desired: &mut Value,
) {
    if dialect != "codex" {
        return;
    }
    let Some(desired_object) = desired.as_object_mut() else {
        return;
    };
    let existing = existing_registration_value(text, format, server_path, dialect);
    let startup = existing
        .as_ref()
        .and_then(|entry| positive_json_integer(entry, "startup_timeout_sec"))
        .unwrap_or(30);
    let tool = existing
        .as_ref()
        .and_then(|entry| positive_json_integer(entry, "tool_timeout_sec"))
        .unwrap_or(720);
    desired_object.insert(
        "startup_timeout_sec".to_owned(),
        Value::Number(startup.into()),
    );
    desired_object.insert("tool_timeout_sec".to_owned(), Value::Number(tool.into()));
}

fn positive_json_integer(entry: &Value, key: &str) -> Option<i64> {
    entry
        .as_object()
        .and_then(|object| object.get(key))
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
}

fn existing_registration_value(
    text: &str,
    format: ClientConfigFormat,
    server_path: &[&str],
    dialect: &str,
) -> Option<Value> {
    match format {
        ClientConfigFormat::Json | ClientConfigFormat::Jsonc => {
            let normalized = if format == ClientConfigFormat::Jsonc {
                normalize_jsonc(text)
            } else {
                text.to_owned()
            };
            let document = serde_json::from_str::<Value>(&normalized).ok()?;
            value_at(&document, server_path, "rea")
                .ok()
                .flatten()
                .cloned()
        }
        ClientConfigFormat::Toml => {
            let document = text.parse::<DocumentMut>().ok()?;
            toml_item_at(&document, server_path, "rea")
                .ok()
                .flatten()
                .and_then(toml_item_to_json)
        }
        ClientConfigFormat::Yaml if dialect == "dsh" => {
            let document = single_yaml_document(text).ok()??;
            find_dsh_registration(&document).and_then(yaml_to_json)
        }
        ClientConfigFormat::Yaml => {
            let document = single_yaml_document(text).ok()??;
            let entry = yaml_at(&document, server_path, "rea").ok().flatten()?;
            yaml_to_json(entry)
        }
    }
}

fn existing_launcher(
    text: &str,
    format: ClientConfigFormat,
    server_path: &[&str],
    dialect: &str,
) -> Option<Vec<String>> {
    let registration = existing_registration_value(text, format, server_path, dialect)?;
    let object = registration.as_object()?;
    if dialect == "opencode" || dialect == "opencode_v2" {
        return object
            .get("command")?
            .as_array()?
            .iter()
            .map(Value::as_str)
            .map(|value| value.map(str::to_owned))
            .collect();
    }
    let command = object.get("command")?.as_str()?.to_owned();
    let mut launcher = vec![command];
    launcher.extend(
        object
            .get("args")?
            .as_array()?
            .iter()
            .map(Value::as_str)
            .map(|value| value.map(str::to_owned))
            .collect::<Option<Vec<_>>>()?,
    );
    Some(launcher)
}

fn toml_item_to_json(item: &Item) -> Option<Value> {
    if let Some(value) = item.as_value() {
        if let Some(value) = value.as_str() {
            return Some(Value::String(value.to_owned()));
        }
        if let Some(value) = value.as_bool() {
            return Some(Value::Bool(value));
        }
        if let Some(value) = value.as_integer() {
            return Some(Value::Number(value.into()));
        }
        if let Some(value) = value.as_array() {
            return Some(Value::Array(
                value.iter().filter_map(toml_value_to_json).collect(),
            ));
        }
        if let Some(value) = value.as_inline_table() {
            return Some(Value::Object(
                value
                    .iter()
                    .filter_map(|(name, value)| {
                        toml_value_to_json(value).map(|value| (name.to_owned(), value))
                    })
                    .collect(),
            ));
        }
    }
    item.as_table_like().map(|table| {
        Value::Object(
            table
                .iter()
                .filter_map(|(name, item)| {
                    toml_item_to_json(item).map(|value| (name.to_owned(), value))
                })
                .collect(),
        )
    })
}

fn toml_value_to_json(value: &TomlValue) -> Option<Value> {
    toml_item_to_json(&Item::Value(value.clone()))
}

fn yaml_to_json(value: &Yaml) -> Option<Value> {
    match value {
        Yaml::Null => Some(Value::Null),
        Yaml::Boolean(value) => Some(Value::Bool(*value)),
        Yaml::Integer(value) => Some(Value::Number((*value).into())),
        Yaml::Real(value) => value
            .parse::<f64>()
            .ok()
            .and_then(|value| serde_json::Number::from_f64(value).map(Value::Number)),
        Yaml::String(value) => Some(Value::String(value.clone())),
        Yaml::Array(values) => Some(Value::Array(
            values.iter().filter_map(yaml_to_json).collect(),
        )),
        Yaml::Hash(values) => Some(Value::Object(
            values
                .iter()
                .filter_map(|(name, value)| {
                    name.as_str()
                        .and_then(|name| yaml_to_json(value).map(|value| (name.to_owned(), value)))
                })
                .collect(),
        )),
        _ => None,
    }
}

fn find_dsh_registration(value: &Yaml) -> Option<&Yaml> {
    if let Some(hash) = value.as_hash() {
        if hash
            .get(&Yaml::String("id".to_owned()))
            .and_then(Yaml::as_str)
            == Some("rea-mcp")
        {
            return hash.get(&Yaml::String("config".to_owned()));
        }
        for child in hash.values() {
            if let Some(found) = find_dsh_registration(child) {
                return Some(found);
            }
        }
    }
    value
        .as_vec()
        .and_then(|values| values.iter().find_map(find_dsh_registration))
}

fn prepare_yaml(
    text: &str,
    operation: RegistrationOperation,
    dialect: &str,
    desired: &Value,
) -> Result<Vec<u8>, String> {
    let rendered = match dialect {
        "dsh" => special::edit_dsh_patch(
            text,
            matches!(operation, RegistrationOperation::Configure).then_some(desired),
        )?,
        _ => special::edit_hermes_yaml(
            text,
            matches!(operation, RegistrationOperation::Configure).then_some(desired),
        )?,
    };
    Ok(rendered.into_bytes())
}

pub fn inspect_path(
    path: impl AsRef<Path>,
    format: ClientConfigFormat,
    server_path: &[&str],
) -> RegistrationInspection {
    inspect_path_with_dialect(path, format, server_path, "")
}

pub fn inspect_path_with_dialect(
    path: impl AsRef<Path>,
    format: ClientConfigFormat,
    server_path: &[&str],
    dialect: &str,
) -> RegistrationInspection {
    inspect_path_with_dialect_and_identity(path, format, server_path, dialect, None, None)
}

/// Inspect a registration with the verified current Node and REA entrypoint.
///
/// These paths are optional because package-runner registrations do not need
/// them. When supplied, direct native and Node-script launchers are accepted
/// only after both executable identities resolve to the verified paths.
pub fn inspect_path_with_dialect_and_identity(
    path: impl AsRef<Path>,
    format: ClientConfigFormat,
    server_path: &[&str],
    dialect: &str,
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> RegistrationInspection {
    let path = path.as_ref().to_path_buf();
    let source = match crate::maintenance_client_transaction::read_client_source_path(&path) {
        Ok(Some(source)) => source,
        Ok(None) => {
            return RegistrationInspection {
                path,
                format,
                server_path: server_path.iter().map(|part| (*part).to_owned()).collect(),
                state: RegistrationState::Missing,
                source_sha256: None,
            };
        }
        Err(error) => {
            return RegistrationInspection {
                path,
                format,
                server_path: server_path.iter().map(|part| (*part).to_owned()).collect(),
                state: RegistrationState::Unreadable(error.to_string()),
                source_sha256: None,
            };
        }
    };
    let resolved_server_path = std::str::from_utf8(&source)
        .ok()
        .map(|text| resolve_server_path(text, format, server_path, dialect))
        .unwrap_or_else(|| server_path.iter().map(|part| (*part).to_owned()).collect());
    let resolved_server_path = resolved_server_path
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let digest = format!("{:x}", Sha256::digest(&source));
    let effective_dialect = effective_dialect(&resolved_server_path, dialect);
    let state = match std::str::from_utf8(&source) {
        Ok(text) => inspect_text_with_dialect_and_identity(
            text,
            format,
            &resolved_server_path,
            effective_dialect,
            current_node,
            current_entrypoint,
        ),
        Err(error) => RegistrationState::Malformed(format!("invalid UTF-8: {error}")),
    };
    RegistrationInspection {
        path,
        format,
        server_path: resolved_server_path
            .iter()
            .map(|part| (*part).to_owned())
            .collect(),
        state,
        source_sha256: Some(digest),
    }
}

fn effective_dialect<'a, T: AsRef<str>>(server_path: &[T], dialect: &'a str) -> &'a str {
    if dialect == "opencode"
        && server_path.len() == 2
        && server_path[0].as_ref() == "mcp"
        && server_path[1].as_ref() == "servers"
    {
        "opencode_v2"
    } else {
        dialect
    }
}

/// Resolve a client dialect's native server table from the parsed source.
///
/// OpenCode V2 stores servers below mcp.servers, while V1 stores them
/// directly below mcp. ZCode always uses the nested mcp.servers table.
pub fn resolve_server_path(
    text: &str,
    format: ClientConfigFormat,
    configured_path: &[&str],
    dialect: &str,
) -> Vec<String> {
    let mut path = configured_path
        .iter()
        .map(|part| (*part).to_owned())
        .collect::<Vec<_>>();
    if dialect == "zcode" && path == ["mcp"] {
        path.push("servers".to_owned());
        return path;
    }
    if dialect != "opencode" || path != ["mcp"] {
        return path;
    }
    let normalized = if format == ClientConfigFormat::Jsonc {
        normalize_jsonc(text)
    } else {
        text.to_owned()
    };
    let Ok(document) = serde_json::from_str::<Value>(&normalized) else {
        return path;
    };
    let Some(mcp) = document.get("mcp").and_then(Value::as_object) else {
        return path;
    };
    let Some(native) = mcp.get("servers") else {
        return path;
    };
    let v1_server_named_servers = native
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .is_some();
    if !v1_server_named_servers {
        path.push("servers".to_owned());
    }
    path
}

/// Compare configuration documents by parsed meaning, ignoring formatting and
/// JSONC comments while preserving malformed input as non-equivalent.
pub fn configuration_semantically_equal(
    source: &[u8],
    prepared: &[u8],
    format: ClientConfigFormat,
) -> bool {
    match format {
        ClientConfigFormat::Json | ClientConfigFormat::Jsonc => {
            let parse = |bytes: &[u8]| {
                let text = std::str::from_utf8(bytes).ok()?;
                let text = if format == ClientConfigFormat::Jsonc {
                    normalize_jsonc(text)
                } else {
                    text.to_owned()
                };
                serde_json::from_str::<Value>(&text).ok()
            };
            matches!((parse(source), parse(prepared)), (Some(left), Some(right)) if left == right)
        }
        ClientConfigFormat::Toml => {
            let parse = |bytes: &[u8]| {
                let text = std::str::from_utf8(bytes).ok()?;
                let document = text.parse::<DocumentMut>().ok()?;
                Some(Value::Object(
                    document
                        .as_table()
                        .iter()
                        .filter_map(|(name, item)| {
                            toml_item_to_json(item).map(|value| (name.to_owned(), value))
                        })
                        .collect(),
                ))
            };
            matches!((parse(source), parse(prepared)), (Some(left), Some(right)) if left == right)
        }
        ClientConfigFormat::Yaml => {
            let parse = |bytes: &[u8]| {
                let text = std::str::from_utf8(bytes).ok()?;
                single_yaml_document(text).ok()?
            };
            matches!((parse(source), parse(prepared)), (Some(left), Some(right)) if left == right)
        }
    }
}

fn inspect_text_with_identity(
    text: &str,
    format: ClientConfigFormat,
    server_path: &[&str],
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> RegistrationState {
    match format {
        ClientConfigFormat::Json => {
            inspect_json(text, server_path, false, current_node, current_entrypoint)
        }
        ClientConfigFormat::Jsonc => {
            inspect_json(text, server_path, true, current_node, current_entrypoint)
        }
        ClientConfigFormat::Toml => {
            inspect_toml(text, server_path, current_node, current_entrypoint)
        }
        ClientConfigFormat::Yaml => {
            inspect_yaml(text, server_path, current_node, current_entrypoint)
        }
    }
}

fn inspect_text_with_dialect_and_identity(
    text: &str,
    format: ClientConfigFormat,
    server_path: &[&str],
    dialect: &str,
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> RegistrationState {
    if format == ClientConfigFormat::Yaml && dialect == "dsh" {
        return match special::inspect_dsh_patch(text) {
            Ok(special::DshInspection::Missing) => RegistrationState::Absent,
            Ok(special::DshInspection::Owned) => RegistrationState::Owned,
            Ok(special::DshInspection::Foreign) => RegistrationState::Foreign,
            Ok(special::DshInspection::Unknown) => RegistrationState::Malformed(
                "Cordis registration shape is structurally unknown".to_owned(),
            ),
            Err(detail) => RegistrationState::Malformed(detail),
        };
    }
    if matches!(format, ClientConfigFormat::Json | ClientConfigFormat::Jsonc) && !dialect.is_empty()
    {
        let normalized = if matches!(format, ClientConfigFormat::Jsonc) {
            normalize_jsonc(text)
        } else {
            text.to_owned()
        };
        let Ok(document) = serde_json::from_str::<Value>(&normalized) else {
            return inspect_text_with_identity(
                text,
                format,
                server_path,
                current_node,
                current_entrypoint,
            );
        };
        let entry = match value_at(&document, server_path, "rea") {
            Ok(Some(entry)) => entry,
            Ok(None) => return RegistrationState::Absent,
            Err(detail) => return RegistrationState::Malformed(detail),
        };
        return if special::is_owned_registration_with_identity(
            dialect,
            entry,
            current_node,
            current_entrypoint,
        ) {
            RegistrationState::Owned
        } else {
            RegistrationState::Foreign
        };
    }
    inspect_text_with_identity(text, format, server_path, current_node, current_entrypoint)
}

pub fn dialect_for_client(client_id: &str) -> &'static str {
    match client_id {
        "codex" => "codex",
        "opencode" => "opencode",
        "vscode" => "vscode",
        "omp" => "omp",
        "pi" => "pi",
        "copilot_cli" => "copilot_cli",
        "commandcode" => "commandcode",
        "hermes" => "hermes",
        "kimi" => "kimi",
        "zcode" => "zcode",
        "dsh" => "dsh",
        _ => "",
    }
}

fn inspect_json(
    text: &str,
    server_path: &[&str],
    jsonc: bool,
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> RegistrationState {
    if text.trim().is_empty() {
        return RegistrationState::Absent;
    }
    let normalized = if jsonc {
        normalize_jsonc(text)
    } else {
        text.to_owned()
    };
    let document = match serde_json::from_str::<Value>(&normalized) {
        Ok(document) => document,
        Err(error) => return RegistrationState::Malformed(error.to_string()),
    };
    let entry = match value_at(&document, server_path, "rea") {
        Ok(Some(entry)) => entry,
        Ok(None) => return RegistrationState::Absent,
        Err(detail) => return RegistrationState::Malformed(detail),
    };
    classify_json_registration(entry, current_node, current_entrypoint)
}

fn inspect_toml(
    text: &str,
    server_path: &[&str],
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> RegistrationState {
    let document = match text.parse::<DocumentMut>() {
        Ok(document) => document,
        Err(error) => return RegistrationState::Malformed(error.to_string()),
    };
    let entry = match toml_item_at(&document, server_path, "rea") {
        Ok(Some(entry)) => entry,
        Ok(None) => return RegistrationState::Absent,
        Err(detail) => return RegistrationState::Malformed(detail),
    };
    classify_toml_registration(entry, current_node, current_entrypoint)
}

fn inspect_yaml(
    text: &str,
    server_path: &[&str],
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> RegistrationState {
    let document = match single_yaml_document(text) {
        Ok(Some(document)) => document,
        Ok(None) => return RegistrationState::Absent,
        Err(error) => return RegistrationState::Malformed(error),
    };
    let entry = match yaml_at(&document, server_path, "rea") {
        Ok(Some(entry)) => entry,
        Ok(None) => return RegistrationState::Absent,
        Err(detail) => return RegistrationState::Malformed(detail),
    };
    classify_yaml_registration(entry, current_node, current_entrypoint)
}

fn single_yaml_document(text: &str) -> Result<Option<Yaml>, String> {
    let documents = YamlLoader::load_from_str(text).map_err(|error| error.to_string())?;
    if documents.len() > 1 {
        return Err("YAML configuration contains multiple documents".to_owned());
    }
    Ok(documents.into_iter().next())
}

fn value_at<'a>(root: &'a Value, path: &[&str], name: &str) -> Result<Option<&'a Value>, String> {
    let mut current = root;
    for key in path {
        let object = current
            .as_object()
            .ok_or_else(|| format!("configuration member {key} is not an object"))?;
        let Some(value) = object.get(*key) else {
            return Ok(None);
        };
        current = value;
    }
    let object = current
        .as_object()
        .ok_or_else(|| "MCP server table is not an object".to_owned())?;
    Ok(object.get(name))
}

fn toml_item_at<'a>(
    root: &'a DocumentMut,
    path: &[&str],
    name: &str,
) -> Result<Option<&'a Item>, String> {
    let mut current: &dyn TableLike = root.as_table();
    for key in path {
        let Some(item) = current.get(*key) else {
            return Ok(None);
        };
        current = item
            .as_table_like()
            .ok_or_else(|| format!("configuration member {key} is not a TOML table"))?;
    }
    Ok(current.get(name))
}

fn yaml_at<'a>(root: &'a Yaml, path: &[&str], name: &str) -> Result<Option<&'a Yaml>, String> {
    let mut current = root;
    for key in path {
        let hash = current
            .as_hash()
            .ok_or_else(|| format!("configuration member {key} is not a YAML mapping"))?;
        let Some(value) = hash.get(&Yaml::String((*key).to_owned())) else {
            return Ok(None);
        };
        current = value;
    }
    let hash = current
        .as_hash()
        .ok_or_else(|| "MCP server table is not a YAML mapping".to_owned())?;
    Ok(hash.get(&Yaml::String(name.to_owned())))
}

fn classify_json_registration(
    entry: &Value,
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> RegistrationState {
    let Some(object) = entry.as_object() else {
        return RegistrationState::Foreign;
    };
    let Some(command) = object.get("command").and_then(Value::as_str) else {
        return RegistrationState::Foreign;
    };
    let Some(args) = object.get("args").and_then(Value::as_array) else {
        return RegistrationState::Foreign;
    };
    let args = args.iter().filter_map(Value::as_str).collect::<Vec<_>>();
    if args.len()
        != object
            .get("args")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    {
        return RegistrationState::Foreign;
    }
    if is_owned_command_with_identity(command, &args, current_node, current_entrypoint) {
        RegistrationState::Owned
    } else {
        RegistrationState::Foreign
    }
}

fn classify_toml_registration(
    entry: &Item,
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> RegistrationState {
    let Some(table) = entry.as_table_like() else {
        return RegistrationState::Foreign;
    };
    let Some(command) = table
        .get("command")
        .and_then(Item::as_value)
        .and_then(TomlValue::as_str)
    else {
        return RegistrationState::Foreign;
    };
    let Some(args) = table
        .get("args")
        .and_then(Item::as_value)
        .and_then(TomlValue::as_array)
    else {
        return RegistrationState::Foreign;
    };
    let values = args
        .iter()
        .filter_map(TomlValue::as_str)
        .collect::<Vec<_>>();
    if values.len() != args.len() {
        return RegistrationState::Foreign;
    }
    if is_owned_command_with_identity(command, &values, current_node, current_entrypoint) {
        RegistrationState::Owned
    } else {
        RegistrationState::Foreign
    }
}

fn classify_yaml_registration(
    entry: &Yaml,
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> RegistrationState {
    let Some(table) = entry.as_hash() else {
        return RegistrationState::Foreign;
    };
    let Some(command) = table
        .get(&Yaml::String("command".to_owned()))
        .and_then(Yaml::as_str)
    else {
        return RegistrationState::Foreign;
    };
    let Some(args) = table
        .get(&Yaml::String("args".to_owned()))
        .and_then(Yaml::as_vec)
    else {
        return RegistrationState::Foreign;
    };
    let values = args.iter().filter_map(Yaml::as_str).collect::<Vec<_>>();
    if values.len() != args.len() {
        return RegistrationState::Foreign;
    }
    if is_owned_command_with_identity(command, &values, current_node, current_entrypoint) {
        RegistrationState::Owned
    } else {
        RegistrationState::Foreign
    }
}

fn is_owned_command(command: &str, args: &[&str]) -> bool {
    is_owned_command_with_identity(command, args, None, None)
}

fn is_owned_command_with_identity(
    command: &str,
    args: &[&str],
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> bool {
    match command {
        "npx" => args.len() == 3 && args[0] == "-y" && is_rea_package(args[1]) && args[2] == "mcp",
        "bunx" => args.len() == 2 && is_rea_package(args[0]) && args[1] == "mcp",
        "bun" => args.len() == 3 && args[0] == "x" && is_rea_package(args[1]) && args[2] == "mcp",
        _ if args == ["mcp"] => current_entrypoint
            .is_some_and(|entrypoint| same_real_path(Path::new(command), entrypoint)),
        _ if args.len() == 2 && args[1] == "mcp" => {
            let (Some(node), Some(entrypoint)) = (current_node, current_entrypoint) else {
                return false;
            };
            same_real_path(Path::new(command), node)
                && same_real_path(Path::new(args[0]), entrypoint)
        }
        _ => false,
    }
}

fn is_rea_package(package: &str) -> bool {
    package == "rea-agents"
        || package == "rea-agents@latest"
        || package
            .strip_prefix("rea-agents@")
            .is_some_and(valid_semver)
}

fn valid_semver(value: &str) -> bool {
    let core = value.split(['-', '+']).next().unwrap_or_default();
    let pieces = core.split('.').collect::<Vec<_>>();
    pieces.len() == 3
        && pieces.iter().all(|piece| {
            !piece.is_empty()
                && piece.chars().all(|character| character.is_ascii_digit())
                && (piece == &"0" || !piece.starts_with('0'))
        })
}

fn normalize_jsonc(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(character) = chars.next() {
        if quoted && escaped {
            escaped = false;
            output.push(character);
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            output.push(character);
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            output.push(character);
            continue;
        }
        if !quoted && character == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for nested in chars.by_ref() {
                if nested == '\n' {
                    output.push('\n');
                    break;
                }
            }
            continue;
        }
        if !quoted && character == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(nested) = chars.next() {
                if nested == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
            continue;
        }
        output.push(character);
    }
    remove_jsonc_trailing_commas(&output)
}

fn remove_jsonc_trailing_commas(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(character) = chars.next() {
        if quoted && escaped {
            escaped = false;
            output.push(character);
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            output.push(character);
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            output.push(character);
            continue;
        }
        if !quoted && character == ',' {
            let mut lookahead = chars.clone();
            while matches!(lookahead.peek(), Some(' ' | '\t' | '\r' | '\n')) {
                lookahead.next();
            }
            if matches!(lookahead.peek(), Some('}' | ']')) {
                continue;
            }
        }
        output.push(character);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_requires_exact_runner_shape() {
        assert!(is_owned_command("npx", &["-y", "rea-agents@latest", "mcp"]));
        assert!(is_owned_command("bunx", &["rea-agents@1.2.3", "mcp"]));
        assert!(!is_owned_command(
            "npx",
            &["--package", "rea-agents", "mcp"]
        ));
        assert!(!is_owned_command("npx", &["-y", "rea-agents", "other"]));
    }

    #[test]
    fn jsonc_comments_and_trailing_commas_are_parsed() {
        let state = inspect_text_with_identity(
            "{ // comment\n \"mcpServers\": { \"rea\": { \"command\": \"npx\", \"args\": [\"-y\", \"rea-agents@latest\", \"mcp\",], }, }, }",
            ClientConfigFormat::Jsonc,
            &["mcpServers"],
            None,
            None,
        );
        assert_eq!(state, RegistrationState::Owned);
    }

    #[test]
    fn malformed_utf8_is_reported_by_path_inspection() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("mcp.json");
        std::fs::write(&path, [0xff, 0xfe]).expect("write fixture");
        let inspection = inspect_path(&path, ClientConfigFormat::Json, &["mcpServers"]);
        assert!(matches!(inspection.state, RegistrationState::Malformed(_)));
        assert!(inspection.source_sha256.is_some());
    }

    #[test]
    fn prepare_json_preserves_unrelated_settings() {
        let source = br#"{"theme":"dark","mcpServers":{"other":{"command":"tool","args":[]}}}"#;
        let change = prepare_change(
            source,
            ClientConfigFormat::Json,
            &["mcpServers"],
            RegistrationOperation::Configure,
        )
        .expect("prepare registration");
        let document: Value = serde_json::from_slice(&change.bytes).expect("valid JSON");
        assert_eq!(document["theme"], "dark");
        assert_eq!(document["mcpServers"]["other"]["command"], "tool");
        assert_eq!(document["mcpServers"]["rea"]["command"], "npx");
    }

    #[test]
    fn prepare_remove_rejects_foreign_registration() {
        let source = br#"{"mcpServers":{"rea":{"command":"other","args":[]}}}"#;
        let error = prepare_change(
            source,
            ClientConfigFormat::Json,
            &["mcpServers"],
            RegistrationOperation::Remove,
        )
        .expect_err("foreign registration must block removal");
        assert!(error.contains("exactly owned"));
    }

    #[test]
    fn dialect_inspection_preserves_malformed_server_container() {
        let state = inspect_text_with_dialect_and_identity(
            r#"{"mcpServers":[]}"#,
            ClientConfigFormat::Json,
            &["mcpServers"],
            "vscode",
            None,
            None,
        );
        assert!(matches!(state, RegistrationState::Malformed(_)));
    }

    #[test]
    fn dsh_inspection_uses_structured_patch_owner() {
        let state = inspect_text_with_dialect_and_identity(
            "- insert:\n    - id: rea-mcp\n      name: '@deepseek-ai/dsh-mcp-client'\n",
            ClientConfigFormat::Yaml,
            &["servers"],
            "dsh",
            None,
            None,
        );
        assert_eq!(state, RegistrationState::Owned);
    }

    #[test]
    fn opencode_v2_resolves_nested_servers_path() {
        let path = resolve_server_path(
            r#"{"mcp":{"servers":{"rea":{"type":"local","command":["npx"]}}}}"#,
            ClientConfigFormat::Json,
            &["mcp"],
            "opencode",
        );
        assert_eq!(path, vec!["mcp", "servers"]);
    }

    #[test]
    fn opencode_v1_keeps_direct_servers_path() {
        let path = resolve_server_path(
            r#"{"mcp":{"servers":{"type":"local","command":["npx"]}}}"#,
            ClientConfigFormat::Json,
            &["mcp"],
            "opencode",
        );
        assert_eq!(path, vec!["mcp"]);
    }

    #[test]
    fn semantic_comparison_rejects_malformed_documents() {
        assert!(!configuration_semantically_equal(
            br#"{"mcpServers":"broken"}"#,
            br#"{"mcpServers":"broken""#,
            ClientConfigFormat::Json,
        ));
        assert!(!configuration_semantically_equal(
            b"mcp_servers = [",
            b"mcp_servers = [",
            ClientConfigFormat::Toml,
        ));
        assert!(!configuration_semantically_equal(
            b"servers: [",
            b"servers: [",
            ClientConfigFormat::Yaml,
        ));
    }

    #[test]
    fn semantic_comparison_rejects_ambiguous_yaml_documents() {
        let source = b"servers:\n  rea:\n    command: rea\n---\nother: true\n";
        assert!(!configuration_semantically_equal(
            source,
            source,
            ClientConfigFormat::Yaml,
        ));
        assert!(matches!(
            inspect_yaml(
                std::str::from_utf8(source).expect("fixture UTF-8"),
                &["servers"],
                None,
                None
            ),
            RegistrationState::Malformed(_)
        ));
    }

    #[test]
    fn selected_registration_command_replaces_stale_owned_launcher() {
        let source =
            br#"{"mcpServers":{"rea":{"command":"npx","args":["-y","rea-agents@1.0.0","mcp"]}}}"#;
        let command = vec!["/opt/rea/scripts/rea.mjs".to_owned(), "mcp".to_owned()];
        let change = prepare_change_with_registration(
            source,
            ClientConfigFormat::Json,
            &["mcpServers"],
            RegistrationOperation::Configure,
            "",
            &command,
            &std::collections::BTreeMap::new(),
        )
        .expect("selected command should be written");
        let document: Value = serde_json::from_slice(&change.bytes).expect("JSON output");
        assert_eq!(document["mcpServers"]["rea"]["command"], command[0]);
        assert_eq!(
            document["mcpServers"]["rea"]["args"],
            serde_json::json!(["mcp"])
        );
    }

    #[test]
    fn codex_registration_adds_defaults_and_preserves_explicit_timeouts() {
        let source = br#"{"mcp_servers":{"rea":{"command":"npx","args":["-y","rea-agents@latest","mcp"],"startup_timeout_sec":91,"tool_timeout_sec":1800}}}"#;
        let change = prepare_change_with_dialect_and_environment(
            source,
            ClientConfigFormat::Json,
            &["mcp_servers"],
            RegistrationOperation::Configure,
            "codex",
            &std::collections::BTreeMap::new(),
        )
        .expect("Codex registration should be prepared");
        let document: Value = serde_json::from_slice(&change.bytes).expect("JSON output");
        assert_eq!(document["mcp_servers"]["rea"]["startup_timeout_sec"], 91);
        assert_eq!(document["mcp_servers"]["rea"]["tool_timeout_sec"], 1800);

        let empty = br#"{"mcp_servers":{}}"#;
        let change = prepare_change_with_dialect_and_environment(
            empty,
            ClientConfigFormat::Json,
            &["mcp_servers"],
            RegistrationOperation::Configure,
            "codex",
            &std::collections::BTreeMap::new(),
        )
        .expect("Codex defaults should be prepared");
        let document: Value = serde_json::from_slice(&change.bytes).expect("JSON output");
        assert_eq!(document["mcp_servers"]["rea"]["startup_timeout_sec"], 30);
        assert_eq!(document["mcp_servers"]["rea"]["tool_timeout_sec"], 720);
    }

    #[test]
    fn codex_toml_registration_serializes_numeric_timeout_defaults() {
        let change = prepare_change_with_dialect_and_environment(
            b"",
            ClientConfigFormat::Toml,
            &["mcp_servers"],
            RegistrationOperation::Configure,
            "codex",
            &std::collections::BTreeMap::new(),
        )
        .expect("Codex TOML registration should be prepared");

        let document = std::str::from_utf8(&change.bytes)
            .expect("generated TOML should be UTF-8")
            .parse::<DocumentMut>()
            .expect("generated TOML should parse");
        let registration = document["mcp_servers"]["rea"]
            .as_table()
            .expect("Codex registration table");
        assert_eq!(registration["startup_timeout_sec"].as_integer(), Some(30));
        assert_eq!(registration["tool_timeout_sec"].as_integer(), Some(720));
    }
}
