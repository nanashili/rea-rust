//! Client-specific registration shapes.
//!
//! The ordinary JSON/TOML editor can preserve a server entry as a
//! `{command,args}` object. Several clients use a different, documented
//! shape. This module owns those shapes so the transaction owner does not
//! scatter client-name conditionals through parsing and rollback code.

use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

/// Build the registration object read by a client-specific configuration
/// dialect. The command is kept as caller-provided values; this function does
/// not infer environment variables or rewrite runner arguments.
pub fn registration(
    dialect: &str,
    command: &[String],
    environment: &BTreeMap<String, String>,
) -> Value {
    let executable = command.first().cloned().unwrap_or_else(|| "rea".to_owned());
    let args = command.iter().skip(1).cloned().collect::<Vec<_>>();
    let mut entry = Map::new();

    match dialect {
        "opencode" => {
            entry.insert("type".to_owned(), Value::String("local".to_owned()));
            entry.insert(
                "command".to_owned(),
                Value::Array(command.iter().cloned().map(Value::String).collect()),
            );
            entry.insert("enabled".to_owned(), Value::Bool(true));
            insert_environment(&mut entry, "environment", environment);
        }
        "opencode_v2" => {
            entry.insert("type".to_owned(), Value::String("local".to_owned()));
            entry.insert(
                "command".to_owned(),
                Value::Array(command.iter().cloned().map(Value::String).collect()),
            );
            insert_environment(&mut entry, "environment", environment);
        }
        "vscode" | "omp" | "pi" => {
            entry.insert("type".to_owned(), Value::String("stdio".to_owned()));
            entry.insert("command".to_owned(), Value::String(executable));
            entry.insert(
                "args".to_owned(),
                Value::Array(args.into_iter().map(Value::String).collect()),
            );
            insert_environment(&mut entry, "env", environment);
        }
        "copilot_cli" => {
            entry.insert("type".to_owned(), Value::String("stdio".to_owned()));
            entry.insert("command".to_owned(), Value::String(executable));
            entry.insert(
                "args".to_owned(),
                Value::Array(args.into_iter().map(Value::String).collect()),
            );
            entry.insert(
                "tools".to_owned(),
                Value::Array(vec![Value::String("*".to_owned())]),
            );
            insert_environment(&mut entry, "env", environment);
        }
        "commandcode" => {
            entry.insert("transport".to_owned(), Value::String("stdio".to_owned()));
            entry.insert("enabled".to_owned(), Value::Bool(true));
            entry.insert("command".to_owned(), Value::String(executable));
            entry.insert(
                "args".to_owned(),
                Value::Array(args.into_iter().map(Value::String).collect()),
            );
            insert_environment(&mut entry, "env", environment);
        }
        "hermes" => {
            entry.insert("command".to_owned(), Value::String(executable));
            entry.insert(
                "args".to_owned(),
                Value::Array(args.into_iter().map(Value::String).collect()),
            );
            insert_environment(&mut entry, "env", environment);
            entry.insert("enabled".to_owned(), Value::Bool(true));
        }
        "kimi" => {
            entry.insert("command".to_owned(), Value::String(executable));
            entry.insert(
                "args".to_owned(),
                Value::Array(args.into_iter().map(Value::String).collect()),
            );
            insert_environment(&mut entry, "env", environment);
        }
        "dsh" => {
            entry.insert("serverName".to_owned(), Value::String("rea".to_owned()));
            entry.insert("transport".to_owned(), Value::String("stdio".to_owned()));
            entry.insert("command".to_owned(), Value::String(executable));
            entry.insert(
                "args".to_owned(),
                Value::Array(args.into_iter().map(Value::String).collect()),
            );
            insert_environment(&mut entry, "env", environment);
        }
        // Codex, Grok and the remaining JSON clients use the ordinary shape.
        _ => {
            entry.insert("command".to_owned(), Value::String(executable));
            entry.insert(
                "args".to_owned(),
                Value::Array(args.into_iter().map(Value::String).collect()),
            );
            insert_environment(&mut entry, "env", environment);
        }
    }

    Value::Object(entry)
}

fn insert_environment(
    entry: &mut Map<String, Value>,
    key: &str,
    environment: &BTreeMap<String, String>,
) {
    if environment.is_empty() {
        return;
    }
    let values = environment
        .iter()
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect();
    entry.insert(key.to_owned(), Value::Object(values));
}

/// Return the native server path for a client dialect. OpenCode V2 is
/// detected from the parsed document by the caller; this helper makes that
/// decision explicit instead of treating every OpenCode file as V1.
pub fn server_path(dialect: &str, opencode_v2: bool) -> Vec<String> {
    match dialect {
        "codex" | "toml" | "grok" | "grok_build" | "hermes" => {
            vec!["mcp_servers".to_owned()]
        }
        "opencode" if opencode_v2 => vec!["mcp".to_owned(), "servers".to_owned()],
        "opencode" => vec!["mcp".to_owned()],
        "vscode" => vec!["servers".to_owned()],
        "zcode" => vec!["mcp".to_owned(), "servers".to_owned()],
        _ => vec!["mcpServers".to_owned()],
    }
}

/// Check ownership for a client-specific entry while preserving the common
/// exact-runner rule. OpenCode stores the complete launcher in `command` and
/// therefore has no separate `args` member.
pub fn is_owned_registration(dialect: &str, entry: &Value) -> bool {
    is_owned_registration_with_identity(dialect, entry, None, None)
}

pub fn is_owned_registration_with_identity(
    dialect: &str,
    entry: &Value,
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> bool {
    let Some(object) = entry.as_object() else {
        return false;
    };
    if matches!(dialect, "opencode" | "opencode_v2") {
        let Some(command) = object.get("command").and_then(Value::as_array) else {
            return false;
        };
        let parts = command.iter().filter_map(Value::as_str).collect::<Vec<_>>();
        return parts.len() == command.len()
            && is_owned_parts(&parts, current_node, current_entrypoint);
    }
    let Some(command) = object.get("command").and_then(Value::as_str) else {
        return false;
    };
    let Some(args) = object.get("args").and_then(Value::as_array) else {
        return false;
    };
    let values = args.iter().filter_map(Value::as_str).collect::<Vec<_>>();
    values.len() == args.len()
        && is_owned_command(command, &values, current_node, current_entrypoint)
}

fn is_owned_parts(
    parts: &[&str],
    current_node: Option<&Path>,
    current_entrypoint: Option<&Path>,
) -> bool {
    let Some((command, args)) = parts.split_first() else {
        return false;
    };
    is_owned_command(command, args, current_node, current_entrypoint)
}

fn is_owned_command(
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

fn same_real_path(candidate: &Path, expected: &Path) -> bool {
    if !candidate.is_absolute() || !expected.is_absolute() {
        return false;
    }
    std::fs::canonicalize(candidate)
        .ok()
        .zip(std::fs::canonicalize(expected).ok())
        .is_some_and(|(left, right)| left == right)
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

/// Preserve comments and unrelated YAML while inserting/removing the Hermes
/// registration. Complex inline mappings are rejected because a textual edit
/// cannot prove their ownership or preserve their source representation.
pub fn edit_hermes_yaml(source: &str, registration: Option<&Value>) -> Result<String, String> {
    if source.trim().is_empty() {
        return Ok(match registration {
            Some(entry) => format!("mcp_servers:\n  rea:\n{}", yaml_entry(entry, 4)?),
            None => String::new(),
        });
    }
    let documents = YamlLoader::load_from_str(source).map_err(|error| error.to_string())?;
    if documents.len() > 1 {
        return Err("YAML configuration contains multiple documents".to_owned());
    }
    if !documents
        .first()
        .is_some_and(|document| document.as_hash().is_some())
    {
        return Err("Hermes configuration must have a YAML mapping root".to_owned());
    }
    let lines = source.lines().collect::<Vec<_>>();
    let root = lines
        .iter()
        .position(|line| line.trim_end() == "mcp_servers:")
        .ok_or_else(|| "Hermes YAML requires a block mcp_servers mapping".to_owned())?;
    let end = lines
        .iter()
        .enumerate()
        .skip(root + 1)
        .find(|(_, line)| {
            !line.trim().is_empty() && !line.starts_with(' ') && !line.starts_with('\t')
        })
        .map_or(lines.len(), |(index, _)| index);
    let rea = (root + 1..end).find(|index| {
        let line = lines[*index];
        line.starts_with("  rea:") && (line.len() == 6 || line.as_bytes().get(6) == Some(&b' '))
    });
    let rea_end = rea.map_or(0, |start| {
        (start + 1..end)
            .find(|index| {
                let line = lines[*index];
                !line.trim().is_empty() && !line.starts_with("   ") && !line.starts_with('\t')
            })
            .unwrap_or(end)
    });
    let mut output = lines[..root + 1]
        .iter()
        .map(|line| (*line).to_owned())
        .collect::<Vec<_>>();
    for index in root + 1..end {
        if rea.is_some_and(|start| index >= start && index < rea_end) {
            continue;
        }
        output.push(lines[index].to_owned());
    }
    if let Some(entry) = registration {
        output.push("  rea:".to_owned());
        output.extend(yaml_entry(entry, 4)?.lines().map(str::to_owned));
    }
    output.extend(lines[end..].iter().map(|line| (*line).to_owned()));
    let mut result = output.join("\n");
    if source.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

/// Add a DeepSeek Harness Cordis entry to an empty patch file. Existing patch
/// lists are intentionally rejected here: selectors and expressions can make
/// applicability unknown, so their dedicated owner must inspect and edit
/// those nodes before a transaction can remove or replace them.
pub fn append_dsh_registration(source: &str, registration: &Value) -> Result<String, String> {
    edit_dsh_patch(source, Some(registration))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DshInspection {
    Missing,
    Owned,
    Foreign,
    Unknown,
}

/// Parse the Cordis document before any source-preserving edit. Textual spans
/// are used only after this structural check, so quoted keys, inline maps, and
/// malformed YAML cannot accidentally be treated as an owned registration.
pub fn inspect_dsh_patch(source: &str) -> Result<DshInspection, String> {
    if source.trim().is_empty() {
        return Ok(DshInspection::Missing);
    }
    let documents = YamlLoader::load_from_str(source).map_err(|error| error.to_string())?;
    if documents.len() > 1 {
        return Err("YAML configuration contains multiple documents".to_owned());
    }
    let Some(root) = documents.first() else {
        return Ok(DshInspection::Missing);
    };
    let Some(operations) = root.as_vec() else {
        return Err("Cordis patches must be a YAML sequence".to_owned());
    };
    let mut found_owned = false;
    let mut found_unknown = false;
    for operation in operations {
        let Some(map) = operation.as_hash() else {
            found_unknown = true;
            continue;
        };
        let Some(inserted) = map.get(&Yaml::String("insert".to_owned())) else {
            continue;
        };
        let Some(entries) = inserted.as_vec() else {
            found_unknown = true;
            continue;
        };
        for entry in entries {
            let Some(entry_map) = entry.as_hash() else {
                found_unknown = true;
                continue;
            };
            let id = yaml_string(entry_map, "id");
            let name = yaml_string(entry_map, "name");
            if id.as_deref() == Some("rea-mcp")
                && name.as_deref() == Some("@deepseek-ai/dsh-mcp-client")
            {
                found_owned = true;
            } else if id.as_deref() == Some("rea-mcp") {
                found_unknown = true;
            }
        }
    }
    Ok(if found_owned {
        DshInspection::Owned
    } else if found_unknown {
        DshInspection::Unknown
    } else {
        DshInspection::Foreign
    })
}

fn yaml_string(map: &yaml_rust2::yaml::Hash, key: &str) -> Option<String> {
    map.get(&Yaml::String(key.to_owned()))
        .and_then(Yaml::as_str)
        .map(str::to_owned)
}

/// Edit literal Cordis patch-list entries while retaining unrelated patch
/// operations and their comments. Expression-backed rows are left unknown;
/// they are never treated as owned REA data.
pub fn edit_dsh_patch(source: &str, registration: Option<&Value>) -> Result<String, String> {
    let inspection = inspect_dsh_patch(source)?;
    if inspection == DshInspection::Unknown {
        return Err(
            "expression-backed or structurally unknown Cordis patches cannot be edited safely"
                .to_owned(),
        );
    }
    if registration.is_none() && inspection != DshInspection::Owned {
        return Err("no owned REA Cordis registration was found".to_owned());
    }
    let lines = source.lines().collect::<Vec<_>>();
    let mut starts = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            (!line.trim().is_empty() && !line.starts_with(' ') && line.starts_with('-'))
                .then_some(index)
        })
        .collect::<Vec<_>>();
    if starts.is_empty() && !source.trim().is_empty() {
        return Err("Cordis patches must be a YAML sequence of mappings".to_owned());
    }
    starts.push(lines.len());
    let mut output = starts.first().map_or_else(Vec::new, |first| {
        lines[..*first]
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<Vec<_>>()
    });
    let mut found_owned = false;
    for span in starts.windows(2) {
        let block = &lines[span[0]..span[1]];
        let text = block.join("\n");
        let expression_backed =
            text.contains("${") || text.contains("!expr") || text.contains("!cordis");
        let owned = !expression_backed
            && block
                .iter()
                .any(|line| is_yaml_scalar_field(line, "id", "rea-mcp"))
            && block.iter().any(|line| {
                let trimmed = line.trim();
                trimmed == "name: @deepseek-ai/dsh-mcp-client"
                    || trimmed == "name: \"@deepseek-ai/dsh-mcp-client\""
                    || trimmed == "name: '@deepseek-ai/dsh-mcp-client'"
            });
        if owned {
            found_owned = true;
            continue;
        }
        output.extend(block.iter().map(|line| (*line).to_owned()));
    }
    if let Some(registration) = registration {
        let appended = dsh_entry(registration)?;
        output.extend(appended.lines().map(str::to_owned));
    } else if !found_owned && !source.trim().is_empty() {
        return Err("no owned REA Cordis registration was found".to_owned());
    }
    let mut result = output.join("\n");
    if source.ends_with('\n') || !result.is_empty() {
        result.push('\n');
    }
    Ok(result)
}

fn is_yaml_scalar_field(line: &str, key: &str, expected: &str) -> bool {
    let trimmed = line
        .trim()
        .strip_prefix("- ")
        .unwrap_or_else(|| line.trim());
    let Some(value) = trimmed.strip_prefix(&format!("{key}:")) else {
        return false;
    };
    value.trim().trim_matches(['\'', '"']) == expected
}

fn dsh_entry(registration: &Value) -> Result<String, String> {
    let object = registration
        .as_object()
        .ok_or_else(|| "DSH registration must be an object".to_owned())?;
    let command = object
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| "DSH registration requires command".to_owned())?;
    let args = object
        .get("args")
        .and_then(Value::as_array)
        .ok_or_else(|| "DSH registration requires args".to_owned())?;
    let mut output = String::from(
        "- insert:\n    - id: rea-mcp\n      name: \"@deepseek-ai/dsh-mcp-client\"\n      config:\n",
    );
    output.push_str(&format!(
        "        serverName: \"rea\"\n        transport: \"stdio\"\n        command: {command:?}\n        args:\n"
    ));
    for arg in args {
        let value = arg
            .as_str()
            .ok_or_else(|| "DSH registration args must be strings".to_owned())?;
        output.push_str(&format!("          - {value:?}\n"));
    }
    if let Some(environment) = object.get("env").and_then(Value::as_object) {
        output.push_str("        env:\n");
        for (name, value) in environment {
            let value = value
                .as_str()
                .ok_or_else(|| "DSH environment values must be strings".to_owned())?;
            output.push_str(&format!("          {name}: {value:?}\n"));
        }
    }
    Ok(output)
}

fn yaml_entry(entry: &Value, indent: usize) -> Result<String, String> {
    let object = entry
        .as_object()
        .ok_or_else(|| "Hermes registration must be an object".to_owned())?;
    let prefix = " ".repeat(indent);
    let mut lines = Vec::new();
    for (key, value) in object {
        match value {
            Value::String(value) => lines.push(format!("{prefix}{key}: {value:?}")),
            Value::Bool(value) => lines.push(format!("{prefix}{key}: {value}")),
            Value::Array(values) => {
                lines.push(format!("{prefix}{key}:"));
                for value in values {
                    let text = value.as_str().ok_or_else(|| {
                        "Hermes registration arrays must contain strings".to_owned()
                    })?;
                    lines.push(format!("{prefix}  - {text:?}"));
                }
            }
            Value::Object(values) => {
                lines.push(format!("{prefix}{key}:"));
                for (name, value) in values {
                    let text = value
                        .as_str()
                        .ok_or_else(|| "Hermes environment values must be strings".to_owned())?;
                    lines.push(format!("{prefix}  {name}: {text:?}"));
                }
            }
            _ => return Err(format!("unsupported Hermes value for {key}")),
        }
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencode_uses_array_command_and_local_transport() {
        let value = registration(
            "opencode",
            &[
                "npx".to_owned(),
                "-y".to_owned(),
                "rea-agents@latest".to_owned(),
                "mcp".to_owned(),
            ],
            &BTreeMap::new(),
        );
        assert_eq!(value["type"], "local");
        assert_eq!(value["enabled"], true);
        assert_eq!(value["command"][0], "npx");
        assert!(value.get("args").is_none());
    }

    #[test]
    fn copilot_declares_all_tools() {
        let value = registration(
            "copilot_cli",
            &["rea".to_owned(), "mcp".to_owned()],
            &BTreeMap::new(),
        );
        assert_eq!(value["type"], "stdio");
        assert_eq!(value["tools"], serde_json::json!(["*"]));
    }

    #[test]
    fn hermes_edit_keeps_unrelated_comments() {
        let source =
            "# retain\nmcp_servers:\n  other:\n    command: tool\nsettings:\n  color: blue\n";
        let entry = registration(
            "hermes",
            &["npx".to_owned(), "mcp".to_owned()],
            &BTreeMap::new(),
        );
        let output = edit_hermes_yaml(source, Some(&entry)).expect("edit YAML");
        assert!(output.contains("# retain"));
        assert!(output.contains("other:"));
        assert!(output.contains("rea:"));
        assert!(output.contains("settings:"));
    }

    #[test]
    fn hermes_remove_keeps_root_and_comments() {
        let source =
            "# retain\nmcp_servers:\n  rea:\n    command: npx\n  other:\n    command: tool\n";
        let output = edit_hermes_yaml(source, None).expect("remove YAML");
        assert!(output.contains("# retain"));
        assert!(!output.contains("  rea:"));
        assert!(output.contains("other:"));
    }

    #[test]
    fn dsh_empty_patch_gets_explicit_cordis_entry() {
        let entry =
            serde_json::json!({"command": "npx", "args": ["-y", "rea-agents@latest", "mcp"]});
        let output = append_dsh_registration("", &entry).expect("append DSH registration");
        assert!(output.contains("id: rea-mcp"));
        assert!(output.contains("name: \"@deepseek-ai/dsh-mcp-client\""));
        assert!(output.contains("- \"mcp\""));
    }

    #[test]
    fn dsh_replaces_owned_operation_and_retains_other_operations() {
        let source = "# keep\n- insert:\n    - id: other\n      name: other\n- insert:\n    - id: rea-mcp\n      name: '@deepseek-ai/dsh-mcp-client'\n      config:\n        command: old\n";
        let entry =
            serde_json::json!({"command": "npx", "args": ["-y", "rea-agents@latest", "mcp"]});
        let output = edit_dsh_patch(source, Some(&entry)).expect("replace DSH entry");
        assert!(output.contains("# keep"));
        assert!(output.contains("id: other"));
        assert!(!output.contains("command: old"));
        assert!(output.contains("command: \"npx\""));
    }

    #[test]
    fn dsh_removes_owned_operation_without_touching_foreign_patch() {
        let source = "- insert:\n    - id: rea-mcp\n      name: \"@deepseek-ai/dsh-mcp-client\"\n      config:\n        command: npx\n- insert:\n    - id: other\n      name: other\n";
        let output = edit_dsh_patch(source, None).expect("remove DSH entry");
        assert!(!output.contains("rea-mcp"));
        assert!(output.contains("id: other"));
    }
}
