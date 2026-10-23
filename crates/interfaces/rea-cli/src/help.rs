//! Help, usage, `--version` and `--schema` rendering, ported from incur's
//! `Help.ts`. REA disables the skills integration (`sync: false`), so the
//! skills built-in is hidden.
use serde_json::Value;

fn kebab(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_uppercase() {
            out.push('-');
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn type_name(property: &Value) -> String {
    if let Some(values) = property.get("enum").and_then(Value::as_array) {
        return values
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("|");
    }
    if property.get("anyOf").is_some() {
        return "value".to_owned();
    }
    match property.get("type").and_then(Value::as_str) {
        Some("integer") => "number".to_owned(),
        Some(other) => other.to_owned(),
        None => "value".to_owned(),
    }
}

/// Global options block shared by root and command help.
fn global_options(root: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if root {
        lines.push(String::new());
        lines.push("Integrations:".to_owned());
        lines.push("  completions  Generate shell completion script".to_owned());
        lines.push("  mcp          Register as MCP server (add, doctor)".to_owned());
    }
    let mut flags: Vec<(&str, &str)> = vec![
        (
            "--filter-output <keys>",
            "Filter output by key paths (e.g. foo,bar.baz,a[0,3])",
        ),
        ("--format <toon|json|yaml|md|jsonl>", "Output format"),
        ("--full-output", "Show full output envelope"),
        ("--help", "Show help"),
        ("--llms, --llms-full", "Print LLM-readable manifest"),
        ("--schema", "Show JSON Schema for command"),
        (
            "--token-count",
            "Print token count of output (instead of output)",
        ),
        ("--token-limit <n>", "Limit output to n tokens"),
        ("--token-offset <n>", "Skip first n tokens of output"),
    ];
    if root {
        flags.push(("--mcp", "Start as MCP stdio server"));
        flags.push(("--update", "Update to latest version"));
        flags.push(("--version", "Show version"));
    }
    flags.sort_by(|a, b| a.0.cmp(b.0));
    let width = flags.iter().map(|(flag, _)| flag.len()).max().unwrap_or(0);
    lines.push(String::new());
    lines.push("Global Options:".to_owned());
    for (flag, desc) in flags {
        lines.push(format!(
            "  {flag}{}  {desc}",
            " ".repeat(width - flag.len())
        ));
    }
    lines
}

/// Root help: the command index plus global options.
pub fn format_root(
    name: &str,
    version: &str,
    description: &str,
    commands: &[(String, String)],
) -> String {
    let mut lines = vec![
        format!("{name}@{version} \u{2014} {description}"),
        String::new(),
        format!("Usage: {name} <command>"),
    ];
    if !commands.is_empty() {
        lines.push(String::new());
        lines.push("Commands:".to_owned());
        let width = commands
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(0);
        for (command, description) in commands {
            if description.is_empty() {
                lines.push(format!("  {command}"));
            } else {
                lines.push(format!(
                    "  {command}{}  {description}",
                    " ".repeat(width - command.len())
                ));
            }
        }
    }
    lines.extend(global_options(true));
    lines.join("\n")
}

/// Per-command help derived from the frozen command contract.
pub fn format_command(name: &str, command: &Value) -> String {
    let description = command
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut lines = vec![format!("{name} \u{2014} {description}"), String::new()];

    let args = command
        .get("args")
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object);
    let required: Vec<&str> = command
        .get("args")
        .and_then(|schema| schema.get("required"))
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let mut synopsis = format!("{name}");
    if let Some(args) = args {
        for (key, property) in args {
            let label = if property.get("type").and_then(Value::as_str) == Some("array") {
                format!("{key}...")
            } else {
                key.clone()
            };
            if required.contains(&key.as_str()) {
                synopsis.push_str(&format!(" <{label}>"));
            } else {
                synopsis.push_str(&format!(" [{label}]"));
            }
        }
    }
    let options = command
        .get("options")
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object);
    if options.is_some() {
        synopsis.push_str(" [options]");
    }
    lines.push(format!("Usage: {synopsis}"));

    if let Some(args) = args
        && !args.is_empty()
    {
        lines.push(String::new());
        lines.push("Arguments:".to_owned());
        let width = args.keys().map(String::len).max().unwrap_or(0);
        for (key, property) in args {
            let description = property
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default();
            lines.push(format!(
                "  {key}{}  {description}",
                " ".repeat(width - key.len())
            ));
        }
    }

    if let Some(options) = options
        && !options.is_empty()
    {
        lines.push(String::new());
        lines.push("Options:".to_owned());
        let entries: Vec<(String, String, Option<String>)> = options
            .iter()
            .map(|(key, property)| {
                let type_text = type_name(property);
                let hint = if type_text == "boolean" {
                    String::new()
                } else {
                    format!(" <{type_text}>")
                };
                let flag = format!("--{}{hint}", kebab(key));
                let description = property
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let default = property.get("default").and_then(|value| {
                    if value == &Value::Bool(false) {
                        None
                    } else {
                        Some(value.to_string())
                    }
                });
                (flag, description, default)
            })
            .collect();
        let width = entries
            .iter()
            .map(|(flag, _, _)| flag.len())
            .max()
            .unwrap_or(0);
        for (flag, description, default) in entries {
            let detail = match default {
                Some(default) => format!("{description} (default: {default})"),
                None => description,
            };
            lines.push(format!(
                "  {flag}{}  {detail}",
                " ".repeat(width - flag.len())
            ));
        }
    }

    lines.extend(global_options(false));
    lines.join("\n")
}

/// `--schema` document: `{ args?, options? }` as the frozen JSON Schemas.
pub fn schema_document(command: &Value) -> Value {
    let mut document = serde_json::Map::new();
    for key in ["args", "options", "env"] {
        if let Some(schema) = command.get(key)
            && !schema.is_null()
        {
            let mut cleaned = schema.clone();
            if let Some(object) = cleaned.as_object_mut() {
                object.remove("$schema");
            }
            document.insert(key.to_owned(), cleaned);
        }
    }
    Value::Object(document)
}
