//! REA's native command-line interface.
//!
//! `rea mcp` (bare) serves stdio MCP from the executable; every other
//! invocation enters [`run`], which ports the incur CLI framework REA uses:
//! argument/option parsing, help/usage/`--version`/`--schema`, the global
//! output flags (`--format`, `--json`, `--filter-output`, `--token-*`,
//! `--full-output`), and the output envelope. Each command executes by
//! invoking the shared MCP tool handlers in-process via [`rea_mcp::invoke`].
mod analysis;
mod commands;
mod format;
mod help;
mod invoke;
mod output;
mod parse;
mod util;

use format::Format;
use invoke::Runner;
use output::OutputCtx;
use rea_core::cancellation::Cancellation;
use rea_mcp::catalog::{catalog, cli_command, cli_command_names};
use rea_mcp::{Composition, Registry, Session};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Instant;

const CLI_NAME: &str = "rea";
const CLI_DESCRIPTION: &str = "Reverse engineer anything from your terminal or agent.";

/// Run one CLI invocation (`arguments` excludes the program name) and return
/// the process exit status.
pub fn run(arguments: Vec<String>, composition: &dyn Composition) -> i32 {
    if let Some(code) = handle_mcp_subcommand(&arguments, composition) {
        return code;
    }
    if let Some(message) = configuration_error() {
        eprintln!("{message}");
        return 1;
    }

    let normalized = normalize_cli_arguments(&arguments);
    let flags = extract_builtin_flags(&normalized);

    let format = flags.format.unwrap_or(Format::Toon);
    if let Some(message) = &flags.parse_error {
        let ctx = base_ctx(format, flags.format_explicit);
        print!("{}", output::deliver_error("UNKNOWN", message, None, &ctx));
        return 1;
    }
    if let Some((code, message)) = validate_output(&flags, format) {
        print!("{}", render_output_error(code, &message, format));
        return 1;
    }

    let mut ctx = base_ctx(format, flags.format_explicit);
    ctx.full_output = flags.full_output;
    ctx.token_count = flags.token_count;
    ctx.token_limit = flags.token_limit.map(|value| value.max(0) as usize);
    ctx.token_offset = flags.token_offset.map(|value| value.max(0) as usize);
    ctx.filter = flags.filter_output.as_deref().map(format::filter::parse);

    if flags.update_check {
        return 0;
    }
    if flags.update && !flags.help {
        print!(
            "{}",
            output::deliver_error(
                "UPDATE_FAILED",
                "Use 'rea update' to update the identified installation. The '--update' alias accepts only global output flags.",
                None,
                &ctx,
            )
        );
        return 1;
    }
    if flags.version && !flags.help {
        println!("{}", catalog().server_version);
        return 0;
    }
    if let Ok(shell) = std::env::var("COMPLETE") {
        return complete(&shell, &normalized);
    }
    if flags.mcp {
        return rea_mcp::run_stdio(composition);
    }
    if flags.llms || flags.llms_full {
        println!("{}", llms_manifest());
        return 0;
    }

    let Some(token) = flags.rest.first().cloned() else {
        println!(
            "{}",
            help::format_root(
                CLI_NAME,
                &catalog().server_version,
                CLI_DESCRIPTION,
                &command_index()
            )
        );
        return 0;
    };

    let Some((canonical, command)) = resolve_command(&token) else {
        let message = command_not_found(&token);
        print!(
            "{}",
            output::deliver_error("COMMAND_NOT_FOUND", &message, None, &ctx)
        );
        return 1;
    };

    if flags.help {
        println!(
            "{}",
            help::format_command(&format!("{CLI_NAME} {canonical}"), command)
        );
        return 0;
    }
    if flags.schema {
        println!(
            "{}",
            format::format(&help::schema_document(command), format)
        );
        return 0;
    }

    if command.get("output_policy").and_then(Value::as_str) == Some("agent-only") {
        ctx.agent_only = true;
    }

    let rest: Vec<String> = flags.rest[1..].to_vec();
    let args_schema = command.get("args").filter(|value| !value.is_null());
    let options_schema = command.get("options").filter(|value| !value.is_null());
    let alias = command.get("alias").filter(|value| !value.is_null());

    let parsed = match parse::parse(&rest, args_schema, options_schema, alias) {
        Ok(parsed) => parsed,
        Err(failure) => {
            print!(
                "{}",
                output::deliver_error("UNKNOWN", &failure.message, None, &ctx)
            );
            return 1;
        }
    };

    let (args_value, mut issues) = validate_part(args_schema, &parsed.args);
    let (options_value, option_issues) = validate_part(options_schema, &parsed.options);
    issues.extend(option_issues);
    if !issues.is_empty() {
        print!(
            "{}",
            validation_error_output(&issues, args_schema, options_schema, &ctx)
        );
        return 1;
    }

    let environment: HashMap<String, String> = std::env::vars().collect();
    let session = Arc::new(Session::new(environment));
    let mut registry = Registry::default();
    composition.register(&mut registry, &session);

    #[cfg(unix)]
    let interrupts = rea_host::command_interrupts::CommandInterrupts::install().ok();
    #[cfg(unix)]
    let cancellation = interrupts
        .as_ref()
        .map(|interrupts| interrupts.cancellation().clone())
        .unwrap_or_default();
    #[cfg(not(unix))]
    let cancellation = Cancellation::default();

    let runner = Runner {
        registry: &registry,
        session: &session,
        cancellation,
    };

    let started = Instant::now();
    let value = commands::run_command(canonical, &args_value, &options_value, &runner);
    let duration = started.elapsed().as_millis();
    let kind = commands::failure_kind(canonical);
    let (text, mut exit) = output::deliver(&value, canonical, duration, kind, &ctx);
    print!("{text}");
    let _ = session.close();

    #[cfg(unix)]
    if let Some(interrupts) = interrupts
        && let Some(signal_exit) = interrupts.finish()
    {
        exit = signal_exit as i32;
    }
    exit
}

fn base_ctx(format: Format, format_explicit: bool) -> OutputCtx {
    OutputCtx {
        format,
        human: std::io::stdout().is_terminal() && !format_explicit,
        full_output: false,
        filter: None,
        token_count: false,
        token_limit: None,
        token_offset: None,
        agent_only: false,
    }
}

// ---------------------------------------------------------------------------
// Builtin flag extraction (incur extractBuiltinFlags + output-flag parsing)
// ---------------------------------------------------------------------------
#[derive(Default)]
struct Flags {
    full_output: bool,
    format: Option<Format>,
    format_explicit: bool,
    filter_output: Option<String>,
    token_limit: Option<i64>,
    token_offset: Option<i64>,
    token_count: bool,
    llms: bool,
    llms_full: bool,
    mcp: bool,
    help: bool,
    update: bool,
    update_check: bool,
    version: bool,
    schema: bool,
    rest: Vec<String>,
    parse_error: Option<String>,
    missing_value: Option<String>,
}

fn extract_builtin_flags(argv: &[String]) -> Flags {
    let mut flags = Flags::default();
    let mut index = 0usize;
    while index < argv.len() {
        let token = argv[index].as_str();
        match token {
            "--full-output" => flags.full_output = true,
            "--llms" => flags.llms = true,
            "--llms-full" => flags.llms_full = true,
            "--mcp" => flags.mcp = true,
            "--help" | "-h" => flags.help = true,
            "--update" => flags.update = true,
            "--incur-update-check" => flags.update_check = true,
            "--schema" => flags.schema = true,
            "--token-count" => flags.token_count = true,
            "--json" => {
                flags.format = Some(Format::Json);
                flags.format_explicit = true;
            }
            "--version" => {
                let next = argv.get(index + 1);
                if next.map_or(true, |value| value.starts_with('-')) {
                    flags.version = true;
                } else {
                    flags.rest.push(token.to_owned());
                }
            }
            "--format" => match argv.get(index + 1) {
                Some(value) => match Format::parse(value) {
                    Some(parsed) => {
                        flags.format = Some(parsed);
                        flags.format_explicit = true;
                        index += 1;
                    }
                    None => {
                        flags.parse_error = Some(format!(
                            "Invalid format: \"{value}\". Expected one of: toon, json, yaml, md, jsonl"
                        ));
                        return flags;
                    }
                },
                None => {
                    flags.missing_value.get_or_insert("--format".to_owned());
                }
            },
            "--filter-output" => match argv.get(index + 1) {
                Some(value) => {
                    flags.filter_output = Some(value.clone());
                    index += 1;
                }
                None => {
                    flags
                        .missing_value
                        .get_or_insert("--filter-output".to_owned());
                }
            },
            "--token-limit" | "--token-offset" => match argv.get(index + 1) {
                Some(value) => match value.trim().parse::<f64>() {
                    Ok(number) if number.is_finite() => {
                        if token == "--token-limit" {
                            flags.token_limit = Some(number as i64);
                        } else {
                            flags.token_offset = Some(number as i64);
                        }
                        index += 1;
                    }
                    _ => {
                        flags.parse_error = Some(format!("Invalid value for {token}: \"{value}\""));
                        return flags;
                    }
                },
                None => {
                    flags.missing_value.get_or_insert(token.to_owned());
                }
            },
            other => flags.rest.push(other.to_owned()),
        }
        index += 1;
    }
    flags
}

// ---------------------------------------------------------------------------
// Argument normalization (cliOutput.normalizeCliArguments)
// ---------------------------------------------------------------------------
fn normalize_cli_arguments(arguments: &[String]) -> Vec<String> {
    const VALUED: [&str; 4] = [
        "--format",
        "--filter-output",
        "--token-limit",
        "--token-offset",
    ];
    const ROOT_UPDATE: [&str; 3] = ["--json", "--full-output", "--token-count"];
    let mut normalized: Vec<String> = Vec::new();
    let mut updates: Vec<usize> = Vec::new();
    let mut root_update = true;
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        if VALUED.contains(&argument.as_str())
            && arguments
                .get(index + 1)
                .is_some_and(|next| !next.is_empty())
        {
            normalized.push(argument.clone());
            normalized.push(arguments[index + 1].clone());
            index += 2;
            continue;
        }
        if let Some(equals) = argument.find('=') {
            let flag = &argument[..equals];
            if VALUED.contains(&flag) {
                normalized.push(flag.to_owned());
                normalized.push(argument[equals + 1..].to_owned());
                index += 1;
                continue;
            }
        }
        if argument == "--update" {
            updates.push(normalized.len());
        } else if !ROOT_UPDATE.contains(&argument.as_str()) {
            root_update = false;
        }
        normalized.push(argument.clone());
        index += 1;
    }
    if root_update && !updates.is_empty() {
        let mut routed = vec!["update".to_owned()];
        for (position, argument) in normalized.into_iter().enumerate() {
            if !updates.contains(&position) {
                routed.push(argument);
            }
        }
        routed
    } else {
        normalized
    }
}

// ---------------------------------------------------------------------------
// Output-argument validation (cliOutput.validateCliOutputArguments)
// ---------------------------------------------------------------------------
fn validate_output(flags: &Flags, format: Format) -> Option<(&'static str, String)> {
    if let Some(expression) = &flags.filter_output
        && has_unclosed_filter_slice(expression)
    {
        return Some((
            "INVALID_OUTPUT_FILTER",
            "The --filter-output expression has a slice without a closing ]. Close the slice or remove --filter-output.".to_owned(),
        ));
    }
    let token_window = flags.token_limit.is_some() || flags.token_offset.is_some();
    if token_window && matches!(format, Format::Json | Format::Jsonl | Format::Yaml) {
        return Some((
            "UNSUPPORTED_OUTPUT_COMBINATION",
            "Token windows cannot preserve structured output. Remove --token-limit/--token-offset and use --filter-output or command pagination.".to_owned(),
        ));
    }
    if let Some(flag) = &flags.missing_value {
        return Some((
            "MISSING_OUTPUT_VALUE",
            format!("{flag} requires a value, as in {flag} <value> or {flag}=<value>."),
        ));
    }
    None
}

fn has_unclosed_filter_slice(expression: &str) -> bool {
    let mut depth = 0i32;
    let mut unclosed = false;
    for ch in expression.chars() {
        match ch {
            '[' => {
                depth += 1;
                unclosed = true;
            }
            ']' => {
                depth -= 1;
                unclosed = false;
            }
            ',' if depth == 0 && unclosed => return true,
            _ => {}
        }
    }
    unclosed
}

fn render_output_error(code: &str, message: &str, format: Format) -> String {
    if format == Format::Yaml {
        return format!(
            "ok: false\nerror:\n  code: {code}\n  message: {}\n",
            serde_json::to_string(message).unwrap_or_else(|_| format!("\"{message}\""))
        );
    }
    let value = serde_json::json!({ "ok": false, "error": { "code": code, "message": message } });
    format!("{}\n", serde_json::to_string(&value).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Command resolution
// ---------------------------------------------------------------------------
fn resolve_command(token: &str) -> Option<(&'static str, &'static Value)> {
    for name in cli_command_names() {
        if name == token {
            return cli_command(name).map(|command| (name, command));
        }
    }
    for name in cli_command_names() {
        if let Some(command) = cli_command(name)
            && command
                .get("aliases")
                .and_then(Value::as_array)
                .is_some_and(|aliases| aliases.iter().any(|alias| alias.as_str() == Some(token)))
        {
            return Some((name, command));
        }
    }
    None
}

fn command_index() -> Vec<(String, String)> {
    let mut commands: Vec<(String, String)> = cli_command_names()
        .into_iter()
        .map(|name| {
            let description = cli_command(name)
                .and_then(|command| command.get("description"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            (name.to_owned(), description)
        })
        .collect();
    commands.sort_by(|a, b| a.0.cmp(&b.0));
    commands
}

fn command_not_found(token: &str) -> String {
    let candidates: Vec<&str> = cli_command_names();
    match suggest(token, &candidates) {
        Some(suggestion) => {
            format!("'{token}' is not a command for 'rea'. Did you mean '{suggestion}'?")
        }
        None => format!("'{token}' is not a command for 'rea'."),
    }
}

fn suggest<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let lower = input.to_lowercase();
    let threshold = if input.len() <= 4 { 2 } else { input.len() / 2 };
    let mut best: Option<&str> = None;
    let mut best_score = usize::MAX;
    for candidate in candidates {
        let lower_candidate = candidate.to_lowercase();
        let distance = levenshtein(&lower, &lower_candidate);
        let score = if lower_candidate.starts_with(&lower) && lower_candidate != lower {
            distance
        } else if lower_candidate.contains(&lower) {
            100 + distance
        } else if distance <= threshold {
            200 + distance
        } else {
            continue;
        };
        if score < best_score {
            best_score = score;
            best = Some(candidate);
        }
    }
    best
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut dp: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut prev = dp[0];
        dp[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let temp = dp[j + 1];
            dp[j + 1] = if ca == cb {
                prev
            } else {
                1 + prev.min(dp[j + 1]).min(dp[j])
            };
            prev = temp;
        }
    }
    dp[b.len()]
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------
fn validate_part(schema: Option<&Value>, value: &Value) -> (Value, Vec<rea_mcp::schema::Issue>) {
    match schema {
        Some(schema) => match rea_mcp::schema::validate(schema, value) {
            Ok(parsed) => (parsed, Vec::new()),
            Err(issues) => (value.clone(), issues),
        },
        None => (Value::Object(Map::new()), Vec::new()),
    }
}

fn validation_error_output(
    issues: &[rea_mcp::schema::Issue],
    args_schema: Option<&Value>,
    options_schema: Option<&Value>,
    ctx: &OutputCtx,
) -> String {
    let message = issues
        .iter()
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>()
        .join("; ");
    if ctx.human && !ctx.full_output {
        let mut lines = Vec::new();
        for issue in issues {
            let target = target_label(&issue.path, args_schema, options_schema);
            if issue.message.contains("received undefined") {
                lines.push(format!("Error: missing required {target}"));
            } else {
                lines.push(format!(
                    "Error: invalid value for {target}: {}",
                    issue.message
                ));
            }
        }
        lines.push(String::new());
        lines.push("See --help for usage.".to_owned());
        return format!("{}\n", lines.join("\n"));
    }
    let fields: Vec<Value> = issues
        .iter()
        .map(|issue| serde_json::json!({ "path": issue.path.join("."), "message": issue.message }))
        .collect();
    output::deliver_error(
        "VALIDATION_ERROR",
        &message,
        Some(Value::Array(fields)),
        ctx,
    )
}

fn target_label(
    path: &[String],
    args_schema: Option<&Value>,
    options_schema: Option<&Value>,
) -> String {
    let Some(head) = path.first() else {
        return "input".to_owned();
    };
    let has = |schema: Option<&Value>| {
        schema
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .is_some_and(|properties| properties.contains_key(head))
    };
    if has(options_schema) {
        let mut kebab = String::new();
        for ch in head.chars() {
            if ch.is_ascii_uppercase() {
                kebab.push('-');
                kebab.push(ch.to_ascii_lowercase());
            } else {
                kebab.push(ch);
            }
        }
        format!("--{kebab}")
    } else if has(args_schema) {
        format!("<{}>", path.join("."))
    } else {
        format!("<{}>", path.join("."))
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
fn configuration_error() -> Option<String> {
    let value = std::env::var("REA_LOG_LEVEL").ok()?;
    const LEVELS: [&str; 7] = ["silent", "fatal", "error", "warn", "info", "debug", "trace"];
    if LEVELS.contains(&value.as_str()) {
        None
    } else {
        Some(
            "REA_LOG_LEVEL must be one of: silent, fatal, error, warn, info, debug, trace."
                .to_owned(),
        )
    }
}

// ---------------------------------------------------------------------------
// Shell completion (incur Completions): minimal command-name completion.
// ---------------------------------------------------------------------------
fn complete(shell: &str, argv: &[String]) -> i32 {
    let separator = argv.iter().position(|token| token == "--");
    let words: &[String] = match separator {
        Some(index) => &argv[index + 1..],
        None => argv,
    };
    let index = std::env::var("_COMPLETE_INDEX")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| words.len().saturating_sub(1));
    let current = words.get(index).map(String::as_str).unwrap_or("");
    let mut candidates: Vec<String> = cli_command_names()
        .into_iter()
        .filter(|name| name.starts_with(current))
        .map(str::to_owned)
        .collect();
    candidates.sort();
    let rendered = match shell {
        "zsh" => candidates.join("\n"),
        "fish" => candidates.join("\n"),
        "nushell" => {
            let records: Vec<Value> = candidates
                .into_iter()
                .map(|value| serde_json::json!({ "value": value }))
                .collect();
            serde_json::to_string(&records).unwrap_or_default()
        }
        _ => candidates.join("\u{000b}"),
    };
    if !rendered.is_empty() {
        print!("{rendered}");
    }
    0
}

// ---------------------------------------------------------------------------
// LLM manifest (`--llms` / `--llms-full`): compact command index.
// ---------------------------------------------------------------------------
fn llms_manifest() -> String {
    let mut lines = vec![
        format!("# {CLI_NAME}"),
        String::new(),
        CLI_DESCRIPTION.to_owned(),
        String::new(),
    ];
    lines.push("| Command | Description |".to_owned());
    lines.push("|---------|-------------|".to_owned());
    for (name, description) in command_index() {
        lines.push(format!("| `{CLI_NAME} {name}` | {description} |"));
    }
    lines.push(String::new());
    lines.push(format!(
        "Run `{CLI_NAME} <command> --schema` for argument details."
    ));
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// `rea mcp doctor` / `mcp add` / `mcp --http`
// ---------------------------------------------------------------------------
fn handle_mcp_subcommand(arguments: &[String], composition: &dyn Composition) -> Option<i32> {
    let first = arguments.first().map(String::as_str)?;
    if first != "mcp" && first != "--mcp" {
        return None;
    }
    if arguments
        .iter()
        .skip(1)
        .any(|argument| argument == "--http")
    {
        eprintln!(
            "MCP over HTTP is not available in this native build. Use `rea mcp` for stdio transport."
        );
        return Some(1);
    }
    match arguments.get(1).map(String::as_str) {
        Some("doctor") => Some(mcp_doctor(&arguments[2..], composition)),
        Some("add") => {
            eprintln!(
                "Automatic MCP registration is not available in this native build. Register `{}` manually with your agent.",
                catalog().server_name
            );
            Some(1)
        }
        _ => None,
    }
}

fn mcp_doctor(arguments: &[String], composition: &dyn Composition) -> i32 {
    let mut format = Format::Toon;
    let mut full_output = false;
    let mut index = 0usize;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--json" => format = Format::Json,
            "--full-output" => full_output = true,
            "--help" | "-h" => {
                println!(
                    "{CLI_NAME} mcp doctor \u{2014} Validate MCP server startup and tool listing"
                );
                return 0;
            }
            "--format" => {
                if let Some(value) = arguments
                    .get(index + 1)
                    .and_then(|value| Format::parse(value))
                {
                    format = value;
                    index += 1;
                }
            }
            _ => {}
        }
        index += 1;
    }

    let environment: HashMap<String, String> = std::env::vars().collect();
    let session = Arc::new(Session::new(environment));
    let mut registry = Registry::default();
    composition.register(&mut registry, &session);

    let expected: Vec<&str> = catalog()
        .tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect();
    let missing: Vec<&str> = registry.unbound();
    let healthy = missing.is_empty();
    let runner = Runner {
        registry: &registry,
        session: &session,
        cancellation: Cancellation::default(),
    };
    let request_flow = matches!(
        runner.invoke("binary_session", serde_json::json!({})),
        rea_mcp::Invocation::Success(_)
    );
    let _ = session.close();

    let result = serde_json::json!({
        "healthy": healthy && request_flow,
        "adapter": "production-stdio",
        "server": { "name": catalog().server_name, "version": catalog().server_version },
        "inventory": {
            "expected": expected.len(),
            "observed": expected.len() - missing.len(),
            "missing": missing,
        },
        "request_flow": { "tool": "binary_session", "ok": request_flow },
    });
    let document = if full_output {
        serde_json::json!({ "ok": healthy && request_flow, "data": result })
    } else {
        result
    };
    println!("{}", format::format(&document, format));
    if healthy && request_flow { 0 } else { 1 }
}
