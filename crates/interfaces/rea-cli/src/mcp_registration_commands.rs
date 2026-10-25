//! The explicit `mcp add` command.
//!
//! Registration is deliberately delegated to the approved maintenance
//! workflow.  This adapter only owns the legacy command-line contract and
//! translates its client names into the canonical maintenance identifiers.

use crate::doctor_commands;
use crate::format::Format;
use crate::invoke::Runner;
use crate::maintenance::{self, SetupOptions};
use rea_application::maintenance_client_config::{self, ClientConfigFormat, RegistrationOperation};
use rea_application::maintenance_client_transaction::{
    self as client_transaction, PreparedClientChange,
};
use rea_application::maintenance_clients::{
    self as client_targets, ClientConfigurationFormat, ClientPlatform, ClientRegistrationTarget,
    ClientResolutionContext,
};
use rea_application::maintenance_registration_environment;
use rea_core::cancellation::Cancellation;
use rea_mcp::{Composition, Registry, Session};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Default)]
struct AddOptions {
    agents: Vec<String>,
    command: Option<String>,
    global: bool,
    format: Option<Format>,
    help: bool,
}

/// Register REA with the selected agent configurations.
pub fn add(arguments: &[String], composition: &dyn Composition) -> i32 {
    let options = match parse_options(arguments) {
        Ok(options) => options,
        Err(message) => {
            return print_result(
                &json!({"status":"failed", "code":"MCP_ADD_INVALID_ARGUMENTS", "message":message}),
                Format::Json,
            );
        }
    };
    if options.help {
        print_help();
        return 0;
    }

    if options.command.is_some() || !options.global {
        let result = register_explicit_command(&options, composition);
        let format = options.format.unwrap_or(Format::Toon);
        return print_result(&result, format);
    }

    let context = match local_resolution_context() {
        Ok(context) => context,
        Err(detail) => {
            let result = json!({
                "status": "needs_human",
                "code": "MCP_ADD_ENVIRONMENT",
                "reason": "environment",
                "detail": detail,
            });
            return print_result(&result, options.format.unwrap_or(Format::Json));
        }
    };
    let (_, selection_blockers) = select_targets(&context, &options);
    if !selection_blockers.is_empty() {
        let result = json!({
            "status": "needs_human",
            "scope": "global",
            "blockers": selection_blockers,
        });
        return print_result(&result, options.format.unwrap_or(Format::Json));
    }

    let environment = std::env::vars().collect::<HashMap<_, _>>();
    let session = Arc::new(Session::new(environment));
    let mut registry = Registry::default();
    composition.register(&mut registry, &session);
    let runner = Runner {
        registry: &registry,
        session: &session,
        cancellation: Cancellation::default(),
    };
    let all_detected_clients = options.agents.is_empty();
    let setup_options = SetupOptions {
        approved: true,
        client_ids: options.agents,
        all_detected_clients,
        install_skill: Some(false),
        ..SetupOptions::default()
    };
    let result = maintenance::setup(&setup_options, &runner);
    let result = match session.close() {
        Ok(()) => result,
        Err(failures) => json!({
            "status": "failed",
            "code": "MCP_ADD_CLEANUP_FAILED",
            "detail": "registration completed but session cleanup retained resources",
            "cleanupFailures": failures.iter().map(|failure| format!("{failure:?}")).collect::<Vec<_>>(),
            "result": result,
        }),
    };

    let status = result.get("status").and_then(Value::as_str);
    let format = options.format.unwrap_or(Format::Toon);
    let code = print_result(&result, format);
    if status == Some("ready") {
        0
    } else {
        code.max(1)
    }
}

fn register_explicit_command(options: &AddOptions, composition: &dyn Composition) -> Value {
    let command = match options.command.as_deref() {
        Some(command_text) => match split_command(command_text) {
            Ok(command) if !command.is_empty() => command,
            Ok(_) => {
                return json!({"status":"needs_human", "code":"MCP_ADD_EMPTY_COMMAND", "reason":"registration_identity"});
            }
            Err(error) => {
                return json!({"status":"needs_human", "code":"MCP_ADD_INVALID_COMMAND", "reason":"registration_identity", "detail":error});
            }
        },
        None => match std::env::current_exe() {
            Ok(executable) => vec![executable.to_string_lossy().into_owned(), "mcp".to_owned()],
            Err(error) => {
                return json!({"status":"needs_human", "code":"MCP_ADD_REGISTRATION_IDENTITY", "reason":"registration_identity", "detail":error.to_string()});
            }
        },
    };
    let context = match local_resolution_context() {
        Ok(context) => context,
        Err(error) => {
            return json!({"status":"needs_human", "code":"MCP_ADD_ENVIRONMENT", "reason":"environment", "detail":error});
        }
    };
    let (targets, selection_blockers) = select_targets(&context, options);
    if !selection_blockers.is_empty() {
        return json!({"status":"needs_human", "scope":scope_name(options), "blockers":selection_blockers});
    }
    let environment = match validated_registration_environment(composition, &context.environment) {
        Ok(environment) => environment,
        Err(detail) => {
            return json!({
                "status": "needs_human",
                "scope": scope_name(options),
                "code": "MCP_ADD_PROVIDER_ENVIRONMENT",
                "reason": "environment",
                "detail": detail,
            });
        }
    };
    let current_entrypoint = options
        .command
        .is_none()
        .then(|| std::env::current_exe().ok())
        .flatten();
    let mut changes = Vec::new();
    let mut blockers = Vec::new();
    for target in targets {
        match prepare_explicit_change(&target, &command, &environment, current_entrypoint.as_deref()) {
            Ok(Some(change)) => changes.push(change),
            Ok(None) => {}
            Err(error) => blockers.push(json!({"client":target.id, "path":target.path, "reason":"preparation_failed", "detail":error})),
        }
    }
    if !blockers.is_empty() {
        return json!({"status":"needs_human", "scope":scope_name(options), "command":command, "blockers":blockers});
    }
    let report = match client_transaction::apply_transaction(&changes, true) {
        Ok(report) => report,
        Err(error) => {
            return json!({"status":"failed", "scope":scope_name(options), "command":command, "detail":error.to_string()});
        }
    };
    let status = if report.primary_failure.is_some() || !report.cleanup_failures.is_empty() {
        "failed"
    } else {
        "ready"
    };
    json!({
        "status": status,
        "scope": scope_name(options),
        "command": command,
        "appliedActions": report.items.iter().map(|item| item.client_id.clone()).collect::<Vec<_>>(),
        "operationDetails": transaction_report(&report),
    })
}

fn scope_name(options: &AddOptions) -> &'static str {
    if options.global { "global" } else { "project" }
}

fn local_resolution_context() -> Result<ClientResolutionContext, String> {
    let environment = std::env::vars().collect::<std::collections::BTreeMap<_, _>>();
    let home = environment
        .get("HOME")
        .or_else(|| environment.get("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "the session environment does not define HOME or USERPROFILE".to_owned())?;
    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    let platform = match std::env::consts::OS {
        "windows" => ClientPlatform::Windows,
        "macos" => ClientPlatform::Macos,
        _ => ClientPlatform::Linux,
    };
    Ok(ClientResolutionContext::new(
        home,
        cwd,
        platform,
        environment,
    ))
}

fn validated_registration_environment(
    composition: &dyn Composition,
    environment: &std::collections::BTreeMap<String, String>,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let session = Arc::new(Session::new(environment.clone().into_iter().collect()));
    let mut registry = Registry::default();
    composition.register(&mut registry, &session);
    let runner = Runner {
        registry: &registry,
        session: &session,
        cancellation: Cancellation::default(),
    };
    let doctor_report = doctor_commands::run(&json!({"client": [], "skill": false}), &runner);
    let result = registration_environment_from_doctor_report(&doctor_report, environment);
    let cleanup_result = session.close();
    if let Err(failures) = cleanup_result {
        let cleanup = failures
            .iter()
            .map(|failure| format!("{failure:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        return match result {
            Ok(_) => Err(format!("provider inspection cleanup failed: {cleanup}")),
            Err(primary) => Err(format!(
                "{primary}; provider inspection cleanup failed: {cleanup}"
            )),
        };
    }
    result
}

fn registration_environment_from_doctor_report(
    doctor_report: &Value,
    environment: &std::collections::BTreeMap<String, String>,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let provider_inspections = doctor_report
        .get("providerInspections")
        .and_then(Value::as_array)
        .ok_or_else(|| "doctor did not return provider inspections".to_owned())?;
    let inspection_environments = validate_provider_inspections(provider_inspections)?;
    let provider = maintenance_registration_environment::provider_registration_environment(
        &inspection_environments,
    );
    maintenance_registration_environment::validate_provider_values(environment, &provider.values)?;
    Ok(maintenance_registration_environment::combine(
        maintenance_registration_environment::explicit_setup_registration_environment(environment),
        provider,
    )
    .values)
}

fn validate_provider_inspections(
    provider_inspections: &[Value],
) -> Result<Vec<std::collections::BTreeMap<String, String>>, String> {
    let mut environments = Vec::new();
    for (index, inspection) in provider_inspections.iter().enumerate() {
        if !inspection.is_object() {
            return Err(format!(
                "doctor provider inspection {index} is not an object"
            ));
        }
        let Some(environment) = inspection.get("registrationEnvironment") else {
            continue;
        };
        let values = environment.as_object().ok_or_else(|| {
            format!(
                "doctor provider inspection {index} returned a non-object registration environment"
            )
        })?;
        let mut admitted = std::collections::BTreeMap::new();
        for (key, value) in values {
            let value = value.as_str().ok_or_else(|| {
                format!(
                    "doctor provider inspection {index} returned a non-string value for `{key}`"
                )
            })?;
            admitted.insert(key.clone(), value.to_owned());
        }
        environments.push(admitted);
    }
    Ok(environments)
}

fn select_targets(
    context: &ClientResolutionContext,
    options: &AddOptions,
) -> (Vec<ClientRegistrationTarget>, Vec<Value>) {
    let known = client_targets::supported_client_targets(context);
    let mut blockers = Vec::new();
    for agent in &options.agents {
        if !known.iter().any(|target| target.id == *agent) {
            blockers.push(json!({"client":agent, "reason":"unknown_client"}));
        } else if !options.global && !client_targets::supports_project_registration(agent) {
            blockers.push(json!({"client":agent, "reason":"project_scope_unsupported"}));
        }
    }
    if !blockers.is_empty() {
        return (Vec::new(), blockers);
    }
    let targets = known
        .into_iter()
        .filter_map(|target| local_or_global_target(target, context, options))
        .collect::<Vec<_>>();
    if targets.is_empty() {
        blockers.push(json!({
            "reason": if options.global { "no_detected_clients" } else { "no_detected_project_clients" },
            "remediation": if options.global { "Pass --agent to target a client explicitly." } else { "Run from a project with a supported agent configuration or pass --agent." },
        }));
    }
    (targets, blockers)
}

fn local_or_global_target(
    mut target: ClientRegistrationTarget,
    context: &ClientResolutionContext,
    options: &AddOptions,
) -> Option<ClientRegistrationTarget> {
    let requested = options.agents.iter().any(|id| id == &target.id);
    if !options.global {
        target = client_targets::project_registration_target(target, context)?;
    }
    let detected = target.evidence_paths.iter().any(|path| path.exists());
    if requested || (options.agents.is_empty() && detected) {
        Some(target)
    } else {
        None
    }
}

fn prepare_explicit_change(
    target: &ClientRegistrationTarget,
    command: &[String],
    environment: &std::collections::BTreeMap<String, String>,
    current_entrypoint: Option<&std::path::Path>,
) -> Result<Option<PreparedClientChange>, String> {
    let format = client_config_format(target.format)?;
    let source =
        client_transaction::read_client_source(target).map_err(|error| error.to_string())?;
    let prepared = maintenance_client_config::prepare_change_with_registration_and_identity(
        &source.clone().unwrap_or_default(),
        format,
        &[target.server_key],
        RegistrationOperation::Configure,
        maintenance_client_config::dialect_for_client(&target.id),
        command,
        environment,
        None,
        current_entrypoint,
    )?;
    if source.as_ref().is_some_and(|source| {
        maintenance_client_config::configuration_semantically_equal(source, &prepared.bytes, format)
    }) {
        return Ok(None);
    }
    let expected = source.as_ref().map(|_| prepared.original_sha256.clone());
    Ok(Some(PreparedClientChange::configure(
        target.clone(),
        expected,
        source,
        prepared.bytes,
    )))
}

fn client_config_format(format: ClientConfigurationFormat) -> Result<ClientConfigFormat, String> {
    match format {
        ClientConfigurationFormat::Json => Ok(ClientConfigFormat::Json),
        ClientConfigurationFormat::Jsonc => Ok(ClientConfigFormat::Jsonc),
        ClientConfigurationFormat::Toml => Ok(ClientConfigFormat::Toml),
        ClientConfigurationFormat::Yaml => Ok(ClientConfigFormat::Yaml),
        ClientConfigurationFormat::Unsupported => {
            Err("client configuration format is unsupported".to_owned())
        }
    }
}

fn split_command(command: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let characters = command.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if let Some(active) = quote {
            if character == active {
                quote = None;
                started = true;
            } else if character == '\\' && active == '"' {
                let next = characters.get(index + 1).copied();
                if matches!(next, Some('"' | '\\' | '$' | '`')) {
                    word.push(next.expect("matched next character"));
                    started = true;
                    index += 1;
                } else {
                    word.push(character);
                    started = true;
                }
            } else {
                word.push(character);
                started = true;
            }
        } else if character == '\'' || character == '"' {
            quote = Some(character);
            started = true;
        } else if character == '\\' {
            let next = characters.get(index + 1).copied();
            if matches!(next, Some(next) if next.is_whitespace() || matches!(next, '\\' | '\'' | '"'))
            {
                word.push(next.expect("matched next character"));
                started = true;
                index += 1;
            } else {
                word.push(character);
                started = true;
            }
        } else if character.is_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(character);
            started = true;
        }
        index += 1;
    }
    if quote.is_some() {
        return Err("command contains an unterminated quote".to_owned());
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

fn transaction_report(
    report: &rea_application::maintenance_client_transaction::TransactionReport,
) -> Value {
    json!({
        "items": report.items.iter().map(|item| json!({
            "client": item.client_id,
            "path": item.path,
            "status": format!("{:?}", item.status),
            "backup": item.backup_path,
            "recovery": item.recovery_path,
            "detail": item.detail,
        })).collect::<Vec<_>>(),
        "primaryFailure": report.primary_failure,
        "cleanupFailures": report.cleanup_failures,
    })
}

fn parse_options(arguments: &[String]) -> Result<AddOptions, String> {
    let mut options = AddOptions {
        global: true,
        ..AddOptions::default()
    };
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--help" | "-h" => options.help = true,
            "--json" => options.format = Some(Format::Json),
            "--format" => {
                index += 1;
                let value = arguments.get(index).ok_or("--format requires a value")?;
                options.format = Format::parse(value);
                if options.format.is_none() {
                    return Err(format!("unknown output format `{value}`"));
                }
            }
            "--no-global" => options.global = false,
            "--command" | "-c" => {
                index += 1;
                options.command = Some(
                    arguments
                        .get(index)
                        .ok_or("--command requires a value")?
                        .clone(),
                );
            }
            "--agent" => {
                index += 1;
                let value = arguments.get(index).ok_or("--agent requires a value")?;
                options.agents.push(normalize_agent(value));
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option `{value}`"));
            }
            value => return Err(format!("unexpected argument `{value}`")),
        }
        index += 1;
    }
    Ok(options)
}

fn normalize_agent(value: &str) -> String {
    match value.to_ascii_lowercase().replace('-', "_").as_str() {
        "claude" => "claude_code".to_owned(),
        "claude_code" => "claude_code".to_owned(),
        "claude_desktop" => "claude_desktop".to_owned(),
        "gemini" => "gemini_cli".to_owned(),
        "gemini_cli" => "gemini_cli".to_owned(),
        "copilot" => "copilot_cli".to_owned(),
        "copilot_cli" => "copilot_cli".to_owned(),
        "qwen" => "qwen_code".to_owned(),
        "qwen_code" => "qwen_code".to_owned(),
        other => other.to_owned(),
    }
}

fn print_help() {
    println!(
        "rea mcp add\n\nRegister REA's MCP server with supported agent configurations.\n\nOptions:\n  -c, --command <command>  Register this explicit command\n      --agent <id>         Register a specific client (repeatable)\n      --no-global           Register in the current project\n      --format <format>     Output as toon, json, yaml, md, or jsonl\n      --json                Output JSON\n  -h, --help               Show this help"
    );
}

fn print_result(result: &Value, format: Format) -> i32 {
    println!("{}", crate::format::format(result, format));
    if result.get("status").and_then(Value::as_str) == Some("ready") {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::{Format, parse_options, split_command};

    #[test]
    fn parses_legacy_registration_options() {
        let options = parse_options(&[
            "--no-global".to_owned(),
            "-c".to_owned(),
            "rea mcp".to_owned(),
            "--agent".to_owned(),
            "claude-code".to_owned(),
            "--json".to_owned(),
        ])
        .expect("options should parse");

        assert!(!options.global);
        assert_eq!(options.command.as_deref(), Some("rea mcp"));
        assert_eq!(options.agents, vec!["claude_code".to_owned()]);
        assert_eq!(options.format, Some(Format::Json));
    }

    #[test]
    fn rejects_missing_option_values() {
        assert!(parse_options(&["--agent".to_owned()]).is_err());
        assert!(parse_options(&["--format".to_owned(), "wat".to_owned()]).is_err());
    }

    #[test]
    fn preserves_empty_quoted_arguments_and_windows_paths() {
        assert_eq!(
            split_command(r#"tool "" '' C:\Tools\rea.exe"#).expect("command should parse"),
            vec![
                "tool".to_owned(),
                String::new(),
                "".to_owned(),
                r"C:\Tools\rea.exe".to_owned(),
            ]
        );
    }
}
