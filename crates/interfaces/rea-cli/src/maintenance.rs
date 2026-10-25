//! Approved, ownership-aware setup, uninstall, and update orchestration.

use crate::doctor_commands;
use crate::invoke::Runner;
use rea_application::maintenance_client_config::{
    self, ClientConfigFormat, RegistrationOperation, RegistrationState,
};
use rea_application::maintenance_client_transaction::{
    self as client_transaction, PreparedClientChange as TransactionChange, TransactionItemStatus,
};
use rea_application::maintenance_clients::{
    self, ClientConfigurationFormat, ClientPlatform, ClientRegistrationTarget,
    ClientResolutionContext,
};
use rea_application::maintenance_hopper::{
    self, HopperInstallRequest, HopperPlatform, SystemHopperInstallHost,
};
use rea_application::maintenance_skills::{self, SkillDestination};
use rea_application::{maintenance_registration_environment, maintenance_update, package_identity};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default)]
pub struct SetupOptions {
    pub approved: bool,
    pub install_hopper: bool,
    pub client_ids: Vec<String>,
    pub skill_client_ids: Vec<String>,
    pub all_detected_clients: bool,
    pub install_skill: Option<bool>,
    pub dry_run: bool,
    pub accessible: bool,
}

pub fn setup(options: &SetupOptions, runner: &Runner<'_>) -> Value {
    if options.accessible && !options.approved && !options.dry_run {
        return run_accessible_setup(options, runner);
    }
    let context = match resolution_context(runner) {
        Ok(context) => context,
        Err(error) => {
            return json!({"status":"needs_human", "code":"environment", "reason":"environment", "detail":error});
        }
    };
    let targets = maintenance_clients::supported_client_targets(&context);
    let selection = select_client_targets(&targets, options);
    let skill_requested = options.install_skill.unwrap_or(
        options.all_detected_clients
            || !options.client_ids.is_empty()
            || !options.skill_client_ids.is_empty(),
    );
    let selected_client_ids = selection
        .targets
        .iter()
        .map(|target| target.id.clone())
        .collect::<Vec<_>>();
    let mut blockers = selection.blockers;
    let (registration_command, current_entrypoint) = match verified_registration_identity(&context)
    {
        Ok(identity) => identity,
        Err(error) => {
            blockers.push(json!({
                "resource": "client",
                "reason": "registration_identity",
                "detail": error,
                "remediation": "Run setup from the verified installed REA CLI."
            }));
            (Vec::new(), None)
        }
    };
    let doctor_scope = doctor_commands::run(
        &json!({"client": selected_client_ids.clone(), "skill": skill_requested}),
        runner,
    );
    let registration_environment = match setup_registration_environment(&context, &doctor_scope) {
        Ok(environment) => environment,
        Err(error) => {
            blockers.push(json!({
                "resource": "provider",
                "reason": "invalid_provider_environment",
                "detail": error,
                "remediation": "Correct the reported provider setting, then rerun setup.",
            }));
            BTreeMap::new()
        }
    };
    let client_preflight = preflight_clients(
        &selection.targets,
        RegistrationOperation::Configure,
        &registration_environment,
        &registration_command,
        current_entrypoint.as_deref(),
        &mut blockers,
    );
    let skill_preflight = if skill_requested {
        preflight_skills(&context, &options.skill_client_ids, &mut blockers)
    } else {
        None
    };
    let hopper_preflight = options.install_hopper.then(|| hopper_plan(&context));
    let planned_actions = planned_setup_actions(
        &client_preflight,
        skill_preflight.as_ref(),
        hopper_preflight.as_ref(),
    );
    let mut result = json!({
        "status": if options.dry_run { "planned" } else { "ready" },
        "plannedActions": planned_actions,
        "appliedActions": [],
        "clients": client_inspections(&client_preflight),
        "clientStates": client_states(&targets, &client_preflight),
        "doctor": doctor_scope,
    });
    if !blockers.is_empty() {
        result["status"] = json!("needs_human");
        result["blockers"] = json!(blockers);
        return result;
    }
    if options.dry_run || planned_actions_is_empty(&result["plannedActions"]) {
        return result;
    }
    if !options.approved {
        result["status"] = json!("needs_confirmation");
        result["remediation"] =
            json!("Review plannedActions and rerun with --yes before changing files.");
        return result;
    }
    let mut applied = Vec::new();
    if !client_preflight.changes.is_empty() {
        match client_transaction::apply_transaction(&client_preflight.changes, true) {
            Ok(report) => {
                let report_value = transaction_report(&report);
                applied.push(json!({"kind":"clients", "report": report_value}));
                if report.primary_failure.is_some() || !report.cleanup_failures.is_empty() {
                    return transaction_failure_result(result, applied, &report);
                }
            }
            Err(error) => return transaction_error_result(result, applied, error),
        }
    }
    if let Some((source_root, destinations)) = skill_preflight {
        match maintenance_skills::install_skill(&source_root, &destinations) {
            Ok(actions) => applied.push(json!({"kind":"skills", "actions": actions})),
            Err(error) => return partial_result(result, applied, error.to_string()),
        }
    }
    if options.install_hopper {
        let mut host = SystemHopperInstallHost::new(
            context.home.clone(),
            context.environment.clone(),
            runner.cancellation.clone(),
        );
        let request = HopperInstallRequest {
            platform: hopper_platform(),
            replace_existing: true,
            approved: true,
        };
        let hopper_result = maintenance_hopper::install_hopper(&request, &mut host);
        let hopper_partial = matches!(
            hopper_result.get("status").and_then(Value::as_str),
            Some("failed") | Some("partial")
        );
        applied.push(json!({"kind":"hopper", "result": hopper_result}));
        if hopper_partial {
            return partial_result(
                result,
                applied,
                "Hopper setup did not finish cleanly; review the retained recovery details."
                    .to_owned(),
            );
        }
    }
    result["doctor"] = doctor_commands::run(
        &json!({"client": selected_client_ids, "skill": skill_requested}),
        runner,
    );
    result["status"] = json!("ready");
    result["appliedActions"] = json!(applied_action_ids(&applied));
    result["operationDetails"] = json!(applied);
    result
}

fn run_accessible_setup(options: &SetupOptions, runner: &Runner<'_>) -> Value {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return setup(
            &SetupOptions {
                accessible: false,
                ..options.clone()
            },
            runner,
        );
    }
    let mut preview_options = SetupOptions {
        dry_run: true,
        accessible: false,
        ..options.clone()
    };
    preview_options.approved = false;

    let preview = setup(&preview_options, runner);
    let Some(states) = preview.get("clientStates").and_then(Value::as_array) else {
        return preview;
    };

    let mut selected_clients = Vec::new();
    for state in states {
        let Some(client) = state.get("client").and_then(Value::as_object) else {
            continue;
        };
        let Some(name) = client.get("name").and_then(Value::as_str) else {
            continue;
        };
        let display = client
            .get("displayName")
            .and_then(Value::as_str)
            .unwrap_or(name);
        let configured = state
            .get("configured")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let detected = state
            .get("detected")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let hint = if configured {
            "already configured"
        } else if detected {
            "detected"
        } else {
            "not detected"
        };
        let initial = options.client_ids.iter().any(|id| id == name)
            || (options.all_detected_clients && detected);
        let prompt = if initial {
            format!("Configure {display} ({hint})? [Y/n] ")
        } else {
            format!("Configure {display} ({hint})? [y/N] ")
        };
        match prompt_for_yes_with_default(&prompt, initial) {
            Some(true) => selected_clients.push(name.to_owned()),
            Some(false) => {}
            None => return cancelled_setup_result(preview),
        }
    }

    let mut approved = options.clone();
    approved.approved = true;
    approved.accessible = false;
    approved.client_ids = selected_clients;
    approved.all_detected_clients = false;
    if options.install_hopper {
        match prompt_for_yes("Install Hopper for deep binary analysis? [y/N] ") {
            Some(true) => {}
            Some(false) => approved.install_hopper = false,
            None => return cancelled_setup_result(preview),
        }
    }

    let mut final_preview = approved.clone();
    final_preview.approved = false;
    final_preview.dry_run = true;
    let planned = setup(&final_preview, runner);
    let has_actions = planned
        .get("plannedActions")
        .and_then(Value::as_array)
        .is_some_and(|actions| !actions.is_empty());
    if has_actions {
        render_accessible_plan(&planned);
        match prompt_for_yes_with_default("Apply these setup changes? [Y/n] ", true) {
            Some(true) => {}
            Some(false) | None => return cancelled_setup_result(planned),
        }
    }

    setup(&approved, runner)
}

fn render_accessible_plan(plan: &Value) {
    eprintln!("\nREA setup plan");
    if let Some(actions) = plan.get("plannedActions").and_then(Value::as_array) {
        for action in actions {
            let operation = action
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or("change");
            let label = action.get("label").and_then(Value::as_str).unwrap_or("");
            let target = action.get("target").and_then(Value::as_str).unwrap_or("");
            let detail = action.get("detail").and_then(Value::as_str).unwrap_or("");
            eprintln!("  {} {}", operation.to_ascii_uppercase(), label);
            if !target.is_empty() {
                eprintln!("    target: {target}");
            }
            if !detail.is_empty() {
                eprintln!("    {detail}");
            }
        }
    }
}

fn prompt_for_yes(prompt: &str) -> Option<bool> {
    prompt_for_yes_with_default(prompt, false)
}

fn prompt_for_yes_with_default(prompt: &str, default: bool) -> Option<bool> {
    use std::io::{self, Write};

    eprint!("{prompt}");
    if io::stderr().flush().is_err() {
        return None;
    }
    let mut answer = String::new();
    match io::stdin().read_line(&mut answer) {
        Ok(0) | Err(_) => return None,
        Ok(_) => {}
    }
    Some(match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    })
}

fn cancelled_setup_result(mut preview: Value) -> Value {
    preview["status"] = json!("cancelled");
    preview["appliedActions"] = json!([]);
    preview["remediation"] = json!("Setup was cancelled before changing files.");
    preview
}

pub fn uninstall(purge_data: bool, runner: &Runner<'_>) -> Value {
    let context = match resolution_context(runner) {
        Ok(context) => context,
        Err(error) => return json!({"status":"failed", "reason":"environment", "detail":error}),
    };
    let targets = maintenance_clients::supported_client_targets(&context);
    let mut blockers = Vec::new();
    let (registration_command, current_entrypoint) =
        verified_registration_identity(&context).unwrap_or_default();
    let client_preflight = preflight_clients(
        &targets,
        RegistrationOperation::Remove,
        &BTreeMap::new(),
        &registration_command,
        current_entrypoint.as_deref(),
        &mut blockers,
    );
    let skills = preflight_skills(&context, &[], &mut blockers);
    if !blockers.is_empty() {
        return json!({
            "status": "failed",
            "items": uninstall_blocker_items(&blockers, &client_preflight),
            "blockers": blockers,
        });
    }
    let mut items = Vec::new();
    if !client_preflight.changes.is_empty() {
        match client_transaction::apply_transaction(&client_preflight.changes, true) {
            Ok(report) => {
                let status =
                    if report.primary_failure.is_some() || !report.cleanup_failures.is_empty() {
                        if transaction_is_partial(&report) {
                            "partial"
                        } else {
                            "failed"
                        }
                    } else {
                        "complete"
                    };
                items.push(json!({"name":"clients", "status":status, "report":transaction_report(&report)}));
                if status != "complete" {
                    return json!({"status":status, "items":items});
                }
            }
            Err(error) => {
                let failure = error.to_string();
                let status = if matches!(
                    error,
                    client_transaction::ClientTransactionError::Committed { .. }
                ) {
                    "partial"
                } else {
                    "failed"
                };
                return json!({"status":status, "items":items, "failure":failure});
            }
        }
    }
    if let Some((_source, destinations)) = skills {
        let actions = maintenance_skills::uninstall_skill(&destinations);
        let failed = actions.iter().any(|action| action.status == "failed");
        items.push(json!({"name":"skills", "status":if failed {"failed"} else {"complete"}, "actions":actions}));
        if failed {
            return json!({"status":"failed", "items":items});
        }
    }
    if purge_data {
        let data_items = purge_managed_data(&context.home);
        let data_failed = data_items
            .iter()
            .any(|item| item["status"] == Value::String("failed".into()));
        items.push(json!({"name":"data", "status":if data_failed {"failed"} else {"complete"}, "items":data_items}));
        if data_failed {
            return json!({"status":"failed", "items":items});
        }
    }
    items.push(json!({"name":"analysis_engine", "status":"retained", "detail":"The analysis engine is not owned by uninstall."}));
    json!({"status":"complete", "items":items})
}

pub fn update(runner: &Runner<'_>) -> Value {
    let environment = runner
        .session
        .environment()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let cancellation = runner.cancellation.clone();
    let Ok(identity) = package_identity::discover_current_package_root() else {
        return json!({"status":"failed", "currentVersion":Value::Null, "latestVersion":Value::Null, "reason":"unknown-installation"});
    };
    if identity.installation_kind == package_identity::PackageInstallationKind::StandaloneRelease {
        return json!({
            "status": "unavailable",
            "currentVersion": identity.version,
            "latestVersion": Value::Null,
            "reason": "standalone-release",
            "remediation": "Install the latest standalone release with the installer from https://github.com/nanashili/rea-rust/releases, then run rea setup again.",
        });
    }
    maintenance_update::run_update_with_maintenance(
        &identity.version,
        &identity.package_root,
        &environment,
        &cancellation,
        |_| {
            setup(
                &SetupOptions {
                    dry_run: true,
                    all_detected_clients: true,
                    install_skill: Some(false),
                    ..SetupOptions::default()
                },
                runner,
            )
        },
    )
}

struct ClientPreflight {
    inspections: Vec<(ClientRegistrationTarget, RegistrationState, Option<String>)>,
    changes: Vec<TransactionChange>,
}

fn setup_registration_environment(
    context: &ClientResolutionContext,
    doctor_scope: &Value,
) -> Result<BTreeMap<String, String>, String> {
    let setup = maintenance_registration_environment::explicit_setup_registration_environment(
        &context.environment,
    );
    let inspections = doctor_scope
        .get("providerInspections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|inspection| inspection.get("registrationEnvironment"))
        .filter_map(Value::as_object)
        .map(|environment| {
            environment
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_owned()))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .collect::<Vec<_>>();
    let provider =
        maintenance_registration_environment::provider_registration_environment(&inspections);
    maintenance_registration_environment::validate_provider_values(
        &context.environment,
        &provider.values,
    )?;
    Ok(maintenance_registration_environment::combine(setup, provider).values)
}

fn preflight_clients(
    targets: &[ClientRegistrationTarget],
    operation: RegistrationOperation,
    registration_environment: &BTreeMap<String, String>,
    registration_command: &[String],
    current_entrypoint: Option<&Path>,
    blockers: &mut Vec<Value>,
) -> ClientPreflight {
    let mut preflight = ClientPreflight {
        inspections: Vec::new(),
        changes: Vec::new(),
    };
    for target in targets {
        if matches!(operation, RegistrationOperation::Configure) {
            if let Some(error) = &target.config_path_error {
                blockers.push(json!({
                    "client": target.id,
                    "reason": "config_path_error",
                    "detail": error,
                    "remediation": "Resolve the client configuration path, then rerun setup."
                }));
                continue;
            }
        }
        if matches!(operation, RegistrationOperation::Configure) && target.manual_registration {
            blockers.push(json!({
                "client": target.id,
                "reason": "manual_registration_required",
                "remediation": "Register REA manually in this client, then rerun setup."
            }));
            continue;
        }
        let Some(format) = config_format(target.format) else {
            if matches!(operation, RegistrationOperation::Configure) {
                blockers
                    .push(json!({"client":target.id,"reason":"unsupported_configuration_format"}));
            }
            continue;
        };
        let inspection = maintenance_client_config::inspect_path_with_dialect_and_identity(
            &target.path,
            format,
            &[target.server_key],
            maintenance_client_config::dialect_for_client(&target.id),
            None,
            current_entrypoint,
        );
        let state = inspection.state.clone();
        preflight.inspections.push((
            target.clone(),
            state.clone(),
            inspection.source_sha256.clone(),
        ));
        match operation {
            RegistrationOperation::Configure
                if matches!(
                    &state,
                    RegistrationState::Foreign
                        | RegistrationState::Malformed(_)
                        | RegistrationState::Unreadable(_)
                ) =>
            {
                blockers.push(json!({"client":target.id,"reason":registration_reason(&state),"detail":registration_detail(&state)}))
            }
            RegistrationOperation::Remove
                if matches!(
                    &state,
                    RegistrationState::Malformed(_) | RegistrationState::Unreadable(_)
                ) =>
            {
                blockers.push(json!({"client":target.id,"reason":registration_reason(&state),"detail":registration_detail(&state)}))
            }
            RegistrationOperation::Remove
                if matches!(
                    &state,
                    RegistrationState::Foreign
                        | RegistrationState::Missing
                        | RegistrationState::Absent
                ) => {}
            _ => match client_change(
                target,
                format,
                operation,
                inspection.source_sha256,
                &state,
                registration_environment,
                registration_command,
                current_entrypoint,
            ) {
                Ok(Some(change)) => preflight.changes.push(change),
                Ok(None) => {}
                Err(error) => blockers
                    .push(json!({"client":target.id,"reason":"preparation_failed","detail":error})),
            },
        }
    }
    preflight
}

fn client_change(
    target: &ClientRegistrationTarget,
    format: ClientConfigFormat,
    operation: RegistrationOperation,
    source_sha256: Option<String>,
    state: &RegistrationState,
    registration_environment: &BTreeMap<String, String>,
    registration_command: &[String],
    current_entrypoint: Option<&Path>,
) -> Result<Option<TransactionChange>, String> {
    let source =
        client_transaction::read_client_source(target).map_err(|error| error.to_string())?;
    let prepared = maintenance_client_config::prepare_change_with_registration_and_identity(
        &source.clone().unwrap_or_default(),
        format,
        &[target.server_key],
        operation,
        maintenance_client_config::dialect_for_client(&target.id),
        registration_command,
        registration_environment,
        None,
        current_entrypoint,
    )?;
    let expected = source
        .as_ref()
        .map(|_| source_sha256.unwrap_or(prepared.original_sha256.clone()));
    if matches!(operation, RegistrationOperation::Configure) {
        if let Some(source) = &source {
            if maintenance_client_config::configuration_semantically_equal(
                source,
                &prepared.bytes,
                format,
            ) {
                return Ok(None);
            }
        }
    }
    Ok(Some(match operation {
        RegistrationOperation::Configure => {
            TransactionChange::configure(target.clone(), expected, source, prepared.bytes)
        }
        RegistrationOperation::Remove if matches!(state, RegistrationState::Owned) => {
            TransactionChange::remove(target.clone(), expected, source, prepared.bytes)
        }
        RegistrationOperation::Remove => return Err("removal requires owned registration".into()),
    }))
}

fn preflight_skills(
    context: &ClientResolutionContext,
    selected: &[String],
    blockers: &mut Vec<Value>,
) -> Option<(PathBuf, Vec<SkillDestination>)> {
    let identity = match package_identity::discover_current_package_root() {
        Ok(identity) => identity,
        Err(error) => {
            blockers.push(json!({"resource":"skill","reason":"unknown_package_root","detail":error.to_string()}));
            return None;
        }
    };
    let clients = (!selected.is_empty()).then_some(selected);
    let destinations = match maintenance_skills::skill_destinations(context, clients) {
        Ok(destinations) => destinations,
        Err(error) => {
            blockers.push(json!({"resource":"skill","reason":"destination_resolution","detail":error.to_string()}));
            return None;
        }
    };
    let source_root = identity
        .package_root
        .join("skills/reverse-engineer-anything");
    let bundle = match maintenance_skills::read_bundle(&source_root) {
        Ok(bundle) => bundle,
        Err(error) => {
            blockers.push(json!({"resource":"skill","reason":"bundle_unavailable","detail":error.to_string()}));
            return None;
        }
    };
    for destination in &destinations {
        let inspection = maintenance_skills::inspect_skill(&destination.path, &bundle);
        if !inspection.issues.is_empty() || (inspection.installed && !inspection.canonical) {
            blockers.push(json!({"resource":"skill","client":destination.client,"path":destination.path,"reason":"foreign_or_unsafe_skill"}));
        }
    }
    Some((source_root, destinations))
}

struct Selection {
    targets: Vec<ClientRegistrationTarget>,
    blockers: Vec<Value>,
}

fn select_client_targets(
    targets: &[ClientRegistrationTarget],
    options: &SetupOptions,
) -> Selection {
    let known = targets
        .iter()
        .map(|target| target.id.as_str())
        .collect::<BTreeSet<_>>();
    let blockers = options
        .client_ids
        .iter()
        .filter(|id| !known.contains(id.as_str()))
        .map(|id| json!({"client":id,"reason":"unknown_client"}))
        .collect::<Vec<_>>();
    let requested = options.client_ids.iter().collect::<BTreeSet<_>>();
    let targets = targets
        .iter()
        .filter(|target| {
            requested.contains(&target.id)
                || (options.all_detected_clients
                    && target.evidence_paths.iter().any(|path| path.exists()))
        })
        .cloned()
        .collect();
    Selection { targets, blockers }
}

fn config_format(format: ClientConfigurationFormat) -> Option<ClientConfigFormat> {
    match format {
        ClientConfigurationFormat::Json => Some(ClientConfigFormat::Json),
        ClientConfigurationFormat::Jsonc => Some(ClientConfigFormat::Jsonc),
        ClientConfigurationFormat::Toml => Some(ClientConfigFormat::Toml),
        ClientConfigurationFormat::Yaml => Some(ClientConfigFormat::Yaml),
        ClientConfigurationFormat::Unsupported => None,
    }
}
fn registration_reason(state: &RegistrationState) -> &'static str {
    match state {
        RegistrationState::Foreign => "foreign_registration",
        RegistrationState::Malformed(_) => "malformed_configuration",
        RegistrationState::Unreadable(_) => "unreadable_configuration",
        RegistrationState::Missing => "missing",
        RegistrationState::Absent => "absent",
        RegistrationState::Owned => "owned",
    }
}

fn registration_detail(state: &RegistrationState) -> Option<&str> {
    match state {
        RegistrationState::Malformed(detail) | RegistrationState::Unreadable(detail) => {
            Some(detail.as_str())
        }
        _ => None,
    }
}

fn verified_registration_identity(
    context: &ClientResolutionContext,
) -> Result<(Vec<String>, Option<PathBuf>), String> {
    let executable = env::current_exe()
        .map_err(|error| format!("could not determine the current executable: {error}"))?;
    let identity =
        package_identity::discover_package_root(&executable).map_err(|error| error.to_string())?;
    if identity.installation_kind == package_identity::PackageInstallationKind::StandaloneRelease {
        return Ok((
            vec![executable.to_string_lossy().into_owned(), "mcp".to_owned()],
            Some(executable),
        ));
    }

    let package_specifier = format!("rea-agents@{}", identity.version);
    let npm_command = context.environment.get("npm_command");
    if npm_command.is_some_and(|value| value == "exec") {
        let runner = context
            .environment
            .get("npm_config_user_agent")
            .filter(|value| value.starts_with("bun/"))
            .map_or("npx", |_| "bunx");
        let command = if runner == "bunx" {
            vec![runner.to_owned(), package_specifier, "mcp".to_owned()]
        } else {
            vec![
                runner.to_owned(),
                "-y".to_owned(),
                package_specifier,
                "mcp".to_owned(),
            ]
        };
        return Ok((command, Some(executable)));
    }
    Ok((
        vec![executable.to_string_lossy().into_owned(), "mcp".to_owned()],
        Some(executable),
    ))
}

fn resolution_context(runner: &Runner<'_>) -> Result<ClientResolutionContext, String> {
    let environment = runner
        .session
        .environment()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let home = environment
        .get("HOME")
        .or_else(|| environment.get("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| "the session environment does not define HOME or USERPROFILE".to_owned())?;
    let cwd = env::current_dir()
        .map_err(|error| format!("the current working directory could not be resolved: {error}"))?;
    Ok(ClientResolutionContext::new(
        home,
        cwd,
        current_platform(),
        environment,
    ))
}
fn current_platform() -> ClientPlatform {
    if cfg!(target_os = "windows") {
        ClientPlatform::Windows
    } else if cfg!(target_os = "macos") {
        ClientPlatform::Macos
    } else {
        ClientPlatform::Linux
    }
}
fn hopper_platform() -> HopperPlatform {
    if cfg!(target_os = "macos") {
        HopperPlatform::MacOs
    } else {
        HopperPlatform::LinuxDeb
    }
}
fn hopper_plan(context: &ClientResolutionContext) -> Value {
    maintenance_hopper::hopper_setup_plan(
        hopper_platform(),
        Some(&context.home.join(".cache/rea/hopper-releases")),
        None,
    )
}
fn planned_setup_actions(
    clients: &ClientPreflight,
    skills: Option<&(PathBuf, Vec<SkillDestination>)>,
    hopper: Option<&Value>,
) -> Vec<Value> {
    let changed_clients = clients
        .changes
        .iter()
        .map(|change| change.target.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut actions = clients
        .inspections
        .iter()
        .filter(|(target, _, _)| changed_clients.contains(target.id.as_str()))
        .map(|(target, _, digest)| {
            let detail = if target.quit_before_setup {
                "Close the client before setup if it is running, then configure the REA MCP registration."
            } else {
                "Configure the REA MCP registration."
            };
            json!({
                "id": format!("configure_client:{}", target.id),
                "kind": "configure_client",
                "label": target.display_name,
                "target": target.path,
                "detail": detail,
                "external": false,
                "operation": "configure",
                "sourceSha256": digest
            })
        })
        .collect::<Vec<_>>();
    if let Some((_, destinations)) = skills {
        actions.push(json!({
            "id": "install_skill",
            "kind": "install_skill",
            "label": "Install the REA skill bundle",
            "target": "selected skill clients",
            "detail": "Install the canonical skill bundle in each selected destination.",
            "external": false,
            "operation": "install",
            "destinations": destinations
        }));
    }
    if let Some(plan) = hopper {
        actions.push(plan.clone());
    }
    actions
}
fn planned_actions_is_empty(actions: &Value) -> bool {
    actions.as_array().map_or(true, Vec::is_empty)
}
fn client_inspections(preflight: &ClientPreflight) -> Value {
    Value::Object(preflight.inspections.iter().map(|(target, state, digest)| (target.id.clone(), json!({"status":registration_reason(state),"path":target.path,"sourceSha256":digest}))).collect())
}

fn uninstall_blocker_items(blockers: &[Value], preflight: &ClientPreflight) -> Vec<Value> {
    let paths = preflight
        .inspections
        .iter()
        .map(|(target, _, _)| (target.id.as_str(), target.path.as_path()))
        .collect::<BTreeMap<_, _>>();
    let mut items = blockers
        .iter()
        .map(|blocker| {
            let name = blocker
                .get("client")
                .or_else(|| blocker.get("resource"))
                .and_then(Value::as_str)
                .unwrap_or("uninstall")
                .to_owned();
            let detail = blocker
                .get("detail")
                .or_else(|| blocker.get("reason"))
                .and_then(Value::as_str)
                .unwrap_or("uninstall preflight failed")
                .to_owned();
            let mut item = json!({"name": name, "status": "failed", "detail": detail});
            if let Some(path) = blocker
                .get("client")
                .and_then(Value::as_str)
                .and_then(|client| paths.get(client))
            {
                item["configuration_path"] = json!(path.display().to_string());
            }
            item
        })
        .collect::<Vec<_>>();
    items.push(json!({
        "name": "uninstall",
        "status": "skipped",
        "detail": "No REA registration, skill, or data was removed. Repair each failed configuration, then rerun uninstall."
    }));
    items.push(json!({
        "name": "analysis_engine",
        "status": "retained",
        "detail": "Hopper is not owned by REA uninstall."
    }));
    items
}

fn client_states(targets: &[ClientRegistrationTarget], preflight: &ClientPreflight) -> Value {
    let inspected = preflight
        .inspections
        .iter()
        .map(|(target, state, _)| (target.id.as_str(), state))
        .collect::<BTreeMap<_, _>>();
    targets
        .iter()
        .map(|target| {
            let detected = target.evidence_paths.iter().any(|path| path.exists());
            let state = inspected.get(target.id.as_str()).copied();
            let status = match state {
                Some(RegistrationState::Owned) => "configured",
                Some(RegistrationState::Missing) | Some(RegistrationState::Absent) => "missing",
                Some(RegistrationState::Foreign) => "needs_configuration",
                Some(RegistrationState::Malformed(_)) => "invalid",
                Some(RegistrationState::Unreadable(_)) => "unknown",
                None if detected => "unknown",
                None => "missing",
            };
            let configured = status == "configured";
            let mut client = json!({
                "name": target.id,
                "displayName": target.display_name,
                "configPath": target.path,
                "markerPath": target.marker_path,
                "format": format!("{:?}", target.format).to_lowercase(),
            });
            if let Some(error) = &target.config_path_error {
                client["configPathError"] = json!(error);
            }
            if target.manual_registration {
                client["manualRegistration"] = json!(true);
            }
            if target.quit_before_setup {
                client["quitBeforeSetup"] = json!(true);
            }
            json!({
                "client": client,
                "detected": detected,
                "configured": configured,
                "status": status
            })
        })
        .collect::<Vec<_>>()
        .into()
}
fn transaction_report(report: &client_transaction::TransactionReport) -> Value {
    json!({"items":report.items.iter().map(|item| json!({"client":item.client_id,"path":item.path,"status":format!("{:?}",item.status),"backup":item.backup_path,"recovery":item.recovery_path,"detail":item.detail})).collect::<Vec<_>>(),"primaryFailure":report.primary_failure,"cleanupFailures":report.cleanup_failures})
}
fn failed_result(mut result: Value, applied: Vec<Value>, failure: String) -> Value {
    result["status"] = json!("needs_human");
    result["appliedActions"] = json!(applied_action_ids(&applied));
    result["operationDetails"] = json!(applied);
    result["code"] = json!("maintenance_failed");
    result["failure"] = json!(failure);
    result
}

fn partial_result(mut result: Value, applied: Vec<Value>, failure: String) -> Value {
    result["status"] = json!("needs_human");
    result["appliedActions"] = json!(applied_action_ids(&applied));
    result["operationDetails"] = json!(applied);
    result["code"] = json!("maintenance_partial");
    result["failure"] = json!(failure);
    result["remediation"] = json!(
        "Some changes were committed. Review appliedActions and recovery details before retrying."
    );
    result
}

fn applied_action_ids(actions: &[Value]) -> Vec<String> {
    actions
        .iter()
        .flat_map(|action| match action.get("kind").and_then(Value::as_str) {
            Some("clients") => action["report"]["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|item| item["client"].as_str())
                .map(|client| format!("configured_client:{client}"))
                .collect::<Vec<_>>(),
            Some("skills") => vec!["install_skill".to_owned()],
            Some("hopper") => vec!["install_hopper".to_owned()],
            Some(kind) => vec![kind.to_owned()],
            None => Vec::new(),
        })
        .collect()
}

fn transaction_failure_result(
    result: Value,
    applied: Vec<Value>,
    report: &client_transaction::TransactionReport,
) -> Value {
    let failure = report
        .primary_failure
        .clone()
        .unwrap_or_else(|| "transaction cleanup failed".to_owned());
    if transaction_is_partial(report) {
        partial_result(result, applied, failure)
    } else {
        failed_result(result, applied, failure)
    }
}

fn transaction_error_result(
    result: Value,
    applied: Vec<Value>,
    error: client_transaction::ClientTransactionError,
) -> Value {
    let failure = error.to_string();
    if matches!(
        error,
        client_transaction::ClientTransactionError::Committed { .. }
    ) {
        partial_result(result, applied, failure)
    } else {
        failed_result(result, applied, failure)
    }
}

fn transaction_is_partial(report: &client_transaction::TransactionReport) -> bool {
    report
        .items
        .iter()
        .any(|item| matches!(item.status, TransactionItemStatus::Applied))
        || !report.cleanup_failures.is_empty()
}

fn purge_managed_data(home: &Path) -> Vec<Value> {
    let root = home.join(".rea");
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ["cache", "state"]
                .into_iter()
                .map(|name| json!({"name":name,"status":"skipped","detail":"managed path does not exist"}))
                .collect();
        }
        Err(error) => {
            return ["cache", "state"]
                .into_iter()
                .map(|name| json!({"name":name,"status":"failed","detail":error.to_string()}))
                .collect();
        }
    };
    if !metadata.is_dir() {
        return ["cache", "state"]
            .into_iter()
            .map(|name| json!({"name":name,"status":"retained","detail":"managed data root is not a directory or is a symlink"}))
            .collect();
    }
    ["cache", "state"]
        .into_iter()
        .map(|name| remove_managed_path(&root.join(name), name))
        .collect()
}

fn remove_managed_path(path: &Path, name: &str) -> Value {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return json!({"name":name,"status":"skipped","detail":"managed path does not exist"});
        }
        Err(error) => return json!({"name":name,"status":"failed","detail":error.to_string()}),
    };
    if metadata.file_type().is_symlink() {
        return json!({"name":name,"status":"retained","detail":"managed path is a symbolic link"});
    }
    let result = if metadata.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Ok(()) => json!({"name":name,"status":"removed","path":path}),
        Err(error) => json!({"name":name,"status":"failed","detail":error.to_string()}),
    }
}
