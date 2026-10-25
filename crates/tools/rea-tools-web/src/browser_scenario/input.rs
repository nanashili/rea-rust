//! Scenario contract refinements and the canonical parsed scenario.
//!
//! Compatibility owners: `src/domain/browserScenario.ts` and
//! `src/domain/browserScenarioValues.ts`. The catalog schema (types, enums,
//! patterns and defaults) is enforced before the handler runs; this owner
//! applies the Zod transforms and refinements in schema traversal order and,
//! only when they all pass, the `superRefine` cross-field checks.
use crate::cdp::{self, Refinement, urls};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) const OPERATION: &str = "capture_browser_scenario";

#[derive(Clone, Debug)]
pub(crate) enum ScenarioValue {
    Literal(String),
    Secret(String),
}

#[derive(Clone, Debug)]
pub(crate) struct ScenarioUrl {
    pub url: String,
    pub query: Vec<(String, ScenarioValue)>,
}

#[derive(Clone, Debug)]
pub(crate) enum Locator {
    TestId(String),
    Role { role: String, name: String },
    Css(String),
}

#[derive(Clone, Debug)]
pub(crate) enum ActionKind {
    Goto {
        destination: ScenarioUrl,
        wait_until: String,
    },
    Click {
        locator: Locator,
        button: String,
        click_count: u64,
    },
    Fill {
        locator: Locator,
        value: ScenarioValue,
    },
    Press {
        locator: Locator,
        key: String,
    },
    SelectOption {
        locator: Locator,
        value: ScenarioValue,
    },
    Check {
        locator: Locator,
        checked: bool,
    },
    WaitFor {
        locator: Locator,
        state: String,
    },
    WaitForTimeout {
        duration_ms: u64,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct Action {
    pub step_id: String,
    pub name: String,
    pub timeout_ms: Option<u64>,
    pub kind: ActionKind,
}

#[derive(Clone, Debug)]
pub(crate) enum BrowserSelection {
    Launch {
        executable_path: String,
        headless: bool,
    },
    Connect {
        endpoint: String,
        target_id: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct Environment {
    pub width: u64,
    pub height: u64,
    pub device_scale_factor: f64,
    pub locale: String,
    pub timezone: String,
    pub color_scheme: String,
    pub reduced_motion: String,
    pub block_service_workers: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Cookie {
    pub name: String,
    pub value: ScenarioValue,
    pub destination: ScenarioUrl,
    pub http_only: bool,
    // `secure` is derived from the destination scheme, as `rewriteCookies` does.
    pub same_site: String,
}

#[derive(Clone, Debug)]
pub(crate) struct StorageSeed {
    pub origin: String,
    pub entries: Vec<(String, ScenarioValue)>,
}

#[derive(Clone, Debug)]
pub(crate) struct SecretDeclaration {
    pub secret_id: String,
    pub environment_variable: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NetworkSelection {
    pub request_body: bool,
    pub response_body: bool,
    pub header_values: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Limits {
    pub max_events: u64,
    pub max_event_allocation_bytes: u64,
    pub max_total_event_allocation_bytes: u64,
    pub max_network_transactions: u64,
    pub max_network_body_bytes: u64,
    pub max_network_body_allocation_bytes: u64,
    pub max_network_header_allocation_bytes: u64,
    pub max_network_metadata_allocation_bytes: u64,
}

impl Limits {
    pub(crate) fn resolver_defaults() -> Self {
        Self {
            max_events: 1024,
            max_event_allocation_bytes: 4 * 1024 * 1024,
            max_total_event_allocation_bytes: 16 * 1024 * 1024,
            max_network_transactions: 64,
            max_network_body_bytes: 4 * 1024 * 1024,
            max_network_body_allocation_bytes: 4 * 1024 * 1024,
            max_network_header_allocation_bytes: 1024 * 1024,
            max_network_metadata_allocation_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Capture {
    pub after_each_step: Vec<String>,
    pub at_end: Vec<String>,
    pub events: Vec<String>,
    pub network: NetworkSelection,
    pub network_value: Value,
    pub limits: Limits,
    pub limits_value: Value,
}

/// One parsed scenario plus its canonical (transformed) JSON form.
#[derive(Clone, Debug)]
pub(crate) struct Scenario {
    pub browser: BrowserSelection,
    pub start_url: ScenarioUrl,
    pub environment: Environment,
    pub actions: Vec<Action>,
    pub cookies: Vec<Cookie>,
    pub local_storage: Vec<StorageSeed>,
    pub session_storage: Vec<StorageSeed>,
    pub secrets: Vec<SecretDeclaration>,
    pub capture: Capture,
    pub canonical: Value,
}

fn path(parts: &[Value]) -> Vec<Value> {
    parts.to_vec()
}

fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn number(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}

fn boolean(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or_default()
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// `browserScenarioBaseUrlSchema`: normalize or report.
fn base_url(value: &mut Value, at: Vec<Value>, issues: &mut Vec<Refinement>) -> String {
    let raw = value.as_str().unwrap_or_default().to_owned();
    match urls::parse(&raw) {
        None => {
            issues.push(Refinement::new(at, "Invalid browser URL"));
            raw
        }
        Some(url)
            if !matches!(url.scheme(), "http" | "https")
                || !url.username().is_empty()
                || url.password().is_some_and(|password| !password.is_empty()) =>
        {
            issues.push(Refinement::new(
                at,
                "Browser URLs must be HTTP(S) and omit credentials",
            ));
            raw
        }
        Some(url) => {
            let normalized = url.as_str().to_owned();
            *value = Value::String(normalized.clone());
            normalized
        }
    }
}

fn scenario_value(value: &Value) -> ScenarioValue {
    if value.get("source").and_then(Value::as_str) == Some("secret") {
        ScenarioValue::Secret(string(value, "secret_id"))
    } else {
        ScenarioValue::Literal(string(value, "value"))
    }
}

fn scenario_url(value: &mut Value, at: &[Value], issues: &mut Vec<Refinement>) -> ScenarioUrl {
    let mut url_path = at.to_vec();
    url_path.push(json!("url"));
    let url = match value.get_mut("url") {
        Some(url) => base_url(url, url_path, issues),
        None => String::new(),
    };
    let query = value
        .get("query")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| {
            (
                string(entry, "name"),
                scenario_value(entry.get("value").unwrap_or(&Value::Null)),
            )
        })
        .collect();
    ScenarioUrl { url, query }
}

fn locator(value: &Value) -> Locator {
    match value.get("kind").and_then(Value::as_str) {
        Some("test_id") => Locator::TestId(string(value, "value")),
        Some("role") => Locator::Role {
            role: string(value, "role"),
            name: string(value, "name"),
        },
        _ => Locator::Css(string(value, "selector")),
    }
}

fn action(value: &mut Value, index: usize, issues: &mut Vec<Refinement>) -> Action {
    let name = string(value, "action");
    let step_id = string(value, "step_id");
    let timeout_ms = value.get("timeout_ms").and_then(Value::as_u64);
    let locate = || locator(value.get("locator").unwrap_or(&Value::Null));
    let kind = match name.as_str() {
        "goto" => {
            let at = [json!("actions"), json!(index), json!("destination")];
            let wait_until = string(value, "wait_until");
            let destination = match value.get_mut("destination") {
                Some(destination) => scenario_url(destination, &at, issues),
                None => ScenarioUrl {
                    url: String::new(),
                    query: Vec::new(),
                },
            };
            ActionKind::Goto {
                destination,
                wait_until,
            }
        }
        "click" => ActionKind::Click {
            locator: locate(),
            button: string(value, "button"),
            click_count: number(value, "click_count"),
        },
        "fill" => ActionKind::Fill {
            locator: locate(),
            value: scenario_value(value.get("value").unwrap_or(&Value::Null)),
        },
        "press" => ActionKind::Press {
            locator: locate(),
            key: string(value, "key"),
        },
        "select_option" => ActionKind::SelectOption {
            locator: locate(),
            value: scenario_value(value.get("value").unwrap_or(&Value::Null)),
        },
        "check" | "uncheck" => ActionKind::Check {
            locator: locate(),
            checked: name == "check",
        },
        "wait_for" => ActionKind::WaitFor {
            locator: locate(),
            state: string(value, "state"),
        },
        _ => ActionKind::WaitForTimeout {
            duration_ms: number(value, "duration_ms"),
        },
    };
    Action {
        step_id,
        name,
        timeout_ms,
        kind,
    }
}

fn storage_seeds(storage: &mut Value, key: &str, issues: &mut Vec<Refinement>) -> Vec<StorageSeed> {
    let Some(items) = storage.get_mut(key).and_then(Value::as_array_mut) else {
        return Vec::new();
    };
    let mut seeds = Vec::new();
    for (index, item) in items.iter_mut().enumerate() {
        let raw = string(item, "origin");
        let origin = match urls::exact_origin(&raw) {
            Some(origin) => {
                item["origin"] = Value::String(origin.clone());
                origin
            }
            None => {
                issues.push(Refinement::new(
                    path(&[json!("storage"), json!(key), json!(index), json!("origin")]),
                    "Expected one exact HTTP(S) origin without a path or wildcard",
                ));
                raw
            }
        };
        let entries = item
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|entry| {
                (
                    string(entry, "name"),
                    scenario_value(entry.get("value").unwrap_or(&Value::Null)),
                )
            })
            .collect();
        seeds.push(StorageSeed { origin, entries });
    }
    seeds
}

fn limits(value: &Value) -> Limits {
    Limits {
        max_events: number(value, "max_events"),
        max_event_allocation_bytes: number(value, "max_event_allocation_bytes"),
        max_total_event_allocation_bytes: number(value, "max_total_event_allocation_bytes"),
        max_network_transactions: number(value, "max_network_transactions"),
        max_network_body_bytes: number(value, "max_network_body_bytes"),
        max_network_body_allocation_bytes: number(value, "max_network_body_allocation_bytes"),
        max_network_header_allocation_bytes: number(value, "max_network_header_allocation_bytes"),
        max_network_metadata_allocation_bytes: number(
            value,
            "max_network_metadata_allocation_bytes",
        ),
    }
}

/// `path.isAbsolute` for the host platform.
fn is_absolute(value: &str) -> bool {
    Path::new(value).is_absolute()
}

/// Which validation layer rejected the input.
pub(crate) enum Rejection {
    /// Registered-schema transforms and refinements: the SDK's text-only
    /// `Input validation error`.
    Schema(Vec<Refinement>),
    /// `browserScenarioSchema.superRefine`: a structured input error.
    Scenario(Vec<Refinement>),
}

/// Parse a schema-valid input, returning every refinement issue otherwise.
pub(crate) fn parse(input: &Value) -> Result<Scenario, Rejection> {
    let mut canonical = input.clone();
    let mut issues = Vec::new();
    // `browserScenarioStorageSchema` defaults that the advertised JSON
    // Schema does not declare.
    if let Some(map) = canonical.as_object_mut() {
        let storage = map.entry("storage").or_insert_with(|| json!({}));
        if let Some(storage) = storage.as_object_mut() {
            for key in ["cookies", "local_storage", "session_storage"] {
                storage.entry(key).or_insert_with(|| json!([]));
            }
        }
    }

    let browser_value = canonical.get_mut("browser").cloned().unwrap_or(Value::Null);
    let browser = if browser_value.get("mode").and_then(Value::as_str) == Some("connect") {
        let raw = string(&browser_value, "cdp_endpoint");
        let endpoint = match cdp::parse_http_endpoint(&raw) {
            Ok(endpoint) => {
                canonical["browser"]["cdp_endpoint"] = Value::String(endpoint.url.clone());
                endpoint.url
            }
            Err(message) => {
                issues.push(Refinement::new(
                    path(&[json!("browser"), json!("cdp_endpoint")]),
                    message,
                ));
                raw
            }
        };
        let target_id = string(&browser_value, "target_id").trim().to_owned();
        if target_id.is_empty() {
            issues.push(Refinement::new(
                path(&[json!("browser"), json!("target_id")]),
                "Too small: expected string to have >=1 characters",
            ));
        } else {
            canonical["browser"]["target_id"] = Value::String(target_id.clone());
        }
        BrowserSelection::Connect {
            endpoint,
            target_id,
        }
    } else {
        let executable_path = string(&browser_value, "executable_path");
        if !is_absolute(&executable_path) {
            issues.push(Refinement::new(
                path(&[json!("browser"), json!("executable_path")]),
                "executable_path must be an absolute local filesystem path (for example /opt/chromium/chrome or C:\\chromium\\chrome.exe)",
            ));
        }
        BrowserSelection::Launch {
            executable_path,
            headless: browser_value
                .get("headless")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        }
    };

    let start_url = match canonical.get_mut("start_url") {
        Some(start) => scenario_url(start, &[json!("start_url")], &mut issues),
        None => ScenarioUrl {
            url: String::new(),
            query: Vec::new(),
        },
    };

    let environment_value = canonical.get("environment").cloned().unwrap_or(Value::Null);
    let viewport = environment_value
        .get("viewport")
        .cloned()
        .unwrap_or(Value::Null);
    let environment = Environment {
        width: number(&viewport, "width"),
        height: number(&viewport, "height"),
        device_scale_factor: viewport
            .get("device_scale_factor")
            .and_then(Value::as_f64)
            .unwrap_or(1.0),
        locale: string(&environment_value, "locale"),
        timezone: string(&environment_value, "timezone"),
        color_scheme: string(&environment_value, "color_scheme"),
        reduced_motion: string(&environment_value, "reduced_motion"),
        block_service_workers: string(&environment_value, "service_workers") == "block",
    };

    let mut actions = Vec::new();
    if let Some(items) = canonical.get_mut("actions").and_then(Value::as_array_mut) {
        for (index, item) in items.iter_mut().enumerate() {
            actions.push(action(item, index, &mut issues));
        }
    }

    let mut cookies = Vec::new();
    let mut local_storage = Vec::new();
    let mut session_storage = Vec::new();
    if let Some(storage) = canonical.get_mut("storage") {
        if let Some(items) = storage.get_mut("cookies").and_then(Value::as_array_mut) {
            for (index, item) in items.iter_mut().enumerate() {
                let at = [
                    json!("storage"),
                    json!("cookies"),
                    json!(index),
                    json!("destination"),
                ];
                let destination = match item.get_mut("destination") {
                    Some(destination) => scenario_url(destination, &at, &mut issues),
                    None => ScenarioUrl {
                        url: String::new(),
                        query: Vec::new(),
                    },
                };
                cookies.push(Cookie {
                    name: string(item, "name"),
                    value: scenario_value(item.get("value").unwrap_or(&Value::Null)),
                    destination,
                    http_only: boolean(item, "http_only"),
                    same_site: string(item, "same_site"),
                });
            }
        }
        local_storage = storage_seeds(storage, "local_storage", &mut issues);
        session_storage = storage_seeds(storage, "session_storage", &mut issues);
    }

    let mut secrets = Vec::new();
    for (index, item) in canonical
        .get("secrets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let environment_variable = string(item, "environment_variable");
        if environment_variable.contains('=') || environment_variable.contains('\0') {
            issues.push(Refinement::new(
                path(&[
                    json!("secrets"),
                    json!(index),
                    json!("environment_variable"),
                ]),
                "Environment variable names cannot contain '=' or NUL",
            ));
        }
        secrets.push(SecretDeclaration {
            secret_id: string(item, "secret_id"),
            environment_variable,
        });
    }

    let capture_value = canonical.get("capture").cloned().unwrap_or(Value::Null);
    let network_value = capture_value.get("network").cloned().unwrap_or_else(
        || json!({ "request_body": false, "response_body": false, "header_values": false }),
    );
    let limits_value = capture_value.get("limits").cloned().unwrap_or(Value::Null);
    let capture = Capture {
        after_each_step: strings(&capture_value, "after_each_step"),
        at_end: strings(&capture_value, "at_end"),
        events: strings(&capture_value, "events"),
        network: NetworkSelection {
            request_body: boolean(&network_value, "request_body"),
            response_body: boolean(&network_value, "response_body"),
            header_values: boolean(&network_value, "header_values"),
        },
        network_value,
        limits: limits(&limits_value),
        limits_value,
    };

    if !issues.is_empty() {
        return Err(Rejection::Schema(issues));
    }
    let scenario = Scenario {
        browser,
        start_url,
        environment,
        actions,
        cookies,
        local_storage,
        session_storage,
        secrets,
        capture,
        canonical,
    };
    let refinements = super_refine(&scenario);
    if refinements.is_empty() {
        Ok(scenario)
    } else {
        Err(Rejection::Scenario(refinements))
    }
}

fn value_references(value: &ScenarioValue) -> Vec<String> {
    match value {
        ScenarioValue::Secret(id) => vec![id.clone()],
        ScenarioValue::Literal(_) => Vec::new(),
    }
}

fn url_references(url: &ScenarioUrl) -> Vec<String> {
    url.query
        .iter()
        .flat_map(|(_, value)| value_references(value))
        .collect()
}

/// `validateBrowserScenario`.
fn super_refine(scenario: &Scenario) -> Vec<Refinement> {
    let mut issues = Vec::new();
    let unique = |values: Vec<&str>, key: &str, label: &str, issues: &mut Vec<Refinement>| {
        let distinct: BTreeSet<&str> = values.iter().copied().collect();
        if distinct.len() != values.len() {
            issues.push(Refinement::new(
                vec![json!(key)],
                format!("{label} must be unique"),
            ));
        }
    };
    unique(
        scenario
            .actions
            .iter()
            .map(|action| action.step_id.as_str())
            .collect(),
        "actions",
        "Action step IDs",
        &mut issues,
    );
    unique(
        scenario
            .secrets
            .iter()
            .map(|secret| secret.secret_id.as_str())
            .collect(),
        "secrets",
        "Secret IDs",
        &mut issues,
    );
    unique(
        scenario
            .secrets
            .iter()
            .map(|secret| secret.environment_variable.as_str())
            .collect(),
        "secrets",
        "Secret environment variables",
        &mut issues,
    );
    let mut references: Vec<String> = Vec::new();
    for action in &scenario.actions {
        match &action.kind {
            ActionKind::Fill { value, .. } | ActionKind::SelectOption { value, .. } => {
                references.extend(value_references(value));
            }
            ActionKind::Goto { destination, .. } => references.extend(url_references(destination)),
            _ => {}
        }
    }
    references.extend(url_references(&scenario.start_url));
    for cookie in &scenario.cookies {
        references.extend(value_references(&cookie.value));
        references.extend(url_references(&cookie.destination));
    }
    for seed in scenario
        .local_storage
        .iter()
        .chain(&scenario.session_storage)
    {
        for (_, value) in &seed.entries {
            references.extend(value_references(value));
        }
    }
    let declared: BTreeSet<&str> = scenario
        .secrets
        .iter()
        .map(|secret| secret.secret_id.as_str())
        .collect();
    for reference in references {
        if !declared.contains(reference.as_str()) {
            issues.push(Refinement::new(
                vec![json!("secrets")],
                format!("Secret reference {reference} is not declared"),
            ));
        }
    }
    issues
}
