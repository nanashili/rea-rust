//! `buildCapabilityInventory` + `compactToolAvailability`
//! (`src/application/CapabilityInventory.ts`) and `tool_availability`
//! (`compactToolAvailability(buildCapabilityInventory(status, policy,
//! features))`).
//!
//! The TS `TOOL_CONTRACTS` constant is provided by the frozen catalog
//! (`rea_mcp::catalog()`: name, kind = surface, effects, annotations).
//! Constants the catalog does not provide (`ENHANCED_REQUIREMENTS`,
//! `FRIDA_TOOL_CONTRACTS` names, `MACHO_TARGET_OPERATIONS`,
//! `NAVIGATION_CONTEXT_MODES`, the native dispatch/ui/call-route operation
//! names, `DEFAULT_CALL_RELATIONSHIP_DIRECTION`) are copied from TS below.

use super::availability_policy::{AvailabilityPolicy, JebAvailability, ProbeAvailability};
use super::client_features::ClientFeatures;
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashMap};

// ---------------------------------------------------------------------------
// Constants copied from TS (not provided by the frozen catalog).
// ---------------------------------------------------------------------------

/// `DEFAULT_CALL_RELATIONSHIP_DIRECTION` (`src/contracts/enhancedInputs.ts`).
const DEFAULT_CALL_RELATIONSHIP_DIRECTION: &str = "forward";

/// `NATIVE_DISPATCH_METADATA_SOURCES`
/// (`src/application/native/NativeDispatchMetadataInspection.ts`).
const NATIVE_DISPATCH_BINARY: &str = "inspect_native_dispatch_metadata";
const NATIVE_DISPATCH_SYMBOLS: &str = "list_names";

/// `NATIVE_UI_ACTION_OPERATIONS` (`src/application/native/NativeUiActionTrace.ts`).
const NATIVE_UI_INTERFACE_BUILDER: &str = "decode_interface_builder";
const NATIVE_UI_NATIVE_SEED: &str = "procedure_address";

/// `NATIVE_CALL_ROUTE_SOURCES` (`src/application/native/NativeCallRoutes.ts`).
const NATIVE_CALL_ROUTE_REFERENCES: &str = "procedure_references";
const NATIVE_CALL_ROUTE_CALLEES: &str = "procedure_callees";

/// `CALL_RELATIONSHIP_TRAVERSALS` (`src/application/CallRelationshipTraversal.ts`).
const CALL_TRAVERSAL_FORWARD: &str = "procedure_callees";
const CALL_TRAVERSAL_BACKWARD: &str = "procedure_callers";

/// `FRIDA_TOOL_CONTRACTS` tool names (`src/contracts/fridaToolContracts.ts`).
const FRIDA_OPERATION_NAMES: [&str; 9] = [
    "list_frida_devices",
    "list_frida_processes",
    "start_frida_session",
    "load_frida_script",
    "resume_frida_session",
    "unload_frida_script",
    "frida_session_status",
    "close_frida_session",
    "instrument_with_frida",
];

/// `MACHO_TARGET_OPERATIONS` (`src/application/CapabilityInventory.ts`).
const MACHO_TARGET_OPERATIONS: [&str; 6] = [
    "inspect_signature",
    "inspect_macho",
    "list_architectures",
    "observe_native_calls",
    "observe_native_ui",
    "capture_native_ui_scenario",
];

/// `ACTIVE_TARGET_KINDS` — contract kinds whose operations run on the target.
const ACTIVE_TARGET_KINDS: [&str; 4] = [
    "official-proxy",
    "enhanced",
    "native-provider",
    "artifact-provider",
];

/// `TOOL_EFFECT_NAMES` order (`src/contracts/toolOutputSchemaPrimitives.ts`).
const TOOL_EFFECT_NAMES: [&str; 10] = [
    "mutatesTarget",
    "mutatesSession",
    "writesFilesystem",
    "launchesProcess",
    "accessesNetwork",
    "changesUiState",
    "mayDiscardData",
    "executesForeignCode",
    "mutatesDevice",
    "idempotent",
];

/// `TOOL_ANNOTATION_NAMES` order (`src/contracts/toolOutputSchemaPrimitives.ts`).
const TOOL_ANNOTATION_NAMES: [&str; 4] = ["read_only", "destructive", "idempotent", "open_world"];

// ---------------------------------------------------------------------------
// Requirement / composition model (TS CompositionRequirements, ModeComposition).
// ---------------------------------------------------------------------------

/// One composition requirement: a single operation, or an operation group any
/// of which satisfies it.
#[derive(Clone)]
enum Requirement {
    One(&'static str),
    Any(Vec<&'static str>),
}

#[derive(Clone)]
struct AvailabilityMode {
    name: &'static str,
    requirements: Vec<Requirement>,
}

#[derive(Clone)]
enum ProviderComposition {
    Requirements(Vec<Requirement>),
    Modes {
        default_mode: Option<&'static str>,
        modes: Vec<AvailabilityMode>,
    },
}

fn call_relationship_composition() -> ProviderComposition {
    // Object.entries order of CALL_RELATIONSHIP_TRAVERSALS: forward, backward.
    ProviderComposition::Modes {
        default_mode: Some(DEFAULT_CALL_RELATIONSHIP_DIRECTION),
        modes: vec![
            AvailabilityMode {
                name: "forward",
                requirements: vec![
                    Requirement::One("procedure_address"),
                    Requirement::One(CALL_TRAVERSAL_FORWARD),
                ],
            },
            AvailabilityMode {
                name: "backward",
                requirements: vec![
                    Requirement::One("procedure_address"),
                    Requirement::One(CALL_TRAVERSAL_BACKWARD),
                ],
            },
        ],
    }
}

fn native_ui_action_composition() -> ProviderComposition {
    ProviderComposition::Modes {
        default_mode: None,
        modes: vec![
            AvailabilityMode {
                name: "authored_ui_dispatch",
                requirements: vec![
                    Requirement::One(NATIVE_UI_INTERFACE_BUILDER),
                    // Object.values(NATIVE_DISPATCH_METADATA_SOURCES).
                    Requirement::Any(vec![NATIVE_DISPATCH_BINARY, NATIVE_DISPATCH_SYMBOLS]),
                ],
            },
            AvailabilityMode {
                name: "native_seed_call_trace",
                requirements: vec![
                    Requirement::Any(vec![NATIVE_DISPATCH_BINARY, NATIVE_DISPATCH_SYMBOLS]),
                    Requirement::One(NATIVE_UI_NATIVE_SEED),
                    // Object.values(NATIVE_CALL_ROUTE_SOURCES).
                    Requirement::Any(vec![
                        NATIVE_CALL_ROUTE_REFERENCES,
                        NATIVE_CALL_ROUTE_CALLEES,
                    ]),
                ],
            },
        ],
    }
}

/// `NAVIGATION_CONTEXT_MODES` (`src/application/CapabilityInventory.ts`).
fn navigation_context_modes() -> Vec<AvailabilityMode> {
    vec![
        AvailabilityMode {
            name: "current_selection",
            requirements: vec![
                Requirement::One("current_document"),
                Requirement::One("current_address"),
                Requirement::One("resolve_containing_procedure"),
            ],
        },
        AvailabilityMode {
            name: "explicit_document",
            requirements: vec![
                Requirement::One("current_address"),
                Requirement::One("resolve_containing_procedure"),
            ],
        },
    ]
}

/// `ENHANCED_REQUIREMENTS` (`src/application/CapabilityInventory.ts`).
fn enhanced_requirements(name: &str) -> Option<ProviderComposition> {
    use ProviderComposition::Requirements;
    let req =
        |ops: &[&'static str]| Requirements(ops.iter().map(|op| Requirement::One(op)).collect());
    Some(match name {
        "trace_native_values" => req(&["analyze_function", "resolve_native_call_targets"]),
        "trace_native_ui_action" => native_ui_action_composition(),
        "inspect_native_dispatch_metadata" => Requirements(vec![Requirement::Any(vec![
            NATIVE_DISPATCH_BINARY,
            NATIVE_DISPATCH_SYMBOLS,
        ])]),
        "get_objc_classes" => req(&["list_names"]),
        "get_objc_protocols" => req(&["list_names"]),
        "batch_decompile" => req(&["procedure_pseudo_code"]),
        "get_call_graph" => call_relationship_composition(),
        "trace_call_path" => call_relationship_composition(),
        "analyze_swift_types" => req(&["list_procedures"]),
        "find_xrefs_to_name" => req(&["list_names", "xrefs"]),
        "binary_overview" => Requirements(vec![
            Requirement::Any(vec!["current_document", "list_documents"]),
            Requirement::One("list_procedures"),
            Requirement::One("list_strings"),
        ]),
        "analyze_function" => req(&["analyze_function"]),
        "inspect_native_api" => req(&["analyze_function"]),
        "trace_feature" => req(&[
            "search_strings",
            "search_procedures",
            "xrefs",
            "resolve_containing_procedure",
        ]),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Session status parse (statusSchema).
// ---------------------------------------------------------------------------

/// A provider capability descriptor decoded from the session status
/// (`ProviderCapability` after `expandProviderCapabilities`).
struct ProviderDescriptor {
    available: bool,
    reason: Option<String>,
    availability_code: Option<String>,
}

struct SessionStatus {
    open: bool,
    kind: Option<String>,
    format: Option<String>,
    descriptors: HashMap<String, ProviderDescriptor>,
}

/// Parse the session status against the TS `statusSchema`, expanding the wire
/// `ProviderCapabilitySet[]` into per-operation descriptors. Returns `Err`
/// only for a status that fails the TS schema parse.
fn parse_status(session_status: &Value) -> Result<SessionStatus, String> {
    let object = session_status
        .as_object()
        .ok_or_else(|| "status must be an object".to_owned())?;

    let open = object
        .get("open")
        .and_then(Value::as_bool)
        .ok_or_else(|| "status.open must be a boolean".to_owned())?;

    let kind = match object.get("kind") {
        None | Some(Value::Null) => None,
        Some(Value::String(kind))
            if matches!(
                kind.as_str(),
                "executable" | "database" | "archive" | "artifact"
            ) =>
        {
            Some(kind.clone())
        }
        Some(_) => return Err("status.kind is not a valid target kind".to_owned()),
    };

    let format = match object.get("format") {
        None | Some(Value::Null) => None,
        Some(Value::String(format)) => Some(format.clone()),
        Some(_) => return Err("status.format must be a string".to_owned()),
    };

    let capabilities = object
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| "status.capabilities must be an array".to_owned())?;

    let mut descriptors: HashMap<String, ProviderDescriptor> = HashMap::new();
    for set in capabilities {
        let shared_limitations_len = set
            .get("shared_limitations")
            .and_then(Value::as_array)
            .ok_or_else(|| "capability set is missing shared_limitations".to_owned())?
            .len();
        let _ = shared_limitations_len; // Limitation values do not affect availability.
        let groups = set
            .get("groups")
            .and_then(Value::as_array)
            .ok_or_else(|| "capability set is missing groups".to_owned())?;
        for group in groups {
            let available = group
                .get("available")
                .and_then(Value::as_bool)
                .ok_or_else(|| "capability group is missing available".to_owned())?;
            let reason = match group.get("reason") {
                Some(Value::String(reason)) => Some(reason.clone()),
                Some(Value::Null) | None => None,
                Some(_) => return Err("capability group reason must be string or null".to_owned()),
            };
            let availability_code = match group.get("availability_code") {
                Some(Value::String(code)) => Some(code.clone()),
                Some(Value::Null) | None => None,
                Some(_) => {
                    return Err(
                        "capability group availability_code must be string or null".to_owned()
                    );
                }
            };
            let operations = group
                .get("operations")
                .and_then(Value::as_array)
                .ok_or_else(|| "capability group is missing operations".to_owned())?;
            for operation in operations {
                let operation = operation
                    .as_str()
                    .ok_or_else(|| "capability operation must be a string".to_owned())?;
                // expandProviderCapabilities overwrites on duplicate operation,
                // matching Map construction from the descriptor list.
                descriptors.insert(
                    operation.to_owned(),
                    ProviderDescriptor {
                        available,
                        reason: reason.clone(),
                        availability_code: availability_code.clone(),
                    },
                );
            }
        }
    }

    Ok(SessionStatus {
        open,
        kind,
        format,
        descriptors,
    })
}

// ---------------------------------------------------------------------------
// Availability model (TS Availability).
// ---------------------------------------------------------------------------

/// A resolved availability decision: `reason` is `"available"` or a
/// `ToolUnavailabilityReason`; `remediation` is null for `"available"`.
#[derive(Clone)]
struct Availability {
    reason: String,
    remediation: Option<String>,
    default_mode_available: Option<bool>,
    modes: Option<Vec<Value>>,
}

impl Availability {
    fn available() -> Self {
        Availability {
            reason: "available".to_owned(),
            remediation: None,
            default_mode_available: None,
            modes: None,
        }
    }

    fn reason(reason: &str, remediation: Option<String>) -> Self {
        Availability {
            reason: reason.to_owned(),
            remediation,
            default_mode_available: None,
            modes: None,
        }
    }
}

struct AvailabilityContext<'a> {
    name: &'a str,
    kind: &'a str,
    target_open: bool,
    target_kind: Option<&'a str>,
    target_format: Option<&'a str>,
    descriptors: &'a HashMap<String, ProviderDescriptor>,
    policy: &'a AvailabilityPolicy,
}

fn is_mach_o_format(format: Option<&str>) -> bool {
    matches!(format, Some("mach-o") | Some("mach-o-universal"))
}

// ---------------------------------------------------------------------------
// availabilityFor and its sub-decisions.
// ---------------------------------------------------------------------------

fn availability_for(context: &AvailabilityContext<'_>) -> Availability {
    if context.name == "observe_web_execution" || context.name == "inspect_web_event_listeners" {
        return Availability::available();
    }
    if context.name == "get_navigation_context" {
        return availability_for_modes(
            &navigation_context_modes(),
            Some("current_selection"),
            context.descriptors,
        );
    }
    if let Some(availability) = javascript_application_availability(context.name) {
        return availability;
    }
    if let Some(failure) = optional_provider_failure_for(context) {
        return Availability::reason(
            "provider_unavailable",
            Some(format!(
                "Adapter {} could not load: {}. Repair the adapter installation and restart REA; other capabilities remain available.",
                failure.0, failure.1
            )),
        );
    }
    if let Some(availability) = workflow_availability_for(context) {
        return availability;
    }
    if let Some(availability) = host_availability(context) {
        return availability;
    }
    if let Some(availability) = target_availability(context) {
        return availability;
    }
    provider_availability(context)
}

/// Returns `(providerId, reason)` of the optional provider load failure, if any.
fn optional_provider_failure_for(context: &AvailabilityContext<'_>) -> Option<(String, String)> {
    let failures = context.policy.optional_provider_load_failures.as_ref()?;
    let pick = |failure: &Option<super::availability_policy::OptionalProviderLoadFailure>| {
        failure
            .as_ref()
            .map(|failure| (failure.provider_id.clone(), failure.reason.clone()))
    };
    if context.name == "capture_browser_scenario" {
        return pick(&failures.browser_scenario_capture);
    }
    if context.kind == "browser-provider" {
        return pick(&failures.browser_observation);
    }
    if context.name == "capture_electron_scenario" {
        return pick(&failures.electron_active_observation);
    }
    if context.kind == "electron-provider" {
        return pick(&failures.electron_observation);
    }
    if context.kind == "runtime-provider" {
        return pick(&failures.javascript_runtime_observation);
    }
    if FRIDA_OPERATION_NAMES.contains(&context.name) {
        return pick(&failures.frida_instrumentation);
    }
    None
}

fn javascript_application_availability(name: &str) -> Option<Availability> {
    if name == "analyze_javascript_application" || name == "reconcile_javascript_runtime" {
        Some(Availability::available())
    } else {
        None
    }
}

fn enabled(flag: bool) -> bool {
    flag
}

fn workflow_availability_for(context: &AvailabilityContext<'_>) -> Option<Availability> {
    let name = context.name;
    let kind = context.kind;
    let policy = context.policy;

    if matches!(
        name,
        "inspect_desktop_application"
            | "inspect_go_binary"
            | "inspect_il2cpp_metadata"
            | "inspect_rust_binary"
            | "inspect_electron_fuses"
    ) {
        return Some(Availability::available());
    }
    if name == "inspect_sqlite_database" {
        // The native runtime does not run on Node, so there is no Node version
        // to admit. The bundled native SQLite inspection worker is always
        // available in this runtime (documented deviation from TS, which gates
        // on `process.versions.node`).
        return Some(Availability::available());
    }
    if name == "trace_web_module_imports" {
        let web_resolution = enabled(policy.web_module_resolution_enabled);
        let native_literal_mode = if web_resolution {
            json!({
                "name": "native-literal-resolution",
                "available": true,
                "missing_operations": [],
                "remediation": null,
            })
        } else {
            json!({
                "name": "native-literal-resolution",
                "available": false,
                "missing_operations": ["native-module-resolver"],
                "remediation": "Provide an absolute REA_BROWSER_EXECUTABLE supporting import.meta.resolve; no binary target is required.",
            })
        };
        return Some(Availability {
            reason: "available".to_owned(),
            remediation: None,
            default_mode_available: Some(web_resolution),
            modes: Some(vec![
                json!({
                    "name": "sources-without-literal-imports",
                    "available": true,
                    "missing_operations": [],
                    "remediation": null,
                }),
                native_literal_mode,
            ]),
        });
    }
    if name == "recover_javascript_sources" {
        return Some(if enabled(policy.javascript_recovery_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("On Linux x64, provide an absolute REA_WAKARU_COMMAND for Wakaru ^1.13.0 (verified with 1.14.0) and util-linux prlimit; see docs/javascript-recovery.md#install-wakaru. No binary target is required.".to_owned()),
            )
        });
    }
    if name == "inspect_binary_layout" {
        return Some(if enabled(policy.binary_layout_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("On Linux x64, set absolute REA_PWNTOOLS_PYTHON to caller-supplied Python with pwntools 4.15.0. No active binary target is required.".to_owned()),
            )
        });
    }
    if name == "inspect_packet_capture" || name == "inspect_packet_fields" {
        return Some(if enabled(policy.packet_capture_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("On Linux, supply TShark 4.x via absolute REA_TSHARK_COMMAND and util-linux prlimit (REA_TSHARK_PRLIMIT_COMMAND, default /usr/bin/prlimit). No active binary target or hardware is required; the tool is checked at execution.".to_owned()),
            )
        });
    }
    if name == "decode_signal_recording" || name == "inspect_signal_decoders" {
        return Some(if enabled(policy.signal_recording_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("On Linux, supply sigrok-cli 0.7.2 via absolute REA_SIGROK_COMMAND and util-linux prlimit (REA_SIGROK_PRLIMIT_COMMAND, default /usr/bin/prlimit). No active binary target or hardware is required; the tool is checked at execution.".to_owned()),
            )
        });
    }
    if name == "inspect_wasm_artifact" {
        return Some(if enabled(policy.wasm_artifact_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("Supply WABT 1.0.42 via absolute REA_WABT_BIN_DIRECTORY. No active binary target is required; tools are checked at execution.".to_owned()),
            )
        });
    }
    if name == "inspect_pe_resources" {
        return Some(Availability::available());
    }
    if name == "inspect_evm_interface" {
        return Some(if enabled(policy.evm_interface_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("The bundled offline EVM interface profile is currently real-verified on Linux x64. No active binary target or chain endpoint is required.".to_owned()),
            )
        });
    }
    if name == "inspect_recorded_crash" {
        return Some(if enabled(policy.recorded_crash_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("On Linux x64, set absolute REA_PWNTOOLS_PYTHON to caller-supplied Python with pwntools 4.15.0. No active binary target is required.".to_owned()),
            )
        });
    }
    if kind == "firmware-provider" {
        let enabled_flag = if name == "inspect_firmware_regions" {
            policy.firmware_inspection_enabled
        } else {
            policy.firmware_extraction_enabled
        };
        return Some(if enabled_flag {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("On Linux, provide an absolute REA_BINWALK_COMMAND (Binwalk 3.1.x, verified with 3.1.0) or REA_UNBLOB_COMMAND (Unblob 26.6.x, verified with 26.6.4) path and util-linux prlimit. Extraction also requires the selected format\u{2019}s external extractor.".to_owned()),
            )
        });
    }
    if kind == "android-provider" {
        return Some(android_availability(
            policy.android_analysis_availability.as_ref(),
        ));
    }
    if kind == "adb-provider" {
        return Some(owner_probe_availability(
            policy.adb_analysis_availability.as_ref(),
            "Set REA_ADB_PATH to a caller-supplied adb executable or make adb available on PATH. This checks the client version only; device and serial availability depend on the request.",
        ));
    }
    if kind == "apktool-provider" {
        return Some(owner_probe_availability(
            policy.apktool_analysis_availability.as_ref(),
            "Set REA_APKTOOL_COMMAND to a caller-supplied Apktool executable or make Apktool 2.7.0 or newer available on PATH.",
        ));
    }
    if kind == "jeb-provider" {
        return Some(jeb_availability(
            name,
            policy.jeb_analysis_availability.as_ref(),
        ));
    }
    if let Some(browser) = browser_provider_availability(name, kind, policy) {
        return Some(browser);
    }
    if name == "capture_process_scenario" && !policy.process_capture_enabled {
        return Some(Availability::reason(
            "unsupported_host",
            Some("Run process capture on a supported Linux or macOS host.".to_owned()),
        ));
    }
    if kind == "application" {
        return Some(Availability::available());
    }
    if kind == "pcap-provider" || kind == "flutter-provider" {
        return Some(Availability::available());
    }
    if let Some(electron) = electron_provider_availability(name, kind, policy) {
        return Some(electron);
    }
    if kind == "runtime-provider" {
        return Some(if enabled(policy.v8_inspector_observation_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("Start REA with its JavaScript runtime provider available.".to_owned()),
            )
        });
    }
    if kind == "session" {
        return Some(Availability::available());
    }
    None
}

fn android_availability(availability: Option<&ProbeAvailability>) -> Availability {
    match availability {
        Some(ProbeAvailability::Available { .. }) => Availability::available(),
        other => {
            let (code, reason) = match other {
                Some(ProbeAvailability::Unavailable { code, reason, .. }) => {
                    (Some(code.as_str()), Some(reason.clone()))
                }
                _ => (None, None),
            };
            let mapped = match code {
                Some("unsupported_host") => "unsupported_host",
                Some("runtime_unavailable") => "provider_unavailable",
                _ => "provider_missing",
            };
            Availability::reason(
                mapped,
                Some(reason.unwrap_or_else(|| "Set REA_JADX_MCP_JAR to a caller-supplied jadx-headless-mcp 0.7.1 JAR and provide a full JDK on Linux, macOS, or Windows x64 with its matching bundled native controls.".to_owned())),
            )
        }
    }
}

fn owner_probe_availability(
    observation: Option<&ProbeAvailability>,
    missing_remediation: &str,
) -> Availability {
    match observation {
        None => Availability::reason("provider_missing", Some(missing_remediation.to_owned())),
        Some(ProbeAvailability::Available { .. }) => Availability::available(),
        Some(ProbeAvailability::Unavailable { code, reason, .. }) => {
            let mapped = match code.as_str() {
                "unsupported_host" => "unsupported_host",
                "not_configured" => "provider_missing",
                _ => "provider_unavailable",
            };
            Availability::reason(mapped, Some(reason.clone()))
        }
    }
}

fn jeb_availability(name: &str, availability: Option<&JebAvailability>) -> Availability {
    const MISSING: &str = "Start a JEB client serving MCP (GUI client, or headless via its programmatic launcher) and point REA_JEB_MCP_URL at it (default http://127.0.0.1:8425/mcp). REA does not install or launch JEB.";
    match availability {
        Some(JebAvailability::Available {
            supported_operations,
        }) => {
            if supported_operations
                .iter()
                .any(|operation| operation == name)
            {
                Availability::available()
            } else {
                Availability::reason(
                    "provider_unavailable",
                    Some(format!(
                        "The running JEB endpoint does not advertise support for {name}. Use a JEB client build that provides this operation."
                    )),
                )
            }
        }
        Some(JebAvailability::Probe(probe)) => owner_probe_availability(Some(probe), MISSING),
        None => owner_probe_availability(None, MISSING),
    }
}

fn electron_provider_availability(
    name: &str,
    kind: &str,
    policy: &AvailabilityPolicy,
) -> Option<Availability> {
    if kind != "electron-provider" {
        return None;
    }
    if name == "capture_electron_scenario" {
        return Some(if enabled(policy.electron_automation_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("Start REA with the Electron scenario provider available.".to_owned()),
            )
        });
    }
    Some(if enabled(policy.electron_observation_enabled) {
        Availability::available()
    } else {
        Availability::reason(
            "provider_missing",
            Some("Start REA with its Electron observation provider available.".to_owned()),
        )
    })
}

fn browser_provider_availability(
    name: &str,
    kind: &str,
    policy: &AvailabilityPolicy,
) -> Option<Availability> {
    if name == "capture_browser_scenario" {
        return Some(if enabled(policy.browser_scenario_enabled) {
            Availability::available()
        } else {
            Availability::reason(
                "provider_missing",
                Some("Start REA with its browser scenario provider available.".to_owned()),
            )
        });
    }
    if kind != "browser-provider" {
        return None;
    }
    Some(if enabled(policy.browser_observation_enabled) {
        Availability::available()
    } else {
        Availability::reason(
            "provider_missing",
            Some("Start REA with its browser observation provider available.".to_owned()),
        )
    })
}

fn host_availability(context: &AvailabilityContext<'_>) -> Option<Availability> {
    if context.kind == "enhanced" {
        return None;
    }
    let descriptor = context.descriptors.get(context.name)?;
    if !descriptor.available && descriptor.availability_code.as_deref() == Some("unsupported_host")
    {
        Some(Availability::reason(
            "unsupported_host",
            descriptor.reason.clone(),
        ))
    } else {
        None
    }
}

fn target_availability(context: &AvailabilityContext<'_>) -> Option<Availability> {
    if FRIDA_OPERATION_NAMES.contains(&context.name) {
        return None;
    }
    if !context.target_open && ACTIVE_TARGET_KINDS.contains(&context.kind) {
        return Some(Availability::reason(
            "target_required",
            Some("Call open_binary with a supported local target.".to_owned()),
        ));
    }
    if let Some(target_kind) = context.target_kind
        && target_kind != "executable"
        && target_kind != "database"
        && (context.kind == "official-proxy" || context.kind == "enhanced")
    {
        return Some(Availability::reason(
            "target_unsupported",
            Some("Inventory or extract a native executable, then call open_binary on that executable.".to_owned()),
        ));
    }
    if context.target_open
        && MACHO_TARGET_OPERATIONS.contains(&context.name)
        && (context.target_kind != Some("executable") || !is_mach_o_format(context.target_format))
    {
        return Some(Availability::reason(
            "target_unsupported",
            Some("Call open_binary with a Mach-O executable or an app bundle whose main executable is Mach-O.".to_owned()),
        ));
    }
    None
}

fn provider_availability(context: &AvailabilityContext<'_>) -> Availability {
    if context.kind == "enhanced" {
        return composed_availability(context.name, context.descriptors);
    }
    let descriptor = context.descriptors.get(context.name);
    match descriptor {
        None if matches!(
            context.kind,
            "artifact-provider" | "managed-provider" | "native-provider"
        ) =>
        {
            Availability::available()
        }
        None => Availability::reason(
            "provider_missing",
            Some("Install or configure a provider that declares this operation.".to_owned()),
        ),
        Some(descriptor) if descriptor.available => Availability::available(),
        Some(descriptor) => Availability::reason(
            "provider_unavailable",
            Some(
                descriptor
                    .reason
                    .clone()
                    .unwrap_or_else(|| "Choose another target or configured provider.".to_owned()),
            ),
        ),
    }
}

fn composed_availability(
    name: &str,
    descriptors: &HashMap<String, ProviderDescriptor>,
) -> Availability {
    if name == "binary_overview"
        && descriptors
            .get("read_binary_inventory_summary")
            .is_some_and(|descriptor| descriptor.available)
    {
        return Availability::available();
    }
    match enhanced_requirements(name) {
        None => Availability::reason(
            "provider_missing",
            Some("No provider composition is declared for this operation.".to_owned()),
        ),
        Some(ProviderComposition::Modes {
            default_mode,
            modes,
        }) => availability_for_modes(&modes, default_mode, descriptors),
        Some(ProviderComposition::Requirements(requirements)) => {
            composed_availability_for(&requirements, descriptors).0
        }
    }
}

/// `composedAvailabilityFor`: evaluate requirement groups, returning the
/// availability plus the de-duplicated missing operations in requirement order.
fn composed_availability_for(
    requirements: &[Requirement],
    descriptors: &HashMap<String, ProviderDescriptor>,
) -> (Availability, Vec<String>) {
    struct UnmetGroup {
        requirement_is_single: bool,
        single_name: Option<&'static str>,
        operations: Vec<&'static str>,
        unavailable_code: Option<Option<String>>, // Some(code) when a declared-but-unavailable descriptor exists.
        unavailable_reason: Option<Option<String>>,
    }

    let mut unmet: Vec<UnmetGroup> = Vec::new();
    for requirement in requirements {
        let operations: Vec<&'static str> = match requirement {
            Requirement::One(op) => vec![*op],
            Requirement::Any(ops) => ops.clone(),
        };
        let available = operations.iter().any(|op| {
            descriptors
                .get(*op)
                .is_some_and(|descriptor| descriptor.available)
        });
        if available {
            continue;
        }
        // First declared-but-unavailable descriptor, in operation order.
        let mut unavailable_code = None;
        let mut unavailable_reason = None;
        for op in &operations {
            if let Some(descriptor) = descriptors.get(*op)
                && !descriptor.available
            {
                unavailable_code = Some(descriptor.availability_code.clone());
                unavailable_reason = Some(descriptor.reason.clone());
                break;
            }
        }
        unmet.push(UnmetGroup {
            requirement_is_single: matches!(requirement, Requirement::One(_)),
            single_name: match requirement {
                Requirement::One(op) => Some(*op),
                Requirement::Any(_) => None,
            },
            operations: operations.clone(),
            unavailable_code: if unavailable_code.is_some() {
                unavailable_code
            } else {
                None
            },
            unavailable_reason: if unavailable_reason.is_some() {
                unavailable_reason
            } else {
                None
            },
        });
    }

    // missingOperations = [...new Set(unmet.flatMap(group => group.operations))].
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    let mut missing_operations: Vec<String> = Vec::new();
    for group in &unmet {
        for op in &group.operations {
            if seen.insert(*op) {
                missing_operations.push((*op).to_owned());
            }
        }
    }

    // Report an undeclared prerequisite before an unhealthy declaration.
    if let Some(undeclared) = unmet.iter().find(|group| group.unavailable_code.is_none()) {
        let remediation = if undeclared.requirement_is_single {
            format!(
                "Configure a provider for required operation {}.",
                undeclared
                    .single_name
                    .expect("single requirement has a name")
            )
        } else {
            format!(
                "Configure a provider for one of: {}.",
                undeclared.operations.join(", ")
            )
        };
        return (
            Availability::reason("provider_missing", Some(remediation)),
            missing_operations,
        );
    }

    if let Some(first) = unmet.first() {
        let code = first.unavailable_code.clone().flatten();
        let reason = first.unavailable_reason.clone().flatten();
        let mapped = if code.as_deref() == Some("unsupported_host") {
            "unsupported_host"
        } else {
            "provider_unavailable"
        };
        return (
            Availability::reason(
                mapped,
                Some(
                    reason.unwrap_or_else(|| {
                        "Choose another target or configured provider.".to_owned()
                    }),
                ),
            ),
            missing_operations,
        );
    }

    (Availability::available(), missing_operations)
}

struct ModeResult {
    name: &'static str,
    available: bool,
    reason: String,
    missing_operations: Vec<String>,
    remediation: Option<String>,
}

fn availability_for_modes(
    declarations: &[AvailabilityMode],
    default_mode: Option<&str>,
    descriptors: &HashMap<String, ProviderDescriptor>,
) -> Availability {
    let mode_results: Vec<ModeResult> = declarations
        .iter()
        .map(|mode| {
            let (availability, missing_operations) =
                composed_availability_for(&mode.requirements, descriptors);
            if availability.reason == "available" {
                ModeResult {
                    name: mode.name,
                    available: true,
                    reason: "available".to_owned(),
                    missing_operations: Vec::new(),
                    remediation: None,
                }
            } else {
                ModeResult {
                    name: mode.name,
                    available: false,
                    reason: availability.reason,
                    missing_operations,
                    remediation: availability.remediation,
                }
            }
        })
        .collect();

    let modes: Vec<Value> = mode_results
        .iter()
        .map(|mode| {
            if mode.available {
                json!({
                    "name": mode.name,
                    "available": true,
                    "missing_operations": [],
                    "remediation": null,
                })
            } else {
                json!({
                    "name": mode.name,
                    "available": false,
                    "missing_operations": mode.missing_operations,
                    "remediation": mode.remediation,
                })
            }
        })
        .collect();

    let available_mode = mode_results.iter().any(|mode| mode.available);

    // failures sorted by priority; stable sort preserves declaration order.
    let mut failures: Vec<&ModeResult> =
        mode_results.iter().filter(|mode| !mode.available).collect();
    failures.sort_by_key(|mode| availability_failure_priority(&mode.reason));
    let failure = failures.first();

    let specific_failure_remediation = failure.and_then(|failure| {
        if failure.reason == "provider_missing" {
            None
        } else {
            failure.remediation.clone()
        }
    });

    let default_mode_available = default_mode.map(|default| {
        modes
            .iter()
            .find(|mode| mode["name"] == Value::String(default.to_owned()))
            .and_then(|mode| mode["available"].as_bool())
            .unwrap_or(false)
    });

    if available_mode {
        return Availability {
            reason: "available".to_owned(),
            remediation: None,
            default_mode_available,
            modes: Some(modes),
        };
    }

    // missingOperations = [...new Set(modes.flatMap(mode => mode.missing_operations))].
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut missing_operations: Vec<String> = Vec::new();
    for mode in &modes {
        if let Some(ops) = mode["missing_operations"].as_array() {
            for op in ops {
                if let Some(op) = op.as_str()
                    && seen.insert(op.to_owned())
                {
                    missing_operations.push(op.to_owned());
                }
            }
        }
    }

    let reason = failure
        .map(|failure| failure.reason.clone())
        .unwrap_or_else(|| "provider_missing".to_owned());
    let remediation = specific_failure_remediation.unwrap_or_else(|| {
        format!(
            "Configure a provider for one of: {}.",
            missing_operations.join(", ")
        )
    });

    Availability {
        reason,
        remediation: Some(remediation),
        default_mode_available,
        modes: Some(modes),
    }
}

fn availability_failure_priority(reason: &str) -> u8 {
    match reason {
        "unsupported_host" => 0,
        "provider_unavailable" => 1,
        "provider_missing" => 2,
        _ => 3,
    }
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// `compactToolAvailability(buildCapabilityInventory(status, policy, features))`.
///
/// `session_status` is the TS `binarySessionStatus` JSON. Returns `Err` only
/// for a status that fails the TS `statusSchema` parse.
pub(crate) fn tool_availability(
    session_status: &Value,
    policy: &AvailabilityPolicy,
    features: &ClientFeatures,
) -> Result<Value, String> {
    let status = parse_status(session_status)?;
    let inventory = build_capability_inventory(&status, policy, features);
    Ok(compact_tool_availability(&inventory))
}

/// `buildCapabilityInventory`: one `ToolAvailability` object per catalog tool,
/// sorted by name in Unicode code-point order.
fn build_capability_inventory(
    status: &SessionStatus,
    policy: &AvailabilityPolicy,
    _features: &ClientFeatures,
) -> Vec<Value> {
    let catalog = rea_mcp::catalog();
    let mut entries: Vec<Value> = Vec::with_capacity(catalog.tools.len());

    for contract in &catalog.tools {
        let context = AvailabilityContext {
            name: &contract.name,
            kind: &contract.kind,
            target_open: status.open,
            target_kind: status.kind.as_deref(),
            target_format: status.format.as_deref(),
            descriptors: &status.descriptors,
            policy,
        };
        let availability = availability_for(&context);

        // clientRequirementsFor always yields empty required/optional, so the
        // client requirements are constant and clientBlocked is never true.
        let client_requirements = empty_client_requirements();

        let effects = contract_effects_object(&contract.effects);
        let annotations = contract_annotations_object(contract.advertised.get("annotations"));

        let mut facts = Map::new();
        facts.insert("name".to_owned(), Value::String(contract.name.clone()));
        facts.insert("surface".to_owned(), Value::String(contract.kind.clone()));
        if let Some(default_mode_available) = availability.default_mode_available {
            facts.insert(
                "default_mode_available".to_owned(),
                Value::Bool(default_mode_available),
            );
        }
        if let Some(modes) = &availability.modes {
            facts.insert("modes".to_owned(), Value::Array(modes.clone()));
        }
        facts.insert("client_requirements".to_owned(), client_requirements);
        facts.insert("effects".to_owned(), effects);
        facts.insert("annotations".to_owned(), annotations);

        if availability.reason == "available" {
            facts.insert("available".to_owned(), Value::Bool(true));
            facts.insert("reason".to_owned(), Value::String("available".to_owned()));
            facts.insert("remediation".to_owned(), Value::Null);
        } else {
            facts.insert("available".to_owned(), Value::Bool(false));
            facts.insert("reason".to_owned(), Value::String(availability.reason));
            facts.insert(
                "remediation".to_owned(),
                availability.remediation.map_or(Value::Null, Value::String),
            );
        }

        entries.push(Value::Object(facts));
    }

    entries.sort_by(|left, right| {
        compare_unicode_code_points(
            left["name"].as_str().unwrap_or(""),
            right["name"].as_str().unwrap_or(""),
        )
    });
    entries
}

fn empty_client_requirements() -> Value {
    json!({
        "required": [],
        "optional": [],
        "missing_required": [],
        "missing_optional": [],
    })
}

/// `effects: { ...contract.effects }` — the camelCase effect flags.
fn contract_effects_object(effects: &Value) -> Value {
    let mut map = Map::new();
    let source = effects.as_object();
    for name in TOOL_EFFECT_NAMES {
        let value = source
            .and_then(|source| source.get(name))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        map.insert(name.to_owned(), Value::Bool(value));
    }
    Value::Object(map)
}

/// `annotations` with the TS defaults: readOnly/destructive/idempotent default
/// false, openWorld defaults true.
fn contract_annotations_object(annotations: Option<&Value>) -> Value {
    let source = annotations.and_then(Value::as_object);
    let hint = |key: &str, default: bool| {
        source
            .and_then(|source| source.get(key))
            .and_then(Value::as_bool)
            .unwrap_or(default)
    };
    json!({
        "read_only": hint("readOnlyHint", false),
        "destructive": hint("destructiveHint", false),
        "idempotent": hint("idempotentHint", false),
        "open_world": hint("openWorldHint", true),
    })
}

/// `compactToolAvailability`: compact repeated metadata into named groups while
/// retaining each operation's current availability inline.
fn compact_tool_availability(availability: &[Value]) -> Value {
    let client_requirements = availability
        .first()
        .and_then(|entry| entry.get("client_requirements"))
        .cloned()
        .unwrap_or_else(empty_client_requirements);

    let mut group_order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Value> = HashMap::new();

    for entry in availability {
        let effects: Vec<Value> = TOOL_EFFECT_NAMES
            .iter()
            .filter(|name| entry["effects"][**name].as_bool().unwrap_or(false))
            .map(|name| Value::String((*name).to_owned()))
            .collect();
        let annotations: Vec<Value> = TOOL_ANNOTATION_NAMES
            .iter()
            .filter(|name| entry["annotations"][**name].as_bool().unwrap_or(false))
            .map(|name| Value::String((*name).to_owned()))
            .collect();

        let mut group_facts = Map::new();
        group_facts.insert("surface".to_owned(), entry["surface"].clone());
        group_facts.insert("effects".to_owned(), Value::Array(effects));
        group_facts.insert("annotations".to_owned(), Value::Array(annotations));
        group_facts.insert("available".to_owned(), entry["available"].clone());
        group_facts.insert("reason".to_owned(), entry["reason"].clone());
        group_facts.insert("remediation".to_owned(), entry["remediation"].clone());
        if let Some(default_mode_available) = entry.get("default_mode_available") {
            group_facts.insert(
                "default_mode_available".to_owned(),
                default_mode_available.clone(),
            );
        }
        if let Some(modes) = entry.get("modes") {
            group_facts.insert("modes".to_owned(), modes.clone());
        }
        // Only attach client_requirements when it differs from the inherited set.
        let entry_requirements = &entry["client_requirements"];
        if !client_requirements_equal(entry_requirements, &client_requirements) {
            group_facts.insert("client_requirements".to_owned(), entry_requirements.clone());
        }

        let key = serde_json::to_string(&Value::Object(group_facts.clone()))
            .expect("group facts serialize");

        if let Some(group) = groups.get_mut(&key) {
            group["names"]
                .as_array_mut()
                .expect("names is an array")
                .push(entry["name"].clone());
        } else {
            let mut group = group_facts;
            group.insert(
                "names".to_owned(),
                Value::Array(vec![entry["name"].clone()]),
            );
            group_order.push(key.clone());
            groups.insert(key, Value::Object(group));
        }
    }

    let group_values: Vec<Value> = group_order
        .into_iter()
        .map(|key| groups.remove(&key).expect("group present"))
        .collect();

    json!({
        "client_requirements": client_requirements,
        "groups": group_values,
    })
}

/// Value-faithful comparison mirroring `JSON.stringify(a) === JSON.stringify(b)`.
fn client_requirements_equal(left: &Value, right: &Value) -> bool {
    serde_json::to_string(left).ok() == serde_json::to_string(right).ok()
}

/// `compareUnicodeCodePoints`: order by Unicode scalar value (code point),
/// not UTF-16 code unit. Rust `str` iterates by scalar value, so a `char`
/// comparison is a code-point comparison.
pub(crate) fn compare_unicode_code_points(left: &str, right: &str) -> std::cmp::Ordering {
    left.chars().cmp(right.chars())
}
