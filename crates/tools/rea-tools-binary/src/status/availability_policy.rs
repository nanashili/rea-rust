//! `AvailabilityPolicy` (`src/application/CapabilityInventory.ts`) and the
//! production MCP composition that fills it
//! (`installSessionToolAvailability` in `src/server/createServer.ts`,
//! `sessionAvailabilityPolicy` in `src/server/sessionAvailabilityPolicy.ts`,
//! `src/main/transport.ts` with the five optional observation providers from
//! `src/composition/optionalObservationProviders.ts`, and
//! `missingAndroidAvailability` from `src/server/registerSessionTools.ts`).

use serde_json::{Map, Value};
use std::collections::HashMap;

/// TS `ProviderAvailability` as consumed by `CapabilityInventory`
/// (`ownerProbeAvailability`, android/adb/apktool/jeb probe observations).
#[derive(Clone, Debug)]
pub(crate) enum ProbeAvailability {
    Available {
        diagnostics: Map<String, Value>,
    },
    Unavailable {
        /// One of the original `ProviderRejectionCode` values (for example
        /// `not_configured`, `unsupported_host`, `runtime_unavailable`).
        code: String,
        reason: String,
        diagnostics: Map<String, Value>,
    },
}

impl ProbeAvailability {
    /// `missingAndroidAvailability` from `src/server/registerSessionTools.ts`.
    pub(crate) fn missing_android() -> Self {
        let mut diagnostics = Map::new();
        diagnostics.insert("configured".to_owned(), Value::Bool(false));
        ProbeAvailability::Unavailable {
            code: "not_configured".to_owned(),
            reason: "Set REA_JADX_MCP_JAR to a caller-supplied jadx-headless-mcp 0.7.1 JAR and provide a full JDK on Linux, macOS, or Windows x64 with its matching bundled native controls.".to_owned(),
            diagnostics,
        }
    }

    pub(crate) fn from_analysis(availability: &rea_analysis::ProviderAvailability) -> Self {
        match availability {
            rea_analysis::ProviderAvailability::Available { diagnostics } => {
                ProbeAvailability::Available {
                    diagnostics: diagnostics.clone(),
                }
            }
            rea_analysis::ProviderAvailability::Unavailable {
                code,
                reason,
                diagnostics,
            } => ProbeAvailability::Unavailable {
                code: code.clone(),
                reason: reason.clone(),
                diagnostics: diagnostics.clone(),
            },
        }
    }
}

/// JEB availability observation (`JebAnalysisAvailability`): an `available`
/// endpoint advertises a supported-operation set; otherwise it reports a
/// probe observation consumed like any other owner probe.
#[derive(Clone, Debug)]
pub(crate) enum JebAvailability {
    Available { supported_operations: Vec<String> },
    Probe(ProbeAvailability),
}

/// An optional provider adapter that failed to load, retained with its exact
/// reason (`OptionalProviderLoadFailure` in
/// `src/application/OptionalObservationProviders.ts`).
#[derive(Clone, Debug)]
pub(crate) struct OptionalProviderLoadFailure {
    pub provider_id: String,
    pub reason: String,
}

/// The independently observed optional-provider load failures
/// (`OptionalProviderLoadFailures`).
#[derive(Clone, Debug, Default)]
pub(crate) struct OptionalProviderLoadFailures {
    pub browser_observation: Option<OptionalProviderLoadFailure>,
    pub browser_scenario_capture: Option<OptionalProviderLoadFailure>,
    pub electron_observation: Option<OptionalProviderLoadFailure>,
    pub electron_active_observation: Option<OptionalProviderLoadFailure>,
    pub javascript_runtime_observation: Option<OptionalProviderLoadFailure>,
    pub frida_instrumentation: Option<OptionalProviderLoadFailure>,
}

/// TS `AvailabilityPolicy` consumed by `buildCapabilityInventory`.
///
/// Optional boolean features default to `false` when unset, matching the TS
/// `=== true` reads. `process_capture_enabled` is required in TS.
#[derive(Clone, Debug, Default)]
pub(crate) struct AvailabilityPolicy {
    pub packet_capture_enabled: bool,
    pub signal_recording_enabled: bool,
    pub wasm_artifact_enabled: bool,
    pub evm_interface_enabled: bool,
    pub process_capture_enabled: bool,
    pub optional_provider_load_failures: Option<OptionalProviderLoadFailures>,
    pub binary_layout_enabled: bool,
    pub recorded_crash_enabled: bool,
    pub firmware_inspection_enabled: bool,
    pub firmware_extraction_enabled: bool,
    pub android_analysis_availability: Option<ProbeAvailability>,
    pub adb_analysis_availability: Option<ProbeAvailability>,
    pub apktool_analysis_availability: Option<ProbeAvailability>,
    pub jeb_analysis_availability: Option<JebAvailability>,
    pub javascript_recovery_enabled: bool,
    pub web_module_resolution_enabled: bool,
    pub browser_observation_enabled: bool,
    pub browser_scenario_enabled: bool,
    pub electron_observation_enabled: bool,
    pub electron_automation_enabled: bool,
    pub v8_inspector_observation_enabled: bool,
}

/// `node:path` `isAbsolute` semantics of the host, applied to a possibly-unset
/// environment value (TS `isAbsolute(environment.X ?? "")`).
///
/// On Windows, `path.isAbsolute` accepts a leading separator (`/` or `\`),
/// a drive-qualified root (`C:\`, `C:/`), or a UNC path. Elsewhere only a
/// leading `/` is absolute. An empty string is never absolute.
fn is_absolute_host(value: Option<&str>) -> bool {
    let value = value.unwrap_or("");
    if value.is_empty() {
        return false;
    }
    if cfg!(target_os = "windows") {
        let bytes = value.as_bytes();
        let first = bytes[0];
        if first == b'/' || first == b'\\' {
            return true;
        }
        // Drive-letter root: `X:\` or `X:/`.
        if value.len() >= 3 {
            let drive = bytes[0];
            let is_letter = drive.is_ascii_alphabetic();
            if is_letter && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
                return true;
            }
        }
        false
    } else {
        value.starts_with('/')
    }
}

/// The TS production MCP composition of `AvailabilityPolicy`.
///
/// Reproduces `installSessionToolAvailability` with no `options.*` feature
/// overrides except the five optional observation providers that production
/// loads (so `browser*/electron*/v8*` are `true`), env-derived absolute-path
/// booleans for the externally-configured tools, `linux`/`linuxX64` from the
/// compile-time target, `processCaptureEnabled = !windows`, no optional
/// provider load failures, and `androidAnalysisAvailability =
/// missingAndroidAvailability`.
pub(crate) fn production_availability_policy(
    environment: &HashMap<String, String>,
) -> AvailabilityPolicy {
    let env = |key: &str| environment.get(key).map(String::as_str);
    let absolute = |key: &str| is_absolute_host(env(key));

    let linux = cfg!(target_os = "linux");
    let linux_x64 = linux && cfg!(target_arch = "x86_64");
    let windows = cfg!(target_os = "windows");
    let pwntools = linux_x64 && absolute("REA_PWNTOOLS_PYTHON");

    AvailabilityPolicy {
        packet_capture_enabled: linux && absolute("REA_TSHARK_COMMAND"),
        signal_recording_enabled: linux && absolute("REA_SIGROK_COMMAND"),
        wasm_artifact_enabled: absolute("REA_WABT_BIN_DIRECTORY"),
        evm_interface_enabled: linux_x64,
        process_capture_enabled: !windows,
        optional_provider_load_failures: None,
        binary_layout_enabled: pwntools,
        recorded_crash_enabled: pwntools,
        firmware_inspection_enabled: linux && absolute("REA_BINWALK_COMMAND"),
        firmware_extraction_enabled: linux && absolute("REA_UNBLOB_COMMAND"),
        // Production passes the missing-android observation; live adb/apktool/jeb
        // probes are owned by other crates and unreachable here (documented gap).
        android_analysis_availability: Some(ProbeAvailability::missing_android()),
        adb_analysis_availability: None,
        apktool_analysis_availability: None,
        jeb_analysis_availability: None,
        javascript_recovery_enabled: linux_x64 && absolute("REA_WAKARU_COMMAND"),
        web_module_resolution_enabled: absolute("REA_BROWSER_EXECUTABLE"),
        // The five optional observation providers load in production.
        browser_observation_enabled: true,
        browser_scenario_enabled: true,
        electron_observation_enabled: true,
        electron_automation_enabled: true,
        v8_inspector_observation_enabled: true,
    }
}
