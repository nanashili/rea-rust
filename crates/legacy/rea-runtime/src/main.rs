//! Experimental native entry point. Never delegates an unported command to Node.
#[cfg(unix)]
use rea_application::android::package::AndroidPackageInspection;
use rea_application::apktool;
#[cfg(unix)]
use rea_application::apple;
#[cfg(unix)]
use rea_application::apple::keyed_archive::{self, KeyedArchiveInspection};
#[cfg(unix)]
use rea_application::apple::plist::PlistInspection;
#[cfg(unix)]
use rea_application::binary::go::GoInspection;
#[cfg(unix)]
use rea_application::binary::layout::BinaryLayoutInspection;
#[cfg(unix)]
use rea_application::binary::macho::MachoInspection;
#[cfg(unix)]
use rea_application::binary::pe_resources::{
    OPERATION as PE_RESOURCES_OPERATION, PeResourcesInspection,
};
#[cfg(unix)]
use rea_application::binary::pe_target::PeTargetInspection;
#[cfg(unix)]
use rea_application::binary::recorded_crash::Inspection as RecordedCrashInspection;
use rea_application::binary::rust::{self as rust_binary, Completion, RustInspection};
#[cfg(unix)]
use rea_application::electron::fuses::ElectronFuseInspection;
#[cfg(unix)]
use rea_application::evm;
#[cfg(unix)]
use rea_application::flutter;
#[cfg(unix)]
use rea_application::interface_builder;
#[cfg(unix)]
use rea_application::interface_builder::nib_archive::NibArchiveInspection;
use rea_application::javascript::graph::json as graph_json;
#[cfg(unix)]
use rea_application::ledger::bundle_comparison_command;
#[cfg(unix)]
use rea_application::ledger::bundle_export_command;
#[cfg(unix)]
use rea_application::managed::artifact::ManagedArtifactInspection;
#[cfg(unix)]
use rea_application::process::observation::observe_processes_evidence;
#[cfg(unix)]
use rea_application::sqlite::SqliteInspection;
#[cfg(unix)]
use rea_application::wasm;
#[cfg(unix)]
use rea_application::web;
#[cfg(unix)]
use rea_application::web::event_listeners::{
    self as web_event_listeners, ConnectedCdpEventListenerPort,
};
#[cfg(unix)]
use rea_application::web::page_cdp::ConnectedCdpWebPagePort;
use rea_application::{
    android, apple::application_graph as apple_application_graph, harmony, javascript,
    reconstruction,
};
#[cfg(unix)]
use rea_application::{
    il2cpp,
    il2cpp::metadata::Il2cppMetadataInspection,
    inputs::{self, InterfaceBuilderInput, PeResourcesInput},
    ledger::artifact_records::ArtifactRecords,
    ledger::bundle_export::BundleExporter,
    ledger::bundle_import::BundleImporter,
};
use rea_core::cancellation::Cancellation;
#[cfg(target_os = "macos")]
use rea_core::evidence::{NativeFormat, Subject};
#[cfg(unix)]
use rea_core::failure::{Detail, Failure, InputIssue};
#[cfg(target_os = "macos")]
use rea_runtime::apple_asset_catalog_host;
#[cfg(unix)]
use rea_runtime::inspect_analysis_view_handler;
#[cfg(unix)]
use rea_runtime::mcp_http_args;
#[cfg(unix)]
mod batch_decompile_runtime_handlers;
#[cfg(unix)]
mod compare_functions_handlers;
#[cfg(unix)]
mod find_changed_behavior_handlers;
#[cfg(unix)]
mod inspect_dart_aot_handler;
#[cfg(unix)]
mod inspect_packet_fields_handler;
#[cfg(unix)]
mod packet_capture_handlers;
#[cfg(unix)]
mod pcap_capture_handler;
#[cfg(unix)]
mod pcap_client_offline_handlers;
#[cfg(unix)]
mod static_runtime_handlers;
#[cfg(unix)]
mod verify_reconstruction_handlers;
#[cfg(unix)]
mod web_capture_comparison_command;
#[cfg(unix)]
mod web_capture_offline_handlers;
#[cfg(unix)]
mod xrefs_runtime_handlers;
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Write},
    process::ExitCode,
    sync::Arc,
};

fn main() -> ExitCode {
    #[cfg(unix)]
    let interrupts = match rea_host::command_interrupts::CommandInterrupts::install() {
        Ok(owner) => owner,
        Err(error) => {
            eprintln!("rea-native: cannot install command interrupts: {error}");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(unix)]
    let cancellation = interrupts.cancellation().clone();
    #[cfg(not(unix))]
    let cancellation = Cancellation::default();
    let code = match run(&cancellation) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let closed_pipe = error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
                || error
                    .downcast_ref::<serde_json::Error>()
                    .is_some_and(|error| error.io_error_kind() == Some(io::ErrorKind::BrokenPipe));
            if closed_pipe {
                ExitCode::from(141)
            } else {
                eprintln!("rea-native: {error}");
                ExitCode::FAILURE
            }
        }
    };
    #[cfg(unix)]
    if let Some(interrupted) = interrupts.finish() {
        return ExitCode::from(interrupted);
    }
    code
}

fn run(cancellation: &Cancellation) -> Result<u8, Box<dyn std::error::Error>> {
    let mut arguments = Vec::new();
    for argument in std::env::args_os().skip(1) {
        match argument.into_string() {
            Ok(argument) => arguments.push(argument),
            Err(_) => {
                emit_json(&rust_binary::invalid(
                    "invalid_format",
                    "Command arguments must be representable as Unicode text.".into(),
                ))?;
                return Ok(1);
            }
        }
    }
    let arguments = normalize_cli_output_arguments(arguments);

    if arguments.is_empty() || arguments == ["--help"] {
        emit_line(
            r#"Experimental native REA (not the production replacement yet)
Usage: rea-native inspect-rust-binary PATH --format json
       rea-native inspect-go-binary PATH --json
       rea-native inspect-pe-resources PATH --json [--max-file-bytes N] [--max-entries N]
       rea-native list-electron-targets ENDPOINT --format json
       rea-native inspect-electron-page ENDPOINT TARGET_ID --format json [--observation-ms N] [--include-script-sources]
       rea-native inspect-web-page ENDPOINT TARGET_ID --format json [options]
       rea-native inspect-web-event-listeners ENDPOINT TARGET_ID SELECTOR --format json [--allowed-origins ORIGIN]
       rea-native evidence-import PATH --format json
       rea-native evidence-export SOURCE OUTPUT --format json [--overwrite]
       rea-native compare LEFT RIGHT --format json
       rea-native compare-web-captures BEFORE_JSON AFTER_JSON --format json [--normalization-json JSON_OR_PATH]
       rea-native compare-wasm-interfaces INPUT --format json
       rea-native compare-application-versions INPUT --format json
       rea-native project-android-application-graph INPUT --format json
       rea-native project-apple-application-graph INPUT --format json
       rea-native project-harmony-application-graph INPUT --format json
       rea-native evaluate-reconstruction-coverage INPUT --format json
       rea-native inspect-wasm-artifact INPUT --format json
       rea-native inspect-il2cpp-metadata PATH --format json [--detail complete|summary] [--evidence_output PATH]
       rea-native inspect-sqlite-database PATH --format json
       rea-native inspect-plist PATH --format json
       rea-native inspect-nib-archive PATH --format json
       rea-native inspect-asset-catalog TARGET_PATH TARGET_SHA256 [--offset N] [--limit N] --format json
       rea-native decode-interface-builder BUNDLE_PATH TARGET_SHA256 [--max-documents N] [--max-objects N] [--max-connections N] --format json
       rea-native inspect-keyed-archive PATH --format json [--root NAME] [--offset N] [--limit N]
       rea-native inspect-android-package PATH --format json
       rea-native inspect-android-class INPUT --format json
       rea-native inspect-android-method INPUT --format json
       rea-native search-android-classes INPUT --format json
       rea-native trace-android-references INPUT --format json
       rea-native inspect-android-resource INPUT --format json
       rea-native inspect-android-manifest-component INPUT --format json
       rea-native inspect-pe-target PATH --format json
       rea-native inspect-process-observation INPUT --format json
       rea-native inspect-process-cmdline INPUT --format json
       rea-native inspect-process-memory INPUT --format json
       rea-native inspect-evm-interface INPUT --format json
       rea-native inspect-revert-evidence INPUT --format json
       rea-native inspect-analysis-view INPUT --format json
       rea-native inspect-macho PATH --format json
       rea-native trace-dylib-resolution INPUT --format json
       rea-native inspect-binary-layout PATH --format json
       rea-native inspect-electron-fuses PATH --format json
       rea-native inspect-recorded-crash PATH --format json
       rea-native inspect-managed-artifact PATH --format json
       rea-native inspect-managed-members INPUT --format json
       rea-native compare-managed-members LEFT_PATH RIGHT_PATH --format json
       rea-native inspect-managed-native-boundaries PATH --format json
       rea-native verify-managed-native-boundaries INPUT --format json
       rea-native inspect-apktool-client --format json
       rea-native batch-decompile TARGET_PATH TARGET_SHA256 INPUT --format json
       rea-native mcp [--http [--host HOST] [--port PORT]]
MCP: inspect_rust_binary, inspect_go_binary, inspect_pe_resources, evaluate_reconstruction_coverage,
     get_evidence_bundle, export_evidence_bundle,
     import_evidence_bundle, list_unknowns, verify_unknown_resolution,
     record_unknown, update_unknown, and inspect_keyed_archive. HTTP MCP serves streamable transport at /mcp."#,
        )?;
        return Ok(0);
    }
    if arguments == ["--version"] {
        emit_line(&format!(
            "rea-native {} (experimental)",
            env!("CARGO_PKG_VERSION")
        ))?;
        return Ok(0);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "evaluate-reconstruction-coverage")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Evaluate authenticated reconstruction coverage against a declared boundary\nUsage: rea-native evaluate-reconstruction-coverage INPUT --format json",
            )?;
            return Ok(0);
        }
        return evaluate_reconstruction_coverage_command(&arguments);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "compare-application-versions")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Compare authenticated application graph Evidence records without executing either application\nUsage: rea-native compare-application-versions INPUT --format json",
            )?;
            return Ok(0);
        }
        return compare_application_versions_command(&arguments);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "project-android-application-graph")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Project authenticated Android APK inventory Evidence into an application graph\nUsage: rea-native project-android-application-graph INPUT --format json",
            )?;
            return Ok(0);
        }
        return project_application_graph_command(
            &arguments,
            android::application_graph::OPERATION,
            "Usage: rea-native project-android-application-graph INPUT --format json",
            project_android_application_graph,
        );
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "project-harmony-application-graph")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Project authenticated HarmonyOS inventory Evidence into an application graph\nUsage: rea-native project-harmony-application-graph INPUT --format json",
            )?;
            return Ok(0);
        }
        return project_application_graph_command(
            &arguments,
            harmony::application_graph::OPERATION,
            "Usage: rea-native project-harmony-application-graph INPUT --format json",
            project_harmony_application_graph,
        );
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "project-apple-application-graph")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Project authenticated Apple artifact inventory Evidence into an application graph\nUsage: rea-native project-apple-application-graph INPUT --format json",
            )?;
            return Ok(0);
        }
        return project_application_graph_command(
            &arguments,
            apple_application_graph::OPERATION,
            "Usage: rea-native project-apple-application-graph INPUT --format json",
            project_apple_application_graph,
        );
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-il2cpp-metadata")
    {
        return inspect_il2cpp_metadata_command(&arguments, cancellation);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "identify-flutter-build")
    {
        return identify_flutter_build_command(&arguments);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "compare-managed-members")
    {
        return compare_managed_members_command(&arguments, cancellation);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "batch-decompile")
        && (arguments.len() == 6
            || arguments
                .get(1)
                .is_some_and(|argument| argument == "--help"))
    {
        return batch_decompile_live_command(&arguments, cancellation);
    }
    #[cfg(unix)]
    if let Some(operation) = offline_cli_operation(arguments.first().map(String::as_str)) {
        return run_offline_cli_command(&arguments, operation, cancellation);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-apktool-client")
    {
        return inspect_apktool_client_command(&arguments);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "trace-dylib-resolution")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Trace static dyld loading below an explicit bundle or root directory\nUsage: rea-native trace-dylib-resolution INPUT --format json",
            )?;
            return Ok(0);
        }
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native trace-dylib-resolution INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let source = &arguments[1];
        let text = if source.trim_start().starts_with('{') {
            source.clone()
        } else {
            std::fs::read_to_string(source)?
        };
        let input: serde_json::Value = serde_json::from_str(&text)?;
        return match rea_runtime::mcp::trace_dylib_resolution_cli(&input, cancellation) {
            Ok(value) => {
                emit_json(&value)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error))?;
                Ok(1)
            }
        };
    }
    if arguments == ["inspect-go-binary", "--help"] {
        emit_line(
            "Inspect embedded Go compiler, modules and build settings without target execution\nUsage: rea-native inspect-go-binary PATH --json",
        )?;
        return Ok(0);
    }
    if arguments == ["inspect-pe-resources", "--help"] {
        emit_line(
            "Inspect a PE32/PE32+ resource tree without executing the image\nUsage: rea-native inspect-pe-resources PATH --json [--max-file-bytes N] [--max-entries N]",
        )?;
        return Ok(0);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-pe-resources")
    {
        #[cfg(not(unix))]
        return Err("native file admission is not implemented on this host yet".into());
        #[cfg(unix)]
        return inspect_pe_resources_command(&arguments, cancellation);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "evidence-export")
    {
        if arguments == ["evidence-export", "--help"] {
            emit_line(
                "Validate and atomically export canonical Evidence JSON\nUsage: rea-native evidence-export <source> <output> --format json [--overwrite]",
            )?;
            return Ok(0);
        }
        let command = match parse_evidence_export_arguments(&arguments) {
            Ok(command) => command,
            Err(message) => {
                emit_json(&rust_binary::invalid("invalid_value", message))?;
                return Ok(1);
            }
        };
        #[cfg(not(unix))]
        return Err("native file admission is not implemented on this host yet".into());
        #[cfg(unix)]
        return export_evidence_bundle(&command, cancellation);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "compare" || argument == "compare-bundles")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Compare two canonical Evidence bundles\nUsage: rea-native compare <left> <right> --format json",
            )?;
            return Ok(0);
        }
        let command = match parse_compare_arguments(&arguments) {
            Ok(command) => command,
            Err(message) => {
                emit_json(&rust_binary::invalid("invalid_value", message))?;
                return Ok(1);
            }
        };
        #[cfg(not(unix))]
        return Err("native file admission is not implemented on this host yet".into());
        #[cfg(unix)]
        return compare_evidence_bundles(&command, cancellation);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "compare-web-captures")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Compare two normalized passive captures or recorded browser scenarios\nUsage: rea-native compare-web-captures BEFORE_JSON AFTER_JSON --format json [--normalization-json JSON_OR_PATH]",
            )?;
            return Ok(0);
        }
        let command = match web_capture_comparison_command::parse_arguments(&arguments) {
            Ok(command) => command,
            Err(message) => {
                let failure = web_capture_comparison_command::invalid_arguments(message);
                emit_json(&CliFailure {
                    error: "Analysis failed",
                    failure: &failure,
                })?;
                return Ok(1);
            }
        };
        return compare_web_captures(&command);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "list-electron-targets")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "List local file pages exposed by a selected Electron CDP endpoint\nUsage: rea-native list-electron-targets ENDPOINT --format json",
            )?;
            return Ok(0);
        }
        let command = match parse_electron_target_list_arguments(&arguments) {
            Ok(command) => command,
            Err(failure) => {
                emit_json(&CliFailure {
                    error: "Analysis failed",
                    failure: &failure,
                })?;
                return Ok(1);
            }
        };
        return list_electron_targets_command(&command, cancellation);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-electron-page")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Passively inspect one selected Electron file page\nUsage: rea-native inspect-electron-page ENDPOINT TARGET_ID --format json [--observation-ms N] [--include-script-sources]",
            )?;
            return Ok(0);
        }
        let command = match parse_electron_page_inspection_arguments(&arguments) {
            Ok(command) => command,
            Err(failure) => {
                emit_json(&CliFailure {
                    error: "Analysis failed",
                    failure: &failure,
                })?;
                return Ok(1);
            }
        };
        return inspect_electron_page_command(&command, cancellation);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-web-page")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Passively inspect one caller-selected browser page through CDP\nUsage: rea-native inspect-web-page ENDPOINT TARGET_ID --format json [--allowed-origins ORIGIN] [--observation-ms N] [--include-accessibility-text] [--include-console-text] [--include-json-body-shapes] [--include-websocket-shapes] [--include-script-sources] [--include-storage-keys] [--include-storage-fingerprints]",
            )?;
            return Ok(0);
        }
        let command = match parse_web_page_inspection_arguments(&arguments) {
            Ok(command) => command,
            Err(failure) => {
                emit_json(&CliFailure {
                    error: "Analysis failed",
                    failure: &failure,
                })?;
                return Ok(1);
            }
        };
        return inspect_web_page_command(&command);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "observe-web-session")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Observe one caller-selected browser session through CDP\nUsage: rea-native observe-web-session ENDPOINT TARGET_ID --format json [--allowed-origins ORIGIN] [--observation-ms N]",
            )?;
            return Ok(0);
        }
        let command = match parse_web_session_observation_arguments(&arguments) {
            Ok(command) => command,
            Err(failure) => {
                emit_json(&CliFailure {
                    error: "Analysis failed",
                    failure: &failure,
                })?;
                return Ok(1);
            }
        };
        return observe_web_session_command(&command, cancellation);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-web-event-listeners")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Passively inspect listeners directly attached to the first CSS match through CDP\nUsage: rea-native inspect-web-event-listeners ENDPOINT TARGET_ID SELECTOR --format json [--allowed-origins ORIGIN]",
            )?;
            return Ok(0);
        }
        let command = match parse_web_event_listener_arguments(&arguments) {
            Ok(command) => command,
            Err(failure) => {
                emit_json(&CliFailure {
                    error: "Analysis failed",
                    failure: &failure,
                })?;
                return Ok(1);
            }
        };
        return inspect_web_event_listeners_command(&command, cancellation);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "compare-wasm-interfaces")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native compare-wasm-interfaces INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let source = &arguments[1];
        let text = if source.trim_start().starts_with('{') || source.trim_start().starts_with('[') {
            source.clone()
        } else {
            match std::fs::read_to_string(source) {
                Ok(text) => text,
                Err(error) => {
                    emit_json(&rust_binary::invalid(
                        "invalid_value",
                        format!("Unable to read comparison input: {error}"),
                    ))?;
                    return Ok(1);
                }
            }
        };
        let input: serde_json::Value = match serde_json::from_str(&text) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&rust_binary::invalid(
                    "invalid_format",
                    format!("Comparison input is not valid JSON: {error}"),
                ))?;
                return Ok(1);
            }
        };
        let output = wasm::comparison::compare(&input, None, cancellation);
        return match output {
            Ok(value) => {
                emit_json(&value)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-android-resource")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-android-resource INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let input: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&arguments[1])?)?;
        let selector = rea_application::android::resources::ResourceSelector {
            resource_id: input["resource_id"].as_str().map(ToOwned::to_owned),
            package_id: input["package_id"].as_u64().map(|value| value as u32),
            type_id: input["type_id"].as_u64().map(|value| value as u32),
            entry_index: input["entry_index"].as_u64().map(|value| value as u32),
            name: input["name"].as_str().map(ToOwned::to_owned),
            locale: input["locale"].as_str().map(ToOwned::to_owned),
            region: input["region"].as_str().map(ToOwned::to_owned),
            density: input["density"].as_u64().map(|value| value as u16),
            sdk: input["sdk"].as_u64().map(|value| value as u16),
            orientation: input["orientation"].as_u64().map(|value| value as u8),
        };
        let path = input["path"].as_str().unwrap_or_default();
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = AndroidPackageInspection::new(access);
        return match inspection.inspect_resource(path, selector, cancellation, Completion::OneShot)
        {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-android-class")
    {
        let input = match parse_android_class_arguments(&arguments[1..]) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error))?;
                return Ok(1);
            }
        };
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = AndroidPackageInspection::new(access);
        return match inspection.inspect_class(
            &input.path,
            input.class_name,
            cancellation,
            Completion::OneShot,
        ) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-android-method")
    {
        let input = match parse_android_method_arguments(&arguments[1..]) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error))?;
                return Ok(1);
            }
        };
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = AndroidPackageInspection::new(access);
        return match inspection.inspect_method(
            &input.path,
            input.class_name,
            input.method_name,
            input.overload_index,
            cancellation,
            Completion::OneShot,
        ) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "search-android-classes")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native search-android-classes INPUT --format json".into(),
            ))?;
            return Ok(1);
        }

        return run_android_class_search(&arguments[1], cancellation);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "trace-android-references")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native trace-android-references INPUT --format json".into(),
            ))?;
            return Ok(1);
        }

        return run_android_reference_trace(&arguments[1], cancellation);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-android-manifest-component")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-android-manifest-component INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let input: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&arguments[1])?)?;
        let path = input["path"].as_str().unwrap_or_default();
        let kind = input["kind"].as_str().unwrap_or_default().to_owned();
        let name = input["name"].as_str().unwrap_or_default().to_owned();
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = AndroidPackageInspection::new(access);
        return match inspection.inspect_manifest_component(
            path,
            kind,
            name,
            cancellation,
            Completion::OneShot,
        ) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-revert-evidence")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-revert-evidence INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let input_text = match std::fs::read_to_string(&arguments[1]) {
            Ok(text) => text,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error.to_string()))?;
                return Ok(1);
            }
        };
        let input: serde_json::Value = match serde_json::from_str(&input_text) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_format", error.to_string()))?;
                return Ok(1);
            }
        };
        let path = match input["path"].as_str().filter(|path| !path.is_empty()) {
            Some(path) => path,
            None => {
                emit_json(&rust_binary::invalid(
                    "invalid_value",
                    "EVM input requires a non-empty path.".into(),
                ))?;
                return Ok(1);
            }
        };
        let encoding = match input["encoding"].as_str() {
            Some("raw") => rea_application::evm::interface::EvmEncoding::Raw,
            Some("hex") => rea_application::evm::interface::EvmEncoding::Hex,
            Some(value) => {
                emit_json(&rust_binary::invalid(
                    "invalid_value",
                    format!("Unsupported EVM encoding: {value}"),
                ))?;
                return Ok(1);
            }
            None => {
                emit_json(&rust_binary::invalid(
                    "invalid_value",
                    "EVM input requires encoding raw or hex.".into(),
                ))?;
                return Ok(1);
            }
        };
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        return match evm::interface::inspect_revert_evidence(access, path, encoding, cancellation) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-analysis-view")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-analysis-view INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let text = match std::fs::read_to_string(&arguments[1]) {
            Ok(text) => text,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error.to_string()))?;
                return Ok(1);
            }
        };
        let input: serde_json::Value = match serde_json::from_str(&text) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_format", error.to_string()))?;
                return Ok(1);
            }
        };
        return match inspect_analysis_view_handler::project(&input) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-wasm-artifact")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-wasm-artifact INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let text = match std::fs::read_to_string(&arguments[1]) {
            Ok(text) => text,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error.to_string()))?;
                return Ok(1);
            }
        };
        let input: serde_json::Value = match serde_json::from_str(&text) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_format", error.to_string()))?;
                return Ok(1);
            }
        };
        return match wasm::producer::inspect(&input, cancellation) {
            Ok(value) => {
                emit_json(&value)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-sqlite-database")
    {
        let input = match parse_sqlite_arguments(&arguments[1..]) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error))?;
                return Ok(1);
            }
        };
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = SqliteInspection::new(access);
        return match inspection.inspect_with_input(
            &input.path,
            input.selection,
            cancellation,
            Completion::OneShot,
        ) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-nib-archive")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Decode one compiled NIBArchive without loading Interface Builder classes\nUsage: rea-native inspect-nib-archive PATH --format json",
            )?;
            return Ok(0);
        }

        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-nib-archive PATH --format json".into(),
            ))?;
            return Ok(1);
        }

        let mut inspection =
            NibArchiveInspection::new(Arc::new(rea_host::fs::unix_file::UnixFiles));
        let outcome = inspection.inspect(&arguments[1], cancellation, Completion::OneShot);
        let cleanup = inspection.close();

        return finish_inspection_command(outcome, cleanup);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-asset-catalog")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Inspect bounded compiled asset catalog metadata in the selected Mach-O's app bundle\nUsage: rea-native inspect-asset-catalog TARGET_PATH TARGET_SHA256 [--offset N] [--limit N] --format json",
            )?;
            return Ok(0);
        }

        let input = match parse_asset_catalog_arguments(&arguments[1..]) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&analysis_input_failure(
                    apple::asset_catalog_workflow::OPERATION,
                    vec![InputIssue {
                        path: vec!["arguments".into()],
                        reason: "invalid_value",
                        message: error,
                        expected: None,
                    }],
                ))?;
                return Ok(1);
            }
        };

        #[cfg(target_os = "macos")]
        let outcome =
            match inspect_asset_catalog_target(&input.path, &input.target_sha256, cancellation) {
                Ok(subject) => {
                    let parameters = serde_json::json!({
                        "offset": input.page.offset,
                        "limit": input.page.limit,
                    });
                    apple_asset_catalog_host::inspect_selected_target(
                        std::path::Path::new(&input.path),
                        subject,
                        input.page,
                        parameters,
                        cancellation,
                    )
                }
                Err(error) => Err(error),
            };

        #[cfg(not(target_os = "macos"))]
        let outcome = Err(Failure::new(
            "provider_unavailable",
            "provider_unavailable",
            "Apple asset catalog inspection requires macOS and its system assetutil provider."
                .into(),
            true,
            "Run this inspection on macOS with the selected app bundle available.".into(),
            BTreeMap::from([
                (
                    "operation",
                    Detail::Text(apple::asset_catalog_workflow::OPERATION.into()),
                ),
                ("path", Detail::Text(input.path.clone())),
                ("target_sha256", Detail::Text(input.target_sha256.clone())),
                ("offset", Detail::Text(input.page.offset.to_string())),
                ("limit", Detail::Text(input.page.limit.to_string())),
            ]),
        ));

        return match outcome {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "decode-interface-builder")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Decode compiled Interface Builder archives in a local app bundle\nUsage: rea-native decode-interface-builder BUNDLE_PATH TARGET_SHA256 [--max-documents N] [--max-objects N] [--max-connections N] --format json",
            )?;
            return Ok(0);
        }

        let input = match parse_interface_builder_arguments(&arguments[1..]) {
            Ok(input) => input,
            Err(error) => {
                let issue = InputIssue {
                    path: vec!["arguments".into()],
                    reason: "invalid_value",
                    message: error,
                    expected: None,
                };
                emit_json(&analysis_input_failure(
                    interface_builder::bundle::OPERATION,
                    vec![issue],
                ))?;
                return Ok(1);
            }
        };

        return match interface_builder::bundle::inspect_bundle_with_limits(
            std::path::Path::new(&input.path),
            input.target_sha256,
            input.limits,
            cancellation,
        ) {
            Ok(report) => {
                emit_json(&report)?;
                Ok(0)
            }
            Err(failure) => {
                emit_json(&failure)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-keyed-archive")
    {
        if arguments
            .get(1)
            .is_some_and(|argument| argument == "--help")
        {
            emit_line(
                "Inspect a caller-selected NSKeyedArchiver property list without instantiating archived classes\nUsage: rea-native inspect-keyed-archive PATH --format json [--root NAME] [--offset N] [--limit N]",
            )?;
            return Ok(0);
        }
        #[cfg(not(unix))]
        return Err("native file admission is not implemented on this host yet".into());
        #[cfg(unix)]
        return inspect_keyed_archive_command(&arguments, cancellation);
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-plist")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-plist PATH --format json".into(),
            ))?;
            return Ok(1);
        }
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = PlistInspection::new(access);
        return match inspection.inspect(&arguments[1], cancellation, Completion::OneShot) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-android-package")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-android-package PATH --format json".into(),
            ))?;
            return Ok(1);
        }
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = AndroidPackageInspection::new(access);
        return match inspection.inspect(&arguments[1], cancellation, Completion::OneShot) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-pe-target")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-pe-target PATH --format json".into(),
            ))?;
            return Ok(1);
        }
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = PeTargetInspection::new(access);
        return match inspection.inspect(&arguments[1], cancellation, Completion::OneShot) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-process-observation")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-process-observation INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let text = match std::fs::read_to_string(&arguments[1]) {
            Ok(text) => text,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error.to_string()))?;
                return Ok(1);
            }
        };
        let input: serde_json::Value = match serde_json::from_str(&text) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_format", error.to_string()))?;
                return Ok(1);
            }
        };
        let pids = input["pids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|pid| pid.as_u64())
            .collect::<Vec<_>>();
        let include_effective_uid = input["include_effective_uid"].as_bool().unwrap_or(false);
        let observer = rea_host::process::linux::identity::ProcessIdentityObserver;
        return match observe_processes_evidence(&observer, pids, include_effective_uid) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error.to_string()))?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-process-cmdline")
        || arguments
            .first()
            .is_some_and(|argument| argument == "inspect-process-memory")
    {
        let command = arguments[0].clone();
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                format!("Usage: rea-native {command} INPUT --format json"),
            ))?;
            return Ok(1);
        }
        let input: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&arguments[1])?)?;
        let pids = input["pids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|pid| pid.as_u64())
            .collect::<Vec<_>>();
        let observer = rea_host::process::linux::identity::ProcessIdentityObserver;
        let result = if command == "inspect-process-cmdline" {
            rea_application::process::observation::observe_cmdlines_evidence(&observer, pids)
        } else {
            rea_application::process::observation::observe_memory_evidence(&observer, pids)
        };
        return match result {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&rust_binary::invalid("invalid_value", error.to_string()))?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-evm-interface")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&evm::interface::invalid_input(
                "arguments",
                "invalid_value",
                "Usage: rea-native inspect-evm-interface INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let input_text = match std::fs::read_to_string(&arguments[1]) {
            Ok(text) => text,
            Err(error) => {
                emit_json(&evm::interface::invalid_input(
                    "input",
                    "invalid_value",
                    error.to_string(),
                ))?;
                return Ok(1);
            }
        };
        let input: serde_json::Value = match serde_json::from_str(&input_text) {
            Ok(input) => input,
            Err(error) => {
                emit_json(&evm::interface::invalid_input(
                    "input",
                    "invalid_format",
                    error.to_string(),
                ))?;
                return Ok(1);
            }
        };
        let path = match input["path"].as_str().filter(|path| !path.is_empty()) {
            Some(path) => path,
            None => {
                emit_json(&evm::interface::invalid_input(
                    "path",
                    "invalid_value",
                    "EVM input requires a non-empty path.".into(),
                ))?;
                return Ok(1);
            }
        };
        let encoding = match input["encoding"].as_str() {
            Some("raw") => rea_application::evm::interface::EvmEncoding::Raw,
            Some("hex") => rea_application::evm::interface::EvmEncoding::Hex,
            Some(value) => {
                emit_json(&evm::interface::invalid_input(
                    "encoding",
                    "invalid_value",
                    format!("Unsupported EVM encoding: {value}"),
                ))?;
                return Ok(1);
            }
            None => {
                emit_json(&evm::interface::invalid_input(
                    "encoding",
                    "invalid_value",
                    "EVM input requires encoding raw or hex.".into(),
                ))?;
                return Ok(1);
            }
        };
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        return match evm::interface::inspect_evidence(access, path, encoding, cancellation) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-macho")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-macho PATH --format json".into(),
            ))?;
            return Ok(1);
        }
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = MachoInspection::new(access);
        return match inspection.inspect(&arguments[1], cancellation, Completion::OneShot) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-electron-fuses")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-electron-fuses PATH --format json".into(),
            ))?;
            return Ok(1);
        }
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = ElectronFuseInspection::new(access);
        return match inspection.inspect(&arguments[1], cancellation, Completion::OneShot) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-binary-layout")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-binary-layout PATH --format json".into(),
            ))?;
            return Ok(1);
        }
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = BinaryLayoutInspection::new(access);
        return match inspection.inspect(&arguments[1], cancellation, Completion::OneShot) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-recorded-crash")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-recorded-crash PATH --format json".into(),
            ))?;
            return Ok(1);
        }

        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = RecordedCrashInspection::new(access);

        return match inspection.inspect(&arguments[1], cancellation, Completion::OneShot) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-managed-artifact")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-managed-artifact PATH --format json".into(),
            ))?;
            return Ok(1);
        }
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = ManagedArtifactInspection::new(access);
        return match inspection.inspect(&arguments[1], cancellation, Completion::OneShot) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-managed-members")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-managed-members INPUT --format json".into(),
            ))?;
            return Ok(1);
        }
        let input: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&arguments[1])?)?;
        let path = input["path"].as_str().unwrap_or_default();
        let type_names = input["type_names"].as_array().map(|names| {
            names
                .iter()
                .filter_map(|name| name.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>()
        });
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = ManagedArtifactInspection::new(access);
        return match inspection.inspect_members(path, type_names, cancellation, Completion::OneShot)
        {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    #[cfg(unix)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect-managed-native-boundaries")
    {
        if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
            emit_json(&rust_binary::invalid(
                "invalid_value",
                "Usage: rea-native inspect-managed-native-boundaries PATH --format json".into(),
            ))?;
            return Ok(1);
        }
        let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
        let mut inspection = ManagedArtifactInspection::new(access);
        return match inspection.inspect_native_boundaries(
            &arguments[1],
            cancellation,
            Completion::OneShot,
        ) {
            Ok(evidence) => {
                emit_json(&evidence)?;
                Ok(0)
            }
            Err(error) => {
                emit_json(&error)?;
                Ok(1)
            }
        };
    }
    if arguments.len() == 4
        && arguments[0] == "evidence-import"
        && arguments[2] == "--format"
        && arguments[3] == "json"
    {
        #[cfg(not(unix))]
        return Err("native file admission is not implemented on this host yet".into());
        #[cfg(unix)]
        return import_evidence_bundle(&arguments[1], cancellation);
    }
    #[cfg(unix)]
    if arguments.first().is_some_and(|argument| argument == "mcp") {
        let command = match mcp_http_args::parse(&arguments[1..]) {
            Ok(command) => command,
            Err(message) => {
                eprintln!("{message}");
                return Ok(1);
            }
        };

        if command == mcp_http_args::McpCommand::Help {
            emit_line(
                "Serve the native MCP server over stdio or streamable HTTP\nUsage: rea-native mcp [--http [--host HOST] [--port PORT]]\nOptions: --http serve at /mcp; --host defaults to MCP_HOST or 127.0.0.1; --port defaults to MCP_PORT or 0; -h, --help show help",
            )?;
            return Ok(0);
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let outcome = match command {
            mcp_http_args::McpCommand::Stdio => {
                runtime.block_on(rea_runtime::mcp::run(cancellation))
            }
            mcp_http_args::McpCommand::Http { host, port } => {
                runtime.block_on(rea_runtime::mcp::run_http(cancellation, &host, port))
            }
            mcp_http_args::McpCommand::Help => unreachable!("help returned before runtime setup"),
        };
        // Tokio's inherited stdin blocking reader cannot be interrupted. All
        // artifact execution/cleanup has been drained by run before this point;
        // only process-owned stdio may remain until this executable exits.
        runtime.shutdown_background();
        outcome?;
        return Ok(0);
    }
    if !is_valid_inspection_arguments(&arguments) {
        emit_json(&rust_binary::invalid(
            "invalid_value",
            "This experimental executable currently accepts identify-flutter-build PATH --format json, offline-identify-flutter-build INPUT --format json, batch-decompile TARGET_PATH TARGET_SHA256 INPUT --format json, inspect-rust-binary PATH --format json, inspect-go-binary PATH --json, inspect-pe-resources PATH --json [--max-file-bytes N] [--max-entries N], inspect-apktool-client --format json, trace-dylib-resolution INPUT --format json, inspect-pe-target PATH --format json, inspect-process-observation INPUT --format json, inspect-process-cmdline INPUT --format json, inspect-process-memory INPUT --format json, inspect-evm-interface INPUT --format json, inspect-revert-evidence INPUT --format json, inspect-macho PATH --format json, inspect-binary-layout PATH --format json, inspect-electron-fuses PATH --format json, inspect-recorded-crash PATH --format json, inspect-managed-artifact PATH --format json, evidence-import PATH --format json, evidence-export SOURCE OUTPUT --format json [--overwrite], compare LEFT RIGHT --format json, compare-web-captures BEFORE_JSON AFTER_JSON --format json [--normalization-json JSON_OR_PATH], compare-wasm-interfaces INPUT --format json, project-android-application-graph INPUT --format json, project-apple-application-graph INPUT --format json, project-harmony-application-graph INPUT --format json, or mcp [--http [--host HOST] [--port PORT]].".into(),
        ))?;
        return Ok(1);
    }
    #[cfg(not(unix))]
    {
        return Err("native file admission is not implemented on this host yet".into());
    }
    #[cfg(unix)]
    {
        let path = rea_host::fs::caller_path::absolute(&arguments[1])?;
        let mut service = match arguments[0].as_str() {
            "inspect-rust-binary" => InspectionCommand::Rust(RustInspection::new(Arc::new(
                rea_host::fs::unix_file::UnixFiles,
            ))),
            "inspect-go-binary" => InspectionCommand::Go(GoInspection::new(Arc::new(
                rea_host::fs::unix_file::UnixFiles,
            ))),
            _ => unreachable!("inspection command was validated above"),
        };
        let outcome = service.inspect(&path, cancellation, Completion::OneShot);
        let cleanup = service.close();
        finish_inspection_command(outcome, cleanup)
    }
}

#[cfg(unix)]
fn project_harmony_application_graph(
    input: &serde_json::Value,
) -> Result<Box<serde_json::value::RawValue>, rea_core::failure::Failure> {
    let graph_input = graph_json::parse(&serde_json::to_string(input).map_err(|error| {
        rea_core::failure::Failure::new(
            "invalid_request",
            "invalid_input",
            error.to_string(),
            false,
            "Provide authenticated HarmonyOS inventory Evidence.".into(),
            std::collections::BTreeMap::new(),
        )
    })?)
    .map_err(|error| {
        rea_core::failure::Failure::new(
            "invalid_request",
            "invalid_input",
            error.to_string(),
            false,
            "Provide authenticated HarmonyOS inventory Evidence.".into(),
            std::collections::BTreeMap::new(),
        )
    })?;
    harmony::application_graph::project_evidence(&graph_input)
}

#[cfg(unix)]
fn offline_cli_operation(command: Option<&str>) -> Option<&'static str> {
    let command = command?;

    if let Some(operation) = rea_runtime::il2cpp_offline_handlers::operation_for_cli(command) {
        return Some(operation);
    }

    match command {
        "offline-identify-flutter-build" => Some("offline_identify_flutter_build"),
        "inspect-packet-fields" => Some("inspect_packet_fields"),
        "inspect-packet-capture" => Some("inspect_packet_capture"),
        "inspect-pcap-client" => Some("inspect_pcap_client"),
        "inspect-pcap-capture" => Some("inspect_pcap_capture"),
        "inspect-signal-decoders" => Some("inspect_signal_decoders"),
        "decode-signal-recording" => Some("decode_signal_recording"),
        "inspect-web-network-capture" => Some("inspect_web_network_capture"),
        "batch-decompile" => Some("batch_decompile"),
        "xrefs" => Some("xrefs"),
        "compare-functions" => Some("compare_functions"),
        "correlate-static-and-runtime" => Some("correlate_static_and_runtime"),
        "find-changed-behavior" => Some("find_changed_behavior"),
        "verify-reconstruction" => Some("verify_reconstruction"),
        "offline-compare-web-captures" => Some("compare_web_captures"),
        "compare-process-captures" => Some("compare_process_captures"),
        "list-bookmarks" => Some("list_bookmarks"),
        "list-documents" => Some("list_documents"),
        "list-names" => Some("list_names"),
        "list-procedures" => Some("list_procedures"),
        "list-segments" => Some("list_segments"),
        "list-strings" => Some("list_strings"),
        "search-procedures" => Some("search_procedures"),
        "search-strings" => Some("search_strings"),
        "inspect-adb-client" => Some("inspect_adb_client"),
        "list-adb-devices" => Some("list_adb_devices"),
        "inspect-adb-device" => Some("inspect_adb_device"),
        "list-adb-packages" => Some("list_adb_packages"),
        "read-adb-logcat" => Some("read_adb_logcat"),
        "inspect-adb-package" => Some("inspect_adb_package"),
        "pull-adb-package" => Some("pull_adb_package"),
        "pull-adb-file" => Some("pull_adb_file"),
        "capture-adb-screen" => Some("capture_adb_screen"),
        "list-adb-processes" => Some("list_adb_processes"),
        "list-adb-directory" => Some("list_adb_directory"),
        "list-adb-features" => Some("list_adb_features"),
        "list-adb-services" => Some("list_adb_services"),
        "inspect-adb-display" => Some("inspect_adb_display"),
        "inspect-adb-window" => Some("inspect_adb_window"),
        "read-adb-setting" => Some("read_adb_setting"),
        "collect-adb-bugreport" => Some("collect_adb_bugreport"),
        "resolve-adb-packages" => Some("resolve_adb_packages"),
        "inspect-firmware-regions" => Some("inspect_firmware_regions"),
        "extract-firmware" => Some("extract_firmware"),
        "compare-artifacts" => Some("compare_artifacts"),
        "inspect-signature" => Some("inspect_signature"),
        "inspect-artifact" => Some("inspect_artifact"),
        "extract-artifact" => Some("extract_artifact"),
        "inspect-desktop-application" => Some("inspect_desktop_application"),
        "inspect-dart-aot" => Some("inspect_dart_aot"),
        "read-bytes" => Some("read_bytes"),
        "search-bytes" => Some("search_bytes"),
        "address-to-file-offset" => Some("address_to_file_offset"),
        "import-managed-reconstruction" => Some("import_managed_reconstruction"),
        "project-managed-application-graph" => Some("project_managed_application_graph"),
        "verify-managed-native-boundaries" => Some("verify_managed_native_boundaries"),
        "inspect-il2cpp-metadata" => Some("inspect_il2cpp_metadata"),
        "inspect-native-annotation" => Some("inspect_native_annotation"),
        "inspect-native-api" => Some("inspect_native_api"),
        "inspect-native-data-type" => Some("inspect_native_data_type"),
        "inspect-native-dispatch-metadata" => Some("inspect_native_dispatch_metadata"),
        "inspect-native-instruction" => Some("inspect_native_instruction"),
        "inspect-native-load-image" => Some("inspect_native_load_image"),
        "inspect-with-objdump" => Some("inspect_with_objdump"),
        "get-navigation-context" => Some("get_navigation_context"),
        "inspect-address-context" => Some("inspect_address_context"),
        "address-name" => Some("address_name"),
        "current-address" => Some("current_address"),
        "current-procedure" => Some("current_procedure"),
        "current-document" => Some("current_document"),
        "next-address" => Some("next_address"),
        "prev-address" => Some("prev_address"),
        "procedure-address" => Some("procedure_address"),
        "procedure-assembly" => Some("procedure_assembly"),
        "procedure-callees" => Some("procedure_callees"),
        "procedure-callers" => Some("procedure_callers"),
        "procedure-info" => Some("procedure_info"),
        "procedure-references" => Some("procedure_references"),
        "procedure-pseudo-code" => Some("procedure_pseudo_code"),
        "read-function-instructions" => Some("read_function_instructions"),
        "resolve-containing-procedure" => Some("resolve_containing_procedure"),
        "trace-call-path" => Some("trace_call_path"),
        "trace-feature" => Some("trace_feature"),
        "build-call-path" => Some("build_call_path"),
        "find-xrefs-to-name" => Some("find_xrefs_to_name"),
        "resolve-native-call-targets" => Some("resolve_native_call_targets"),
        "analyze-web-bundle" => Some("analyze_web_bundle"),
        "export-web-scripts" => Some("export_web_scripts"),
        "compare-source-to-bundle" => Some("compare_source_to_bundle"),
        "trace-web-module-imports" => Some("trace_web_module_imports"),
        "trace-web-source-location" => Some("trace_web_source_location"),
        "recover-javascript-sources" => Some("recover_javascript_sources"),
        "compare-javascript-export-shapes" => Some("compare_javascript_export_shapes"),
        "decode-android-resources" => Some("decode_android_resources"),
        "offline-list-browser-targets" => Some("list_browser_targets"),
        "offline-list-electron-targets" => Some("list_electron_targets"),
        "offline-inspect-electron-fuses" => Some("inspect_electron_fuses"),
        "offline-inspect-electron-page" => Some("inspect_electron_page"),
        "offline-reconcile-electron" => Some("reconcile_electron"),
        "offline-capture-browser-scenario" => Some("capture_browser_scenario"),
        "offline-capture-electron-scenario" => Some("capture_electron_scenario"),
        "offline-inspect-web-page" => Some("inspect_web_page"),
        "offline-inspect-web-event-listeners" => Some("inspect_web_event_listeners"),
        "offline-observe-web-execution" => Some("observe_web_execution"),
        "offline-observe-web-session" => Some("observe_web_session"),
        "environment-replay" | "environment-serve" => Some("environment-serve"),
        "offline-discover-webmcp-tools" => Some("discover_webmcp_tools"),
        "list-javascript-runtime-targets" => Some("list_javascript_runtime_targets"),
        "observe-javascript-runtime" => Some("observe_javascript_runtime"),
        _ => None,
    }
}

#[cfg(unix)]
fn identify_flutter_build_command(arguments: &[String]) -> Result<u8, Box<dyn std::error::Error>> {
    const USAGE: &str = "Usage: rea-native identify-flutter-build ABSOLUTE_APK_PATH --format json";

    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--help")
    {
        emit_line(&format!(
            "Identify a Flutter APK's engine and Dart snapshot facts\n{USAGE}"
        ))?;
        return Ok(0);
    }
    if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
        emit_json(&rust_binary::invalid("invalid_value", USAGE.into()))?;
        return Ok(1);
    }

    let input = serde_json::json!({"path": arguments[1]});
    match flutter::build::inspect(&input) {
        Ok(result) => {
            emit_json(&result)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&failure)?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn run_offline_cli_command(
    arguments: &[String],
    operation: &'static str,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    const FORMAT_USAGE: &str = "INPUT --format json";

    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--help")
    {
        emit_line(&format!(
            "Use retained caller-supplied JSON for {operation}\nUsage: rea-native {} {FORMAT_USAGE}",
            arguments[0]
        ))?;
        return Ok(0);
    }

    if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
        emit_json(&rust_binary::invalid(
            "invalid_value",
            format!("Usage: rea-native {} {FORMAT_USAGE}", arguments[0]),
        ))?;
        return Ok(1);
    }

    let source = &arguments[1];
    let text = if source.trim_start().starts_with('{') || source.trim_start().starts_with('[') {
        source.clone()
    } else {
        match std::fs::read_to_string(source) {
            Ok(text) => text,
            Err(error) => {
                return emit_offline_failure(operation, "invalid_input", error.to_string());
            }
        }
    };
    let input = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(input) => input,
        Err(error) => return emit_offline_failure(operation, "invalid_format", error.to_string()),
    };

    let result = dispatch_offline_value(operation, input, cancellation);

    match result {
        Ok(value) => {
            emit_json(&value)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&OfflineCliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn batch_decompile_live_command(
    arguments: &[String],
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    const OPERATION: &str = "batch_decompile";
    const USAGE: &str =
        "Usage: rea-native batch-decompile TARGET_PATH TARGET_SHA256 INPUT --format json";

    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--help")
    {
        let help = format!(
            "Run the caller-selected target through the native Ghidra batch provider\n{USAGE}"
        );
        emit_line(&help)?;
        return Ok(0);
    }

    if arguments.len() != 6 || arguments[4] != "--format" || arguments[5] != "json" {
        emit_json(&rust_binary::invalid("invalid_value", USAGE.into()))?;
        return Ok(1);
    }

    let input = match read_json_cli_input(&arguments[3]) {
        Ok(input) => input,
        Err(failure) => {
            emit_json(&OfflineCliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            return Ok(1);
        }
    };

    let target = batch_decompile_runtime_handlers::GhidraRustTarget {
        path: arguments[1].clone(),
        sha256: arguments[2].clone(),
    };
    let cancelled = || cancellation.reason().is_some();
    let context = batch_decompile_runtime_handlers::GhidraRustBatchContext {
        target: &target,
        cancelled: &cancelled,
    };

    match batch_decompile_runtime_handlers::dispatch_with_context(input, context) {
        Ok(result) => {
            emit_json(&result)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&OfflineCliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn read_json_cli_input(source: &str) -> Result<serde_json::Value, Failure> {
    let text = if source.trim_start().starts_with('{') || source.trim_start().starts_with('[') {
        source.to_owned()
    } else {
        std::fs::read_to_string(source).map_err(|error| {
            Failure::new(
                "invalid_input",
                "invalid_input",
                error.to_string(),
                false,
                "Provide inline JSON or a readable JSON file.".into(),
                BTreeMap::from([("operation", Detail::Text("batch_decompile".into()))]),
            )
        })?
    };

    serde_json::from_str(&text).map_err(|error| {
        Failure::new(
            "invalid_format",
            "invalid_input",
            error.to_string(),
            false,
            "Provide valid JSON containing batch selectors.".into(),
            BTreeMap::from([("operation", Detail::Text("batch_decompile".into()))]),
        )
    })
}

#[cfg(unix)]
fn compare_managed_members_command(
    arguments: &[String],
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    const USAGE: &str =
        "Usage: rea-native compare-managed-members LEFT_PATH RIGHT_PATH --format json";

    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--help")
    {
        emit_line(&format!(
            "Compare managed PE/CLI member inventories from two selected artifacts\n{USAGE}"
        ))?;
        return Ok(0);
    }

    if arguments.len() != 5 || arguments[3] != "--format" || arguments[4] != "json" {
        emit_json(&rust_binary::invalid("invalid_value", USAGE.into()))?;
        return Ok(1);
    }

    let input = serde_json::json!({
        "left_path": arguments[1],
        "right_path": arguments[2],
    });

    match rea_runtime::managed_member_comparison_handler::inspect(&input, cancellation) {
        Ok(result) => {
            emit_json(&result)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&OfflineCliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn inspect_il2cpp_metadata_command(
    arguments: &[String],
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    const USAGE: &str = "Usage: rea-native inspect-il2cpp-metadata PATH --format json [--detail complete|summary] [--evidence_output PATH]";

    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--help")
    {
        emit_line(&format!(
            "Inspect a caller-selected Unity IL2CPP global-metadata.dat artifact\n{USAGE}"
        ))?;
        return Ok(0);
    }

    let options = match parse_il2cpp_metadata_arguments(arguments) {
        Ok(options) => options,
        Err(reason) => {
            emit_json(&rust_binary::invalid("invalid_value", reason))?;
            return Ok(1);
        }
    };

    let path = match rea_host::fs::caller_path::absolute(&options.path) {
        Ok(path) => path,
        Err(error) => {
            emit_json(&rust_binary::invalid(
                "invalid_path",
                format!("Could not resolve the selected IL2CPP metadata path: {error}"),
            ))?;
            return Ok(1);
        }
    };

    let mut inspection =
        Il2cppMetadataInspection::new(Arc::new(rea_host::fs::unix_file::UnixFiles));
    let result =
        inspect_and_deliver_il2cpp_metadata(&mut inspection, &path, &options, cancellation);
    let result = close_il2cpp_metadata_inspection(result, &mut inspection);

    match result {
        Ok(delivery) => {
            emit_json(&delivery)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&failure)?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn inspect_and_deliver_il2cpp_metadata(
    inspection: &mut Il2cppMetadataInspection<rea_host::fs::unix_file::UnixFiles>,
    absolute_path: &str,
    options: &Il2cppMetadataCliOptions,
    cancellation: &Cancellation,
) -> Result<serde_json::Value, Failure> {
    let input = serde_json::json!({
        "path": absolute_path,
        "detail": "complete",
    });

    let complete = rea_runtime::inspect_il2cpp_metadata_handler::inspect(
        inspection,
        &input,
        cancellation,
        Completion::OneShot,
    )?;

    deliver_il2cpp_metadata(&complete, options, cancellation)
}

#[cfg(unix)]
fn close_il2cpp_metadata_inspection(
    result: Result<serde_json::Value, Failure>,
    inspection: &mut Il2cppMetadataInspection<rea_host::fs::unix_file::UnixFiles>,
) -> Result<serde_json::Value, Failure> {
    let cleanup = inspection.close();

    match (result, cleanup) {
        (Ok(delivery), Ok(())) => Ok(delivery),
        (Ok(_), Err(cleanup_failure)) => Err(cleanup_failure),
        (Err(failure), Ok(())) => Err(failure),
        (Err(mut failure), Err(cleanup_failure)) => {
            match serde_json::value::to_raw_value(&cleanup_failure) {
                Ok(cleanup) => failure.detail("cleanup_failure", Detail::Raw(cleanup)),
                Err(error) => {
                    failure.detail("cleanup_failure_encoding", Detail::Text(error.to_string()))
                }
            }
            Err(failure)
        }
    }
}

#[cfg(unix)]
fn deliver_il2cpp_metadata(
    complete: &serde_json::value::RawValue,
    options: &Il2cppMetadataCliOptions,
    cancellation: &Cancellation,
) -> Result<serde_json::Value, Failure> {
    let complete_value: serde_json::Value = serde_json::from_str(complete.get())
        .map_err(|error| il2cpp_metadata_delivery_failure(error.to_string()))?;

    let evidence_bundle = match options.evidence_output.as_deref() {
        Some(path) => match export_il2cpp_metadata_evidence(complete, path, cancellation) {
            Ok(receipt) => Some(receipt),
            Err(mut failure) => {
                retain_failure_detail(&mut failure, "partial_observation", complete);
                return Err(failure);
            }
        },
        None => None,
    };

    let delivery = if options.detail == "complete" {
        complete_value
    } else {
        let evidence_bundle = evidence_bundle.ok_or_else(|| {
            rust_binary::invalid(
                "invalid_value",
                "Summary delivery requires --evidence_output.".into(),
            )
        })?;
        let summary = il2cpp::metadata_view::project(
            &complete_value,
            &serde_json::json!({"kind": "summary"}),
        )?;
        let summary: serde_json::Value = serde_json::from_str(summary.get())
            .map_err(|error| il2cpp_metadata_delivery_failure(error.to_string()))?;

        serde_json::json!({
            "summary": summary,
            "evidence_bundle": evidence_bundle,
        })
    };

    if cancellation.reason().is_some() {
        return Err(il2cpp_metadata_cancelled_with_partial(&delivery));
    }

    Ok(delivery)
}

#[cfg(unix)]
fn il2cpp_metadata_delivery_failure(reason: String) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        "IL2CPP metadata output could not be prepared.".into(),
        false,
        "Report this output projection failure with the command input.".into(),
        BTreeMap::from([
            ("operation", Detail::Text("inspect_il2cpp_metadata".into())),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

#[cfg(unix)]
fn il2cpp_metadata_cancelled_with_partial<T: serde::Serialize + std::fmt::Debug>(
    partial: &T,
) -> Failure {
    let mut failure = Failure::new(
        "cancelled",
        "cancelled",
        "IL2CPP metadata delivery was cancelled after inspection completed.".into(),
        false,
        "Use the retained partial observation if it is still needed.".into(),
        BTreeMap::from([("operation", Detail::Text("inspect_il2cpp_metadata".into()))]),
    );
    retain_failure_detail(&mut failure, "partial_observation", partial);
    failure
}

#[cfg(unix)]
struct Il2cppMetadataCliOptions {
    path: String,
    detail: &'static str,
    evidence_output: Option<String>,
}

#[cfg(unix)]
fn parse_il2cpp_metadata_arguments(
    arguments: &[String],
) -> Result<Il2cppMetadataCliOptions, String> {
    const USAGE: &str = "Usage: rea-native inspect-il2cpp-metadata PATH --format json [--detail complete|summary] [--evidence_output PATH]";

    let Some(path) = arguments.get(1).filter(|path| !path.starts_with('-')) else {
        return Err(USAGE.into());
    };
    let mut format = None;
    let mut detail = "complete";
    let mut evidence_output = None;
    let mut index = 2;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err("--format requires a value; this command supports json.".into());
                };
                if format.replace(value.as_str()).is_some() {
                    return Err("--format may be supplied only once.".into());
                }
            }
            "--detail" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err("--detail requires complete or summary.".into());
                };
                if !matches!(value.as_str(), "complete" | "summary") {
                    return Err("--detail must be complete or summary.".into());
                }
                detail = if value == "complete" {
                    "complete"
                } else {
                    "summary"
                };
            }
            "--evidence_output" | "--evidence-output" => {
                index += 1;
                let Some(value) = arguments.get(index).filter(|value| !value.is_empty()) else {
                    return Err("--evidence_output requires a non-empty path.".into());
                };
                if evidence_output.replace(value.clone()).is_some() {
                    return Err("--evidence_output may be supplied only once.".into());
                }
            }
            argument => {
                return Err(format!(
                    "Unsupported inspect-il2cpp-metadata option: {argument}"
                ));
            }
        }
        index += 1;
    }

    if format != Some("json") {
        return Err(USAGE.into());
    }
    if detail == "summary" && evidence_output.is_none() {
        return Err("Summary delivery requires --evidence_output.".into());
    }

    Ok(Il2cppMetadataCliOptions {
        path: path.clone(),
        detail,
        evidence_output,
    })
}

#[cfg(unix)]
fn export_il2cpp_metadata_evidence(
    complete: &serde_json::value::RawValue,
    output_path: &str,
    cancellation: &Cancellation,
) -> Result<serde_json::Value, Failure> {
    let records = ArtifactRecords::default();
    records
        .record_raw(complete)
        .map_err(|error| error.into_export_failure())?;
    let snapshot = records
        .snapshot()
        .map_err(|error| error.into_export_failure())?;
    // The named input parser owns path admission; never construct it directly.
    let mut export_arguments = serde_json::Map::new();
    export_arguments.insert(
        "path".into(),
        serde_json::Value::String(output_path.to_owned()),
    );
    let input = rea_application::inputs::export(&export_arguments).map_err(|error| {
        let mut failure = rust_binary::invalid("invalid_value", error.to_string());
        failure.detail("input_issues", Detail::Issues(error.0));
        failure
    })?;
    let receipt = BundleExporter::export_one_shot(&snapshot, input, cancellation)?;
    Ok(serde_json::json!({
        "path": receipt.path(),
        "bytes": receipt.bytes(),
    }))
}

#[cfg(unix)]
fn dispatch_offline_value(
    operation: &str,
    input: serde_json::Value,
    cancellation: &Cancellation,
) -> Result<serde_json::Value, Failure> {
    if rea_runtime::il2cpp_offline_handlers::supports(operation) {
        return rea_runtime::il2cpp_offline_handlers::dispatch(operation, input);
    }

    if operation == rea_runtime::adb_client_live_handler::OPERATION
        && (input.get("selection").is_some() || input.get("binary_path").is_some())
    {
        return rea_runtime::adb_client_live_handler::dispatch(operation, &input, cancellation);
    }
    if operation == rea_runtime::adb_device_live_handler::OPERATION
        && (input.get("selection").is_some() || input.get("binary_path").is_some())
    {
        return rea_runtime::adb_device_live_handler::dispatch(operation, &input, cancellation);
    }
    if operation == rea_runtime::adb_package_pull_live_handler::OPERATION
        && input.get("package").is_some()
    {
        return rea_runtime::adb_package_pull_live_handler::dispatch(
            operation,
            &input,
            cancellation,
        );
    }
    if operation == rea_runtime::web_session_live_handler::OPERATION
        && input.get("cdp_endpoint").is_some()
    {
        return rea_runtime::web_session_live_handler::observe(&input, cancellation);
    }
    if operation == "observe_javascript_runtime" && input.get("inspector_endpoint").is_some() {
        return rea_runtime::javascript_runtime_handler::observe(&input, cancellation);
    }
    if operation == "list_javascript_runtime_targets" && input.get("inspector_endpoint").is_some() {
        return rea_runtime::javascript_runtime_handler::list(&input, cancellation);
    }
    if operation == rea_runtime::managed_member_comparison_handler::OPERATION
        && (input.get("left_path").is_some() || input.get("right_path").is_some())
    {
        return rea_runtime::managed_member_comparison_handler::inspect(&input, cancellation);
    }

    match operation {
        "list_bookmarks" | "list_documents" | "list_names" | "list_procedures"
        | "list_segments" | "list_strings" | "search_procedures" | "search_strings" => {
            rea_runtime::analysis_inventory_handlers::dispatch(operation, input)
        }
        "inspect_adb_client"
        | "list_adb_devices"
        | "inspect_adb_device"
        | "list_adb_packages"
        | "read_adb_logcat"
        | "inspect_adb_package"
        | "pull_adb_package"
        | "pull_adb_file"
        | "capture_adb_screen"
        | "list_adb_processes"
        | "list_adb_directory"
        | "list_adb_features"
        | "list_adb_services"
        | "inspect_adb_display"
        | "inspect_adb_window"
        | "read_adb_setting"
        | "collect_adb_bugreport"
        | "resolve_adb_packages" => rea_runtime::adb_offline_handlers::dispatch(operation, input),
        "inspect_firmware_regions"
        | "extract_firmware"
        | "compare_artifacts"
        | "inspect_signature"
        | "inspect_artifact"
        | "extract_artifact"
        | "inspect_desktop_application" => {
            rea_runtime::artifact_workflow_handlers::dispatch(operation, input)
        }
        "inspect_dart_aot" => inspect_dart_aot_handler::inspect(&input, cancellation),
        "offline_identify_flutter_build" => {
            rea_runtime::polyglot_static_handlers::dispatch("offline_identify_flutter_build", input)
        }
        "compare_functions" => compare_functions_handlers::dispatch(operation, input),
        "find_changed_behavior" => find_changed_behavior_handlers::dispatch(operation, input),
        "correlate_static_and_runtime" => static_runtime_handlers::dispatch(operation, input),
        "verify_reconstruction" => {
            let object = input.as_object().ok_or_else(|| {
                Failure::new(
                    "invalid_request",
                    "invalid_input",
                    "verify_reconstruction input must be an object".into(),
                    false,
                    "Provide specification and bundle objects.".into(),
                    BTreeMap::new(),
                )
            })?;
            let specification = object.get("specification").ok_or_else(|| {
                Failure::new(
                    "invalid_request",
                    "invalid_input",
                    "verify_reconstruction specification is required".into(),
                    false,
                    "Provide specification and bundle objects.".into(),
                    BTreeMap::new(),
                )
            })?;
            let bundle = object.get("bundle").ok_or_else(|| {
                Failure::new(
                    "invalid_request",
                    "invalid_input",
                    "verify_reconstruction bundle is required".into(),
                    false,
                    "Provide specification and bundle objects.".into(),
                    BTreeMap::new(),
                )
            })?;
            verify_reconstruction_handlers::dispatch_typed(
                verify_reconstruction_handlers::Operation::VerifyReconstruction,
                specification,
                bundle,
            )
        }
        "list_browser_targets"
        | "list_electron_targets"
        | "inspect_electron_fuses"
        | "inspect_electron_page"
        | "reconcile_electron"
        | "capture_browser_scenario"
        | "capture_electron_scenario" => {
            rea_runtime::browser_electron_offline_handlers::dispatch(operation, input)
        }
        "read_bytes" | "search_bytes" | "address_to_file_offset" => {
            rea_runtime::bytes_observation_handlers::dispatch(operation, input)
        }
        "import_managed_reconstruction"
        | "project_managed_application_graph"
        | "compare_managed_members"
        | "verify_managed_native_boundaries" => {
            rea_runtime::managed_handlers::dispatch(operation, input)
        }
        "inspect_managed_native_boundaries" => {
            rea_runtime::inspect_managed_native_boundaries_handler::handle(&input)
        }
        "environment-serve" => {
            rea_runtime::environment_replay_handler::inspect(&input, cancellation)
        }
        "inspect_native_annotation"
        | "inspect_native_api"
        | "inspect_native_data_type"
        | "inspect_native_dispatch_metadata"
        | "inspect_native_instruction"
        | "inspect_native_load_image"
        | "inspect_with_objdump" => {
            rea_runtime::native_analysis_handlers::dispatch(operation, input)
        }
        "get_navigation_context"
        | "inspect_address_context"
        | "address_name"
        | "current_address"
        | "current_procedure"
        | "current_document"
        | "next_address"
        | "prev_address" => rea_runtime::native_navigation_handlers::dispatch(operation, input),
        "procedure_address"
        | "procedure_assembly"
        | "procedure_callees"
        | "procedure_callers"
        | "procedure_info"
        | "procedure_references"
        | "procedure_pseudo_code"
        | "read_function_instructions"
        | "resolve_containing_procedure" => {
            rea_runtime::native_procedure_handlers::dispatch(operation, input)
        }
        "trace_call_path"
        | "trace_feature"
        | "build_call_path"
        | "find_xrefs_to_name"
        | "resolve_native_call_targets" => {
            rea_runtime::native_relationship_handlers::dispatch(operation, input)
        }
        "analyze_web_bundle"
        | "export_web_scripts"
        | "compare_source_to_bundle"
        | "trace_web_module_imports"
        | "trace_web_source_location"
        | "recover_javascript_sources"
        | "compare_javascript_export_shapes" => {
            rea_runtime::web_static_handlers::dispatch(operation, input)
        }
        "inspect_web_page"
        | "inspect_web_event_listeners"
        | "observe_web_execution"
        | "observe_web_session"
        | "discover_webmcp_tools"
        | "compare_web_captures" => web_capture_offline_handlers::dispatch(operation, input),
        "compare_process_captures" => {
            rea_application::process::offline_evidence::compare_process_captures(&input)
        }
        "inspect_packet_fields" => inspect_packet_fields_handler::inspect_packet_fields(&input),
        "inspect_packet_capture" => packet_capture_handlers::dispatch(operation, input),
        "inspect_pcap_client" => pcap_client_offline_handlers::dispatch(input),
        "inspect_pcap_capture" => pcap_capture_handler::dispatch(input),
        "inspect_signal_decoders" | "decode_signal_recording" | "inspect_web_network_capture" => {
            rea_runtime::network_signal_offline_handlers::dispatch(operation, input)
        }
        "batch_decompile" => batch_decompile_runtime_handlers::dispatch(input),
        "xrefs" => xrefs_runtime_handlers::dispatch(input),
        "decode_android_resources" => {
            rea_runtime::android_resource_handlers::dispatch(operation, input)
        }
        _ => Err(Failure::new(
            "unsupported_request",
            "unsupported_request",
            format!("Native offline CLI operation is unsupported: {operation}"),
            false,
            "Select a supported retained offline workflow.".into(),
            BTreeMap::new(),
        )),
    }
}

#[cfg(unix)]
fn emit_offline_failure(
    operation: &str,
    code: &'static str,
    reason: String,
) -> Result<u8, Box<dyn std::error::Error>> {
    let failure = Failure::new_with_details(
        code,
        code,
        reason,
        false,
        "Provide valid caller-supplied retained JSON.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(operation.into()))]),
    );
    emit_json(&OfflineCliFailure {
        error: "Analysis failed",
        failure: &failure,
    })?;
    Ok(1)
}

#[cfg(unix)]
fn project_android_application_graph(
    input: &serde_json::Value,
) -> Result<Box<serde_json::value::RawValue>, rea_core::failure::Failure> {
    let graph_input = graph_json::parse(&serde_json::to_string(input).map_err(|error| {
        rea_core::failure::Failure::new(
            "invalid_request",
            "invalid_input",
            error.to_string(),
            false,
            "Provide authenticated Android inventory Evidence.".into(),
            std::collections::BTreeMap::new(),
        )
    })?)
    .map_err(|error| {
        rea_core::failure::Failure::new(
            "invalid_request",
            "invalid_input",
            error.to_string(),
            false,
            "Provide authenticated Android inventory Evidence.".into(),
            std::collections::BTreeMap::new(),
        )
    })?;
    rea_application::android::application_graph::project_evidence(&graph_input)
}

fn project_apple_application_graph(
    input: &serde_json::Value,
) -> Result<Box<serde_json::value::RawValue>, rea_core::failure::Failure> {
    let graph_input = graph_json::parse(&serde_json::to_string(input).map_err(|error| {
        rea_core::failure::Failure::new(
            "invalid_request",
            "invalid_input",
            error.to_string(),
            false,
            "Provide authenticated Apple inventory Evidence.".into(),
            std::collections::BTreeMap::new(),
        )
    })?)
    .map_err(|error| {
        rea_core::failure::Failure::new(
            "invalid_request",
            "invalid_input",
            error.to_string(),
            false,
            "Provide authenticated Apple inventory Evidence.".into(),
            std::collections::BTreeMap::new(),
        )
    })?;
    apple_application_graph::project_evidence(&graph_input)
}

#[derive(serde::Serialize)]
struct OfflineCliFailure<'a> {
    error: &'static str,
    #[serde(flatten)]
    failure: &'a Failure,
}

fn project_application_graph_command(
    arguments: &[String],
    operation: &'static str,
    usage: &'static str,
    project: fn(
        &serde_json::Value,
    ) -> Result<Box<serde_json::value::RawValue>, rea_core::failure::Failure>,
) -> Result<u8, Box<dyn std::error::Error>> {
    let input = match parse_application_json_input(
        arguments,
        operation,
        usage,
        "Provide inline JSON or a readable JSON file containing authenticated inventory Evidence.",
    ) {
        Ok(input) => input,
        Err(failure) => {
            emit_json(&ApplicationCliFailure {
                error: "Application workflow failed",
                failure: &failure,
            })?;
            return Ok(1);
        }
    };

    match project(&input) {
        Ok(evidence) => {
            emit_json(evidence.as_ref())?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&ApplicationCliFailure {
                error: "Application workflow failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

fn evaluate_reconstruction_coverage_command(
    arguments: &[String],
) -> Result<u8, Box<dyn std::error::Error>> {
    const USAGE: &str = "Usage: rea-native evaluate-reconstruction-coverage INPUT --format json";
    const GUIDANCE: &str = "Provide inline reconstruction coverage JSON or a readable JSON file with authenticated Evidence and a declared boundary.";
    let input = match parse_application_json_input(
        arguments,
        reconstruction::coverage::OPERATION,
        USAGE,
        GUIDANCE,
    ) {
        Ok(input) => input,
        Err(failure) => {
            emit_json(&ApplicationCliFailure {
                error: "Reconstruction coverage evaluation failed",
                failure: &failure,
            })?;
            return Ok(1);
        }
    };

    match reconstruction::coverage::evaluate(&input) {
        Ok(result) => {
            emit_json(&result)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&ApplicationCliFailure {
                error: "Reconstruction coverage evaluation failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

fn compare_application_versions_command(
    arguments: &[String],
) -> Result<u8, Box<dyn std::error::Error>> {
    const USAGE: &str = "Usage: rea-native compare-application-versions INPUT --format json";
    const GUIDANCE: &str = "Provide inline comparison JSON or a readable JSON file containing two authenticated application graph Evidence records.";
    let input = match parse_application_json_input(
        arguments,
        javascript::version_comparison::OPERATION,
        USAGE,
        GUIDANCE,
    ) {
        Ok(input) => input,
        Err(failure) => {
            emit_json(&ApplicationCliFailure {
                error: "Application version comparison failed",
                failure: &failure,
            })?;
            return Ok(1);
        }
    };

    match javascript::version_comparison::compare(&input, None) {
        Ok(evidence) => {
            emit_json(evidence.as_ref())?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&ApplicationCliFailure {
                error: "Application version comparison failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

fn parse_application_json_input(
    arguments: &[String],
    operation: &'static str,
    usage: &'static str,
    guidance: &str,
) -> Result<serde_json::Value, rea_core::failure::Failure> {
    if arguments.len() != 4 || arguments[2] != "--format" || arguments[3] != "json" {
        return Err(application_workflow_cli_failure(
            operation,
            "invalid_value",
            usage.into(),
            guidance,
            None,
        ));
    }

    let source = &arguments[1];
    let text = if source.trim_start().starts_with('{') || source.trim_start().starts_with('[') {
        source.clone()
    } else {
        std::fs::read_to_string(source).map_err(|error| {
            application_workflow_cli_failure(
                operation,
                "invalid_value",
                format!("Could not read JSON input: {error}"),
                guidance,
                Some(source),
            )
        })?
    };

    serde_json::from_str(&text).map_err(|error| {
        application_workflow_cli_failure(
            operation,
            "invalid_format",
            format!("Input is not valid JSON: {error}"),
            guidance,
            Some(source),
        )
    })
}

fn application_workflow_cli_failure(
    operation: &'static str,
    code: &'static str,
    reason: String,
    guidance: &str,
    source: Option<&str>,
) -> rea_core::failure::Failure {
    let mut details = BTreeMap::from([(
        "operation",
        rea_core::failure::Detail::Text(operation.into()),
    )]);
    if let Some(source) = source {
        details.insert("source", rea_core::failure::Detail::Text(source.into()));
    }

    rea_core::failure::Failure::new(
        code,
        if code == "invalid_format" {
            "invalid_format"
        } else {
            "invalid_input"
        },
        reason,
        false,
        guidance.to_owned(),
        details,
    )
}

#[derive(serde::Serialize)]
struct ApplicationCliFailure<'a> {
    error: &'static str,
    #[serde(flatten)]
    failure: &'a rea_core::failure::Failure,
}

#[cfg(unix)]
fn parse_sqlite_arguments(arguments: &[String]) -> Result<inputs::SqliteInspectionInput, String> {
    let usage = "Usage: rea-native inspect-sqlite-database PATH [--table NAME] [--column NAME] [--schema-scope inventory|selected_table|database] [--row-limit N] --format json";
    let path = arguments.first().cloned().ok_or_else(|| usage.to_owned())?;
    let mut fields = serde_json::Map::from_iter([("path".into(), serde_json::Value::String(path))]);
    let mut columns = Vec::new();
    let mut format_was_json = false;
    let mut index = 1;

    while index < arguments.len() {
        let option = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("Option {option} requires a value"))?;

        match option {
            "--table" | "--schema-scope" => {
                let field_name = option.trim_start_matches('-').replace('-', "_");
                if fields.contains_key(&field_name) {
                    return Err(format!("{option} may only be provided once"));
                }
                fields.insert(field_name, serde_json::Value::String(value.clone()));
            }
            "--column" => columns.push(serde_json::Value::String(value.clone())),
            "--row-limit" => {
                if fields.contains_key("row_limit") {
                    return Err("--row-limit may only be provided once".into());
                }
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| "--row-limit must be a nonnegative integer".to_owned())?;
                fields.insert("row_limit".into(), serde_json::Value::Number(parsed.into()));
            }
            "--format" => {
                if format_was_json || value != "json" {
                    return Err("--format must be provided once with value json".into());
                }
                format_was_json = true;
            }
            _ => return Err(format!("Unknown SQLite option: {option}")),
        }

        index += 2;
    }

    if !columns.is_empty() {
        fields.insert("columns".into(), serde_json::Value::Array(columns));
    }
    if !format_was_json {
        return Err("--format json is required".into());
    }

    inputs::sqlite_inspection(&fields).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn parse_interface_builder_arguments(
    arguments: &[String],
) -> Result<InterfaceBuilderInput, String> {
    if arguments.len() < 2 {
        return Err("Usage: rea-native decode-interface-builder BUNDLE_PATH TARGET_SHA256 [--max-documents N] [--max-objects N] [--max-connections N] --format json".into());
    }

    let mut fields = serde_json::Map::from_iter([
        (
            "path".into(),
            serde_json::Value::String(arguments[0].clone()),
        ),
        (
            "target_sha256".into(),
            serde_json::Value::String(arguments[1].clone()),
        ),
    ]);
    let mut format_was_json = false;
    let mut index = 2;

    while index < arguments.len() {
        let option = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("Option {option} requires a value"))?;

        match option {
            "--format" => {
                if format_was_json || value != "json" {
                    return Err("--format must be provided once with value json".into());
                }
                format_was_json = true;
            }
            "--max-documents" => {
                insert_interface_builder_limit(&mut fields, "max_documents", value)?;
            }
            "--max-objects" => {
                insert_interface_builder_limit(&mut fields, "max_objects", value)?;
            }
            "--max-connections" => {
                insert_interface_builder_limit(&mut fields, "max_connections", value)?;
            }
            _ => return Err(format!("Unknown Interface Builder option: {option}")),
        }

        index += 2;
    }

    if !format_was_json {
        return Err("--format json is required".into());
    }

    inputs::interface_builder(&fields).map_err(|error| error.to_string())
}

#[cfg(unix)]
struct AndroidClassCliInput {
    path: String,
    class_name: String,
}

#[cfg(unix)]
struct AndroidMethodCliInput {
    path: String,
    class_name: String,
    method_name: String,
    overload_index: Option<usize>,
}

#[cfg(unix)]
fn parse_android_class_arguments(arguments: &[String]) -> Result<AndroidClassCliInput, String> {
    let usage = "Usage: rea-native inspect-android-class PATH --class-name NAME --format json";
    let path = arguments.first().cloned().ok_or_else(|| usage.to_owned())?;
    let mut class_name = None;
    let mut format_was_json = false;
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--class-name" => {
                if class_name.is_some() {
                    return Err("--class-name may only be provided once".into());
                }
                class_name = Some(parse_android_option_value(
                    arguments,
                    &mut index,
                    "--class-name",
                )?);
            }
            "--format" => {
                let format = parse_android_option_value(arguments, &mut index, "--format")?;
                if format_was_json || format != "json" {
                    return Err("--format must be provided once with value json".into());
                }
                format_was_json = true;
            }
            option => return Err(format!("Unknown Android class option: {option}")),
        }
    }

    let class_name = class_name.ok_or_else(|| "--class-name is required".to_owned())?;
    if !format_was_json {
        return Err("--format json is required".into());
    }

    Ok(AndroidClassCliInput { path, class_name })
}

#[cfg(unix)]
fn parse_android_method_arguments(arguments: &[String]) -> Result<AndroidMethodCliInput, String> {
    let usage = "Usage: rea-native inspect-android-method PATH --class-name CLASS --method-name NAME [--overload-index N] --format json";
    let path = arguments.first().cloned().ok_or_else(|| usage.to_owned())?;
    let mut class_name = None;
    let mut method_name = None;
    let mut overload_index = None;
    let mut format_was_json = false;
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--class-name" => {
                if class_name.is_some() {
                    return Err("--class-name may only be provided once".into());
                }
                class_name = Some(parse_android_option_value(
                    arguments,
                    &mut index,
                    "--class-name",
                )?);
            }
            "--method-name" => {
                if method_name.is_some() {
                    return Err("--method-name may only be provided once".into());
                }
                method_name = Some(parse_android_option_value(
                    arguments,
                    &mut index,
                    "--method-name",
                )?);
            }
            "--overload-index" => {
                if overload_index.is_some() {
                    return Err("--overload-index may only be provided once".into());
                }
                let value = parse_android_option_value(arguments, &mut index, "--overload-index")?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| "--overload-index must be a nonnegative integer".to_owned())?;
                overload_index = Some(parsed);
            }
            "--format" => {
                let format = parse_android_option_value(arguments, &mut index, "--format")?;
                if format_was_json || format != "json" {
                    return Err("--format must be provided once with value json".into());
                }
                format_was_json = true;
            }
            option => return Err(format!("Unknown Android method option: {option}")),
        }
    }

    let class_name = class_name.ok_or_else(|| "--class-name is required".to_owned())?;
    let method_name = method_name.ok_or_else(|| "--method-name is required".to_owned())?;
    if !format_was_json {
        return Err("--format json is required".into());
    }

    Ok(AndroidMethodCliInput {
        path,
        class_name,
        method_name,
        overload_index,
    })
}

#[cfg(unix)]
fn parse_android_option_value(
    arguments: &[String],
    index: &mut usize,
    option: &str,
) -> Result<String, String> {
    let value = arguments
        .get(*index + 1)
        .cloned()
        .ok_or_else(|| format!("{option} requires a value"))?;
    *index += 2;
    Ok(value)
}

#[cfg(unix)]
fn parse_asset_catalog_arguments(
    arguments: &[String],
) -> Result<inputs::AssetCatalogCliInput, String> {
    if arguments.len() < 2 {
        return Err("Usage: rea-native inspect-asset-catalog TARGET_PATH TARGET_SHA256 [--offset N] [--limit N] --format json".into());
    }

    let mut fields = serde_json::Map::from_iter([
        (
            "path".into(),
            serde_json::Value::String(arguments[0].clone()),
        ),
        (
            "target_sha256".into(),
            serde_json::Value::String(arguments[1].clone()),
        ),
    ]);
    let mut format_was_json = false;
    let mut index = 2;

    while index < arguments.len() {
        let option = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("Option {option} requires a value"))?;

        match option {
            "--format" => {
                if format_was_json || value != "json" {
                    return Err("--format must be provided once with value json".into());
                }
                format_was_json = true;
            }
            "--offset" | "--limit" => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("{option} requires a nonnegative integer"))?;
                let key = option.trim_start_matches("--");
                if fields.contains_key(key) {
                    return Err(format!("{option} may only be provided once"));
                }
                fields.insert(key.into(), serde_json::Value::Number(parsed.into()));
            }
            _ => return Err(format!("Unknown asset catalog option: {option}")),
        }
        index += 2;
    }

    if !format_was_json {
        return Err("inspect-asset-catalog requires --format json".into());
    }
    inputs::asset_catalog_cli(&fields).map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn inspect_asset_catalog_target(
    path: &str,
    expected_sha256: &str,
    cancellation: &Cancellation,
) -> Result<Subject, Failure> {
    let mut inspection = MachoInspection::new(Arc::new(rea_host::fs::unix_file::UnixFiles));
    let observed = inspection.inspect(path, cancellation, Completion::OneShot);
    let cleanup = inspection.close();

    let evidence = match observed {
        Ok(evidence) => {
            if let Err(error) = cleanup {
                return Err(error);
            }
            evidence
        }
        Err(mut failure) => {
            if let Err(cleanup_failure) = cleanup {
                let cleanup_detail = match serde_json::value::to_raw_value(&cleanup_failure) {
                    Ok(cleanup_failure) => Detail::Raw(cleanup_failure),
                    Err(error) => Detail::Text(format!(
                        "{} (cleanup detail serialization failed: {error})",
                        cleanup_failure.code()
                    )),
                };
                failure.detail("cleanup_failure", cleanup_detail);
            }
            return Err(failure);
        }
    };

    let observed_sha256 = evidence.subject().sha256();
    if observed_sha256 != expected_sha256 {
        return Err(Failure::new(
            "target_changed",
            "target_changed",
            "Selected Mach-O digest does not match the caller-provided digest.".into(),
            false,
            "Recompute the target digest from the selected local Mach-O and retry.".into(),
            BTreeMap::from([
                (
                    "operation",
                    Detail::Text(apple::asset_catalog_workflow::OPERATION.into()),
                ),
                ("path", Detail::Text(path.to_owned())),
                ("expected_sha256", Detail::Text(expected_sha256.to_owned())),
                ("observed_sha256", Detail::Text(observed_sha256.to_owned())),
            ]),
        ));
    }

    Subject::new(path, observed_sha256.to_owned(), NativeFormat::MachO, None).map_err(|error| {
        Failure::new(
            "invalid_request",
            "invalid_input",
            error.to_string(),
            false,
            "Select an absolute, readable Mach-O file and retry.".into(),
            BTreeMap::from([
                (
                    "operation",
                    Detail::Text(apple::asset_catalog_workflow::OPERATION.into()),
                ),
                ("path", Detail::Text(path.to_owned())),
            ]),
        )
    })
}

#[cfg(unix)]
fn insert_interface_builder_limit(
    fields: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &str,
) -> Result<(), String> {
    if fields.contains_key(key) {
        return Err(format!("{key} may be provided only once"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{key} must be an integer"))?;
    fields.insert(key.into(), serde_json::Value::Number(parsed.into()));
    Ok(())
}

fn inspect_apktool_client_command(arguments: &[String]) -> Result<u8, Box<dyn std::error::Error>> {
    if arguments.len() != 3 || arguments[1] != "--format" || arguments[2] != "json" {
        emit_json(&rust_binary::invalid(
            "invalid_value",
            "Usage: rea-native inspect-apktool-client --format json".into(),
        ))?;
        return Ok(1);
    }

    let environment = rea_runtime::apktool_client_live_handler::LauncherEnvironment::current();
    match rea_runtime::apktool_client_live_handler::inspect(&environment, &Cancellation::default())
    {
        Ok(inspection) => {
            emit_json(&inspection)?;
            Ok(0)
        }
        Err(error) => {
            emit_json(&error)?;
            Ok(1)
        }
    }
}

fn is_valid_inspection_arguments(arguments: &[String]) -> bool {
    match arguments.first().map(String::as_str) {
        Some("inspect-rust-binary") => {
            arguments.len() == 4 && arguments[2] == "--format" && arguments[3] == "json"
        }
        Some("inspect-go-binary") => {
            (arguments.len() == 3 && arguments[2] == "--json")
                || (arguments.len() == 4 && arguments[2] == "--format" && arguments[3] == "json")
        }
        _ => false,
    }
}

#[cfg(unix)]
struct KeyedArchiveCliValues {
    object: serde_json::Map<String, serde_json::Value>,
    issues: Vec<InputIssue>,
    output_format_seen: bool,
}

#[cfg(unix)]
fn inspect_keyed_archive_command(
    arguments: &[String],
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let input = match parse_keyed_archive_input(arguments) {
        Ok(input) => input,
        Err(failure) => {
            emit_json(&failure)?;
            return Ok(1);
        }
    };

    let mut inspection = KeyedArchiveInspection::new(Arc::new(rea_host::fs::unix_file::UnixFiles));
    let outcome = inspection.inspect(
        &input.path,
        &input.selection,
        cancellation,
        Completion::OneShot,
    );
    let cleanup = inspection.close();

    finish_inspection_command(outcome, cleanup)
}

#[cfg(unix)]
fn parse_keyed_archive_input(arguments: &[String]) -> Result<inputs::KeyedArchiveInput, Failure> {
    let mut parsed = collect_keyed_archive_cli_values(arguments);
    if !parsed.output_format_seen {
        parsed.issues.push(keyed_archive_cli_issue(
            "--format",
            "invalid_value",
            "inspect-keyed-archive requires --format json output.",
        ));
    }

    match inputs::keyed_archive(&parsed.object) {
        Ok(input) if parsed.issues.is_empty() => Ok(input),
        Ok(_) => Err(analysis_input_failure(
            keyed_archive::OPERATION,
            parsed.issues,
        )),
        Err(error) => {
            parsed.issues.extend(error.0);
            Err(analysis_input_failure(
                keyed_archive::OPERATION,
                parsed.issues,
            ))
        }
    }
}

#[cfg(unix)]
fn collect_keyed_archive_cli_values(arguments: &[String]) -> KeyedArchiveCliValues {
    let mut parsed = KeyedArchiveCliValues {
        object: serde_json::Map::new(),
        issues: Vec::new(),
        output_format_seen: false,
    };
    let mut index = 1;
    let mut positional_only = false;

    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" && !positional_only {
            positional_only = true;
            index += 1;
            continue;
        }

        if !positional_only && argument == "--format" {
            record_output_format(arguments, &mut parsed, index);
            index += 2;
            continue;
        }

        if !positional_only && matches!(argument.as_str(), "--root" | "--offset" | "--limit") {
            record_keyed_archive_value(arguments, &mut parsed, index, argument);
            index += 2;
            continue;
        }

        if !positional_only && argument.starts_with('-') {
            parsed.issues.push(keyed_archive_cli_issue(
                argument,
                "invalid_value",
                format!("Unknown inspect-keyed-archive argument: {argument}"),
            ));
            index += 1;
            continue;
        }

        if parsed.object.contains_key("path") {
            parsed.issues.push(keyed_archive_cli_issue(
                "path",
                "invalid_value",
                "Supply exactly one archive path.",
            ));
        } else {
            parsed
                .object
                .insert("path".into(), serde_json::Value::String(argument.clone()));
        }
        index += 1;
    }

    parsed
}

#[cfg(unix)]
fn record_output_format(
    arguments: &[String],
    parsed: &mut KeyedArchiveCliValues,
    option_index: usize,
) {
    if parsed.output_format_seen {
        parsed.issues.push(keyed_archive_cli_issue(
            "--format",
            "invalid_value",
            "Specify the output format only once.",
        ));
        return;
    }
    parsed.output_format_seen = true;

    let Some(value) = arguments.get(option_index + 1) else {
        parsed.issues.push(keyed_archive_cli_issue(
            "--format",
            "invalid_value",
            "--format requires the value json.",
        ));
        return;
    };
    if value != "json" {
        parsed.issues.push(keyed_archive_cli_issue(
            "--format",
            "invalid_value",
            "inspect-keyed-archive supports only --format json.",
        ));
    }
}

#[cfg(unix)]
fn record_keyed_archive_value(
    arguments: &[String],
    parsed: &mut KeyedArchiveCliValues,
    option_index: usize,
    option: &str,
) {
    let key = option.trim_start_matches('-');
    if parsed.object.contains_key(key) {
        parsed.issues.push(keyed_archive_cli_issue(
            option,
            "invalid_value",
            format!("Specify {option} only once."),
        ));
        return;
    }

    let Some(value) = arguments.get(option_index + 1) else {
        parsed.issues.push(keyed_archive_cli_issue(
            option,
            "invalid_value",
            format!("{option} requires a value."),
        ));
        return;
    };
    let value = if key == "root" {
        serde_json::Value::String(value.clone())
    } else {
        serde_json::from_str(value).unwrap_or_else(|_| serde_json::Value::String(value.clone()))
    };
    parsed.object.insert(key.to_owned(), value);
}

#[cfg(unix)]
fn keyed_archive_cli_issue(
    path: &str,
    reason: &'static str,
    message: impl Into<String>,
) -> InputIssue {
    InputIssue {
        path: vec![path.into()],
        reason,
        message: message.into(),
        expected: None,
    }
}

#[cfg(unix)]
fn inspect_pe_resources_command(
    arguments: &[String],
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let input = match parse_pe_resources_input(arguments) {
        Ok(input) => input,
        Err(failure) => {
            emit_json(&failure)?;
            return Ok(1);
        }
    };

    let mut service = PeResourcesInspection::new(Arc::new(rea_host::fs::unix_file::UnixFiles));
    let outcome = service.inspect(input, cancellation, Completion::OneShot);
    let cleanup = service.close();

    finish_inspection_command(outcome, cleanup)
}

#[cfg(unix)]
fn parse_pe_resources_input(arguments: &[String]) -> Result<PeResourcesInput, Failure> {
    let mut parsed = collect_pe_resource_cli_values(arguments);

    if !parsed.output_format_seen {
        parsed.issues.push(pe_cli_issue(
            "--json",
            "invalid_value",
            "inspect-pe-resources requires --json output.",
        ));
    }

    normalize_pe_resource_cli_path(&mut parsed);

    match inputs::pe_resources(&parsed.object) {
        Ok(input) if parsed.issues.is_empty() => Ok(input),
        Ok(_) => Err(pe_input_failure(parsed.issues)),
        Err(error) => {
            parsed.issues.extend(error.0);
            Err(pe_input_failure(parsed.issues))
        }
    }
}

#[cfg(unix)]
struct PeResourceCliValues {
    object: serde_json::Map<String, serde_json::Value>,
    paths: Vec<String>,
    issues: Vec<InputIssue>,
    output_format_seen: bool,
}

#[cfg(unix)]
fn collect_pe_resource_cli_values(arguments: &[String]) -> PeResourceCliValues {
    let mut parsed = PeResourceCliValues {
        object: serde_json::Map::new(),
        paths: Vec::new(),
        issues: Vec::new(),
        output_format_seen: false,
    };
    let mut positional_only = false;
    let mut index = 1;

    while index < arguments.len() {
        let argument = arguments[index].as_str();

        if positional_only {
            parsed.paths.push(argument.to_owned());
            index += 1;
            continue;
        }

        match argument {
            "--" => positional_only = true,
            "--json" => {
                if parsed.output_format_seen {
                    parsed.issues.push(pe_cli_issue(
                        "--json",
                        "invalid_value",
                        "Choose one JSON output option and supply it only once.",
                    ));
                }
                parsed.output_format_seen = true;
            }
            "--format" => {
                index += 1;
                match arguments.get(index).map(String::as_str) {
                    Some("json") if !parsed.output_format_seen => {
                        parsed.output_format_seen = true;
                    }
                    Some("json") => parsed.issues.push(pe_cli_issue(
                        "--format",
                        "invalid_value",
                        "Choose one JSON output option and supply it only once.",
                    )),
                    Some(_) => parsed.issues.push(pe_cli_issue(
                        "--format",
                        "invalid_value",
                        "This command supports JSON output only.",
                    )),
                    None => parsed.issues.push(pe_cli_issue(
                        "--format",
                        "invalid_value",
                        "--format requires the value json.",
                    )),
                }
            }
            "--max-file-bytes" | "--max-entries" => {
                let field = if argument == "--max-file-bytes" {
                    "max_file_bytes"
                } else {
                    "max_entries"
                };
                index += 1;

                let Some(value) = arguments.get(index) else {
                    parsed.issues.push(pe_cli_issue(
                        argument,
                        "invalid_value",
                        format!("{argument} requires an integer value."),
                    ));
                    index += 1;
                    continue;
                };

                if parsed.object.contains_key(field) {
                    parsed.issues.push(pe_cli_issue(
                        argument,
                        "invalid_value",
                        format!("{argument} may be supplied only once."),
                    ));
                } else {
                    let json_value = value
                        .parse::<serde_json::Number>()
                        .map(serde_json::Value::Number)
                        .unwrap_or_else(|_| serde_json::Value::String(value.clone()));
                    parsed.object.insert(field.to_owned(), json_value);
                }
            }
            option if option.starts_with('-') => parsed.issues.push(pe_cli_issue(
                "arguments",
                "unrecognized_keys",
                format!("Unsupported inspect-pe-resources option: {option}"),
            )),
            path => parsed.paths.push(path.to_owned()),
        }

        index += 1;
    }

    parsed
}

#[cfg(unix)]
fn normalize_pe_resource_cli_path(parsed: &mut PeResourceCliValues) {
    if parsed.paths.len() > 1 {
        parsed.issues.push(pe_cli_issue(
            "path",
            "invalid_value",
            "Supply exactly one artifact path.",
        ));
        return;
    }

    let Some(path) = parsed.paths.first() else {
        return;
    };

    if !path.is_empty() {
        match rea_host::fs::caller_path::absolute(path) {
            Ok(path) => {
                parsed
                    .object
                    .insert("path".into(), serde_json::Value::String(path));
            }
            Err(error) => parsed.issues.push(pe_cli_issue(
                "path",
                "invalid_value",
                format!("Could not resolve the artifact path: {error}"),
            )),
        }
    } else {
        parsed
            .object
            .insert("path".into(), serde_json::Value::String(path.to_owned()));
    }
}

#[cfg(unix)]
fn pe_cli_issue(path: &str, reason: &'static str, message: impl Into<String>) -> InputIssue {
    InputIssue {
        path: vec![path.into()],
        reason,
        message: message.into(),
        expected: None,
    }
}

#[cfg(unix)]
fn pe_input_failure(issues: Vec<InputIssue>) -> Failure {
    analysis_input_failure(PE_RESOURCES_OPERATION, issues)
}

#[cfg(unix)]
fn analysis_input_failure(operation: &str, issues: Vec<InputIssue>) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and try again.".into(),
        true,
        "Correct the listed arguments and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            ("issues", Detail::Issues(issues)),
        ]),
    )
}

#[cfg(unix)]
fn read_json_object_argument(
    input_path: &str,
    operation: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, Failure> {
    let text = std::fs::read_to_string(input_path).map_err(|error| {
        analysis_input_failure(
            operation,
            vec![pe_cli_issue(
                "",
                "invalid_value",
                format!("Could not read JSON input: {error}"),
            )],
        )
    })?;
    let input = serde_json::from_str::<serde_json::Value>(&text).map_err(|error| {
        analysis_input_failure(
            operation,
            vec![pe_cli_issue(
                "",
                "invalid_format",
                format!("Input is not valid JSON: {error}"),
            )],
        )
    })?;

    match input {
        serde_json::Value::Object(object) => Ok(object),
        _ => Err(analysis_input_failure(
            operation,
            vec![InputIssue {
                path: Vec::new(),
                reason: "invalid_type",
                message: "Invalid input: expected object".into(),
                expected: Some("object"),
            }],
        )),
    }
}

#[cfg(unix)]
fn run_android_class_search(
    input_path: &str,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let operation = rea_application::android::analysis::SEARCH_OPERATION;
    let input = match read_json_object_argument(input_path, operation) {
        Ok(input) => input,
        Err(failure) => {
            emit_json(&failure)?;
            return Ok(1);
        }
    };
    let request = match inputs::android_class_search(&input) {
        Ok(request) => request,
        Err(error) => {
            emit_json(&analysis_input_failure(operation, error.0))?;
            return Ok(1);
        }
    };

    let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
    let mut inspection = AndroidPackageInspection::new(access);
    let outcome = inspection.search_classes(
        &request.path,
        request.query,
        cancellation,
        Completion::OneShot,
    );
    let cleanup = inspection.close();

    finish_inspection_command(outcome, cleanup)
}

#[cfg(unix)]
fn run_android_reference_trace(
    input_path: &str,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let operation = rea_application::android::analysis::TRACE_OPERATION;
    let input = match read_json_object_argument(input_path, operation) {
        Ok(input) => input,
        Err(failure) => {
            emit_json(&failure)?;
            return Ok(1);
        }
    };
    let request = match inputs::android_reference_trace(&input) {
        Ok(request) => request,
        Err(error) => {
            emit_json(&analysis_input_failure(operation, error.0))?;
            return Ok(1);
        }
    };

    let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
    let mut inspection = AndroidPackageInspection::new(access);
    let outcome = inspection.trace_references(
        &request.path,
        request.class_name,
        request.method_name,
        request.overload_index,
        cancellation,
        Completion::OneShot,
    );
    let cleanup = inspection.close();

    finish_inspection_command(outcome, cleanup)
}

#[cfg(unix)]
enum InspectionCommand {
    Rust(RustInspection<rea_host::fs::unix_file::UnixFiles>),
    Go(GoInspection<rea_host::fs::unix_file::UnixFiles>),
}

#[cfg(unix)]
impl InspectionCommand {
    fn inspect(
        &mut self,
        path: &str,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<rea_core::evidence::ArtifactEvidence>, Failure> {
        match self {
            Self::Rust(service) => service.inspect(path, cancellation, completion),
            Self::Go(service) => service.inspect(path, cancellation, completion),
        }
    }

    fn close(&mut self) -> Result<(), Failure> {
        match self {
            Self::Rust(service) => service.close(),
            Self::Go(service) => service.close(),
        }
    }
}

struct EvidenceExportArguments {
    source: String,
    output: String,
    overwrite: bool,
}

struct CompareArguments {
    left: String,
    right: String,
}

#[cfg(unix)]
struct WebPageInspectionArguments {
    endpoint: String,
    target_id: String,
    allowed_origins: Vec<String>,
    observation_ms: u64,
    include_accessibility_text: bool,
    include_console_text: bool,
    include_json_body_shapes: bool,
    include_websocket_shapes: bool,
    include_script_sources: bool,
    include_storage_keys: bool,
    include_storage_fingerprints: bool,
}

#[cfg(unix)]
struct WebSessionObservationArguments {
    endpoint: String,
    target_id: String,
    allowed_origins: Vec<String>,
    observation_ms: u64,
}

#[cfg(unix)]
struct ElectronTargetListArguments {
    endpoint: String,
}

#[cfg(unix)]
struct ElectronPageInspectionArguments {
    endpoint: String,
    target_id: String,
    observation_ms: u64,
    include_script_sources: bool,
}

#[cfg(unix)]
struct WebEventListenerArguments {
    endpoint: String,
    target_id: String,
    selector: String,
    allowed_origins: Vec<String>,
}

#[cfg(unix)]
struct PreparedWebEventListenerInspection {
    input: serde_json::Value,
    websocket_endpoint: String,
    target_id: String,
}

#[cfg(unix)]
fn parse_electron_target_list_arguments(
    arguments: &[String],
) -> Result<ElectronTargetListArguments, Failure> {
    let mut positional = Vec::with_capacity(1);
    let mut format = None;
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(electron_cli_failure(
                        "list_electron_targets",
                        "--format requires a value; this command supports json.",
                    ));
                };
                if format.replace(value.as_str()).is_some() {
                    return Err(electron_cli_failure(
                        "list_electron_targets",
                        "--format may be supplied only once.",
                    ));
                }
            }
            argument if argument.starts_with('-') => {
                return Err(electron_cli_failure(
                    "list_electron_targets",
                    &format!("Unsupported list-electron-targets option: {argument}"),
                ));
            }
            argument => positional.push(argument.to_owned()),
        }
        index += 1;
    }

    if format != Some("json") {
        return Err(electron_cli_failure(
            "list_electron_targets",
            "list-electron-targets requires --format json in this experimental executable.",
        ));
    }
    let [endpoint] = positional.as_slice() else {
        return Err(electron_cli_failure(
            "list_electron_targets",
            "Usage: rea-native list-electron-targets ENDPOINT --format json",
        ));
    };

    Ok(ElectronTargetListArguments {
        endpoint: endpoint.clone(),
    })
}

#[cfg(unix)]
fn parse_electron_page_inspection_arguments(
    arguments: &[String],
) -> Result<ElectronPageInspectionArguments, Failure> {
    let mut positional = Vec::with_capacity(2);
    let mut format = None;
    let mut observation_ms = 100;
    let mut observation_ms_supplied = false;
    let mut include_script_sources = false;
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(electron_cli_failure(
                        "inspect_electron_page",
                        "--format requires a value; this command supports json.",
                    ));
                };
                if format.replace(value.as_str()).is_some() {
                    return Err(electron_cli_failure(
                        "inspect_electron_page",
                        "--format may be supplied only once.",
                    ));
                }
            }
            "--observation-ms" => {
                if observation_ms_supplied {
                    return Err(electron_cli_failure(
                        "inspect_electron_page",
                        "--observation-ms may be supplied only once.",
                    ));
                }
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(electron_cli_failure(
                        "inspect_electron_page",
                        "--observation-ms requires a non-negative integer.",
                    ));
                };
                observation_ms = value.parse().map_err(|_| {
                    electron_cli_failure(
                        "inspect_electron_page",
                        "--observation-ms must be a non-negative integer.",
                    )
                })?;
                observation_ms_supplied = true;
            }
            "--include-script-sources" => include_script_sources = true,
            argument if argument.starts_with('-') => {
                return Err(electron_cli_failure(
                    "inspect_electron_page",
                    &format!("Unsupported inspect-electron-page option: {argument}"),
                ));
            }
            argument => positional.push(argument.to_owned()),
        }
        index += 1;
    }

    if format != Some("json") {
        return Err(electron_cli_failure(
            "inspect_electron_page",
            "inspect-electron-page requires --format json in this experimental executable.",
        ));
    }
    let [endpoint, target_id] = positional.as_slice() else {
        return Err(electron_cli_failure(
            "inspect_electron_page",
            "Usage: rea-native inspect-electron-page ENDPOINT TARGET_ID --format json [--observation-ms N] [--include-script-sources]",
        ));
    };

    Ok(ElectronPageInspectionArguments {
        endpoint: endpoint.clone(),
        target_id: target_id.clone(),
        observation_ms,
        include_script_sources,
    })
}

#[cfg(unix)]
fn electron_cli_failure(operation: &'static str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide the selected loopback Electron endpoint and supported options.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}

#[cfg(unix)]
fn list_electron_targets_command(
    arguments: &ElectronTargetListArguments,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let input = serde_json::json!({"cdp_endpoint": arguments.endpoint});
    match rea_runtime::mcp::list_electron_targets(&input, cancellation) {
        Ok(evidence) => {
            emit_json(&evidence)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn inspect_electron_page_command(
    arguments: &ElectronPageInspectionArguments,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let input = serde_json::json!({
        "cdp_endpoint": arguments.endpoint,
        "target_id": arguments.target_id,
        "observation_ms": arguments.observation_ms,
        "include_script_sources": arguments.include_script_sources,
    });
    match rea_runtime::electron_page_handler::execute(input, cancellation) {
        Ok(evidence) => {
            emit_json(&evidence)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn parse_web_session_observation_arguments(
    arguments: &[String],
) -> Result<WebSessionObservationArguments, Failure> {
    let mut positional = Vec::with_capacity(2);
    let mut format = None;
    let mut allowed_origins = Vec::new();
    let mut observation_ms = 10_000;
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(web_session_cli_failure(
                        "--format requires a value; this command supports json.",
                    ));
                };
                if format.replace(value.as_str()).is_some() {
                    return Err(web_session_cli_failure(
                        "--format may be supplied only once.",
                    ));
                }
            }
            "--allowed-origins" => {
                index += 1;
                let Some(origin) = arguments.get(index) else {
                    return Err(web_session_cli_failure(
                        "--allowed-origins requires an exact origin.",
                    ));
                };
                allowed_origins.push(origin.clone());
            }
            "--observation-ms" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(web_session_cli_failure(
                        "--observation-ms requires a positive integer.",
                    ));
                };
                observation_ms = value.parse::<u64>().map_err(|_| {
                    web_session_cli_failure("--observation-ms must be a positive integer.")
                })?;
            }
            argument if argument.starts_with('-') => {
                return Err(web_session_cli_failure(&format!(
                    "Unsupported observe-web-session option: {argument}"
                )));
            }
            argument => positional.push(argument.to_owned()),
        }
        index += 1;
    }

    if format != Some("json") {
        return Err(web_session_cli_failure(
            "observe-web-session requires --format json in this experimental executable.",
        ));
    }
    let [endpoint, target_id] = positional.as_slice() else {
        return Err(web_session_cli_failure(
            "Usage: rea-native observe-web-session ENDPOINT TARGET_ID --format json [--allowed-origins ORIGIN] [--observation-ms N]",
        ));
    };
    if observation_ms == 0 || observation_ms > i32::MAX as u64 {
        return Err(web_session_cli_failure(
            "--observation-ms must be between 1 and 2147483647.",
        ));
    }

    Ok(WebSessionObservationArguments {
        endpoint: endpoint.clone(),
        target_id: target_id.clone(),
        allowed_origins,
        observation_ms,
    })
}

#[cfg(unix)]
fn observe_web_session_command(
    arguments: &WebSessionObservationArguments,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let input = serde_json::json!({
        "cdp_endpoint": arguments.endpoint,
        "target_id": arguments.target_id,
        "allowed_origins": arguments.allowed_origins,
        "observation_ms": arguments.observation_ms,
    });
    if let Err(error) = web::session_observation::validate_input(&input) {
        emit_json(&CliFailure {
            error: "Analysis failed",
            failure: &error,
        })?;
        return Ok(1);
    }
    if let Err(reason) = validate_loopback_cdp_endpoint(&arguments.endpoint) {
        let failure = web_session_cli_failure(reason);
        emit_json(&CliFailure {
            error: "Analysis failed",
            failure: &failure,
        })?;
        return Ok(1);
    }
    let websocket = match rea_runtime::mcp::resolve_page_websocket_endpoint(
        &arguments.endpoint,
        &arguments.target_id,
        cancellation,
    ) {
        Ok(websocket) => websocket,
        Err(error) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &error,
            })?;
            return Ok(1);
        }
    };
    match web_capture_offline_handlers::observe_live(&input, &websocket, cancellation) {
        Ok(result) => {
            emit_json(&result)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn web_session_cli_failure(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide a loopback CDP endpoint, target ID, and supported observation options.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(web::session_observation::OPERATION.into()),
        )]),
    )
}

#[cfg(unix)]
fn parse_web_event_listener_arguments(
    arguments: &[String],
) -> Result<WebEventListenerArguments, Failure> {
    let mut positional = Vec::with_capacity(3);
    let mut format = None;
    let mut allowed_origins = Vec::new();
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(web_event_listener_cli_failure(
                        "--format requires a value; this command supports json.",
                    ));
                };
                if format.replace(value.as_str()).is_some() {
                    return Err(web_event_listener_cli_failure(
                        "--format may be supplied only once.",
                    ));
                }
            }
            "--allowed-origins" => {
                index += 1;
                let Some(origin) = arguments.get(index) else {
                    return Err(web_event_listener_cli_failure(
                        "--allowed-origins requires an exact HTTP(S) origin.",
                    ));
                };
                allowed_origins.push(origin.clone());
            }
            argument if argument.starts_with('-') => {
                return Err(web_event_listener_cli_failure(&format!(
                    "Unsupported inspect-web-event-listeners option: {argument}"
                )));
            }
            argument => positional.push(argument.to_owned()),
        }
        index += 1;
    }

    if format != Some("json") {
        return Err(web_event_listener_cli_failure(
            "inspect-web-event-listeners requires --format json in this experimental executable.",
        ));
    }
    let [endpoint, target_id, selector] = positional.as_slice() else {
        return Err(web_event_listener_cli_failure(
            "Usage: rea-native inspect-web-event-listeners ENDPOINT TARGET_ID SELECTOR --format json [--allowed-origins ORIGIN]",
        ));
    };

    Ok(WebEventListenerArguments {
        endpoint: endpoint.clone(),
        target_id: target_id.clone(),
        selector: selector.clone(),
        allowed_origins,
    })
}

#[cfg(unix)]
fn web_event_listener_cli_failure(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide the caller-selected loopback endpoint, target ID, CSS selector, and exact origin filters."
            .into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(web_event_listeners::OPERATION.into()),
        )]),
    )
}

#[cfg(unix)]
fn parse_web_page_inspection_arguments(
    arguments: &[String],
) -> Result<WebPageInspectionArguments, Failure> {
    let mut positional = Vec::with_capacity(2);
    let mut format = None;
    let mut allowed_origins = Vec::new();
    let mut observation_ms = 500;
    let mut include_accessibility_text = false;
    let mut include_console_text = false;
    let mut include_json_body_shapes = false;
    let mut include_websocket_shapes = false;
    let mut include_script_sources = false;
    let mut include_storage_keys = false;
    let mut include_storage_fingerprints = false;
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(web_page_cli_failure(
                        "--format requires a value; this command supports json.",
                    ));
                };
                if format.replace(value.as_str()).is_some() {
                    return Err(web_page_cli_failure("--format may be supplied only once."));
                }
            }
            "--allowed-origins" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(web_page_cli_failure(
                        "--allowed-origins requires an exact HTTP(S) origin.",
                    ));
                };
                allowed_origins.push(value.clone());
            }
            "--observation-ms" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(web_page_cli_failure(
                        "--observation-ms requires a non-negative integer.",
                    ));
                };
                observation_ms = value.parse().map_err(|_| {
                    web_page_cli_failure("--observation-ms must be a non-negative integer.")
                })?;
            }
            "--include-accessibility-text" => include_accessibility_text = true,
            "--include-console-text" => include_console_text = true,
            "--include-json-body-shapes" => include_json_body_shapes = true,
            "--include-websocket-shapes" => include_websocket_shapes = true,
            "--include-script-sources" => include_script_sources = true,
            "--include-storage-keys" => include_storage_keys = true,
            "--include-storage-fingerprints" => include_storage_fingerprints = true,
            argument if argument.starts_with('-') => {
                return Err(web_page_cli_failure(&format!(
                    "Unsupported inspect-web-page option: {argument}"
                )));
            }
            argument => positional.push(argument.to_owned()),
        }
        index += 1;
    }

    if format != Some("json") {
        return Err(web_page_cli_failure(
            "inspect-web-page requires --format json in this experimental executable.",
        ));
    }
    let [endpoint, target_id] = positional.as_slice() else {
        return Err(web_page_cli_failure(
            "Usage: rea-native inspect-web-page ENDPOINT TARGET_ID --format json [options]",
        ));
    };

    Ok(WebPageInspectionArguments {
        endpoint: endpoint.clone(),
        target_id: target_id.clone(),
        allowed_origins,
        observation_ms,
        include_accessibility_text,
        include_console_text,
        include_json_body_shapes,
        include_websocket_shapes,
        include_script_sources,
        include_storage_keys,
        include_storage_fingerprints,
    })
}

#[cfg(unix)]
fn web_page_cli_failure(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide the caller-selected loopback endpoint, target ID, and valid inspection options."
            .into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(web::page_inspection::OPERATION.into()),
        )]),
    )
}

fn parse_compare_arguments(arguments: &[String]) -> Result<CompareArguments, String> {
    let mut positional = Vec::with_capacity(2);
    let mut format = None;
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err("--format requires a value; this command supports json.".into());
                };
                if format.replace(value.as_str()).is_some() {
                    return Err("--format may be supplied only once.".into());
                }
            }
            argument if argument.starts_with('-') => {
                return Err(format!("Unsupported compare option: {argument}"));
            }
            argument => positional.push(argument.to_owned()),
        }
        index += 1;
    }

    if format != Some("json") {
        return Err("compare requires --format json in this experimental executable.".into());
    }
    let [left, right] = positional.as_slice() else {
        return Err("Usage: rea-native compare <left> <right> --format json".into());
    };
    Ok(CompareArguments {
        left: left.clone(),
        right: right.clone(),
    })
}

fn parse_evidence_export_arguments(
    arguments: &[String],
) -> Result<EvidenceExportArguments, String> {
    let mut positional = Vec::with_capacity(2);
    let mut format = None;
    let mut overwrite = false;
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(
                        "--format requires a value; this experimental command supports json."
                            .into(),
                    );
                };
                if format.replace(value.as_str()).is_some() {
                    return Err("--format may be supplied only once.".into());
                }
            }
            "--overwrite" => overwrite = true,
            "--no-overwrite" => overwrite = false,
            argument if argument.starts_with('-') => {
                return Err(format!("Unsupported evidence-export option: {argument}"));
            }
            argument => positional.push(argument.to_owned()),
        }
        index += 1;
    }

    if format != Some("json") {
        return Err(
            "evidence-export requires --format json in this experimental executable.".into(),
        );
    }
    let [source, output] = positional.as_slice() else {
        return Err(
            "Usage: rea-native evidence-export <source> <output> --format json [--overwrite]"
                .into(),
        );
    };
    Ok(EvidenceExportArguments {
        source: source.clone(),
        output: output.clone(),
        overwrite,
    })
}

#[cfg(unix)]
fn export_evidence_bundle(
    arguments: &EvidenceExportArguments,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
    match bundle_export_command::export_source(
        access,
        &arguments.source,
        &arguments.output,
        arguments.overwrite,
        cancellation,
    ) {
        Ok(receipt) => {
            emit_json(&CliExportReceipt {
                path: receipt.path(),
                bytes: receipt.bytes(),
                records: receipt.records(),
            })?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn compare_evidence_bundles(
    arguments: &CompareArguments,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
    match bundle_comparison_command::compare_files(
        access,
        &arguments.left,
        &arguments.right,
        cancellation,
    ) {
        Ok(comparison) => {
            emit_json(&comparison)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn compare_web_captures(
    arguments: &web_capture_comparison_command::Arguments,
) -> Result<u8, Box<dyn std::error::Error>> {
    match web_capture_comparison_command::compare(arguments) {
        Ok(comparison) => {
            emit_json(&comparison)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn inspect_web_page_command(
    arguments: &WebPageInspectionArguments,
) -> Result<u8, Box<dyn std::error::Error>> {
    let input = serde_json::json!({
        "cdp_endpoint": arguments.endpoint,
        "allowed_origins": arguments.allowed_origins,
        "target_id": arguments.target_id,
        "observation_ms": arguments.observation_ms,
        "include_accessibility_text": arguments.include_accessibility_text,
        "include_console_text": arguments.include_console_text,
        "include_json_body_shapes": arguments.include_json_body_shapes,
        "include_websocket_shapes": arguments.include_websocket_shapes,
        "include_script_sources": arguments.include_script_sources,
        "include_storage_keys": arguments.include_storage_keys,
        "include_storage_fingerprints": arguments.include_storage_fingerprints,
    });

    if let Err(error) = web::page_inspection::validate_input(&input) {
        emit_json(&CliFailure {
            error: "Analysis failed",
            failure: &error,
        })?;
        return Ok(1);
    }

    if let Err(reason) = validate_loopback_cdp_endpoint(arguments.endpoint.as_str()) {
        let failure = web_page_cli_failure(reason);
        emit_json(&CliFailure {
            error: "Analysis failed",
            failure: &failure,
        })?;
        return Ok(1);
    }

    let websocket_endpoint = page_websocket_endpoint(&arguments.endpoint, &arguments.target_id)
        .map_err(|reason| web_page_cli_failure(&reason));
    let websocket_endpoint = match websocket_endpoint {
        Ok(endpoint) => endpoint,
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            return Ok(1);
        }
    };

    let started_at = capture_timestamp();
    let mut port = match ConnectedCdpWebPagePort::connect(&websocket_endpoint, &arguments.target_id)
    {
        Ok(port) => port,
        Err(error) => {
            let failure = web_page_connection_failure(error.to_string());
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            return Ok(1);
        }
    };
    let ended_at = capture_timestamp();

    let result = match port.inspect(&input, &started_at, &ended_at) {
        Ok(result) => result,
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            return Ok(1);
        }
    };
    let result = match web::page_inspection::retain_result(&input, result) {
        Ok(result) => result,
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            return Ok(1);
        }
    };

    emit_json(&result)?;
    Ok(0)
}

#[cfg(unix)]
fn inspect_web_event_listeners_command(
    arguments: &WebEventListenerArguments,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let result = inspect_web_event_listeners(arguments, cancellation);
    match result {
        Ok(result) => {
            emit_json(&result)?;
            Ok(0)
        }
        Err(failure) => {
            emit_json(&CliFailure {
                error: "Analysis failed",
                failure: &failure,
            })?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn inspect_web_event_listeners(
    arguments: &WebEventListenerArguments,
    cancellation: &Cancellation,
) -> Result<serde_json::Value, Failure> {
    let prepared = prepare_web_event_listener_inspection(arguments)?;
    let mut port = connect_web_event_listener_target(&prepared)?;

    inspect_connected_web_event_listener_target(&prepared, &mut port, cancellation)
}

#[cfg(unix)]
fn prepare_web_event_listener_inspection(
    arguments: &WebEventListenerArguments,
) -> Result<PreparedWebEventListenerInspection, Failure> {
    let input = serde_json::json!({
        "cdp_endpoint": arguments.endpoint,
        "allowed_origins": arguments.allowed_origins,
        "target_id": arguments.target_id,
        "selector": arguments.selector,
    });

    web_event_listeners::validate_input(&input)?;

    validate_loopback_cdp_endpoint(&arguments.endpoint).map_err(web_event_listener_cli_failure)?;
    let websocket_endpoint = page_websocket_endpoint(&arguments.endpoint, &arguments.target_id)
        .map_err(|reason| web_event_listener_cli_failure(&reason))?;

    Ok(PreparedWebEventListenerInspection {
        input,
        websocket_endpoint,
        target_id: arguments.target_id.clone(),
    })
}

#[cfg(unix)]
fn connect_web_event_listener_target(
    prepared: &PreparedWebEventListenerInspection,
) -> Result<ConnectedCdpEventListenerPort<rea_host::cdp_transport::CdpWebSocketTransport>, Failure>
{
    ConnectedCdpEventListenerPort::connect(&prepared.websocket_endpoint, &prepared.target_id)
        .map_err(|error| web_event_listener_connection_failure(error.to_string()))
}

#[cfg(unix)]
fn inspect_connected_web_event_listener_target(
    prepared: &PreparedWebEventListenerInspection,
    port: &mut ConnectedCdpEventListenerPort<rea_host::cdp_transport::CdpWebSocketTransport>,
    cancellation: &Cancellation,
) -> Result<serde_json::Value, Failure> {
    let started_at = capture_timestamp();
    let result = port.inspect_with_cancellation(
        &prepared.input,
        &started_at,
        &capture_timestamp(),
        cancellation,
    )?;

    web_event_listeners::retain_result(&prepared.input, result)
}

#[cfg(unix)]
fn validate_loopback_cdp_endpoint(endpoint: &str) -> Result<(), &'static str> {
    let authority = endpoint
        .strip_prefix("http://")
        .ok_or("cdp_endpoint must use an HTTP loopback endpoint")?;
    if authority.is_empty() || authority.contains(['/', '?', '#']) {
        return Err("cdp_endpoint must be a bare loopback HTTP origin");
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or("cdp_endpoint must include an explicit port")?;
    if !matches!(host, "127.0.0.1" | "[::1]" | "::1") {
        return Err("cdp_endpoint must target loopback");
    }
    if port.is_empty() || !port.chars().all(|character| character.is_ascii_digit()) {
        return Err("cdp_endpoint port must be numeric");
    }
    Ok(())
}

#[cfg(unix)]
fn page_websocket_endpoint(endpoint: &str, target_id: &str) -> Result<String, String> {
    let authority = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| "native CDP transport requires an HTTP endpoint".to_owned())?;
    if target_id.is_empty() || target_id.contains(['/', '?', '#']) {
        return Err("target_id must be a non-empty target identifier".into());
    }
    Ok(format!("ws://{authority}/devtools/page/{target_id}"))
}

#[cfg(unix)]
fn capture_timestamp() -> String {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", elapsed.as_secs(), elapsed.subsec_millis())
}

#[cfg(unix)]
fn web_page_connection_failure(reason: String) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        "The selected browser page could not be inspected.".into(),
        true,
        "Check the caller-selected browser endpoint and target, then retry.".into(),
        BTreeMap::from([
            (
                "operation",
                Detail::Text(web::page_inspection::OPERATION.into()),
            ),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

#[cfg(unix)]
fn web_event_listener_connection_failure(reason: String) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        "The selected browser page could not be inspected for event listeners.".into(),
        true,
        "Check the caller-selected browser endpoint and target, then retry.".into(),
        BTreeMap::from([
            (
                "operation",
                Detail::Text(web_event_listeners::OPERATION.into()),
            ),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

#[cfg(unix)]
#[derive(serde::Serialize)]
struct CliFailure<'a> {
    error: &'static str,
    #[serde(flatten)]
    failure: &'a rea_core::failure::Failure,
}

#[cfg(unix)]
#[derive(serde::Serialize)]
struct CliExportReceipt<'a> {
    path: &'a str,
    bytes: u64,
    records: usize,
}

#[cfg(unix)]
fn import_evidence_bundle(
    input_path: &str,
    cancellation: &Cancellation,
) -> Result<u8, Box<dyn std::error::Error>> {
    let path = rea_host::fs::caller_path::absolute(input_path)?;
    let access = Arc::new(rea_host::fs::unix_file::UnixFiles);
    let records = ArtifactRecords::default();
    let mut importer = BundleImporter::new(access);

    let imported = importer.import(&records, &path, cancellation, Completion::OneShot);
    let cleanup = importer.close();

    match (imported, cleanup) {
        (Ok(receipt), Ok(())) => {
            emit_json(&CliImportReceipt {
                imported: receipt.imported,
                unknowns_added: receipt.unknowns_added,
                total: receipt.total,
            })?;
            Ok(0)
        }
        (Err(failure), Ok(())) | (Ok(_), Err(failure)) => {
            emit_json(&failure)?;
            Ok(1)
        }
        (Err(mut primary), Err(cleanup)) => {
            retain_failure_detail(&mut primary, "cleanup_failure", &cleanup);
            emit_json(&primary)?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn finish_inspection_command(
    outcome: Result<Arc<rea_core::evidence::ArtifactEvidence>, Failure>,
    cleanup: Result<(), Failure>,
) -> Result<u8, Box<dyn std::error::Error>> {
    match (outcome, cleanup) {
        (Ok(evidence), Ok(())) => {
            emit_json(&evidence)?;
            Ok(0)
        }
        (Err(failure), Ok(())) => {
            emit_json(&failure)?;
            Ok(1)
        }
        (Err(mut failure), Err(cleanup)) => {
            retain_failure_detail(&mut failure, "cleanup_failure", &cleanup);
            emit_json(&failure)?;
            Ok(1)
        }
        (Ok(evidence), Err(mut cleanup)) => {
            retain_failure_detail(&mut cleanup, "partial_observation", evidence.as_ref());
            emit_json(&cleanup)?;
            Ok(1)
        }
    }
}

#[cfg(unix)]
fn retain_failure_detail<T: serde::Serialize + std::fmt::Debug + ?Sized>(
    failure: &mut Failure,
    name: &'static str,
    value: &T,
) {
    match serde_json::value::to_raw_value(value) {
        Ok(value) => failure.detail(name, Detail::Raw(value)),
        Err(error) => {
            failure.detail(name, Detail::Text(format!("{value:?}")));
            failure.detail("detail_encoding_failure", Detail::Text(error.to_string()));
        }
    }
}

#[cfg(unix)]
#[derive(serde::Serialize)]
struct CliImportReceipt {
    imported: usize,
    unknowns_added: usize,
    total: usize,
}

// One stdout owner for every command branch, including help and failures.
// A buffered write may succeed before its newline/flush reports a closed peer.
fn emit_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let pretty = stdout.is_terminal();
    let mut output = stdout.lock();
    write_json_document(value, &mut output, pretty)
}

fn write_json_document<T: serde::Serialize + ?Sized, W: Write>(
    value: &T,
    output: &mut W,
    pretty: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if pretty {
        serde_json::to_writer_pretty(&mut *output, value)?;
    } else {
        serde_json::to_writer(&mut *output, value)?;
    }

    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn normalize_cli_output_arguments(arguments: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::with_capacity(arguments.len() + 1);
    let mut positional_only = false;
    let mut index = 0;

    while index < arguments.len() {
        let argument = &arguments[index];

        if positional_only {
            normalized.push(argument.clone());
            index += 1;
            continue;
        }

        if argument == "--" {
            positional_only = true;
            normalized.push(argument.clone());
            index += 1;
            continue;
        }

        if let Some(format) = argument.strip_prefix("--format=") {
            normalized.push("--format".into());
            normalized.push(format.into());
            index += 1;
            continue;
        }

        if argument == "--format" {
            normalized.push(argument.clone());
            if let Some(value) = arguments.get(index + 1) {
                normalized.push(value.clone());
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if takes_value(argument) {
            normalized.push(argument.clone());
            if let Some(value) = arguments.get(index + 1) {
                normalized.push(value.clone());
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if argument == "--json" {
            normalized.push("--format".into());
            normalized.push("json".into());
        } else {
            normalized.push(argument.clone());
        }

        index += 1;
    }

    normalized
}

fn takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "--max-file-bytes"
            | "--max-entries"
            | "--host"
            | "--port"
            | "--normalization-json"
            | "--root"
            | "--offset"
            | "--limit"
            | "--detail"
            | "--evidence_output"
            | "--evidence-output"
    )
}

fn emit_line(text: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

#[cfg(test)]
mod cli_output_tests {
    use super::{normalize_cli_output_arguments, write_json_document};

    #[test]
    fn terminal_json_is_indented_and_ends_with_a_newline() {
        let value = serde_json::json!({"artifact": {"format": "ELF"}});
        let mut output = Vec::new();

        write_json_document(&value, &mut output, true).expect("write terminal JSON");

        assert_eq!(
            output,
            b"{\n  \"artifact\": {\n    \"format\": \"ELF\"\n  }\n}\n"
        );
    }

    #[test]
    fn redirected_json_is_compact_and_ends_with_a_newline() {
        let value = serde_json::json!({"artifact": {"format": "ELF"}});
        let mut output = Vec::new();

        write_json_document(&value, &mut output, false).expect("write redirected JSON");

        assert_eq!(output, b"{\"artifact\":{\"format\":\"ELF\"}}\n");
    }

    #[test]
    fn json_alias_and_equals_form_normalize_for_every_command() {
        assert_eq!(
            normalize_cli_output_arguments(vec![
                "inspect-plist".into(),
                "sample.plist".into(),
                "--json".into(),
            ]),
            ["inspect-plist", "sample.plist", "--format", "json"]
        );
        assert_eq!(
            normalize_cli_output_arguments(vec![
                "inspect-plist".into(),
                "sample.plist".into(),
                "--format=json".into(),
            ]),
            ["inspect-plist", "sample.plist", "--format", "json"]
        );
    }

    #[test]
    fn option_values_and_positional_only_arguments_are_not_output_aliases() {
        assert_eq!(
            normalize_cli_output_arguments(vec![
                "inspect-pe-resources".into(),
                "sample.exe".into(),
                "--max-entries".into(),
                "--json".into(),
            ]),
            [
                "inspect-pe-resources",
                "sample.exe",
                "--max-entries",
                "--json"
            ]
        );
        assert_eq!(
            normalize_cli_output_arguments(vec![
                "inspect-plist".into(),
                "--".into(),
                "--json".into(),
            ]),
            ["inspect-plist", "--", "--json"]
        );
    }
}
